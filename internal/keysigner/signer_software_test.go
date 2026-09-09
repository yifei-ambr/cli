// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package keysigner

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestSoftwareSignerRS256Lifecycle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	unlock := func(context.Context) ([]byte, error) { return []byte("synthetic-rsa-unlock-secret-32-bytes"), nil }
	signer, err := NewSoftwareSigner(dir, unlock)
	if err != nil {
		t.Fatal(err)
	}
	ref := KeyRef{Label: "rsa-registration", Algorithm: AlgRS256}
	public, err := signer.EnsureKey(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := NewSoftwareSigner(dir, unlock)
	if err != nil {
		t.Fatal(err)
	}
	for _, wrongAlgorithm := range []string{"", AlgES256} {
		wrong := KeyRef{Label: ref.Label, Algorithm: wrongAlgorithm}
		if _, err := reopened.EnsureKey(ctx, wrong); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("algorithm switch replaced the existing key: %v", err)
		}
		if _, err := reopened.PublicKey(ctx, wrong); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("algorithm switch accepted the existing public key: %v", err)
		}
		if _, _, err := reopened.Sign(ctx, wrong, []byte("check")); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("algorithm switch signed with the wrong key: %v", err)
		}
		if err := reopened.DeleteKey(ctx, wrong); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("algorithm switch deleted the existing key: %v", err)
		}
	}
	got, err := reopened.PublicKey(ctx, ref)
	if err != nil || !public.(*rsa.PublicKey).Equal(got) {
		t.Fatalf("reopening RSA key changed its public identity: %v", err)
	}
	input := []byte("registration.header.payload")
	signature, algorithm, err := reopened.Sign(ctx, ref, input)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(input)
	if algorithm != AlgRS256 || rsa.VerifyPKCS1v15(public.(*rsa.PublicKey), crypto.SHA256, digest[:], signature) != nil {
		t.Fatal("persisted RS256 signature failed independent verification")
	}
	if err := reopened.DeleteKey(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.PublicKey(ctx, ref); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("public key after deletion: %v", err)
	}
	if _, _, err := reopened.Sign(ctx, ref, input); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("sign recreated a missing RSA key: %v", err)
	}
}

func TestSoftwareSignerPersistenceAndTampering(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	unlock := func(context.Context) ([]byte, error) { return []byte("synthetic-test-unlock-secret-32-bytes"), nil }
	signer, err := NewSoftwareSigner(dir, unlock)
	if err != nil {
		t.Fatal(err)
	}
	ref := KeyRef{Label: "software-test-persistence"}
	public, err := signer.EnsureKey(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, fmt.Sprintf("%x.json", sha256.Sum256([]byte(ref.Label))))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("key file must be mode 0600:", err)
	}
	var record keyFileRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	var envelope softwareEnvelope
	if err := json.Unmarshal(record.Data, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.KDF != softwareKDF || len(envelope.Salt) != 16 || len(envelope.Nonce) != 12 || len(envelope.Ciphertext) < 16 {
		t.Fatal("invalid encrypted envelope")
	}
	if _, err := x509.ParsePKCS8PrivateKey(envelope.Ciphertext); err == nil {
		t.Fatal("ciphertext contains plaintext PKCS8")
	}

	t.Run("new_instance_opens_same_key_and_signs", func(t *testing.T) {
		reopened, err := NewSoftwareSigner(dir, unlock)
		if err != nil {
			t.Fatal(err)
		}
		got, err := reopened.PublicKey(ctx, ref)
		if err != nil || !public.(*ecdsa.PublicKey).Equal(got) {
			t.Fatal("public key changed:", err)
		}
		input := []byte("independent signature check")
		sig, alg, err := reopened.Sign(ctx, ref, input)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(input)
		if alg != AlgES256 || len(sig) != 64 || !ecdsa.Verify(public.(*ecdsa.PublicKey), digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			t.Fatal("invalid ES256 signature")
		}
		if _, err := reopened.(KeyCreator).CreateKey(ctx, ref); !errors.Is(err, ErrKeyExists) {
			t.Errorf("duplicate creation: %v", err)
		}
	})
	t.Run("wrong_unlock", func(t *testing.T) {
		wrong, err := NewSoftwareSigner(dir, func(context.Context) ([]byte, error) { return []byte("different-synthetic-unlock-secret"), nil })
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := wrong.Sign(ctx, ref, []byte("check")); !errors.Is(err, ErrUnlock) {
			t.Errorf("wrong secret: %v", err)
		}
	})
	t.Run("encrypted_key_cannot_be_relabelled", func(t *testing.T) {
		// Keep the ciphertext and public key intact, but move them to a valid
		// new label/path. The encrypted envelope must authenticate ownership.
		moved := record
		moved.Label = "different-valid-identity"
		payload, err := json.Marshal(moved)
		if err != nil {
			t.Fatal(err)
		}
		movedPath := filepath.Join(dir, fmt.Sprintf("%x.json", sha256.Sum256([]byte(moved.Label))))
		if err := os.WriteFile(movedPath, payload, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := signer.Sign(ctx, KeyRef{Label: moved.Label}, []byte("check")); !errors.Is(err, ErrUnlock) {
			t.Fatalf("encrypted key accepted a different identity: %v", err)
		}
	})
	for _, field := range []string{"ciphertext", "label", "public_key", "backend", "symlink"} {
		t.Run(field, func(t *testing.T) {
			defer func() {
				_ = os.Remove(path)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Error(err)
				}
			}()
			var changed keyFileRecord
			if err := json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "ciphertext":
				var encrypted softwareEnvelope
				if err := json.Unmarshal(changed.Data, &encrypted); err != nil {
					t.Fatal(err)
				}
				encrypted.Ciphertext[0] ^= 1
				changed.Data, _ = json.Marshal(encrypted)
			case "label":
				changed.Label = "different-label"
			case "public_key":
				changed.PublicKey[0] ^= 1
			case "backend":
				changed.Backend = "different-provider"
			case "symlink":
				other := filepath.Join(dir, "symlink-target.json")
				if err := os.WriteFile(other, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, path); err != nil {
					t.Fatal(err)
				}
			}
			if field != "symlink" {
				tampered, _ := json.Marshal(changed)
				if err := os.WriteFile(path, tampered, 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, _, err := signer.Sign(ctx, ref, []byte("check"))
			if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrUnlock) {
				t.Errorf("tampering was not rejected with typed cause: %v", err)
			}
		})
	}
	t.Run("concurrent_ensure_preserves_identity", func(t *testing.T) {
		// Race first creation, not reads of an already committed key.
		fresh := KeyRef{Label: "concurrent-first-creation"}
		start := make(chan struct{})
		publicKeys := make(chan *ecdsa.PublicKey, 3)
		var wg sync.WaitGroup
		for range 3 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				got, err := signer.EnsureKey(ctx, fresh)
				if err != nil {
					t.Errorf("concurrent creation: %v", err)
					return
				}
				publicKeys <- got.(*ecdsa.PublicKey)
			}()
		}
		close(start)
		wg.Wait()
		close(publicKeys)
		var first *ecdsa.PublicKey
		for public := range publicKeys {
			if first == nil {
				first = public
			} else if !first.Equal(public) {
				t.Error("concurrent creators committed different identities")
			}
		}
	})
	t.Run("cancellation_and_no_recreation", func(t *testing.T) {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, _, err := signer.Sign(canceled, ref, []byte("check")); !errors.Is(err, context.Canceled) {
			t.Errorf("cancellation: %v", err)
		}
		if err := signer.DeleteKey(ctx, ref); err != nil {
			t.Fatal(err)
		}
		if _, err := signer.PublicKey(ctx, ref); !errors.Is(err, ErrKeyNotFound) {
			t.Errorf("public key after delete: %v", err)
		}
		if _, _, err := signer.Sign(ctx, ref, []byte("check")); !errors.Is(err, ErrKeyNotFound) {
			t.Errorf("sign after delete: %v", err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Error("missing key was recreated")
		}
	})
}

func TestSoftwareSignerClearsUnlockBuffersAndPreservesFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		secret := []byte("synthetic-unlock-secret-at-least-16-bytes")
		cause := errors.New("unlock provider failed")
		signer, err := NewSoftwareSigner(t.TempDir(), func(context.Context) ([]byte, error) {
			if fail {
				return secret, cause
			}
			return secret, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = signer.EnsureKey(context.Background(), KeyRef{Label: "unlock-buffer"})
		if fail && !errors.Is(err, cause) {
			t.Fatalf("lost unlock cause: %v", err)
		}
		if !fail && err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatal("caller-supplied unlock buffer was retained")
		}
	}
	for _, size := range []int{0, 15, 1025} {
		dir := t.TempDir()
		signer, err := NewSoftwareSigner(dir, func(context.Context) ([]byte, error) { return make([]byte, size), nil })
		if err != nil {
			t.Fatal(err)
		}
		if _, err := signer.EnsureKey(context.Background(), KeyRef{Label: "invalid-unlock"}); !errors.Is(err, ErrUnlockRequired) {
			t.Fatalf("unlock length %d: %v", size, err)
		}
		files, err := filepath.Glob(filepath.Join(dir, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) != 0 {
			t.Fatal("failed creation published a key record")
		}
	}
}
