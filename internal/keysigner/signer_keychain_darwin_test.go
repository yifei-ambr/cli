//go:build darwin

// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package keysigner

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/larksuite/cli/internal/vfs"
)

type metadataOnlyKeychainFS struct {
	vfs.FS
	metadata []byte
}

func (f metadataOnlyKeychainFS) ReadFile(string) ([]byte, error) { return f.metadata, nil }

func TestKeychainRS256MetadataAndAlgorithmIsolation(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	nativePublic := x509.MarshalPKCS1PublicKey(&private.PublicKey)
	label := sha1.Sum(nativePublic)
	// Same PKIX/public-key and PKCS#1/application-label format as the RSA signer.
	pkix, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	md := keyMetadata{PublicKey: base64.StdEncoding.EncodeToString(pkix), AppLabel: hex.EncodeToString(label[:])}
	algorithm := rs256Algorithm{}
	public, err := algorithm.keychainMetadataPublicKey(&md)
	if err != nil || !private.PublicKey.Equal(public) {
		t.Fatalf("RSA metadata lost public identity: %v", err)
	}
	parsed, err := algorithm.parseKeychainPublicKey(nativePublic)
	if err != nil || !private.PublicKey.Equal(parsed) {
		t.Fatalf("native RSA public key parse: %v", err)
	}
	if id, bits := algorithm.keychainKeyParameters(); id != 42 || bits != 2048 {
		t.Fatalf("RSA native generation parameters = %d, %d", id, bits)
	}
	wrongLabel := md
	wrongLabel.AppLabel = hex.EncodeToString(make([]byte, sha1.Size))
	if _, err := algorithm.keychainMetadataPublicKey(&wrongLabel); err == nil {
		t.Fatal("RSA metadata accepted an unrelated application label")
	}
	data, err := json.Marshal(md)
	if err != nil {
		t.Fatal(err)
	}
	previous := vfs.DefaultFS
	vfs.DefaultFS = metadataOnlyKeychainFS{metadata: data}
	t.Cleanup(func() { vfs.DefaultFS = previous })
	ctx := context.Background()
	ref := KeyRef{Label: "existing-rsa", Algorithm: AlgES256}
	// Any storage mutation panics through the nil FS. No native key is touched.
	for _, operation := range []func() error{
		func() error { _, err := ensureKeyUnlocked(ctx, ref, es256Algorithm{}); return err },
		func() error { _, err := publicKeyUnlocked(ctx, ref, es256Algorithm{}); return err },
		func() error { _, _, err := signWithKeychain(ctx, ref, nil, es256Algorithm{}); return err },
		func() error { return deleteKeyUnlocked(ctx, ref, es256Algorithm{}) },
	} {
		if err := operation(); err == nil {
			t.Fatal("ES256 operation accepted an existing RSA identity")
		}
	}
}

// Only these reads are allowed: an unexpected filesystem operation panics
// through the nil embedded FS instead of reaching the developer's keychain.
type existingKeychainTestFS struct {
	vfs.FS
	path          string
	passwordReads [][]byte
}

func (f *existingKeychainTestFS) ReadFile(path string) ([]byte, error) {
	if path != filepath.Join(filepath.Dir(f.path), "keychain.pass") {
		return nil, fs.ErrPermission
	}
	data := []byte("fixture-existing-password\n")
	f.passwordReads = append(f.passwordReads, data)
	return data, nil
}

func (f *existingKeychainTestFS) Stat(path string) (fs.FileInfo, error) {
	if path != f.path {
		return nil, fs.ErrPermission
	}
	return (fstest.MapFS{"keychain": &fstest.MapFile{Mode: 0600}}).Stat("keychain")
}

func TestExistingKeychainIsUnlockedOnEveryUseAndPasswordCleared(t *testing.T) {
	path, err := keychainFilePath()
	if err != nil {
		t.Fatal(err)
	}
	fakeFS := &existingKeychainTestFS{path: path}
	oldFS, oldCreate, oldUnlock := vfs.DefaultFS, createKeychainFile, unlockKeychainFile
	t.Cleanup(func() { vfs.DefaultFS, createKeychainFile, unlockKeychainFile = oldFS, oldCreate, oldUnlock })
	vfs.DefaultFS = fakeFS
	createKeychainFile = func(string, []byte) error { t.Fatal("existing keychain was recreated"); return nil }
	cause := errors.New("native unlock denied")
	for _, failure := range []error{nil, cause} {
		var nativePassword []byte
		unlockKeychainFile = func(gotPath string, password []byte) error {
			if gotPath != path || string(password) != "fixture-existing-password" {
				t.Fatal("unlock used the wrong keychain or password")
			}
			nativePassword = password
			return failure
		}
		got, err := ensureKeychainLocked()
		if !errors.Is(err, failure) || (failure == nil && got != path) {
			t.Fatalf("unlock result = %q, %v", got, err)
		}
		if len(nativePassword) == 0 || !bytes.Equal(nativePassword, make([]byte, len(nativePassword))) {
			t.Fatal("unlock was skipped or retained its password buffer")
		}
	}
	for _, data := range fakeFS.passwordReads {
		if !bytes.Equal(data, make([]byte, len(data))) {
			t.Fatal("password file read buffer was retained")
		}
	}
}

func TestKeychainInteractionStateRestoredOnFailureAndPanic(t *testing.T) {
	oldGet, oldSet := getKeychainUserInteractionAllowed, setKeychainUserInteractionAllowed
	t.Cleanup(func() { getKeychainUserInteractionAllowed, setKeychainUserInteractionAllowed = oldGet, oldSet })
	for _, previous := range []bool{false, true} {
		for _, scenario := range []string{"success", "operation_error", "restore_error", "both_errors", "panic"} {
			t.Run(scenario+"/"+map[bool]string{false: "already_disabled", true: "enabled"}[previous], func(t *testing.T) {
				allowed := previous
				var transitions []bool
				operationErr, restoreErr := errors.New("operation failed"), errors.New("restore failed")
				getKeychainUserInteractionAllowed = func() (bool, error) { return allowed, nil }
				setKeychainUserInteractionAllowed = func(value bool) error {
					transitions = append(transitions, value)
					if len(transitions) == 2 && (scenario == "restore_error" || scenario == "both_errors") {
						return restoreErr
					}
					allowed = value
					return nil
				}
				var got error
				var panicked any
				func() {
					defer func() { panicked = recover() }()
					got = withKeychainUserInteractionDisabled(context.Background(), func() error {
						if allowed {
							t.Error("native operation could display UI")
						}
						switch scenario {
						case "operation_error", "both_errors":
							return operationErr
						case "panic":
							panic("fixture panic")
						default:
							return nil
						}
					})
				}()
				if !slices.Equal(transitions, []bool{false, previous}) {
					t.Fatalf("UI transitions = %v", transitions)
				}
				if (scenario == "operation_error" || scenario == "both_errors") && !errors.Is(got, operationErr) {
					t.Fatalf("lost operation cause: %v", got)
				}
				if (scenario == "restore_error" || scenario == "both_errors") && !errors.Is(got, restoreErr) {
					t.Fatalf("lost restoration cause: %v", got)
				}
				if scenario == "success" && (got != nil || allowed != previous) {
					t.Fatalf("successful operation did not restore UI: %v", got)
				}
				if scenario == "panic" && (panicked != "fixture panic" || allowed != previous) {
					t.Fatal("panic skipped restoration")
				}
				select {
				case <-keychainUserInteractionOperation:
					keychainUserInteractionOperation <- struct{}{}
				default:
					t.Fatal("UI operation lock was not released")
				}
			})
		}
	}
}

func TestKeychainInteractionFailuresPreventNativeOperation(t *testing.T) {
	oldGet, oldSet := getKeychainUserInteractionAllowed, setKeychainUserInteractionAllowed
	t.Cleanup(func() { getKeychainUserInteractionAllowed, setKeychainUserInteractionAllowed = oldGet, oldSet })
	cause := errors.New("native UI state unavailable")
	for _, failGet := range []bool{true, false} {
		getKeychainUserInteractionAllowed = func() (bool, error) {
			if failGet {
				return false, cause
			}
			return true, nil
		}
		setKeychainUserInteractionAllowed = func(bool) error { return cause }
		if err := withKeychainUserInteractionDisabled(context.Background(), func() error { t.Fatal("native operation ran without suppressing UI"); return nil }); !errors.Is(err, cause) {
			t.Fatal(err)
		}
	}
	// Cancellation while waiting for the process-global UI lock must not wait
	// for another native operation or alter that operation's interaction state.
	<-keychainUserInteractionOperation
	defer func() { keychainUserInteractionOperation <- struct{}{} }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := withKeychainUserInteractionDisabled(ctx, func() error { t.Fatal("canceled operation ran"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestKeychainMetadataRejectsPublicKeySubstitution(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	label := sha1.Sum(elliptic.Marshal(elliptic.P256(), key.X, key.Y))
	md := keyMetadata{PublicKey: base64.StdEncoding.EncodeToString(der), AppLabel: hex.EncodeToString(label[:])}
	algorithm := es256Algorithm{}
	public, err := algorithm.keychainMetadataPublicKey(&md)
	if err != nil || !key.PublicKey.Equal(public) {
		t.Fatalf("valid native metadata: %v", err)
	}
	for _, scenario := range []string{"different_key", "different_label", "invalid_hex", "short_label", "wrong_curve"} {
		changed := md
		switch scenario {
		case "different_key", "wrong_curve":
			curve := elliptic.P256()
			if scenario == "wrong_curve" {
				curve = elliptic.P384()
			}
			other, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			data, err := x509.MarshalPKIXPublicKey(&other.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			changed.PublicKey = base64.StdEncoding.EncodeToString(data)
		case "different_label":
			changed.AppLabel = hex.EncodeToString(make([]byte, sha1.Size))
		case "invalid_hex":
			changed.AppLabel = "not-hex"
		case "short_label":
			changed.AppLabel = "00"
		}
		if _, err := algorithm.keychainMetadataPublicKey(&changed); err == nil {
			t.Errorf("accepted %s", scenario)
		}
	}
}
