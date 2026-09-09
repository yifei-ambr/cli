// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package keysigner

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"testing"
)

func TestES256JOSEEncodingRejectsInvalidScalars(t *testing.T) {
	algorithm := es256Algorithm{}
	n := elliptic.P256().Params().N
	for _, tc := range []struct {
		name            string
		r, s            *big.Int
		trailing, valid bool
	}{
		{"padding", big.NewInt(1), big.NewInt(128), false, true},
		{"max_scalar", new(big.Int).Sub(n, big.NewInt(1)), big.NewInt(1), false, true},
		{"zero", big.NewInt(0), big.NewInt(1), false, false},
		{"negative", big.NewInt(1), big.NewInt(-1), false, false},
		{"r_outside_curve_order", new(big.Int).Set(n), big.NewInt(1), false, false},
		{"s_outside_curve_order", big.NewInt(1), new(big.Int).Set(n), false, false},
		{"trailing_data", big.NewInt(1), big.NewInt(1), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der, err := asn1.Marshal(struct{ R, S *big.Int }{tc.r, tc.s})
			if err != nil {
				t.Fatal(err)
			}
			if tc.trailing {
				der = append(der, 0)
			}
			sig, err := algorithm.signatureToJOSE(der)
			if !tc.valid {
				if err == nil {
					t.Fatal("accepted malformed signature")
				}
				return
			}
			if err != nil || len(sig) != 64 || new(big.Int).SetBytes(sig[:32]).Cmp(tc.r) != 0 || new(big.Int).SetBytes(sig[32:]).Cmp(tc.s) != 0 {
				t.Fatalf("invalid JOSE representation: %x, %v", sig, err)
			}
		})
	}
}

type brokenCryptoSigner struct {
	crypto.Signer
	err error
}

func (s brokenCryptoSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return []byte{0x30, 0}, s.err
}

func TestES256SignatureVerificationAndPrivateKeyClearing(t *testing.T) {
	algorithm := es256Algorithm{}
	key, err := algorithm.generateKey()
	if err != nil {
		t.Fatal(err)
	}
	public := key.Public().(*ecdsa.PublicKey)
	input := []byte("proof.header.payload")
	sig, err := algorithm.sign(key, input)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(input)
	if len(sig) != 64 || !ecdsa.Verify(public, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("signature rejected by independent verifier")
	}
	if _, err := algorithm.sign(brokenCryptoSigner{Signer: key}, input); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid backend signature accepted: %v", err)
	}
	cause := errors.New("backend signing error")
	if _, err := algorithm.sign(brokenCryptoSigner{Signer: key, err: cause}, input); !errors.Is(err, cause) {
		t.Fatalf("lost signing cause: %v", err)
	}
	before := elliptic.Marshal(public.Curve, public.X, public.Y)
	algorithm.clearPrivateKey(key)
	if key.(*ecdsa.PrivateKey).D.Sign() != 0 || !bytes.Equal(before, elliptic.Marshal(public.Curve, public.X, public.Y)) {
		t.Fatal("clearing private scalar invalidated public identity")
	}
}

func TestES256RejectsInvalidPublicKeys(t *testing.T) {
	for _, public := range []crypto.PublicKey{
		nil, (*ecdsa.PublicKey)(nil), []byte("not a key"),
		&ecdsa.PublicKey{Curve: elliptic.P384(), X: elliptic.P384().Params().Gx, Y: elliptic.P384().Params().Gy},
		&ecdsa.PublicKey{Curve: elliptic.P256()},
		&ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)},
	} {
		if _, err := P256PublicKey(public); err == nil {
			t.Errorf("accepted invalid public key: %T", public)
		}
	}
}

func TestRS256SignatureVerificationAndPrivateKeyClearing(t *testing.T) {
	algorithm := rs256Algorithm{}
	key, err := algorithm.generateKey()
	if err != nil {
		t.Fatal(err)
	}
	private := key.(*rsa.PrivateKey)
	public := private.Public().(*rsa.PublicKey)
	modulus := new(big.Int).Set(public.N)
	input := []byte("header.payload")
	signature, err := algorithm.sign(key, input)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(input)
	if public.N.BitLen() != 2048 || len(signature) != 256 || rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature) != nil {
		t.Fatal("RS256 signature failed independent verification")
	}
	if _, err := algorithm.sign(brokenCryptoSigner{Signer: key}, input); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid backend signature accepted: %v", err)
	}
	cause := errors.New("backend signing failed")
	if _, err := algorithm.sign(brokenCryptoSigner{Signer: key, err: cause}, input); !errors.Is(err, cause) {
		t.Fatalf("lost signing cause: %v", err)
	}
	algorithm.clearPrivateKey(key)
	for _, value := range append(private.Primes, private.D, private.Precomputed.Dp, private.Precomputed.Dq, private.Precomputed.Qinv) {
		if value.Sign() != 0 {
			t.Fatal("retained private key material")
		}
	}
	if modulus.Cmp(public.N) != 0 || rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature) != nil {
		t.Fatal("clearing private material changed public identity")
	}
}

func TestRS256RejectsInvalidPublicKeys(t *testing.T) {
	modulus := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 2047), big.NewInt(1))
	for _, public := range []crypto.PublicKey{
		nil, (*rsa.PublicKey)(nil), &ecdsa.PublicKey{}, &rsa.PublicKey{},
		&rsa.PublicKey{N: big.NewInt(17), E: 65537},
		&rsa.PublicKey{N: modulus, E: 1},
		&rsa.PublicKey{N: modulus, E: 4},
		&rsa.PublicKey{N: new(big.Int).Neg(modulus), E: 65537},
		&rsa.PublicKey{N: new(big.Int).Sub(modulus, big.NewInt(1)), E: 65537},
	} {
		if err := (rs256Algorithm{}).validatePublicKey(public); err == nil {
			t.Errorf("accepted invalid public key: %T", public)
		}
		if _, err := AlgForKey(public); err == nil {
			t.Errorf("derived an algorithm for invalid key: %T", public)
		}
		if _, err := PublicKeyJWK(public); err == nil {
			t.Errorf("encoded invalid JWK: %T", public)
		}
		if _, err := EncodePublicKey(public); err == nil {
			t.Errorf("encoded invalid PKIX key: %T", public)
		}
	}
}
