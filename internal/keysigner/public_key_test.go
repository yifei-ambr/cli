// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package keysigner

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

func TestRegistrationPublicKeyEncodings(t *testing.T) {
	for _, algorithm := range []signingAlgorithm{es256Algorithm{}, rs256Algorithm{}} {
		t.Run(algorithm.name(), func(t *testing.T) {
			private, err := algorithm.generateKey()
			if err != nil {
				t.Fatal(err)
			}
			defer algorithm.clearPrivateKey(private)
			public := private.Public()
			if got, err := AlgForKey(public); err != nil || got != algorithm.name() {
				t.Fatalf("AlgForKey = %q, %v", got, err)
			}
			encoded, err := EncodePublicKey(public)
			if err != nil {
				t.Fatal(err)
			}
			der, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				t.Fatal(err)
			}
			jwk, err := PublicKeyJWK(public)
			if err != nil {
				t.Fatalf("JWK = %v, %v", jwk, err)
			}
			data, err := json.Marshal(jwk)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]string
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			decode := func(field string) []byte {
				t.Helper()
				text, ok := fields[field]
				if !ok {
					t.Fatalf("missing JWK field %q", field)
				}
				value, err := base64.RawURLEncoding.DecodeString(text)
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			switch key := public.(type) {
			case *ecdsa.PublicKey:
				x, y := decode("x"), decode("y")
				if len(fields) != 4 || fields["kty"] != "EC" || fields["crv"] != "P-256" || len(x) != 32 || len(y) != 32 ||
					new(big.Int).SetBytes(x).Cmp(key.X) != 0 || new(big.Int).SetBytes(y).Cmp(key.Y) != 0 || !key.Equal(parsed) {
					t.Fatal("EC registration key encoding changed identity or exposed private fields")
				}
			case *rsa.PublicKey:
				if len(fields) != 3 || fields["kty"] != "RSA" || new(big.Int).SetBytes(decode("n")).Cmp(key.N) != 0 ||
					new(big.Int).SetBytes(decode("e")).Int64() != int64(key.E) || !key.Equal(parsed) {
					t.Fatal("RSA registration key encoding changed identity or exposed private fields")
				}
			}
		})
	}
}
