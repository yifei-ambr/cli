// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package keysigner

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyFileRejectsUntrustedFormatAndKeepsCommittedData(t *testing.T) {
	algorithm := es256Algorithm{}
	private, err := algorithm.generateKey()
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	ref := KeyRef{Label: "key-file-test"}
	record := keyFileRecord{Version: 1, Label: ref.Label, Backend: "test", PublicKey: public, Data: []byte("encrypted")}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.json")
	if err := writeKeyFile(context.Background(), path, record); err != nil {
		t.Fatal(err)
	}
	changed := record
	changed.Data = []byte("replacement")
	if err := writeKeyFile(context.Background(), path, changed); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("overwrote existing key: %v", err)
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(unchanged, encoded) {
		t.Fatal("duplicate creation damaged committed key")
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"truncated", encoded[:len(encoded)-1]},
		{"extra_json", append(append([]byte(nil), encoded...), []byte(` {}`)...)},
		{"unknown_field", bytes.Replace(encoded, []byte(`"version":1`), []byte(`"version":1,"unexpected":true`), 1)},
		{"unsupported_version", bytes.Replace(encoded, []byte(`"version":1`), []byte(`"version":2`), 1)},
		{"oversized", bytes.Repeat([]byte(" "), maxKeyFileSize+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readKeyFile(path, ref, "test", algorithm); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("bad record was not rejected: %v", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	missing := filepath.Join(t.TempDir(), "canceled.json")
	if err := writeKeyFile(ctx, missing, record); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled write: %v", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled write published a key")
	}
}
