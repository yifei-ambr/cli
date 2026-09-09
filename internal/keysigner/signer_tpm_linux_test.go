//go:build linux

// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package keysigner

import (
	"errors"
	"fmt"
	"io/fs"
	"syscall"
	"testing"
)

func TestTPMErrorClassificationOnlyPermitsKnownFallbacks(t *testing.T) {
	for _, tc := range []struct {
		name        string
		path        string
		cause       error
		unavailable bool
	}{
		{"missing TPM", "/dev/tpmrm0", syscall.ENOENT, true},
		{"permission denied", "/dev/tpmrm0", syscall.EACCES, false},
		{"operation not permitted", "/dev/tpmrm0", syscall.EPERM, false},
		{"I/O failure", "/dev/tpmrm0", syscall.EIO, false},
		{"missing key file", "/keys/test-key", syscall.ENOENT, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pathErr := &fs.PathError{Op: "open", Path: tc.path, Err: tc.cause}
			wrapped := fmt.Errorf("native backend: %w", pathErr)
			err := classifyTPMError(wrapped)
			if !errors.Is(err, wrapped) || !errors.Is(err, tc.cause) {
				t.Fatal("classification lost native error")
			}
			if errors.Is(err, ErrUnavailable) != tc.unavailable || errors.Is(err, ErrKeyNotFound) {
				t.Fatalf("classification = %v, want unavailable=%v without rebinding", err, tc.unavailable)
			}
		})
	}
}
