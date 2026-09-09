// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package keysigner

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

type registryTestSigner struct {
	Signer
	name  string
	level SecurityLevel
}

func (s *registryTestSigner) Name() string                 { return s.name }
func (s *registryTestSigner) SecurityLevel() SecurityLevel { return s.level }

func TestRegistryOrdersReplacesAndReturnsIsolatedSnapshots(t *testing.T) {
	activeMu.Lock()
	saved := active
	active = nil
	activeMu.Unlock()
	t.Cleanup(func() { activeMu.Lock(); active = saved; activeMu.Unlock() })
	Register(nil)
	if len(Candidates()) != 0 {
		t.Fatal("empty registry has a signer")
	}
	l3 := &registryTestSigner{name: "software", level: SecurityLevelL3}
	l2 := &registryTestSigner{name: "native", level: SecurityLevelL2}
	l1 := &registryTestSigner{name: "hardware", level: SecurityLevelL1}
	Register(l3)
	Register(l2)
	Register(l1)
	if !slices.Equal(Candidates(), []Signer{l1, l2, l3}) {
		t.Fatal("registry does not prefer strongest protection")
	}
	replacement := &registryTestSigner{name: "native", level: SecurityLevelL3}
	Register(replacement)
	want := []Signer{l1, replacement, l3}
	snapshot := Candidates()
	if !slices.Equal(snapshot, want) {
		t.Fatal("same-name registration did not replace the existing backend")
	}
	snapshot[0] = nil
	if !slices.Equal(Candidates(), want) {
		t.Fatal("caller can mutate the active registry through a snapshot")
	}
}

func TestKeyReferenceValidationBeforeStorage(t *testing.T) {
	for _, label := range []string{"", strings.Repeat("a", 257), "a\x00b", "a\nb", "a\x7fb", string([]byte{0xff})} {
		if _, err := algorithmForRef(context.Background(), KeyRef{Label: label}); err == nil {
			t.Errorf("accepted invalid reference %q", label)
		}
	}
	for _, label := range []string{"label", "中文标签", strings.Repeat("a", 256), ".", "..", "a:b", "a/b", `a\b`} {
		if _, err := algorithmForRef(nil, KeyRef{Label: label}); err != nil {
			t.Errorf("rejected valid reference: %v", err)
		}
	}
	if _, err := algorithmForRef(nil, KeyRef{Label: "valid", Algorithm: "PS256"}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unsupported algorithm: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := algorithmForRef(ctx, KeyRef{Label: "valid"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled operation: %v", err)
	}
}
