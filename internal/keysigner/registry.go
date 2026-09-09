// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package keysigner

import "sync"

var (
	activeMu sync.RWMutex
	active   []Signer
)

// Register installs a signer compiled for this host. Signers are kept in
// strongest-to-weakest order and a later registration replaces the same
// backend name.
func Register(signer Signer) {
	if signer == nil {
		return
	}
	activeMu.Lock()
	defer activeMu.Unlock()
	name := signer.Name()
	for i := range active {
		if active[i].Name() == name {
			active[i] = signer
			sortSigners(active)
			return
		}
	}
	active = append(active, signer)
	sortSigners(active)
}

// Candidates returns a snapshot ordered from L1 to L3.
func Candidates() []Signer {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return append([]Signer(nil), active...)
}

func sortSigners(signers []Signer) {
	for i := 1; i < len(signers); i++ {
		for j := i; j > 0 && levelRank(signers[j].SecurityLevel()) < levelRank(signers[j-1].SecurityLevel()); j-- {
			signers[j], signers[j-1] = signers[j-1], signers[j]
		}
	}
}

func levelRank(level SecurityLevel) int {
	switch level {
	case SecurityLevelL1:
		return 1
	case SecurityLevelL2:
		return 2
	case SecurityLevelL3:
		return 3
	default:
		return 4
	}
}
