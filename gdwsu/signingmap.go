package gdwsu

import (
	"fmt"
	"sync"

	"github.com/gordian-engine/gordian/tm/tmconsensus"
)

// signingMap is a pair of mutex-protected maps
// to track signing content by block hash.
//
// We assume it is relatively expensive to calculate signing content,
// so this shared map structure reduces redundant work.
// It is possible that two or more goroutines may race
// to create the same content; in that event, the first to complete
// becomes the canonical value.
type signingMap struct {
	h uint64
	r uint32

	scheme tmconsensus.SignatureScheme

	pvMu     sync.RWMutex
	prevotes map[string][]byte

	pcMu       sync.RWMutex
	precommits map[string][]byte
}

func newSigningMap(
	h uint64, r uint32,
	scheme tmconsensus.SignatureScheme,
) *signingMap {
	return &signingMap{
		h: h,
		r: r,

		scheme: scheme,

		prevotes:   make(map[string][]byte),
		precommits: make(map[string][]byte),
	}
}

func (m *signingMap) PrevoteSignContent(blockHash []byte) ([]byte, error) {
	m.pvMu.RLock()
	sc, ok := m.prevotes[string(blockHash)]
	m.pvMu.RUnlock()

	if ok {
		return sc, nil
	}

	// Didn't have it, so attempt to build it outside the lock.
	vt := tmconsensus.VoteTarget{
		Height:    m.h,
		Round:     m.r,
		BlockHash: string(blockHash),
	}
	built, err := tmconsensus.PrevoteSignBytes(vt, m.scheme)
	if err != nil {
		return nil, fmt.Errorf("failed to build prevote sign bytes: %w", err)
	}

	// Now attempt to store the value we just built.
	m.pvMu.Lock()
	defer m.pvMu.Unlock()
	sc, ok = m.prevotes[vt.BlockHash]
	if ok {
		// If another goroutine raced to write the entry first,
		// use their copy since it may already have outstanding references.
		return sc, nil
	}

	m.prevotes[vt.BlockHash] = built
	return built, nil
}

func (m *signingMap) PrecommitSignContent(blockHash []byte) ([]byte, error) {
	m.pcMu.RLock()
	sc, ok := m.precommits[string(blockHash)]
	m.pcMu.RUnlock()

	if ok {
		return sc, nil
	}

	// Didn't have it, so attempt to build it outside the lock.
	vt := tmconsensus.VoteTarget{
		Height:    m.h,
		Round:     m.r,
		BlockHash: string(blockHash),
	}
	built, err := tmconsensus.PrecommitSignBytes(vt, m.scheme)
	if err != nil {
		return nil, fmt.Errorf("failed to build precommit sign bytes: %w", err)
	}

	// Now attempt to store the value we just built.
	m.pcMu.Lock()
	defer m.pcMu.Unlock()
	sc, ok = m.precommits[vt.BlockHash]
	if ok {
		// If another goroutine raced to write the entry first,
		// use their copy since it may already have outstanding references.
		return sc, nil
	}

	m.precommits[vt.BlockHash] = built
	return built, nil
}
