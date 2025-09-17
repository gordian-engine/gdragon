package gdwsu

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/wingspan/wspacket"
	"github.com/gordian-engine/gordian/gcrypto"
)

type InboundState struct {
	keys []gcrypto.PubKey

	// Indexes that the central state has, which are allowed to be sent.
	centralPrevotesAvailable   *bitset.BitSet
	centralPrecommitsAvailable *bitset.BitSet

	peerSentPrevote, peerSentPrecommit *bitset.BitSet

	signingMap *signingMap

	// References to fields in the central state.
	// It is a data race to read any index that does not have
	// a corresponding bit set in central{Prevotes,Precommits}Available.
	prevoteTargets, precommitTargets [][]byte
	prevoteSigs, precommitSigs       [][]byte

	// Target hashes that are part of this stateful connection.
	inboundHashes [][]byte

	sigLen, hashLen uint16
}

func (s *InboundState) ApplyUpdateFromCentral(u UpdateFromCentral) error {
	// We only need to note that the key index is now readable.
	if u.IsPrecommit {
		s.centralPrecommitsAvailable.Set(uint(u.KeyIdx))
	} else {
		s.centralPrevotesAvailable.Set(uint(u.KeyIdx))
	}
	return nil
}

func (s *InboundState) ApplyUpdateFromPeer(r ReceivedFromPeer) error {
	// No-op here.
	return nil
}

func (s *InboundState) CheckIncoming(p ParsedPacket) error {
	if p.IsPrecommit {
		// Was this a duplicate packet?
		if s.peerSentPrecommit.Test(uint(p.KeyIdx)) {
			return wspacket.ErrDuplicateSentPacket
		}

		// First time the peer sent us a packet for this index.
		// Are we already aware of it?
		if s.centralPrecommitsAvailable.Test(uint(p.KeyIdx)) {
			if !bytes.Equal(s.precommitSigs[p.KeyIdx], p.Sig) {
				return fmt.Errorf(
					"mismatched precommit signature for key index %d against target hash %x (got %x, expected %x)",
					p.KeyIdx, p.TargetHash, p.Sig, s.precommitSigs[p.KeyIdx],
				)
			}

			return wspacket.ErrAlreadyHavePacket
		}

		return nil
	}

	// Otherwise, check the same things for prevote.
	// Was this a duplicate packet?
	if s.peerSentPrevote.Test(uint(p.KeyIdx)) {
		return wspacket.ErrDuplicateSentPacket
	}

	// First time the peer sent us a packet for this index.
	// Are we already aware of it?
	if s.centralPrevotesAvailable.Test(uint(p.KeyIdx)) {
		if !bytes.Equal(s.prevoteSigs[p.KeyIdx], p.Sig) {
			return fmt.Errorf(
				"mismatched prevote signature for key index %d against target hash %x (got %x, expected %x)",
				p.KeyIdx, p.TargetHash, p.Sig, s.prevoteSigs[p.KeyIdx],
			)
		}

		return wspacket.ErrAlreadyHavePacket
	}

	return nil
}

// ParsePacket deserializes a packet from r.
//
// ParsePacket implements [wspacket.InboundState].
func (s *InboundState) ParsePacket(r io.Reader) (ParsedPacket, error) {
	var typeAndHashID [3]byte
	if _, err := io.ReadFull(r, typeAndHashID[:]); err != nil {
		return ParsedPacket{}, fmt.Errorf(
			"failed to read type and index: %w", err,
		)
	}

	var isPrecommit bool
	switch typeAndHashID[0] {
	case 0:
		// isPrecommit is already false.
	case 1:
		isPrecommit = true
	default:
		return ParsedPacket{}, fmt.Errorf(
			"invalid isPrecommit byte %x (must be 0 or 1)", typeAndHashID[0],
		)
	}

	hashID := binary.BigEndian.Uint16(typeAndHashID[1:])

	var targetHash []byte
	if hashID == 0 {
		// We need to read the hash.
		targetHash = make([]byte, s.hashLen)
		if _, err := io.ReadFull(r, targetHash); err != nil {
			return ParsedPacket{}, fmt.Errorf(
				"failed to read new target hash: %w", err,
			)
		}

		// TODO: confirm this is the first send of this hash.

		s.inboundHashes = append(s.inboundHashes, targetHash)
	} else if hashID > 1 {
		// Index 1 means nil, so we only care about 2 and higher.

		// We know this does not underflow since hashIdx >= 2.
		aIdx := hashID - 2
		if int(aIdx) >= len(s.inboundHashes) {
			return ParsedPacket{}, fmt.Errorf(
				"hash ID %d out of bounds", hashID,
			)
		}

		targetHash = s.inboundHashes[aIdx]
	}

	var keyBuf [2]byte
	if _, err := io.ReadFull(r, keyBuf[:]); err != nil {
		return ParsedPacket{}, fmt.Errorf(
			"failed to read key index: %w", err,
		)
	}
	keyIdx := binary.BigEndian.Uint16(keyBuf[:])

	sig := make([]byte, s.sigLen)
	if _, err := io.ReadFull(r, sig); err != nil {
		return ParsedPacket{}, fmt.Errorf(
			"failed to read signature: %w", err,
		)
	}

	return ParsedPacket{
		IsPrecommit: isPrecommit,

		KeyIdx: keyIdx,
		HashID: hashID, // Do we even need this?

		TargetHash: targetHash,

		Sig: sig,
	}, nil
}

func (s *InboundState) PacketToDelta(p ParsedPacket) (ReceivedFromPeer, error) {
	// We have the lightweight packet.
	// Before we can send the delta to the central state,
	// we validate the actual signature.
	if int(p.KeyIdx) >= len(s.keys) {
		return ReceivedFromPeer{}, fmt.Errorf(
			"key index %d out of bounds (must be <= %d)",
			p.KeyIdx, len(s.keys),
		)
	}

	var signContent []byte
	var err error
	if p.IsPrecommit {
		signContent, err = s.signingMap.PrecommitSignContent(p.TargetHash)
	} else {
		signContent, err = s.signingMap.PrevoteSignContent(p.TargetHash)
	}
	if err != nil {
		return ReceivedFromPeer{}, fmt.Errorf(
			"failed to produce sign content: %w", err,
		)
	}

	key := s.keys[p.KeyIdx]
	if !key.Verify(signContent, p.Sig) {
		return ReceivedFromPeer{}, fmt.Errorf(
			"peer provided invalid signature: %w", err,
		)
	}

	// Finally, note that the peer sent this packet,
	// so that we can identify double sends in CheckIncoming.
	if p.IsPrecommit {
		s.peerSentPrecommit.Set(uint(p.KeyIdx))
	} else {
		s.peerSentPrevote.Set(uint(p.KeyIdx))
	}

	return ReceivedFromPeer{
		KeyIdx: p.KeyIdx,
		Sig:    p.Sig,

		TargetHash: p.TargetHash,

		IsPrecommit: p.IsPrecommit,
	}, nil
}
