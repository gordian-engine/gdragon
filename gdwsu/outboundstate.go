package gdwsu

import (
	"encoding/binary"
	"iter"

	"github.com/bits-and-blooms/bitset"
)

type OutboundState struct {
	// Indexes that the central state has, which are allowed to be sent.
	centralPrevotesAvailable   *bitset.BitSet
	centralPrecommitsAvailable *bitset.BitSet

	// Which votes we believe the peer already has.
	peerHasPrevote, peerHasPrecommit *bitset.BitSet

	// References to fields in the central state.
	// It is a data race to read any index that does not have
	// a corresponding bit set in central{Prevotes,Precommits}Available.
	prevoteTargets, precommitTargets [][]byte
	prevoteSigs, precommitSigs       [][]byte

	// Block hash -> HashIdx.
	hashIDs map[string]uint16

	sigLen, hashLen uint16
}

func (s *OutboundState) ApplyUpdateFromCentral(u UpdateFromCentral) error {
	// We only need to note that the key index is now readable.
	if u.IsPrecommit {
		s.centralPrecommitsAvailable.Set(uint(u.KeyIdx))
	} else {
		s.centralPrevotesAvailable.Set(uint(u.KeyIdx))
	}
	return nil
}

func (s *OutboundState) AddUnverifiedFromPeer(r ReceivedFromPeer) error {
	if r.IsPrecommit {
		s.peerHasPrecommit.Set(uint(r.KeyIdx))
	} else {
		s.peerHasPrevote.Set(uint(r.KeyIdx))
	}
	return nil
}

func (s *OutboundState) UnsentPackets() iter.Seq[OutboundPacket] {
	p := OutboundPacket{s: s}
	p.ensureBuf()
	return func(yield func(OutboundPacket) bool) {
		// We always want to send the precommits first,
		// as they are capable of completing the round, unlike prevotes.

		// All the bits of what could possibly be sent,
		// then clear the bits of what we know the peer has.
		canSendBS := s.centralPrecommitsAvailable.Difference(s.peerHasPrecommit)
		for u, ok := canSendBS.NextSet(0); ok; u, ok = canSendBS.NextSet(u + 1) {
			p.isPrecommit = true
			p.keyIdx = uint16(u)
			p.targetHash = s.precommitTargets[u]
			p.sig = s.precommitSigs[u]

			p.setBytes()
			if !yield(p) {
				return
			}

			p.reset()
		}

		s.centralPrevotesAvailable.CopyFull(canSendBS)
		canSendBS.InPlaceDifference(s.peerHasPrevote)
		for u, ok := canSendBS.NextSet(0); ok; u, ok = canSendBS.NextSet(u + 1) {
			p.isPrecommit = false
			p.keyIdx = uint16(u)
			p.targetHash = s.prevoteTargets[u]
			p.sig = s.prevoteSigs[u]

			p.setBytes()
			if !yield(p) {
				return
			}

			p.reset()
		}
	}
}

const fixedMaxOutboundPacketSize = 1 + // IsPrecommit, a whole byte.
	2 + // HashIdx (uint16)
	0 + // Placeholder for TargetHash (zero if known hash, fixed size if new hash)
	2 + // KeyIdx (fixed uint16)
	0 // Placeholder for Sig (fixed size per session)

type OutboundPacket struct {
	s *OutboundState

	buf []byte

	isPrecommit bool

	keyIdx uint16

	targetHash, sig []byte
	newHashIdx      uint16
}

func (p *OutboundPacket) setBytes() {
	p.buf = p.buf[:0]
	if p.isPrecommit {
		p.buf = append(p.buf, 1)
	} else {
		p.buf = append(p.buf, 0)
	}

	// Do we have the hash ID?
	hid, ok := p.s.hashIDs[string(p.targetHash)]
	if ok {
		// Only need to send the ID.
		p.buf = binary.BigEndian.AppendUint16(p.buf, hid)
	} else {
		// We need to reserve a new hash ID.
		hid = uint16(len(p.s.hashIDs)) + 1

		// And send both the ID and the hash.
		p.buf = binary.BigEndian.AppendUint16(p.buf, hid)
		p.buf = append(p.buf, p.targetHash...)

		p.newHashIdx = hid
	}

	// Key index set unconditionally.
	p.buf = binary.BigEndian.AppendUint16(p.buf, p.keyIdx)

	// And finally the signature.
	p.buf = append(p.buf, p.sig...)
}

func (p *OutboundPacket) ensureBuf() {
	if p.buf != nil {
		return
	}

	p.buf = make([]byte, fixedMaxOutboundPacketSize+p.s.sigLen+p.s.hashLen)
}

func (p *OutboundPacket) reset() {
	// Only keep these fields on p.
	*p = OutboundPacket{s: p.s, buf: p.buf[:0]}
}

func (p OutboundPacket) Bytes() []byte {
	return p.buf
}

func (p OutboundPacket) MarkSent() {
	if p.isPrecommit {
		p.s.peerHasPrecommit.Set(uint(p.keyIdx))
	} else {
		p.s.peerHasPrevote.Set(uint(p.keyIdx))
	}

	if p.newHashIdx > 0 {
		p.s.hashIDs[string(p.targetHash)] = p.newHashIdx
	}
}
