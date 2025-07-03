package gdtmp2p

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"maps"

	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/wingspan/wspacket"
	"github.com/gordian-engine/gordian/gcrypto"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
)

// UnaggregatedCentralVoteState implements
// [wspacket.CentralState[VoteDelta]].
type UnaggregatedCentralVoteState struct {
	// Height and round are constant in the state lifecycle.
	h uint64
	r uint32

	signers   []gcrypto.PubKey
	sigScheme tmconsensus.SignatureScheme

	// Block hash -> Signer index -> Signature
	votes map[string]map[uint16][]byte

	peerUpdates chan unaggregatedUpdateFromPeer

	outboundRequests chan (chan<- unaggregatedOutboundResult)
	inboundRequests  chan (chan<- unaggregatedInboundResult)

	stream *dpubsub.Stream[VoteDelta]

	done chan struct{}
}

func NewUnaggregatedCentralVoteState(
	ctx context.Context,
	height uint64, round uint32,
	signers []gcrypto.PubKey,
	sigScheme tmconsensus.SignatureScheme,
) (*UnaggregatedCentralVoteState, *dpubsub.Stream[VoteDelta]) {
	stream := dpubsub.NewStream[VoteDelta]()
	state := &UnaggregatedCentralVoteState{
		h: height,
		r: round,

		signers:   signers,
		sigScheme: sigScheme,

		votes: map[string]map[uint16][]byte{},

		// Unbuffered since caller blocks.
		peerUpdates:      make(chan unaggregatedUpdateFromPeer),
		outboundRequests: make(chan (chan<- unaggregatedOutboundResult)),
		inboundRequests:  make(chan (chan<- unaggregatedInboundResult)),

		stream: stream,

		done: make(chan struct{}),
	}

	go state.mainLoop(ctx)
	return state, stream
}

func (s *UnaggregatedCentralVoteState) Wait() {
	<-s.done
}

type unaggregatedUpdateFromPeer struct {
	VerifiedDelta VoteDelta

	Resp chan error
}

// unaggregatedOutboundResult is the internal type used
// when getting an outbound state instance from the central state.
type unaggregatedOutboundResult struct {
	State  *unaggregatedOutboundState
	Stream *dpubsub.Stream[VoteDelta]
}

// unaggregatedOutboundResult is the internal type used
// when getting an inbound state instance from the central state.
type unaggregatedInboundResult struct {
	State  *unaggregatedInboundState
	Stream *dpubsub.Stream[VoteDelta]
}

func (s *UnaggregatedCentralVoteState) mainLoop(ctx context.Context) {
	defer close(s.done)

	for {
		select {
		case <-ctx.Done():
			return

		case u := <-s.peerUpdates:
			s.handleUpdateFromPeer(u)

		case ch := <-s.outboundRequests:
			s.handleOutboundRequest(ch)

		case ch := <-s.inboundRequests:
			s.handleInboundRequest(ch)
		}
	}
}

func (s *UnaggregatedCentralVoteState) UpdateFromPeer(
	ctx context.Context, d VoteDelta,
) error {
	// Verify signature here before handing off to the main loop.
	if int(d.KeyIndex) >= len(s.signers) {
		return fmt.Errorf("key index %d out of range [0,%d)", d.KeyIndex, len(s.signers))
	}
	signer := s.signers[d.KeyIndex]

	vt := tmconsensus.VoteTarget{
		Height: s.h,
		Round:  s.r,

		BlockHash: string(d.BlockHash),
	}
	msg, err := tmconsensus.PrevoteSignBytes(vt, s.sigScheme)
	if err != nil {
		return fmt.Errorf(
			"failed to generate prevote sign bytes: %w", err,
		)
	}

	if !signer.Verify(msg, d.Signature) {
		return errors.New("invalid signature")
	}

	resp := make(chan error, 1)
	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while handling update: %w",
			context.Cause(ctx),
		)
	case s.peerUpdates <- unaggregatedUpdateFromPeer{
		VerifiedDelta: d,
		Resp:          resp,
	}:
		// Wait for response.
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while waiting for update response: %w",
			context.Cause(ctx),
		)
	case err := <-resp:
		// Don't wrap this error.
		return err
	}
}

func (s *UnaggregatedCentralVoteState) handleUpdateFromPeer(
	u unaggregatedUpdateFromPeer,
) {
	d := u.VerifiedDelta
	byIdx, ok := s.votes[string(d.BlockHash)]
	if !ok {
		byIdx = map[uint16][]byte{}
		s.votes[string(d.BlockHash)] = byIdx
	}

	if _, ok := byIdx[d.KeyIndex]; ok {
		// The earlier signature was verified so assume it's the same.
		// Response channel is buffered.
		u.Resp <- wspacket.ErrRedundantUpdate
		return
	}

	byIdx[d.KeyIndex] = d.Signature

	// Respond to the sender first,
	// to increase the likelihood that they see the success
	// before the pubsub stream update.
	u.Resp <- nil

	s.stream.Publish(d)

	// TODO: this needs to feed the signature back up to the engine
	// so that the round can advance if this crossed a threshold.
	// Or maybe just the stream suffices here?
}

func (s *UnaggregatedCentralVoteState) NewOutboundRemoteState(ctx context.Context) (
	wspacket.OutboundRemoteState[VoteDelta], *dpubsub.Stream[VoteDelta], error,
) {
	ch := make(chan unaggregatedOutboundResult, 1)

	select {
	case <-ctx.Done():
		return nil, nil, fmt.Errorf(
			"context canceled while requesting outbound state: %w",
			context.Cause(ctx),
		)

	case s.outboundRequests <- ch:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return nil, nil, fmt.Errorf(
			"context canceled while awaiting outbound state result: %w",
			context.Cause(ctx),
		)
	case res := <-ch:
		return res.State, res.Stream, nil
	}
}

func (s *UnaggregatedCentralVoteState) handleOutboundRequest(
	ch chan<- unaggregatedOutboundResult,
) {
	unsentVotes := make(map[string]map[uint16][]byte, len(s.votes))
	for h, m := range s.votes {
		unsentVotes[h] = maps.Clone(m)
	}

	state := &unaggregatedOutboundState{
		unsentVotes: unsentVotes,
	}

	ch <- unaggregatedOutboundResult{
		State:  state,
		Stream: s.stream,
	}
}

func (s *UnaggregatedCentralVoteState) NewInboundRemoteState(ctx context.Context) (
	wspacket.InboundRemoteState[VoteDelta], *dpubsub.Stream[VoteDelta], error,
) {
	ch := make(chan unaggregatedInboundResult, 1)

	select {
	case <-ctx.Done():
		return nil, nil, fmt.Errorf(
			"context canceled while requesting inbound state: %w",
			context.Cause(ctx),
		)

	case s.inboundRequests <- ch:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return nil, nil, fmt.Errorf(
			"context canceled while awaiting inbound state result: %w",
			context.Cause(ctx),
		)
	case res := <-ch:
		return res.State, res.Stream, nil
	}
}

func (s *UnaggregatedCentralVoteState) handleInboundRequest(
	ch chan<- unaggregatedInboundResult,
) {
	state := &unaggregatedInboundState{}
	ch <- unaggregatedInboundResult{
		State:  state,
		Stream: s.stream,
	}
}

// unaggregatedOutboundState implements [wspacket.OutboundRemoteState[VoteDelta]].
type unaggregatedOutboundState struct {
	// BlockHash -> KeyIndex -> Signature
	unsentVotes, unverifiedVotes map[string]map[uint16][]byte
}

func (s *unaggregatedOutboundState) ApplyUpdateFromCentral(d VoteDelta) error {
	// Is there an unverified vote for this hash and key index?
	if m := s.unverifiedVotes[string(d.BlockHash)]; m != nil {
		if sig := m[d.KeyIndex]; sig != nil {
			// Had an unverified match.
			// If they differed then this stream will get closed
			// once the session observes the difference.
			delete(m, d.KeyIndex)
			return nil
		}
	}

	// There was no match in unverified votes
	// so just accumulate the update in the unsent votes.
	m := s.unsentVotes[string(d.BlockHash)]
	if m == nil {
		m = map[uint16][]byte{}
		s.unsentVotes[string(d.BlockHash)] = m
	}

	m[d.KeyIndex] = d.Signature
	return nil
}

func (s *unaggregatedOutboundState) AddUnverifiedFromPeer(d VoteDelta) error {
	if s.unverifiedVotes == nil {
		s.unverifiedVotes = map[string]map[uint16][]byte{}
	}
	m := s.unverifiedVotes[string(d.BlockHash)]
	if m == nil {
		m = map[uint16][]byte{}
		s.unverifiedVotes[string(d.BlockHash)] = m
	}

	m[d.KeyIndex] = d.Signature
	return nil
}

func (s *unaggregatedOutboundState) UnsentPackets() iter.Seq[wspacket.Packet] {
	return func(yield func(wspacket.Packet) bool) {
		p := unaggregatedPacket{state: s}

		// For now, just iterate the unsent packets in arbitrary order.
		// But it would probably be better to apply some priority.
		for blockHash, sigMap := range s.unsentVotes {
			p.blockHash = blockHash

			for keyIndex, sig := range sigMap {
				p.keyIndex = keyIndex
				p.sig = sig

				if !yield(p) {
					return
				}
			}
		}
	}
}

// unaggregatedPacket implements [wspacket.Packet].
type unaggregatedPacket struct {
	blockHash string // A string because the value comes from a map key.
	keyIndex  uint16
	sig       []byte

	state *unaggregatedOutboundState
}

func (p unaggregatedPacket) Bytes() []byte {
	if p.blockHash == "" {
		// Never have to teach the remote about nil votes.
		buf := make([]byte, 1+1+2+len(p.sig))
		buf[0] = upHeaderHashReference
		// buf[1] remains zero, reserved for nil hash.
		binary.BigEndian.PutUint16(buf[2:4], p.keyIndex)
		_ = copy(buf[4:], p.sig)
		return buf
	}

	// TODO: check on state whether we have sent this block hash before.
	// For now send as literal until state tracks which hashes we've sent.
	buf := make([]byte, 1+len(p.blockHash)+2+len(p.sig))
	buf[0] = upHeaderHashLiteral
	_ = copy(buf[1:], p.blockHash)
	binary.BigEndian.PutUint16(buf[1+len(p.blockHash):], p.keyIndex)
	_ = copy(buf[1+len(p.blockHash)+2:], p.sig)
	return buf
}

func (p unaggregatedPacket) MarkSent() {
	// This only has to remove the entry from the unsent votes.
	delete(p.state.unsentVotes[p.blockHash], p.keyIndex)
}

const (
	upHeaderHashReference byte = 0
	upHeaderHashLiteral   byte = 1
)

// unaggregatedInboundState implements [wspacket.InboundRemoteState[VoteDelta]].
type unaggregatedInboundState struct {
	checked, fromCentral map[string]map[uint16]struct{}
}

func (s *unaggregatedInboundState) ApplyUpdateFromCentral(d VoteDelta) error {
	if s.fromCentral == nil {
		s.fromCentral = map[string]map[uint16]struct{}{}
	}

	byKeyIndex := s.fromCentral[string(d.BlockHash)]
	if byKeyIndex == nil {
		byKeyIndex = map[uint16]struct{}{}
		s.fromCentral[string(d.BlockHash)] = byKeyIndex
	}

	byKeyIndex[d.KeyIndex] = struct{}{}
	return nil
}

func (s *unaggregatedInboundState) ApplyUpdateFromPeer(d VoteDelta) error {
	// Nothing to do here.
	// We did all the work in CheckIncoming.
	return nil
}

func (s *unaggregatedInboundState) CheckIncoming(d VoteDelta) error {
	if s.checked == nil {
		s.checked = map[string]map[uint16]struct{}{}
	}

	byKeyIndex := s.checked[string(d.BlockHash)]
	if byKeyIndex == nil {
		byKeyIndex = map[uint16]struct{}{}
		s.checked[string(d.BlockHash)] = byKeyIndex
	}

	_, hadCheckedSig := byKeyIndex[d.KeyIndex]
	if hadCheckedSig {
		// Doesn't matter if the signature matches.
		return wspacket.ErrDuplicateSentPacket
	}

	// Now mark this as received from the peer.
	byKeyIndex[d.KeyIndex] = struct{}{}

	// Do we already have a corresponding signature from the central state?
	if s.fromCentral == nil {
		// Don't bother making the map yet.
		return nil
	}

	byKeyIndex = s.fromCentral[string(d.BlockHash)]
	if byKeyIndex == nil {
		return nil
	}

	if _, have := byKeyIndex[d.KeyIndex]; have {
		return wspacket.ErrAlreadyHavePacket
	}

	return nil
}
