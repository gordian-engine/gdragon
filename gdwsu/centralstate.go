package gdwsu

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/wingspan/wspacket"
	"github.com/gordian-engine/gordian/gcrypto"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
)

// CentralState is the implementation of [wspacket.CentralState] for unaggregated signatures.
type CentralState struct {
	log *slog.Logger

	// For serialization and certain optimizations,
	// we need to know the fixed size of signatures and block hashes.
	sigLen, hashLen uint16

	keys []gcrypto.PubKey

	updates *dpubsub.Stream[UpdateFromCentral]

	signingMap *signingMap

	// The targets are currently referenced directly from the incoming Delta.
	// It may be better to intern these with the state's scope,
	// since they are usually going to be repeated values.
	prevoteTargets, precommitTargets [][]byte

	// The signature sets are each backed by a single slice.
	prevoteSigs, precommitSigs [][]byte

	// Bitsets indicating what prevotes and precommits we already have.
	// Every new derived state will receive a clone of each of these,
	// so it is worth maintaining a canonical copy.
	availablePrevoteBS, availablePrecommitBS *bitset.BitSet

	peerUpdates           chan peerUpdateRequest
	inboundStateRequests  chan (chan<- inboundStateResult)
	outboundStateRequests chan (chan<- outboundStateResult)

	verifiedPrevotes, verifiedPrecommits chan VerifiedVote

	done chan struct{}
}

type peerUpdateRequest struct {
	Delta ReceivedFromPeer
	Resp  chan error
}

type inboundStateResult struct {
	I *InboundState
	U *dpubsub.Stream[UpdateFromCentral]
}

type outboundStateResult struct {
	O *OutboundState
	U *dpubsub.Stream[UpdateFromCentral]
}

// VerifiedVote is the value used for the [*CentralState.Prevotes] and [*CentralState.Precommits] channels.
type VerifiedVote struct {
	TargetHash []byte
	Signature  []byte

	KeyIdx      uint16
	IsPrecommit bool
}

var _ wspacket.CentralState[
	ParsedPacket, OutboundPacket,
	ReceivedFromPeer, UpdateFromCentral,
] = (*CentralState)(nil)

// NewCentralState returns a new instance of CentralState.
func NewCentralState(
	ctx context.Context,
	log *slog.Logger,
	height uint64, round uint32,
	keys []gcrypto.PubKey,
	sigLen, hashLen uint16,
	sigScheme tmconsensus.SignatureScheme,
) (*CentralState, *dpubsub.Stream[UpdateFromCentral]) {
	// Back the prevote and precommit signatures with a single slice each.
	// Using a single backing slice reduces the number of allocated objects.
	// Arbitrarily decided to separate prevotes and precommits here,
	// as the precommits may possibly be referenced longer than the prevotes.
	prevoteSigBacking := make([]byte, int(sigLen)*len(keys))
	precommitSigBacking := make([]byte, int(sigLen)*len(keys))

	// Initialize as zero-length slices,
	// so we can trivially identify unset signatures.
	prevoteSigs := make([][]byte, len(keys))
	precommitSigs := make([][]byte, len(keys))
	var offset uint16
	for i := range keys {
		prevoteSigs[i] = prevoteSigBacking[offset:offset]
		precommitSigs[i] = precommitSigBacking[offset:offset]
		offset += sigLen
	}

	s := &CentralState{
		log: log,

		sigLen:  sigLen,
		hashLen: hashLen,

		keys: keys,

		updates: dpubsub.NewStream[UpdateFromCentral](),

		signingMap: newSigningMap(height, round, sigScheme),

		prevoteTargets:   make([][]byte, len(keys)),
		precommitTargets: make([][]byte, len(keys)),

		prevoteSigs:   prevoteSigs,
		precommitSigs: precommitSigs,

		availablePrevoteBS:   bitset.MustNew(uint(len(keys))),
		availablePrecommitBS: bitset.MustNew(uint(len(keys))),

		// Arbitrarily buffered to assist FIFO ordering.
		peerUpdates: make(chan peerUpdateRequest, 8),

		inboundStateRequests:  make(chan chan<- inboundStateResult),
		outboundStateRequests: make(chan chan<- outboundStateResult),

		// Both buffered to the same size as the number of keys,
		// as we will send at most one vote per key,
		// and we do not want sends to block.
		verifiedPrevotes:   make(chan VerifiedVote, len(keys)),
		verifiedPrecommits: make(chan VerifiedVote, len(keys)),

		done: make(chan struct{}),
	}

	go s.mainLoop(ctx)

	return s, s.updates
}

func (s *CentralState) mainLoop(ctx context.Context) {
	defer close(s.done)

	defer close(s.verifiedPrecommits)
	defer close(s.verifiedPrevotes)

	for {
		select {
		case <-ctx.Done():
			return

		case u := <-s.peerUpdates:
			u.Resp <- s.handleUpdateFromPeer(u.Delta)

		case ch := <-s.outboundStateRequests:
			ch <- outboundStateResult{
				O: s.newOutboundState(),
				U: s.updates,
			}

		case ch := <-s.inboundStateRequests:
			ch <- inboundStateResult{
				I: s.newInboundState(),
				U: s.updates,
			}
		}
	}
}

func (s *CentralState) Wait() {
	<-s.done
}

// Prevotes returns a receive-only channel of verified prevotes.
// The channel is closed when s's context is canceled.
func (s *CentralState) Prevotes() <-chan VerifiedVote {
	return s.verifiedPrevotes
}

// Precommits returns a receive-only channel of verified precommits.
// The channel is closed when s's context is canceled.
func (s *CentralState) Precommits() <-chan VerifiedVote {
	return s.verifiedPrecommits
}

// UpdateFromPeer implements [wspacket.CentralState].
func (s *CentralState) UpdateFromPeer(ctx context.Context, d ReceivedFromPeer) error {
	req := peerUpdateRequest{
		Delta: d,
		Resp:  make(chan error, 1),
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while sending update request: %w", context.Cause(ctx),
		)
	case s.peerUpdates <- req:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while awaiting update response: %w", context.Cause(ctx),
		)
	case err := <-req.Resp:
		return err
	}
}

func (s *CentralState) handleUpdateFromPeer(d ReceivedFromPeer) error {
	// The peer is supposed to have validated the delta,
	// to reduce central state contention.

	if len(d.Sig) != int(s.sigLen) {
		panic(fmt.Errorf(
			"BUG: observed peer update with signature length %d (must be %d)",
			len(d.Sig), s.sigLen,
		))
	}

	var haveSig []byte
	if d.IsPrecommit {
		haveSig = s.precommitSigs[d.KeyIdx]
	} else {
		haveSig = s.prevoteSigs[d.KeyIdx]
	}

	if len(haveSig) != 0 {
		// Just make sure it matches.
		if bytes.Equal(haveSig, d.Sig) {
			return wspacket.ErrRedundantUpdate
		}

		// A mismatch should be impossible if the workers are validating the signatures.
		panic(fmt.Errorf(
			"BUG: received conflicting signatures (%x and %x) for key index %d",
			haveSig, d.Sig, d.KeyIdx,
		))
	}

	// We didn't have the signature, so now we need to add it to the collection and publish the delta.
	// We copy the incoming signature to the single backing slice
	// and reassign the reference on the Delta.
	if d.IsPrecommit {
		s.precommitSigs[d.KeyIdx] = append(s.precommitSigs[d.KeyIdx], d.Sig...)
		d.Sig = s.precommitSigs[d.KeyIdx]

		s.precommitTargets[d.KeyIdx] = d.TargetHash

		s.availablePrecommitBS.Set(uint(d.KeyIdx))

		s.log.Debug(
			"Verified incoming precommit",
			"key_idx", d.KeyIdx,
			"target_hash", fmt.Sprintf("%x", d.TargetHash), // TODO: log hex helper.
		)

		// Channel buffered to full key length,
		// so this will not block, as long as we only send each vote once.
		s.verifiedPrecommits <- VerifiedVote{
			TargetHash: d.TargetHash,
			Signature:  d.Sig,

			KeyIdx:      d.KeyIdx,
			IsPrecommit: true,
		}
	} else {
		s.prevoteSigs[d.KeyIdx] = append(s.prevoteSigs[d.KeyIdx], d.Sig...)
		d.Sig = s.prevoteSigs[d.KeyIdx]

		s.prevoteTargets[d.KeyIdx] = d.TargetHash

		s.availablePrevoteBS.Set(uint(d.KeyIdx))

		s.log.Debug(
			"Verified incoming prevote",
			"key_idx", d.KeyIdx,
			"target_hash", fmt.Sprintf("%x", d.TargetHash), // TODO: log hex helper.
		)

		// Channel buffered to full key length,
		// so this will not block, as long as we only send each vote once.
		s.verifiedPrevotes <- VerifiedVote{
			TargetHash: d.TargetHash,
			Signature:  d.Sig,

			KeyIdx:      d.KeyIdx,
			IsPrecommit: false,
		}
	}

	// Convert to an update from central now.
	s.updates.Publish(UpdateFromCentral{
		KeyIdx:      d.KeyIdx,
		IsPrecommit: d.IsPrecommit,
	})
	s.updates = s.updates.Next

	return nil
}

// NewOutboundRemoteState implements [wspacket.CentralState].
func (s *CentralState) NewOutboundRemoteState(ctx context.Context) (
	wspacket.OutboundRemoteState[
		ParsedPacket, OutboundPacket,
		ReceivedFromPeer, UpdateFromCentral,
	],
	*dpubsub.Stream[UpdateFromCentral],
	error,
) {
	ch := make(chan outboundStateResult, 1)

	select {
	case <-ctx.Done():
		return nil, nil, fmt.Errorf(
			"context canceled while sending outbound state request: %w",
			context.Cause(ctx),
		)
	case s.outboundStateRequests <- ch:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return nil, nil, fmt.Errorf(
			"context canceled while awaiting outbound state response: %w",
			context.Cause(ctx),
		)
	case res := <-ch:
		return res.O, res.U, nil
	}
}

func (s *CentralState) newOutboundState() *OutboundState {
	return &OutboundState{
		log: s.log.With("cs_sub", "outbound"),

		centralPrevotesAvailable:   s.availablePrevoteBS.Clone(),
		centralPrecommitsAvailable: s.availablePrecommitBS.Clone(),

		peerHasPrevote:   bitset.MustNew(uint(len(s.keys))),
		peerHasPrecommit: bitset.MustNew(uint(len(s.keys))),

		prevoteTargets:   s.prevoteTargets,
		precommitTargets: s.precommitTargets,

		prevoteSigs:   s.prevoteSigs,
		precommitSigs: s.precommitSigs,

		hashIDs: map[string]uint16{"": 1},
	}
}

// NewInboundRemoteState implements [wspacket.CentralState].
func (s *CentralState) NewInboundRemoteState(ctx context.Context) (
	wspacket.InboundRemoteState[ParsedPacket, ReceivedFromPeer, UpdateFromCentral],
	*dpubsub.Stream[UpdateFromCentral],
	error,
) {
	ch := make(chan inboundStateResult, 1)

	select {
	case <-ctx.Done():
		return nil, nil, fmt.Errorf(
			"context canceled while sending outbound state request: %w",
			context.Cause(ctx),
		)
	case s.inboundStateRequests <- ch:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return nil, nil, fmt.Errorf(
			"context canceled while awaiting outbound state response: %w",
			context.Cause(ctx),
		)
	case res := <-ch:
		return res.I, res.U, nil
	}
}

func (s *CentralState) newInboundState() *InboundState {
	i := &InboundState{
		log: s.log.With("cs_sub", "inbound"),

		keys: s.keys,

		centralPrevotesAvailable:   s.availablePrevoteBS.Clone(),
		centralPrecommitsAvailable: s.availablePrecommitBS.Clone(),

		peerSentPrevote:   bitset.MustNew(uint(len(s.keys))),
		peerSentPrecommit: bitset.MustNew(uint(len(s.keys))),

		signingMap: s.signingMap,

		prevoteTargets:   s.prevoteTargets,
		precommitTargets: s.precommitTargets,

		prevoteSigs:   s.prevoteSigs,
		precommitSigs: s.precommitSigs,

		sigLen:  s.sigLen,
		hashLen: s.hashLen,
	}

	return i
}

func (s *CentralState) AddLocalPrevote(
	ctx context.Context,
	keyIdx uint16,
	targetHash, sig []byte,
) error {
	// Be defensive and validate the signature first.
	if int(keyIdx) >= len(s.keys) {
		return fmt.Errorf(
			"key index %d out of bounds (must be < %d)",
			keyIdx, len(s.keys),
		)
	}

	signContent, err := s.signingMap.PrevoteSignContent(targetHash)
	if err != nil {
		return fmt.Errorf("failed to build prevote sign content: %w", err)
	}

	if !s.keys[keyIdx].Verify(signContent, sig) {
		return fmt.Errorf(
			"prevote signature invalid for key index %d and target hash %x",
			keyIdx, targetHash,
		)
	}

	// Now just effectively convert this to a peer delta
	// and go through that main path.
	if err := s.UpdateFromPeer(ctx, ReceivedFromPeer{
		KeyIdx:      keyIdx,
		Sig:         sig,
		TargetHash:  targetHash,
		IsPrecommit: false,
	}); err != nil {
		return fmt.Errorf(
			"failed to apply local prevote: %w", err,
		)
	}

	return nil
}

func (s *CentralState) AddLocalPrecommit(
	ctx context.Context,
	keyIdx uint16,
	targetHash, sig []byte,
) error {
	// Be defensive and validate the signature first.
	if int(keyIdx) >= len(s.keys) {
		return fmt.Errorf(
			"key index %d out of bounds (must be < %d)",
			keyIdx, len(s.keys),
		)
	}

	signContent, err := s.signingMap.PrecommitSignContent(targetHash)
	if err != nil {
		return fmt.Errorf("failed to build precommit sign content: %w", err)
	}

	if !s.keys[keyIdx].Verify(signContent, sig) {
		return fmt.Errorf(
			"precommit signature invalid for key index %d and target hash %x",
			keyIdx, targetHash,
		)
	}

	// Now just effectively convert this to a peer delta
	// and go through that main path.
	if err := s.UpdateFromPeer(ctx, ReceivedFromPeer{
		KeyIdx:      keyIdx,
		Sig:         sig,
		TargetHash:  targetHash,
		IsPrecommit: true,
	}); err != nil {
		return fmt.Errorf(
			"failed to apply local precommit: %w", err,
		)
	}

	return nil
}
