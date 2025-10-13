package gdna

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

	"github.com/gordian-engine/dragon/wingspan"
	"github.com/gordian-engine/gdragon/gdbc"
	"github.com/gordian-engine/gdragon/gdwsu"
	"github.com/gordian-engine/gordian/gcrypto"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
	"github.com/gordian-engine/gordian/tm/tmengine/tmelink"
)

// OriginationDetails is the struct that the driver or application must provide
// in order for the [NetworkAdapter] to be able to broadcast a proposed block.
type OriginationDetails struct {
	// This is the serialized proposed headers.
	AppHeader []byte

	// The prepared origination details in order to call Originate.
	PreparedOrigination gdbc.PreparedOrigination
}

// NetworkAdapter abstracts most of the translation to and from the networking layer,
// for integration with dragon.
//
// Note, this current implementation is hardcoded to use unaggregated votes.
// Once this implementation is more complete,
// there will be a way to specify either aggregated or unaggregated votes,
// probably through two distinct adapter types.
//
// The NetworkAdapter implements [github.com/gordian-engine/gordian/tm/tmgossip.Strategy].
type NetworkAdapter struct {
	log *slog.Logger

	h tmconsensus.ConsensusHandler

	bc *gdbc.Adapter
	ws *wingspan.Protocol[
		gdwsu.ParsedPacket, gdwsu.OutboundPacket,
		gdwsu.ReceivedFromPeer, gdwsu.UpdateFromCentral,
	]

	pubKey gcrypto.PubKey

	sigScheme tmconsensus.SignatureScheme

	sigLen, hashLen uint16

	getOriginationDetails func([]byte) OriginationDetails

	startCh chan (<-chan tmelink.NetworkViewUpdate)

	done chan struct{}
}

// NetworkAdapterConfig is the configuration value for [NewNetworkAdapter].
type NetworkAdapterConfig struct {
	BreathcastAdapter *gdbc.Adapter

	Wingspan *wingspan.Protocol[
		gdwsu.ParsedPacket, gdwsu.OutboundPacket,
		gdwsu.ReceivedFromPeer, gdwsu.UpdateFromCentral,
	]

	// If validating, the validator's public key.
	// This is used to determine whether a reported proposed header
	// must be an originating broadcast to peers.
	//
	// The value may be nil if participating in p2p but not validating.
	OwnPubKey gcrypto.PubKey

	// Needed for validating votes.
	SignatureScheme tmconsensus.SignatureScheme

	// Also needed for validating votes.
	SignatureLen, HashLen uint16

	// How to get the origination details for outgoing proposals.
	// Used when constructing the broadcast.
	// May be nil if OwnPubKey is also nil.
	//
	// This function does not return an error;
	// inability to retrieve the origination details for a header
	// proposed by the current validator is fatal.
	GetOriginationDetailsFunc func(blockHash []byte) OriginationDetails
}

// NewNetworkAdapter returns a new NetworkAdapter.
func NewNetworkAdapter(
	ctx context.Context,
	log *slog.Logger,
	cfg NetworkAdapterConfig,
) *NetworkAdapter {
	s := &NetworkAdapter{
		log: log,

		bc: cfg.BreathcastAdapter,
		ws: cfg.Wingspan,

		pubKey: cfg.OwnPubKey,

		sigScheme: cfg.SignatureScheme,
		sigLen:    cfg.SignatureLen,
		hashLen:   cfg.HashLen,

		getOriginationDetails: cfg.GetOriginationDetailsFunc,

		// 1-buffered so the Start call doesn't block.
		startCh: make(chan (<-chan tmelink.NetworkViewUpdate), 1),

		done: make(chan struct{}),
	}

	go s.mainLoop(ctx)

	return s
}

// Start implements [github.com/gordian-engine/gordian/tm/tmgossip.Strategy].
// (This may get extracted to its own type
func (s *NetworkAdapter) Start(updates <-chan tmelink.NetworkViewUpdate) {
	s.startCh <- updates
}

// SetConsensusHandler sets the consensus handler for the adapter.
// Typically this is the actual [github.com/gordian-engine/gordian/tm/tmengine.Engine] instance.
//
// This method must be called before [*NetworkAdapter.Start].
func (s *NetworkAdapter) SetConsensusHandler(h tmconsensus.ConsensusHandler) {
	s.h = h
}

func (s *NetworkAdapter) mainLoop(ctx context.Context) {
	defer close(s.done)

	// First, block on the start signal.
	var updates <-chan tmelink.NetworkViewUpdate
	select {
	case <-ctx.Done():
		return
	case updates = <-s.startCh:
		// Got the updates channel; the source channel will never be used again,
		// so let GC take it.
		s.startCh = nil
	}

	// Now the real main loop.
	liveSessions := make(sessionSet)
	for {
		select {
		case <-ctx.Done():
			return

		case u := <-updates:
			s.processUpdate(ctx, liveSessions, u)
		}
	}
}

// Wait blocks until all background work for s has finished.
func (s *NetworkAdapter) Wait() {
	<-s.done
}

// processUpdate handles a single network view update from the core engine.
func (s *NetworkAdapter) processUpdate(
	ctx context.Context,
	liveSessions sessionSet,
	u tmelink.NetworkViewUpdate,
) {
	s.handleSessionChanges(ctx, liveSessions, u)

	s.initiateBroadcasts(ctx, liveSessions, u.Voting)
}

func (s *NetworkAdapter) handleSessionChanges(
	ctx context.Context,
	liveSessions sessionSet,
	u tmelink.NetworkViewUpdate,
) {
	for _, c := range u.RoundSessionChanges {
		if c.State == tmelink.RoundSessionStateActive {
			s.handleActivatedSession(ctx, liveSessions, u, c.Height, c.Round)
			continue
		}

		if c.State == tmelink.RoundSessionStateExpired {
			s.handleExpiredSession(liveSessions, c.Height, c.Round)
			continue
		}
	}
}

func (s *NetworkAdapter) handleActivatedSession(
	ctx context.Context,
	liveSessions sessionSet,
	u tmelink.NetworkViewUpdate,
	h uint64,
	r uint32,
) {
	// Active session -- make sure we have an entry in liveSessions.
	k := hr{H: h, R: r}
	if _, ok := liveSessions[k]; !ok {
		// The voting session can be initialized immediately,
		// regardless of whether we've seen any votes yet.

		// The voting session app header is just height and round.
		voteSessionID := make([]byte, 8+4)
		binary.BigEndian.PutUint64(voteSessionID, k.H)
		binary.BigEndian.PutUint32(voteSessionID[8:], k.R)

		voteCtx, cancel := context.WithCancel(ctx)

		var pubKeys []gcrypto.PubKey
		if u.Voting != nil {
			pubKeys = u.Voting.ValidatorSet.PubKeys
		} else if u.NextRound != nil {
			// Questionable but maybe okay.
			pubKeys = u.NextRound.ValidatorSet.PubKeys
		} else {
			panic(fmt.Errorf(
				"BUG: cannot retrieve public keys for activated voting round at %d/%d due to missing views",
				h, r,
			))
		}
		voteState, voteDeltas := gdwsu.NewCentralState(
			voteCtx,
			k.H, k.R,
			pubKeys,
			s.sigLen, s.hashLen,
			s.sigScheme,
		)

		vs, err := s.ws.NewSession(
			voteCtx,
			voteSessionID,
			nil, // TODO: what do we actually need in the appHeader?
			voteState, voteDeltas,
		)
		if err != nil {
			panic(fmt.Errorf(
				"TODO: handle error from new voting session: %w", err,
			))
		}

		liveSessions[k] = sessions{
			// Initialize the collection of broadcasts.
			Headers: make(map[string]cancelableBroadcast),

			VoteSession:  vs,
			CancelVoting: cancel,
		}
	}
}

func (s *NetworkAdapter) handleExpiredSession(
	liveSessions sessionSet,
	height uint64, round uint32,
) {
	k := hr{H: height, R: round}
	sess, ok := liveSessions[k]
	if !ok {
		return
	}
	// Cancel any outstanding sessions.
	for hk, b := range sess.Headers {
		b.Cancel()

		// TODO: where is the right place to call b.Wait
		// to ensure it is fully shut down?

		// Deleting the entry as we iterate the map
		// probably helps GC.
		delete(sess.Headers, hk)
	}

	// We assume CancelVoting cannot be nil,
	// because we always initialize the cancel func
	// when creating the function.
	sess.CancelVoting()

	// TODO: where can we wait on the voting session either?

	// Finally remove the session entry.
	delete(liveSessions, k)
}

// initiateBroadcasts creates an outgoing broadcast,
// if the voting view contains a proposed header for which we are the signer
// and which does not yet have a running broadcast operation.
func (s *NetworkAdapter) initiateBroadcasts(
	ctx context.Context,
	liveSessions sessionSet,
	votingView *tmconsensus.VersionedRoundView,
) {
	if votingView == nil || s.pubKey == nil {
		// No updates to check.
		return
	}

	needsBroadcastIdx := -1
	for i, ph := range votingView.ProposedHeaders {
		if !s.pubKey.Equal(ph.ProposerPubKey) {
			continue
		}

		// The current public key matches ours.
		needsBroadcastIdx = i
		break
	}

	// Didn't find a proposed header that we need to originate.
	if needsBroadcastIdx < 0 {
		return
	}

	// Now, has the broadcast already been initialized?
	ph := votingView.ProposedHeaders[needsBroadcastIdx]
	sKey := hr{
		H: ph.Header.Height,
		R: ph.Round,
	}
	ss, ok := liveSessions[sKey]
	if !ok {
		// Just need to initialize the map here.
		liveSessions[sKey] = sessions{
			Headers: make(map[string]cancelableBroadcast),
		}
	}

	if _, ok := ss.Headers[string(ph.Header.Hash)]; ok {
		// We already have a session for this hash.
		return
	}

	// We didn't have a session, so it's time to propagate it.
	proposerIdx := -1
	for i, pk := range votingView.ValidatorSet.PubKeys {
		if s.pubKey.Equal(pk) {
			proposerIdx = i
			break
		}
	}
	if proposerIdx < 0 {
		panic(errors.New(
			"BUG: failed to find index for own pubkey in own proposal",
		))
	}

	d := s.getOriginationDetails(ph.Header.Hash)
	bopCtx, cancel := context.WithCancel(ctx)
	bop, err := s.bc.Originate(bopCtx, d.AppHeader, d.PreparedOrigination)
	if err != nil {
		panic(fmt.Errorf(
			"TODO: handle error in origination: %w", err,
		))
	}

	// Finally, store the session.
	liveSessions[sKey].Headers[string(ph.Header.Hash)] = cancelableBroadcast{
		Op:     bop,
		Cancel: cancel,
	}
}
