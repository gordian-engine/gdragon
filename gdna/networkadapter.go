package gdna

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/wingspan"
	"github.com/gordian-engine/gdragon/gdbc"
	"github.com/gordian-engine/gdragon/gdna/internal/gdnai"
	"github.com/gordian-engine/gdragon/gdwsu"
	"github.com/gordian-engine/gordian/gcrypto"
	"github.com/gordian-engine/gordian/gexchange"
	"github.com/gordian-engine/gordian/tm/tmcodec"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
	"github.com/gordian-engine/gordian/tm/tmengine/tmelink"
)

// OriginationDetails is the struct that the driver or application must provide
// in order for the [NetworkAdapter] to be able to broadcast a proposed block.
type OriginationDetails struct {
	// This is the serialized proposed header.
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

	bcChecks chan gdnai.BreathcastCheck

	incomingHeaders chan gdnai.IncomingHeader

	cc *dpubsub.Stream[dconn.Change]

	sab gdnai.StreamAccepterBase

	wg   sync.WaitGroup
	done chan struct{}
}

// AcceptedStream is the type representing
// a bidirectional stream accepted by the [NetworkAdapter].
type AcceptedStream = gdnai.AcceptedStream

// AcceptedUniStream is the type representing
// a unidirectional stream accepted by the [NetworkAdapter].
type AcceptedUniStream = gdnai.AcceptedUniStream

// NetworkAdapterConfig is the configuration value for [NewNetworkAdapter].
type NetworkAdapterConfig struct {
	// The initial connections, just like in the protocols.
	InitialConnections []dconn.Conn

	// The stream of connection changes, just like in the protocols.
	ConnectionChanges *dpubsub.Stream[dconn.Change]

	BreathcastAdapter *gdbc.Adapter

	Wingspan *wingspan.Protocol[
		gdwsu.ParsedPacket, gdwsu.OutboundPacket,
		gdwsu.ReceivedFromPeer, gdwsu.UpdateFromCentral,
	]

	// Needed for internal routing of QUIC streams.
	BreathcastProtocolID, WingspanProtocolID byte

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

	// How to get the broadcast details when decoding a proposed header.
	// Necessary for the receiving side of a breathcast-distributed block.
	GetBroadcastDetailsFunc func(proposalDriverAnnotations []byte) (gdbc.BroadcastDetails, error)

	// The [NetworkAdapter] starts goroutines per connection to accept streams.
	// If the stream has a protocol ID that does not match a protocol owned by the adapter,
	// that stream is sent on one of these two channels.
	// The application is responsible for draining these channels;
	// otherwise the network adapter will eventually deadlock.
	// These channels should be buffered.
	// The correct size is probably a multiple of the active peer set size in Dragon.
	AcceptedStreamCh    chan<- AcceptedStream
	AcceptedUniStreamCh chan<- AcceptedUniStream

	// How to deserialize a proposed header from a breathcast application header.
	Unmarshaler tmcodec.Unmarshaler
}

// NewNetworkAdapter returns a new NetworkAdapter.
func NewNetworkAdapter(
	ctx context.Context,
	log *slog.Logger,
	cfg NetworkAdapterConfig,
) *NetworkAdapter {

	// Unbuffered seems correct for this.
	breathcastChecks := make(chan gdnai.BreathcastCheck)
	incomingHeaders := make(chan gdnai.IncomingHeader)

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

		bcChecks: breathcastChecks,

		incomingHeaders: incomingHeaders,

		cc: cfg.ConnectionChanges,

		sab: gdnai.StreamAccepterBase{
			AcceptedStreamCh:    cfg.AcceptedStreamCh,
			AcceptedUniStreamCh: cfg.AcceptedUniStreamCh,
			IncomingHeaders:     incomingHeaders,

			BreathcastChecks: breathcastChecks,

			Unmarshaler: cfg.Unmarshaler,

			GetBroadcastDetails: cfg.GetBroadcastDetailsFunc,

			BCA: cfg.BreathcastAdapter,

			BCID: cfg.BreathcastProtocolID,
			WSID: cfg.WingspanProtocolID,
		},

		done: make(chan struct{}),
	}

	go s.mainLoop(ctx, cfg.InitialConnections)

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

func (s *NetworkAdapter) mainLoop(ctx context.Context, initialConns []dconn.Conn) {
	defer close(s.done)

	// First, block on the start signal.
	// (We could possibly consume the connection changes here,
	// but for now we will save that for the looped select.)
	var updates <-chan tmelink.NetworkViewUpdate
	select {
	case <-ctx.Done():
		return
	case updates = <-s.startCh:
		// Got the updates channel; the source channel will never be used again,
		// so let GC take it.
		s.startCh = nil
	}

	// Set up stream accepters on the initial connections.
	accepters := make(map[dcert.LeafCertHandle]*gdnai.StreamAccepter, len(initialConns))
	for _, conn := range initialConns {
		s.addStreamAccepter(ctx, accepters, conn)
	}

	// Now the real main loop.
	liveSessions := make(sessionSet)
	for {
		select {
		case <-ctx.Done():
			return

		case u := <-updates:
			s.processUpdate(ctx, liveSessions, u)

		case <-s.cc.Ready:
			s.handleConnectionChange(ctx, accepters)

		case c := <-s.bcChecks:
			res := s.handleBreathcastCheck(ctx, liveSessions, c)
			select {
			case <-ctx.Done():
				return
			case c.CheckResult <- res:
				// Okay.
			}

		case ih := <-s.incomingHeaders:
			s.handleIncomingHeader(ctx, liveSessions, ih)
		}
	}
}

// addStreamAccepter creates a new StreamAccepter instance
// for the given connection, and runs its background goroutines.
func (s *NetworkAdapter) addStreamAccepter(
	ctx context.Context,
	accepters map[dcert.LeafCertHandle]*gdnai.StreamAccepter,
	conn dconn.Conn,
) {
	connCtx, cancel := context.WithCancelCause(ctx)

	sa := gdnai.NewStreamAccepter(conn, cancel, &s.sab)

	s.wg.Add(2)
	go sa.AcceptStreams(connCtx, &s.wg)
	go sa.AcceptUniStreams(connCtx, &s.wg)

	accepters[conn.Chain.LeafHandle] = sa
}

// Wait blocks until all background work for s has finished.
func (s *NetworkAdapter) Wait() {
	<-s.done
	s.wg.Wait()
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

		// For now, we aren't doing anything with sessions in the grace period.
		// They will expire upon the expiration signal from the engine.
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
			if ctx.Err() != nil {
				// Shutting down due to context cancellation.
				cancel() // Free vote context anyway.
				return
			}
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
		if ctx.Err() != nil {
			// Context cancellation, so just quit.
			cancel() // Free bopCtx resources anyway.
			return
		}
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

// handleConnectionChange handles a new value on s.cc (the ConnChange pubsub stream).
func (s *NetworkAdapter) handleConnectionChange(
	ctx context.Context,
	accepters map[dcert.LeafCertHandle]*gdnai.StreamAccepter,
) {
	cc := s.cc.Val
	s.cc = s.cc.Next

	if !cc.Adding {
		// Removing is the simple case.
		sa, ok := accepters[cc.Conn.Chain.LeafHandle]
		if !ok {
			panic(errors.New(
				"BUG: attempting to handle a removed connection lacking a stream accepter",
			))
		}

		sa.Cancel(errors.New("connection closing"))

		// TODO: where should we call sa.Wait?

		delete(accepters, cc.Conn.Chain.LeafHandle)
		return
	}

	// Adding. First, sanity check that we don't already have an accepter for this connection.
	if _, ok := accepters[cc.Conn.Chain.LeafHandle]; ok {
		// A second connection from the same peer, or at least a peer with an identical Chain,
		// should have been blocked earlier in the Dragon peer management code.
		panic(fmt.Errorf(
			"BUG: second connection from same peer reached network adapter (%#v)",
			cc.Conn.Chain,
		))
	}

	s.addStreamAccepter(ctx, accepters, cc.Conn)
}

// handleBreathcastCheck handles a check from a [gdnai.StreamAccepter].
// If the check matches an existing live session,
// the underlying stream is associated with the corresponding operation.
func (s *NetworkAdapter) handleBreathcastCheck(
	ctx context.Context,
	liveSessions sessionSet,
	c gdnai.BreathcastCheck,
) gdnai.BreathcastCheckResult {
	// TODO: actually compare against real sessions.
	return gdnai.BreathcastCheckNeedsProcessed
}

func (s *NetworkAdapter) handleIncomingHeader(
	ctx context.Context,
	liveSessions sessionSet,
	ih gdnai.IncomingHeader,
) {
	// First, do we have a matching session?
	sessKey := hr{
		H: binary.BigEndian.Uint64(ih.BroadcastID),
		R: binary.BigEndian.Uint32(ih.BroadcastID[8:]),
	}

	sess, ok := liveSessions[sessKey]
	if !ok {
		panic("TODO: consult consensus handler for missing session")
	}

	// We have a matching session, so first we have to check if we raced on this particular header.
	if cb, ok := sess.Headers[string(ih.ProposedHeader.Header.Hash)]; ok {
		// It was a race.
		// We can just pass the stream directly to the operation.
		if err := cb.Op.AcceptBroadcast(ctx, ih.Conn, ih.Stream); err != nil {
			panic(fmt.Errorf(
				"TODO: handle error when accepting broadcast: %w", err,
			))
		}
		return
	}

	// First time we've seen this header.
	// So, it's up to the mirror (the consensus handler, actually) whether we accept it.
	f := s.h.HandleProposedHeader(ctx, ih.ProposedHeader)
	switch f {
	case gexchange.FeedbackAccepted:
		// This is the case we are hoping for.
		// Process it outside the switch.
		break

	case gexchange.FeedbackRejected:
		// TODO: we don't yet have a way to "penalize" the sender in Dragon,
		// which we are supposed to do in the reject case.
		// So for now just close the stream.
		ih.Stream.CancelWrite(ProposedHeaderRejected)
		_ = ih.Stream.Close()
		return

	case gexchange.FeedbackIgnored:
		// Just close the connection without penalizing the source.
		ih.Stream.CancelWrite(ProposedHeaderIgnored)
		_ = ih.Stream.Close()
		return

	case gexchange.FeedbackRejectAndDisconnect:
		// The sender did something egregious,
		// so we close the entire connection.
		_ = ih.Conn.QUIC.CloseWithError(DisconnectDueToProposedHeader, "rejected proposed header")
		return

	default:
		panic(fmt.Errorf(
			"BUG: unhandled feedback value %s when handling proposed header", f,
		))
	}

	// Now we can make a broadcast operation.
	bCtx, cancel := context.WithCancel(ctx)
	bop, err := s.bc.NewIncomingBroadcast(bCtx, gdbc.IncomingBroadcastConfig{
		BroadcastID: ih.BroadcastID,
		AppHeader:   ih.AppHeaderBytes,

		BroadcastDetails: ih.BroadcastDetails,
	})
	if err != nil {
		ih.Stream.CancelWrite(InternalBroadcastOperationFailure)
		_ = ih.Stream.Close()
		cancel()
		return
	}

	// Store the session.
	sess.Headers[string(ih.ProposedHeader.Header.Hash)] = cancelableBroadcast{
		Op:     bop,
		Cancel: cancel,
	}

	// And finally add the incoming stream to that session.
	if err := bop.AcceptBroadcast(bCtx, ih.Conn, ih.Stream); err != nil {
		ih.Stream.CancelWrite(InternalBroadcastOperationFailure)
		_ = ih.Stream.Close()
		cancel()
		return
	}
}
