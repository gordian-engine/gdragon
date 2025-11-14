package gdna

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/breathcast"
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

	getOriginationDetails func(tmconsensus.ProposedHeader) OriginationDetails

	onDataReady func(context.Context, uint64, uint32, []byte, io.Reader)

	startCh chan (<-chan tmelink.NetworkViewUpdate)

	bcChecks chan gdnai.BreathcastCheck

	incomingHeaders     <-chan gdnai.IncomingHeader
	breathcastDatagrams <-chan gdnai.BreathcastDatagram

	incomingWingspanStreams <-chan gdnai.IncomingWingspanStream

	blockDataArrivalCh chan<- tmelink.BlockDataArrival

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

type IncomingDatagram = gdnai.IncomingDatagram

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
	GetOriginationDetailsFunc func(tmconsensus.ProposedHeader) OriginationDetails

	// How to get the broadcast details when decoding a proposed header.
	// Necessary for the receiving side of a breathcast-distributed block.
	GetBroadcastDetailsFunc func(proposalDriverAnnotations []byte) (gdbc.BroadcastDetails, error)

	// Optional callback for once the data is ready for a particular broadcast operation.
	// This function will be called after the data has been reconstructed
	// but before the engine is notified.
	OnDataReadyFunc func(
		ctx context.Context, height uint64, round uint32, dataID []byte, r io.Reader,
	)

	// The [NetworkAdapter] starts goroutines per connection to accept streams.
	// If the stream has a protocol ID that does not match a protocol owned by the adapter,
	// that stream is sent on one of these two channels.
	// The application is responsible for draining these channels;
	// otherwise the network adapter will eventually deadlock.
	// These channels should be buffered.
	// The correct size is probably a multiple of the active peer set size in Dragon.
	AcceptedStreamCh    chan<- AcceptedStream
	AcceptedUniStreamCh chan<- AcceptedUniStream

	// The NetworkAdapter sends to this channel,
	// and the core engine receives from it,
	// to refresh the consensus strategy once the block data is readable.
	//
	// The appropriate buffer size for this channel will be application-dependent.
	BlockDataArrivalCh chan<- tmelink.BlockDataArrival

	// When the managed connections send a datagram,
	// if it does not match a controlled protocol,
	// the datagram is exposed through this channel.
	// The channel must be drained or the network adapter will deadlock.
	IncomingDatagrams chan<- IncomingDatagram

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
	incomingWingspanStreams := make(chan gdnai.IncomingWingspanStream)

	// We need to be very sure to not block datagrams from being processed,
	// so this is an unusually large channel
	// (in the context of the dragon stack).
	breathcastDatagrams := make(chan gdnai.BreathcastDatagram, 128)

	s := &NetworkAdapter{
		log: log,

		bc: cfg.BreathcastAdapter,
		ws: cfg.Wingspan,

		pubKey: cfg.OwnPubKey,

		sigScheme: cfg.SignatureScheme,
		sigLen:    cfg.SignatureLen,
		hashLen:   cfg.HashLen,

		getOriginationDetails: cfg.GetOriginationDetailsFunc,

		onDataReady: cfg.OnDataReadyFunc,

		// 1-buffered so the Start call doesn't block.
		startCh: make(chan (<-chan tmelink.NetworkViewUpdate), 1),

		bcChecks: breathcastChecks,

		incomingHeaders:     incomingHeaders,
		breathcastDatagrams: breathcastDatagrams,

		incomingWingspanStreams: incomingWingspanStreams,

		blockDataArrivalCh: cfg.BlockDataArrivalCh,

		cc: cfg.ConnectionChanges,

		sab: gdnai.StreamAccepterBase{
			AcceptedStreamCh:    cfg.AcceptedStreamCh,
			AcceptedUniStreamCh: cfg.AcceptedUniStreamCh,

			IncomingHeaders:     incomingHeaders,
			BreathcastDatagrams: breathcastDatagrams,

			IncomingWingspanStreams: incomingWingspanStreams,

			IncomingDatagrams: nil, // TODO

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

	// Block until we get the first network view update.
	//
	// We need this in order to handle some edge cases at the initial height.
	//
	// The engine is supposed to send this synchronously at startup,
	// so it should be safe to block here.
	liveSessions := make(sessionSet)
	select {
	case <-ctx.Done():
		return
	case u := <-updates:
		s.processNetworkViewUpdate(ctx, liveSessions, u)
	}

	// Now the real main loop.
	for {
		select {
		case <-ctx.Done():
			return

		case u := <-updates:
			s.processNetworkViewUpdate(ctx, liveSessions, u)

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

		case d := <-s.breathcastDatagrams:
			s.handleBreathcastDatagram(ctx, liveSessions, d)

		case iws := <-s.incomingWingspanStreams:
			s.handleIncomingWingspanStream(ctx, liveSessions, iws)
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

// processNetworkViewUpdate handles a single network view update from the core engine.
func (s *NetworkAdapter) processNetworkViewUpdate(
	ctx context.Context,
	liveSessions sessionSet,
	u tmelink.NetworkViewUpdate,
) {
	s.handleSessionChanges(ctx, liveSessions, u)

	s.initiateBroadcasts(ctx, liveSessions, u.Voting)

	s.processAllVotes(ctx, liveSessions, u)
}

func (s *NetworkAdapter) handleSessionChanges(
	ctx context.Context,
	liveSessions sessionSet,
	u tmelink.NetworkViewUpdate,
) {
	for _, c := range u.RoundSessionChanges {
		if c.State == tmelink.RoundSessionStateActive {
			if u.Voting != nil && u.Voting.Height == c.Height && u.Voting.Round == c.Round {
				s.handleActivatedSession(
					ctx,
					liveSessions,
					c.Height,
					c.Round,
					u.Voting.ValidatorSet.PubKeys,
					u.Voting.ValidatorSet.PubKeyHash,
				)
				continue
			}

			if u.Committing != nil && u.Committing.Height == c.Height && u.Committing.Round == c.Round {
				s.handleActivatedSession(
					ctx,
					liveSessions,
					c.Height,
					c.Round,
					u.Committing.ValidatorSet.PubKeys,
					u.Committing.ValidatorSet.PubKeyHash,
				)
				continue
			}

			panic(errors.New(
				"BUG: received network view update that activated session which did not match voting or committing",
			))
		}

		if c.State == tmelink.RoundSessionStateExpired {
			s.handleExpiredSession(liveSessions, c.Height, c.Round)
			continue
		}

		// For now, we aren't doing anything with sessions in the grace period.
		// They will expire upon the expiration signal from the engine.
	}
}

// handleActivatedSession responds to an activated "logical" session
// as reported by the engine.
func (s *NetworkAdapter) handleActivatedSession(
	ctx context.Context,
	liveSessions sessionSet,
	h uint64,
	r uint32,
	pubKeys []gcrypto.PubKey,
	pubKeyHash []byte,
) {
	// Active session -- make sure we have an entry in liveSessions.
	k := hr{H: h, R: r}
	if _, ok := liveSessions[k]; !ok {
		// The voting session can be initialized immediately,
		// regardless of whether we've seen any votes yet.

		// The voting session ID is just height and round.
		voteSessionID := make([]byte, 8+4)
		binary.BigEndian.PutUint64(voteSessionID, k.H)
		binary.BigEndian.PutUint32(voteSessionID[8:], k.R)

		voteCtx, cancel := context.WithCancel(ctx)

		voteState, voteDeltas := gdwsu.NewCentralState(
			voteCtx,
			s.log.With(
				"na_sub", "central_vote_state",
				"h", k.H,
				"r", k.R,
			),
			k.H, k.R,
			pubKeys,
			s.sigLen, s.hashLen,
			s.sigScheme,
		)

		voteSess, err := s.ws.NewSession(
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
			Headers: make(map[uint16]cancelableBroadcast),

			VoteSession:  voteSess,
			CentralState: voteState,
			VoteRecord:   new(voteRecord),
			CancelVoting: cancel,
		}

		s.wg.Add(2)
		go forwardUnaggregatedPrevotes(
			ctx, &s.wg,
			k.H, k.R,
			string(pubKeyHash),
			s.h,
			voteState.Prevotes(),
		)
		go forwardUnaggregatedPrecommits(
			ctx, &s.wg,
			k.H, k.R,
			string(pubKeyHash),
			s.h,
			voteState.Precommits(),
		)
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
		liveSessions[sKey] = sessions{
			Headers:    make(map[uint16]cancelableBroadcast),
			VoteRecord: new(voteRecord),
		}
	}

	// Need our proposer index so we can determine if we have a broadcast operation.
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

	if _, ok := ss.Headers[uint16(proposerIdx)]; ok {
		// We already have a session for this hash.
		return
	}

	// Didn't have a broadcast operation, so now we can create one.

	d := s.getOriginationDetails(ph)
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
	liveSessions[sKey].Headers[uint16(proposerIdx)] = cancelableBroadcast{
		Op:     bop,
		Cancel: cancel,

		ProposedHeader: ph,
	}

	// And link the operation's data to the block data arrival.
	s.wg.Add(1)
	go notifyBlockDataArrival(
		bopCtx, &s.wg,
		bop,
		s.blockDataArrivalCh,
		ph.Header.Height,
		ph.Round,
		ph.Header.DataID,
		s.onDataReady,
	)
}

// processAllVotes scans the network view update
// for prevotes and precommits originating from the adapter's pubkey,
// and then calls into the appropriate central state methods.
func (s *NetworkAdapter) processAllVotes(
	ctx context.Context,
	liveSessions sessionSet,
	u tmelink.NetworkViewUpdate,
) {
	if s.pubKey == nil {
		// Calls to s.processVotes assume presence of our own public key,
		// and if we didn't have them, then we wouldn't be sending out
		// an original vote anyway.
		return
	}

	if u.Committing != nil {
		s.processVotes(ctx, liveSessions, u.Committing)
	}

	if u.Voting != nil {
		s.processVotes(ctx, liveSessions, u.Voting)
	}

	if u.NextRound != nil {
		s.processVotes(ctx, liveSessions, u.NextRound)
	}
}

// processVotes adds our own vote to the central state value,
// if detected and if not sent earlier.
func (s *NetworkAdapter) processVotes(
	ctx context.Context,
	liveSessions sessionSet,
	vrv *tmconsensus.VersionedRoundView,
) {
	sessKey := hr{H: vrv.Height, R: vrv.Round}

	sess, ok := liveSessions[sessKey]
	if !ok {
		panic(fmt.Errorf(
			"BUG: session %d/%d should have been live but was not found",
			sessKey.H, sessKey.R,
		))
	}

	if !sess.VoteRecord.NeedsProcessed(vrv.ValidatorSet.PubKeys, s.pubKey) {
		return
	}

	// TODO: this bitset should probably be passed in,
	// so we don't reallocated repeatedly.
	bs := bitset.MustNew(uint(len(vrv.ValidatorSet.Validators)))

	if !sess.VoteRecord.RecordedOwnPrevote {
		// We need to look through each set of prevotes,
		// as we cannot predict which one contains our vote,
		// if any does at all.
		for hash, proof := range vrv.PrevoteProofs {
			// Copy the signature bits.
			proof.SignatureBitSet(bs)

			// Is our vote present?
			if !bs.Test(uint(sess.VoteRecord.OwnKeyIdx)) {
				continue
			}

			// We need to extract the individual signature for the central state.
			// This is a very awkward API,
			// because most of the Gordian code wants to abstract
			// whether signatures are aggregated,
			// and extracting individual signatures.

			expKeyID := make([]byte, 2)
			uo := uint16(sess.VoteRecord.OwnKeyIdx)
			binary.BigEndian.PutUint16(expKeyID, uo)

			var sig []byte
			for _, ss := range proof.AsSparse().Signatures {
				if bytes.Equal(expKeyID, ss.KeyID) {
					sig = ss.Sig
					break
				}
			}
			if sig == nil {
				panic(errors.New(
					"BUG: reported prevote signature not found after sparse conversion",
				))
			}

			if err := sess.CentralState.AddLocalPrevote(
				ctx, uo, []byte(hash), sig,
			); err != nil {
				panic(fmt.Errorf(
					"TODO: handle error when adding local prevote: %w", err,
				))
			}

			sess.VoteRecord.RecordedOwnPrevote = true
			break
		}
	}

	// Now do the same thing, but with precommits.
	if !sess.VoteRecord.RecordedOwnPrecommit {
		// We need to look through each set of precommits,
		// as we cannot predict which one contains our vote,
		// if any does at all.
		for hash, proof := range vrv.PrecommitProofs {
			// Copy the signature bits.
			proof.SignatureBitSet(bs)

			// Is our vote present?
			if !bs.Test(uint(sess.VoteRecord.OwnKeyIdx)) {
				continue
			}

			// We need to extract the individual signature for the central state.
			// This is a very awkward API,
			// because most of the Gordian code wants to abstract
			// whether signatures are aggregated,
			// and extracting individual signatures.

			expKeyID := make([]byte, 2)
			uo := uint16(sess.VoteRecord.OwnKeyIdx)
			binary.BigEndian.PutUint16(expKeyID, uo)

			var sig []byte
			for _, ss := range proof.AsSparse().Signatures {
				if bytes.Equal(expKeyID, ss.KeyID) {
					sig = ss.Sig
					break
				}
			}
			if sig == nil {
				panic(errors.New(
					"BUG: reported precommit signature not found after sparse conversion",
				))
			}

			if err := sess.CentralState.AddLocalPrecommit(
				ctx, uo, []byte(hash), sig,
			); err != nil {
				panic(fmt.Errorf(
					"TODO: handle error when adding local precommit: %w", err,
				))
			}

			sess.VoteRecord.RecordedOwnPrecommit = true
			break
		}
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

func (s *NetworkAdapter) handleBreathcastDatagram(
	ctx context.Context,
	liveSessions sessionSet,
	d gdnai.BreathcastDatagram,
) {
	// First, do we have a session for this?
	sessKey := hr{
		H: d.BID.Height,
		R: d.BID.Round,
	}

	sess, ok := liveSessions[sessKey]
	if !ok {
		// We don't have a session for this.
		// TODO: further inspection of the packet to decide
		// whether this was an acceptable out-of-bounds packet
		// or whether this is congestion that should be penalized.
		return
	}

	cb, ok := sess.Headers[d.BID.ProposerIdx]
	if !ok {
		// No matching broadcast ID.
		panic(errors.New(
			"TODO: handle datagram for valid session but missing broadcast operation",
		))
	}

	// We have the matching operation.
	if err := cb.Op.HandlePacket(ctx, d.Datagram); err != nil {
		panic(fmt.Errorf(
			"TODO: handle error in handling packet: %w", err,
		))
	}
}

func (s *NetworkAdapter) handleIncomingWingspanStream(
	ctx context.Context,
	liveSessions sessionSet,
	iws gdnai.IncomingWingspanStream,
) {
	// Check session first.
	sessKey := hr{
		H: iws.SessionHeight,
		R: iws.SessionRound,
	}

	sess, ok := liveSessions[sessKey]
	if !ok {
		s.handleMissingSessionWingspanStream(ctx, liveSessions, iws)
		return
	}

	// Okay, we have a session for this height/round,
	// which means we also have a wingspan session.
	if err := sess.VoteSession.AcceptStream(ctx, iws.Conn, iws.Stream); err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		panic(fmt.Errorf(
			"TODO: handle error when accepting wingspan stream: %w", err,
		))
	}
}

func (s *NetworkAdapter) handleMissingSessionWingspanStream(
	ctx context.Context,
	liveSessions sessionSet,
	iws gdnai.IncomingWingspanStream,
) {
	// If underflow here, we just won't find a matching session.
	prevHeight := iws.SessionHeight - 1
	found := false
	var prevSess sessions
	for k, ss := range liveSessions {
		if k.H == prevHeight {
			// Any session with the previous height; round unimportant.
			prevSess = ss
			found = true
			break
		}
	}
	if !found {
		// Didn't find it.
		panic(fmt.Errorf(
			"TODO: need to reject this stream (height %d, due to no prev match) with a meaningful error code",
			iws.SessionHeight,
		))
	}

	// We found a session with the previous height.
	// Does the incoming stream match the pub key hash?
	var valSet tmconsensus.ValidatorSet
	found = false
	for _, cb := range prevSess.Headers {
		valSet = cb.ProposedHeader.Header.NextValidatorSet
		found = true
		break
	}
	if !found {
		panic(errors.New(
			"TODO: need to reject this stream (due to no prev header) with a meaningful error code",
		))
	}

	s.handleActivatedSession(
		ctx,
		liveSessions,
		iws.SessionHeight, iws.SessionRound,
		valSet.PubKeys,
		valSet.PubKeyHash,
	)

	sess, ok := liveSessions[hr{
		H: iws.SessionHeight,
		R: iws.SessionRound,
	}]
	if !ok {
		s.log.Warn("Attempted to handle session but there must have been a context error")
		return
	}

	if err := sess.VoteSession.AcceptStream(ctx, iws.Conn, iws.Stream); err != nil {
		panic(fmt.Errorf(
			"TODO: handle error when accepting wingspan stream: %w", err,
		))
	}
}

func (s *NetworkAdapter) handleIncomingHeader(
	ctx context.Context,
	liveSessions sessionSet,
	ih gdnai.IncomingHeader,
) {
	// First, do we have a matching session?
	sessKey := hr{
		H: ih.BroadcastID.Height,
		R: ih.BroadcastID.Round,
	}

	sess, ok := liveSessions[sessKey]
	if !ok {
		panic(fmt.Errorf(
			"TODO: consult consensus handler for missing session (requested %d/%d)",
			sessKey.H, sessKey.R,
		))
	}

	// We have a matching session, so first we have to check if we raced on this particular header.
	if cb, ok := sess.Headers[ih.BroadcastID.ProposerIdx]; ok {
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
	sess.Headers[ih.BroadcastID.ProposerIdx] = cancelableBroadcast{
		Op:     bop,
		Cancel: cancel,

		ProposedHeader: ih.ProposedHeader,
	}

	// And finally add the incoming stream to that session.
	if err := bop.AcceptBroadcast(bCtx, ih.Conn, ih.Stream); err != nil {
		ih.Stream.CancelWrite(InternalBroadcastOperationFailure)
		_ = ih.Stream.Close()
		cancel()
		return
	}

	s.wg.Add(1)
	go notifyBlockDataArrival(
		bCtx, &s.wg,
		bop,
		s.blockDataArrivalCh,
		ih.ProposedHeader.Header.Height,
		ih.ProposedHeader.Round,
		ih.ProposedHeader.Header.DataID,
		s.onDataReady,
	)
}

// notifyBlockDataArrival sends a notification on bdaCh
// when the data is ready for a particular block.
//
// This is run in its own goroutine.
func notifyBlockDataArrival(
	ctx context.Context,
	wg *sync.WaitGroup,
	bop *breathcast.BroadcastOperation,
	bdaCh chan<- tmelink.BlockDataArrival,
	height uint64,
	round uint32,
	dataID []byte,
	onDataReady func(context.Context, uint64, uint32, []byte, io.Reader),
) {
	defer wg.Done()

	// Wait for the data to be ready.
	select {
	case <-ctx.Done():
		return
	case <-bop.DataReady():
		// Okay to notify.
	}

	if onDataReady != nil {
		onDataReady(ctx, height, round, dataID, bop.Data(ctx))
	}

	select {
	case <-ctx.Done():
		return
	case bdaCh <- tmelink.BlockDataArrival{
		Height: height,
		Round:  round,
		ID:     string(dataID),
	}:
		// Done.
	}
}
