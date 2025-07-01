package gdtmp2p

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/gordian-engine/dragon"
	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/gordian/gexchange"
	"github.com/gordian-engine/gordian/tm/tmcodec"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
	"github.com/gordian-engine/gordian/tm/tmp2p"
	"github.com/quic-go/quic-go"
)

type incomingStream struct {
	ProtocolID byte
	Stream     quic.Stream
}

type incomingUniStream struct {
	ProtocolID byte
	Stream     quic.ReceiveStream
}

type Connection struct {
	log *slog.Logger

	n *dragon.Node

	h tmconsensus.ConsensusHandler

	unmarshaler tmcodec.Unmarshaler

	bc *breathcast.Protocol

	bcProtoID byte

	getOriginationConfig OriginationConfigFunc

	cancel context.CancelFunc

	connChanges *dpubsub.Stream[dconn.Change]

	setConsensusHandlerRequests chan setConsensusHandlerRequest

	outgoingProposedHeaders chan tmconsensus.ProposedHeader
	outgoingPrevoteProofs   chan tmconsensus.PrevoteSparseProof
	outgoingPrecommitProofs chan tmconsensus.PrecommitSparseProof

	// Shared channel across any QUIC connection.
	// Upon any new QUIC connection, we start a [connWorker]
	// that accepts streams and routes them to this Connection's main loop.
	incomingStreams    chan incomingStream
	incomingUniStreams chan incomingUniStream

	disconnectOnce sync.Once
	disconnectCh   chan struct{}
	disconnected   chan struct{}
}

type setConsensusHandlerRequest struct {
	Handler tmconsensus.ConsensusHandler
	Resp    chan struct{}
}

// OriginationConfigFunc is used in the [Connection]'s main loop.
// The consensus engine only provides a proposed header;
// the driver is responsible for definining how to create
// a breathcast origination from only the information in the proposed header.
type OriginationConfigFunc func(
	context.Context, tmconsensus.ProposedHeader,
) (breathcast.OriginationConfig, error)

// ConnectionConfig is the configuration for [NewConnection].
type ConnectionConfig struct {
	Node   *dragon.Node
	Cancel context.CancelFunc

	Breathcast  *breathcast.Protocol
	Unmarshaler tmcodec.Unmarshaler

	BreathcastProtocolID byte

	OriginationConfigFunc OriginationConfigFunc

	ConnChanges *dpubsub.Stream[dconn.Change]
}

func NewConnection(
	ctx context.Context,
	log *slog.Logger,
	cfg ConnectionConfig,
) *Connection {
	c := &Connection{
		log: log,

		n: cfg.Node,

		bc:        cfg.Breathcast,
		bcProtoID: cfg.BreathcastProtocolID,

		unmarshaler: cfg.Unmarshaler,

		getOriginationConfig: cfg.OriginationConfigFunc,

		cancel: cfg.Cancel,

		connChanges: cfg.ConnChanges,

		// Unbuffered since caller blocks.
		setConsensusHandlerRequests: make(chan setConsensusHandlerRequest),

		outgoingProposedHeaders: make(chan tmconsensus.ProposedHeader, 1),
		outgoingPrevoteProofs:   make(chan tmconsensus.PrevoteSparseProof, 1),
		outgoingPrecommitProofs: make(chan tmconsensus.PrecommitSparseProof, 1),

		// Arbitrary size at this point.
		incomingStreams:    make(chan incomingStream, 4),
		incomingUniStreams: make(chan incomingUniStream, 4),

		disconnectCh: make(chan struct{}),
		disconnected: make(chan struct{}),
	}

	go c.handleDisconnect(ctx)

	go c.mainLoop(ctx)

	return c
}

func (c *Connection) mainLoop(ctx context.Context) {
	workers := map[dcert.LeafCertHandle]*connWorker{}
	bops := map[string]*breathcast.BroadcastOperation{}

	for {
		select {
		case <-ctx.Done():
			return

		case req := <-c.setConsensusHandlerRequests:
			c.h = req.Handler
			close(req.Resp)

		case ph := <-c.outgoingProposedHeaders:
			c.handleOutgoingProposedHeader(ctx, ph, bops)

		case <-c.connChanges.Ready:
			cc := c.connChanges.Val
			c.connChanges = c.connChanges.Next
			if cc.Adding {
				aCtx, cancel := context.WithCancel(ctx)
				w := &connWorker{
					log: c.log.With("remote", cc.Conn.QUIC.RemoteAddr()),

					Cancel: cancel,

					incomingStreams:    c.incomingStreams,
					incomingUniStreams: c.incomingUniStreams,
				}
				w.Run(aCtx, cc.Conn.QUIC)
				workers[cc.Conn.Chain.LeafHandle] = w
			}

		case is := <-c.incomingStreams:
			c.handleIncomingStream(ctx, is.ProtocolID, is.Stream, bops)

		case ius := <-c.incomingUniStreams:
			panic(fmt.Errorf(
				"TODO: handle incoming uni streams: %v", ius,
			))
		}
	}
}

func (c *Connection) handleOutgoingProposedHeader(
	ctx context.Context,
	ph tmconsensus.ProposedHeader,
	bops map[string]*breathcast.BroadcastOperation,
) {
	oc, err := c.getOriginationConfig(ctx, ph)
	if err != nil {
		c.log.Error(
			"Failed to get origination config",
			"height", ph.Header.Height,
			"round", ph.Round,
			"err", err,
		)
		return
	}

	bop, err := c.bc.NewOrigination(ctx, oc)
	if err != nil {
		c.log.Error("Failed to create origination", "err", err)
		return
	}

	// TODO: this should check whether an entry already exists.
	bops[string(oc.BroadcastID)] = bop
}

func (c *Connection) handleIncomingStream(
	ctx context.Context,
	pid byte,
	s quic.Stream,
	bops map[string]*breathcast.BroadcastOperation,
) {
	switch pid {
	case c.bcProtoID:
		// It's a breathcast protocol,
		// so first we have to extract the broadcast ID,
		// which normally would require the protocol instance,
		// but in this case we don't have a particular instance
		// and we do have the broadcast ID length.
		bid, err := c.bc.ExtractStreamBroadcastID(
			s, nil,
		)
		if err != nil {
			panic(err)
		}

		appHeader, _, err := breathcast.ExtractStreamApplicationHeader(s, nil)
		if err != nil {
			panic(err)
		}

		if _, ok := bops[string(bid)]; ok {
			// TODO: we should still check the app header.
			return
		}

		var ph tmconsensus.ProposedHeader
		err = c.unmarshaler.UnmarshalProposedHeader(appHeader, &ph)
		if err != nil {
			panic(err)
		}

		f := c.h.HandleProposedHeader(ctx, ph)
		switch f {
		case gexchange.FeedbackAccepted:
			// Accept the broadcast operation.
			var ann BroadcastAnnotation
			if err := json.Unmarshal(ph.Annotations.Driver, &ann); err != nil {
				panic(err)
			}

			bop, err := c.bc.NewIncomingBroadcast(ctx, breathcast.IncomingBroadcastConfig{
				BroadcastID: bid,
				AppHeader:   appHeader,

				NData:   ann.NData,
				NParity: ann.NParity,

				TotalDataSize: ann.TotalDataSize,

				Hasher:   bcsha256.Hasher{},
				HashSize: bcsha256.HashSize,

				HashNonce: ann.HashNonce,

				RootProofs: ann.RootProofs,

				ChunkSize: ann.ChunkSize,
			})
			if err != nil {
				panic(fmt.Errorf(
					"TODO: handle error on making incoming broadcast: %w", err,
				))
			}

			bops[string(bid)] = bop
		default:
			panic(fmt.Errorf(
				"TODO: handle exchange feedback %q (%d) for proposed header",
				f, f,
			))
		}

	default:
		panic(fmt.Errorf(
			"unexpected protocol ID 0x%x", pid,
		))
	}
}

type consensusBroadcaster struct {
	proposedHeaders chan tmconsensus.ProposedHeader
	prevoteProofs   chan tmconsensus.PrevoteSparseProof
	precommitProofs chan tmconsensus.PrecommitSparseProof
}

func (b consensusBroadcaster) OutgoingProposedHeaders() chan<- tmconsensus.ProposedHeader {
	return b.proposedHeaders
}
func (b consensusBroadcaster) OutgoingPrevoteProofs() chan<- tmconsensus.PrevoteSparseProof {
	return b.prevoteProofs
}
func (b consensusBroadcaster) OutgoingPrecommitProofs() chan<- tmconsensus.PrecommitSparseProof {
	return b.precommitProofs
}

func (c *Connection) ConsensusBroadcaster() tmp2p.ConsensusBroadcaster {
	return consensusBroadcaster{
		proposedHeaders: c.outgoingProposedHeaders,
		prevoteProofs:   c.outgoingPrevoteProofs,
		precommitProofs: c.outgoingPrecommitProofs,
	}
}

func (c *Connection) SetConsensusHandler(ctx context.Context, h tmconsensus.ConsensusHandler) {
	req := setConsensusHandlerRequest{
		Handler: h,
		Resp:    make(chan struct{}),
	}

	select {
	case <-ctx.Done():
		return
	case c.setConsensusHandlerRequests <- req:
		// Okay.
	}

	select {
	case <-ctx.Done():
	case <-req.Resp:
	}
}

func (c *Connection) handleDisconnect(ctx context.Context) {
	// Wait for either context cancellation or a call to Disconnect.
	select {
	case <-ctx.Done():
	case <-c.disconnectCh:
	}

	c.cancel()
	c.n.Wait()
	close(c.disconnected)
}

func (c *Connection) Disconnect() {
	c.disconnectOnce.Do(func() {
		close(c.disconnectCh)
	})
}

func (c *Connection) Disconnected() <-chan struct{} {
	return c.disconnected
}
