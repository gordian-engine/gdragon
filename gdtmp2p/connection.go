package gdtmp2p

import (
	"context"
	"sync"

	"github.com/gordian-engine/dragon"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
	"github.com/gordian-engine/gordian/tm/tmp2p"
)

type Connection struct {
	n *dragon.Node

	h tmconsensus.ConsensusHandler

	cancel context.CancelFunc

	connChanges <-chan dconn.Change

	setConsensusHandlerRequests chan setConsensusHandlerRequest

	outgoingProposedHeaders chan tmconsensus.ProposedHeader
	outgoingPrevoteProofs   chan tmconsensus.PrevoteSparseProof
	outgoingPrecommitProofs chan tmconsensus.PrecommitSparseProof

	disconnectOnce sync.Once
	disconnectCh   chan struct{}
	disconnected   chan struct{}
}

type setConsensusHandlerRequest struct {
	Handler tmconsensus.ConsensusHandler
	Resp    chan struct{}
}

func NewConnection(
	ctx context.Context,
	n *dragon.Node,
	cancel context.CancelFunc,
	connChanges <-chan dconn.Change,
) *Connection {
	c := &Connection{
		n: n,

		cancel: cancel,

		connChanges: connChanges,

		// Unbuffered since caller blocks.
		setConsensusHandlerRequests: make(chan setConsensusHandlerRequest),

		outgoingProposedHeaders: make(chan tmconsensus.ProposedHeader, 1),
		outgoingPrevoteProofs:   make(chan tmconsensus.PrevoteSparseProof, 1),
		outgoingPrecommitProofs: make(chan tmconsensus.PrecommitSparseProof, 1),

		disconnectCh: make(chan struct{}),
		disconnected: make(chan struct{}),
	}

	go c.handleDisconnect(ctx)

	go c.mainLoop(ctx)

	return c
}

func (c *Connection) mainLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-c.setConsensusHandlerRequests:
			c.h = req.Handler
			close(req.Resp)
		}
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
	select {
	case <-ctx.Done():
		return
	case <-c.disconnectCh:
		c.cancel()
		c.n.Wait()
		close(c.disconnected)
	}
}

func (c *Connection) Disconnect() {
	c.disconnectOnce.Do(func() {
		close(c.disconnectCh)
	})
}

func (c *Connection) Disconnected() <-chan struct{} {
	return c.disconnected
}
