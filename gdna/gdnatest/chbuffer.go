package gdnatest

import (
	"context"

	"github.com/gordian-engine/gordian/tm/tmconsensus"
)

// CHBuffer is an implementation of [tmconsensus.FineGrainedConsensusHandler]
// that accumulates values into channels,
// so that a test can confirm calls into the handler's methods.
//
// Values are indicated as accepted, unless there is a context cancellation,
// which is indicated as ignored.
type CHBuffer struct {
	ProposedHeaders       chan tmconsensus.ProposedHeader
	PrevoteSparseProofs   chan tmconsensus.PrevoteSparseProof
	PrecommitSparseProofs chan tmconsensus.PrecommitSparseProof
}

func NewCHBuffer(chanSize int) CHBuffer {
	return CHBuffer{
		ProposedHeaders:       make(chan tmconsensus.ProposedHeader, chanSize),
		PrevoteSparseProofs:   make(chan tmconsensus.PrevoteSparseProof, chanSize),
		PrecommitSparseProofs: make(chan tmconsensus.PrecommitSparseProof, chanSize),
	}
}

func (b CHBuffer) HandleProposedHeader(ctx context.Context, ph tmconsensus.ProposedHeader) tmconsensus.HandleProposedHeaderResult {
	select {
	case <-ctx.Done():
		return tmconsensus.HandleProposedHeaderInternalError
	case b.ProposedHeaders <- ph:
		return tmconsensus.HandleProposedHeaderAccepted
	}
}

func (b CHBuffer) HandlePrevoteProofs(ctx context.Context, p tmconsensus.PrevoteSparseProof) tmconsensus.HandleVoteProofsResult {
	select {
	case <-ctx.Done():
		return tmconsensus.HandleVoteProofsInternalError
	case b.PrevoteSparseProofs <- p:
		return tmconsensus.HandleVoteProofsAccepted
	}
}

func (b CHBuffer) HandlePrecommitProofs(ctx context.Context, p tmconsensus.PrecommitSparseProof) tmconsensus.HandleVoteProofsResult {
	select {
	case <-ctx.Done():
		return tmconsensus.HandleVoteProofsInternalError
	case b.PrecommitSparseProofs <- p:
		return tmconsensus.HandleVoteProofsAccepted
	}
}
