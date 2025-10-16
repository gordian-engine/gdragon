package gdnatest

import (
	"context"

	"github.com/gordian-engine/gordian/gexchange"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
)

// CHBuffer is an implementation of [tmconsensus.ConsensusHandler]
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

func (b CHBuffer) HandleProposedHeader(ctx context.Context, ph tmconsensus.ProposedHeader) gexchange.Feedback {
	select {
	case <-ctx.Done():
		return gexchange.FeedbackIgnored
	case b.ProposedHeaders <- ph:
		return gexchange.FeedbackAccepted
	}
}

func (b CHBuffer) HandlePrevoteProofs(ctx context.Context, p tmconsensus.PrevoteSparseProof) gexchange.Feedback {
	select {
	case <-ctx.Done():
		return gexchange.FeedbackIgnored
	case b.PrevoteSparseProofs <- p:
		return gexchange.FeedbackAccepted
	}
}

func (b CHBuffer) HandlePrecommitProofs(ctx context.Context, p tmconsensus.PrecommitSparseProof) gexchange.Feedback {
	select {
	case <-ctx.Done():
		return gexchange.FeedbackIgnored
	case b.PrecommitSparseProofs <- p:
		return gexchange.FeedbackAccepted
	}
}
