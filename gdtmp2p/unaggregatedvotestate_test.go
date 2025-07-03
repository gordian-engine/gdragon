package gdtmp2p_test

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/gordian-engine/dragon/wingspan/wspacket"
	"github.com/gordian-engine/dragon/wingspan/wspacket/wspackettest"
	"github.com/gordian-engine/gdragon/gdtmp2p"
	"github.com/gordian-engine/gordian/gcrypto"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
	"github.com/gordian-engine/gordian/tm/tmconsensus/tmconsensustest"
)

func TestUnaggregatedVoteState_compliance(t *testing.T) {
	t.Parallel()

	wspackettest.TestStateCompliance(t, makeUnaggregatedVoteStateFixture)
}

func makeUnaggregatedVoteStateFixture(t *testing.T, ctx context.Context, nDeltas int) (
	wspacket.CentralState[gdtmp2p.VoteDelta],
	wspackettest.StateFixture[gdtmp2p.VoteDelta],
) {

	keys := make([]gcrypto.PubKey, nDeltas)
	signers := make([]gcrypto.Signer, nDeltas)
	for i := range nDeltas {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}
		keys[i] = gcrypto.Ed25519PubKey(pub)
		signers[i] = gcrypto.NewEd25519Signer(priv)
	}

	state, _ := gdtmp2p.NewUnaggregatedCentralVoteState(
		ctx, 1, 2, keys, tmconsensustest.SimpleSignatureScheme{},
	)

	fx := unaggregatedStateFixture{
		ctx:     ctx,
		signers: signers,
	}

	return state, fx
}

type unaggregatedStateFixture struct {
	ctx     context.Context
	signers []gcrypto.Signer
}

func (f unaggregatedStateFixture) GetDelta(n int) gdtmp2p.VoteDelta {
	vt := tmconsensus.VoteTarget{
		Height: 1, Round: 2,
		BlockHash: "test_hash",
	}

	signContent, err := tmconsensus.PrevoteSignBytes(
		vt, tmconsensustest.SimpleSignatureScheme{},
	)
	if err != nil {
		panic(err)
	}

	sig, err := f.signers[n].Sign(f.ctx, signContent)
	if err != nil {
		panic(err)
	}

	return gdtmp2p.VoteDelta{
		BlockHash: []byte(vt.BlockHash),
		KeyIndex:  uint16(n),
		Signature: sig,
	}
}

func (f unaggregatedStateFixture) GetInvalidDelta() gdtmp2p.VoteDelta {
	return gdtmp2p.VoteDelta{}
}
