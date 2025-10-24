package gdna

import (
	"context"
	"encoding/binary"
	"sync"

	"github.com/gordian-engine/gdragon/gdwsu"
	"github.com/gordian-engine/gordian/gcrypto"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
)

func forwardUnaggregatedPrevotes(
	ctx context.Context,
	wg *sync.WaitGroup,
	height uint64,
	round uint32,
	pubKeyHash string,
	h tmconsensus.ConsensusHandler,
	ch <-chan gdwsu.VerifiedVote,
) {
	defer wg.Done()

	for vv := range ch {
		// Convert verified vote to prevote sparse proof.

		sp := tmconsensus.PrevoteSparseProof{
			Height:     height,
			Round:      round,
			PubKeyHash: pubKeyHash,

			Proofs: map[string][]gcrypto.SparseSignature{
				string(vv.TargetHash): {
					{
						// TODO: constructing the key ID here is very dubious.
						// Furthermore, this highlights the particular impedance mismatch
						// with the engine and the p2p layer,
						// in that we have a fully constructed verified vote
						// and we have to make it more opaque
						// because of the existing engine vote API.
						KeyID: binary.BigEndian.AppendUint16(nil, vv.KeyIdx),
						Sig:   vv.Signature,
					},
				},
			},
		}

		// Just discard the response.
		// We already verified the vote before reaching this function.
		_ = h.HandlePrevoteProofs(ctx, sp)
	}
}

func forwardUnaggregatedPrecommits(
	ctx context.Context,
	wg *sync.WaitGroup,
	height uint64,
	round uint32,
	pubKeyHash string,
	h tmconsensus.ConsensusHandler,
	ch <-chan gdwsu.VerifiedVote,
) {
	defer wg.Done()

	for vv := range ch {
		// Convert verified vote to precommit sparse proof.

		sp := tmconsensus.PrecommitSparseProof{
			Height:     height,
			Round:      round,
			PubKeyHash: pubKeyHash,

			Proofs: map[string][]gcrypto.SparseSignature{
				string(vv.TargetHash): {
					{
						// TODO: constructing the key ID here is very dubious.
						// Furthermore, this highlights the particular impedance mismatch
						// with the engine and the p2p layer,
						// in that we have a fully constructed verified vote
						// and we have to make it more opaque
						// because of the existing engine vote API.
						KeyID: binary.BigEndian.AppendUint16(nil, vv.KeyIdx),
						Sig:   vv.Signature,
					},
				},
			},
		}

		// Just discard the response.
		// We already verified the vote before reaching this function.
		_ = h.HandlePrecommitProofs(ctx, sp)
	}
}
