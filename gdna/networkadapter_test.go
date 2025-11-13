package gdna_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/gdragon/gdbc"
	"github.com/gordian-engine/gdragon/gdna/gdnatest"
	"github.com/gordian-engine/gordian/gcrypto"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
	"github.com/gordian-engine/gordian/tm/tmconsensus/tmconsensustest"
	"github.com/gordian-engine/gordian/tm/tmengine/tmelink"
	"github.com/gordian-engine/gordian/tm/tmintegration"
	"github.com/stretchr/testify/require"
)

func TestNetworkAdapter_applicationProtocolsExposed(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	blockDataStores := make([]gdnatest.BlockDataStore, 2)
	for i := range blockDataStores {
		blockDataStores[i] = tmintegration.NewBlockDataMap()
	}
	nfx := gdnatest.NewFixture(t, ctx, blockDataStores)
	nfx.NetworkAdapters[0].Start(nil)
	nfx.NetworkAdapters[1].Start(nil)

	// Join node zero to node one.
	nw := nfx.Network
	require.NoError(t, nw.Nodes[0].Node.DialAndJoin(ctx, nw.Nodes[1].UDP.LocalAddr()))

	// Now each node should expose a connection change.
	// We only need the first change from each stream, so skip typical bookkeeping.
	<-nfx.ConnChangeStreams[0].Ready
	cc0 := nfx.ConnChangeStreams[0].Val
	require.True(t, cc0.Adding)

	<-nfx.ConnChangeStreams[1].Ready
	cc1 := nfx.ConnChangeStreams[1].Val
	require.True(t, cc1.Adding)

	t.Run("bidirectional stream", func(t *testing.T) {
		// Open a bidirectional stream from 0 to 1.
		s01, err := cc0.Conn.QUIC.OpenStreamSync(ctx)
		require.NoError(t, err)

		_, err = s01.Write([]byte("\xFFbidi"))
		require.NoError(t, err)

		as := <-nfx.AcceptedStreamChs[1]
		require.Equal(t, byte(0xFF), as.ProtocolID)

		// The rest of the sent message is available.
		bidiBuf := make([]byte, 4)
		_, err = io.ReadFull(as.Stream, bidiBuf)
		require.NoError(t, err)
		require.Equal(t, "bidi", string(bidiBuf))
	})

	t.Run("unidirectional stream", func(t *testing.T) {
		s10, err := cc1.Conn.QUIC.OpenUniStreamSync(ctx)
		require.NoError(t, err)

		_, err = s10.Write([]byte("\xFEuni"))
		require.NoError(t, err)

		aus := <-nfx.AcceptedUniStreamChs[0]
		require.Equal(t, byte(0xFE), aus.ProtocolID)

		// The rest of the sent message is available.
		uniBuf := make([]byte, 3)
		_, err = io.ReadFull(aus.Stream, uniBuf)
		require.NoError(t, err)
		require.Equal(t, "uni", string(uniBuf))
	})
}

func TestNetworkAdapter_proposedBlock(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	const nNodes = 3

	// This time we do need network view update channels for each node.
	blockDataStores := make([]gdnatest.BlockDataStore, nNodes)
	for i := range blockDataStores {
		blockDataStores[i] = tmintegration.NewBlockDataMap()
	}
	nfx := gdnatest.NewFixture(t, ctx, blockDataStores)

	nvuChs, chBufs := nfx.StartWithBufferedConsensusHandlers()

	nw := nfx.Network
	require.NoError(t, nw.Nodes[0].Node.DialAndJoin(ctx, nw.Nodes[1].UDP.LocalAddr()))
	require.NoError(t, nw.Nodes[1].Node.DialAndJoin(ctx, nw.Nodes[2].UDP.LocalAddr()))

	// All the nodes need to be aware of the initial height,
	// just as would happen during normal engine initialization.
	u := tmelink.NetworkViewUpdate{
		Voting: &tmconsensus.VersionedRoundView{
			RoundView: tmconsensus.RoundView{
				Height: 1, Round: 0,

				ValidatorSet: nfx.Fx.ValSet(),
			},
		},
		RoundSessionChanges: []tmelink.RoundSessionChange{
			{Height: 1, Round: 0, State: tmelink.RoundSessionStateActive},
		},
	}
	nvuChs[0] <- u
	nvuChs[1] <- u
	nvuChs[2] <- u

	// Now, node 0 is going to make a proposed block.
	const dataID = "dataid0"
	ph := nfx.Fx.NextProposedHeader([]byte(dataID), 0)

	// Make some random enough data for the block.
	blockData := []byte(strings.Repeat("abcdefghijklmnopqrstuv", 1024))

	// And we have to manually put that data in the block data store, for this test.
	// Normally the consensus strategy would do this directly,
	// or we would do this in the proposed header interceptor.
	blockDataStores[0].PutData([]byte(dataID), blockData)

	// The node has to prepare an origination through the breathcast adapter.
	nonce := []byte{1, 2, 4, 8, 16} // Arbitrary nonce for origination.
	po, err := nfx.GDBCAdapters[0].PrepareOrigination(gdbc.PrepareOriginationConfig{
		BlockData: blockData,

		ParityRatio: 0.1,

		HashNonce: nonce,

		Height: 1, Round: 0,
		ProposerIdx: 0,
	})
	require.NoError(t, err)

	ph.Annotations.Driver, err = json.Marshal(po.BroadcastDetails())
	require.NoError(t, err)

	nfx.Fx.SignProposal(ctx, &ph, 0)

	// Make a separate update for the proposer,
	// to avoid possible memory conflict.
	vClone := u.Voting.Clone()
	vClone.ProposedHeaders = []tmconsensus.ProposedHeader{ph}
	u = tmelink.NetworkViewUpdate{
		Voting: &vClone,
		RoundSessionChanges: []tmelink.RoundSessionChange{
			{Height: 1, Round: 0, State: tmelink.RoundSessionStateActive},
		},
	}
	nvuChs[0] <- u

	// If the origination worked, the proposed header should be available
	// quickly on the first receiver's consensus handler.
	gotPH := <-chBufs[1].ProposedHeaders
	require.Equal(t, ph, gotPH)

	// And it should be ready very quickly on the other nodes too.
	gotPH = <-chBufs[2].ProposedHeaders
	require.Equal(t, ph, gotPH)

	// Block data is ready quickly on both receiving nodes.
	expBDA := tmelink.BlockDataArrival{
		Height: 1,
		Round:  0,
		ID:     dataID,
	}
	bda := <-nfx.BlockDataArrivalChs[0]
	require.Equal(t, expBDA, bda)

	bda = <-nfx.BlockDataArrivalChs[1]
	require.Equal(t, expBDA, bda)

	bda = <-nfx.BlockDataArrivalChs[2]
	require.Equal(t, expBDA, bda)
}

func TestNetworkAdapter_bidirectionalVotes(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	const nNodes = 2
	blockDataStores := make([]gdnatest.BlockDataStore, nNodes)
	for i := range blockDataStores {
		blockDataStores[i] = tmintegration.NewBlockDataMap()
	}
	nfx := gdnatest.NewFixture(t, ctx, blockDataStores)

	// Join node zero to node one.
	nw := nfx.Network
	require.NoError(t, nw.Nodes[0].Node.DialAndJoin(ctx, nw.Nodes[1].UDP.LocalAddr()))

	nvuChs, chBufs := nfx.StartWithBufferedConsensusHandlers()
	_, _ = nvuChs, chBufs

	// Use an empty VRV for the initial view.
	u := tmelink.NetworkViewUpdate{
		Voting: &tmconsensus.VersionedRoundView{
			RoundView: tmconsensus.RoundView{
				Height: 1, Round: 0,

				ValidatorSet: nfx.Fx.ValSet(),
			},
		},
		RoundSessionChanges: []tmelink.RoundSessionChange{
			{Height: 1, Round: 0, State: tmelink.RoundSessionStateActive},
		},
	}
	nvuChs[0] <- u
	nvuChs[1] <- u

	// Preparation for nil prevotes at 0/0.
	sigScheme := tmconsensustest.SimpleSignatureScheme{}
	prevoteSignContent, err := tmconsensus.PrevoteSignBytes(
		tmconsensus.VoteTarget{
			Height: 1, Round: 0, BlockHash: "",
		},
		sigScheme,
	)
	require.NoError(t, err)

	t.Run("prevote from 0 to 1", func(t *testing.T) {
		p0, err := gcrypto.NewSimpleCommonMessageSignatureProof(
			prevoteSignContent, nfx.Fx.ValSet().PubKeys, string(nfx.Fx.ValSet().PubKeyHash),
		)
		require.NoError(t, err)

		sig0, err := nfx.Fx.PrivVals[0].Signer.Sign(ctx, prevoteSignContent)
		require.NoError(t, err)

		require.NoError(t, p0.AddSignature(sig0, nfx.Fx.PrivVals[0].Signer.PubKey()))

		nvuChs[0] <- tmelink.NetworkViewUpdate{
			Voting: &tmconsensus.VersionedRoundView{
				RoundView: tmconsensus.RoundView{
					Height: 1, Round: 0,

					ValidatorSet: nfx.Fx.ValSet(),

					PrevoteProofs: map[string]gcrypto.CommonMessageSignatureProof{
						"": p0,
					},
				},
			},
		}

		// With that update sent, node 1 should receive the packet with the vote.
		// Upon receiving the vote packet, it writes to the consensus handler,
		// which in our case is the CHBuffer instance.
		var psp1 tmconsensus.PrevoteSparseProof
		select {
		case psp1 = <-chBufs[1].PrevoteSparseProofs:
			// Assert outside of select.
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for consensus handler call")
		}

		pf1, err := psp1.ToFull(
			gcrypto.SimpleCommonMessageSignatureProofScheme{},
			sigScheme,
			nfx.Fx.ValSet().PubKeys,
			string(nfx.Fx.ValSet().PubKeyHash),
		)
		require.NoError(t, err)

		// And the received proof includes the signature for the zeroth validator.
		var bs bitset.BitSet
		pf1.Proofs[""].SignatureBitSet(&bs)
		require.True(t, bs.Test(0))
	})

	// Now do this again in the other direction.
	t.Run("prevote from 1 to 0", func(t *testing.T) {
		p1, err := gcrypto.NewSimpleCommonMessageSignatureProof(
			prevoteSignContent, nfx.Fx.ValSet().PubKeys, string(nfx.Fx.ValSet().PubKeyHash),
		)
		require.NoError(t, err)

		sig1, err := nfx.Fx.PrivVals[1].Signer.Sign(ctx, prevoteSignContent)
		require.NoError(t, err)

		require.NoError(t, p1.AddSignature(sig1, nfx.Fx.PrivVals[1].Signer.PubKey()))

		nvuChs[1] <- tmelink.NetworkViewUpdate{
			Voting: &tmconsensus.VersionedRoundView{
				RoundView: tmconsensus.RoundView{
					Height: 1, Round: 0,

					ValidatorSet: nfx.Fx.ValSet(),

					PrevoteProofs: map[string]gcrypto.CommonMessageSignatureProof{
						"": p1,
					},
				},
			},
		}

		var psp0 tmconsensus.PrevoteSparseProof
		// Have to discard the self-observed prevote on zero first.
		select {
		case _ = <-chBufs[0].PrevoteSparseProofs:
			// Assert outside of select.
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for consensus handler call")
		}
		select {
		case psp0 = <-chBufs[0].PrevoteSparseProofs:
			// Assert outside of select.
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for consensus handler call")
		}

		pf0, err := psp0.ToFull(
			gcrypto.SimpleCommonMessageSignatureProofScheme{},
			sigScheme,
			nfx.Fx.ValSet().PubKeys,
			string(nfx.Fx.ValSet().PubKeyHash),
		)
		require.NoError(t, err)

		var bs bitset.BitSet
		pf0.Proofs[""].SignatureBitSet(&bs)
		require.True(t, bs.Test(1))
	})

	// Now swap precommits.
	precommitSignContent, err := tmconsensus.PrecommitSignBytes(
		tmconsensus.VoteTarget{
			Height: 1, Round: 0, BlockHash: "",
		},
		sigScheme,
	)
	require.NoError(t, err)
	t.Run("precommit from 0 to 1", func(t *testing.T) {
		p0, err := gcrypto.NewSimpleCommonMessageSignatureProof(
			precommitSignContent, nfx.Fx.ValSet().PubKeys, string(nfx.Fx.ValSet().PubKeyHash),
		)
		require.NoError(t, err)

		sig0, err := nfx.Fx.PrivVals[0].Signer.Sign(ctx, precommitSignContent)
		require.NoError(t, err)

		require.NoError(t, p0.AddSignature(sig0, nfx.Fx.PrivVals[0].Signer.PubKey()))

		nvuChs[0] <- tmelink.NetworkViewUpdate{
			Voting: &tmconsensus.VersionedRoundView{
				RoundView: tmconsensus.RoundView{
					Height: 1, Round: 0,

					ValidatorSet: nfx.Fx.ValSet(),

					PrecommitProofs: map[string]gcrypto.CommonMessageSignatureProof{
						"": p0,
					},
				},
			},
		}

		// With that update sent, node 1 should receive the packet with the vote.
		// Upon receiving the vote packet, it writes to the consensus handler,
		// which in our case is the CHBuffer instance.
		var psp1 tmconsensus.PrecommitSparseProof
		select {
		case psp1 = <-chBufs[1].PrecommitSparseProofs:
			// Assert outside of select.
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for consensus handler call")
		}

		pf1, err := psp1.ToFull(
			gcrypto.SimpleCommonMessageSignatureProofScheme{},
			sigScheme,
			nfx.Fx.ValSet().PubKeys,
			string(nfx.Fx.ValSet().PubKeyHash),
		)
		require.NoError(t, err)

		// And the received proof includes the signature for the zeroth validator.
		var bs bitset.BitSet
		pf1.Proofs[""].SignatureBitSet(&bs)
		require.True(t, bs.Test(0))
	})

	t.Run("precommit from 1 to 0", func(t *testing.T) {
		p1, err := gcrypto.NewSimpleCommonMessageSignatureProof(
			precommitSignContent, nfx.Fx.ValSet().PubKeys, string(nfx.Fx.ValSet().PubKeyHash),
		)
		require.NoError(t, err)

		sig1, err := nfx.Fx.PrivVals[1].Signer.Sign(ctx, precommitSignContent)
		require.NoError(t, err)

		require.NoError(t, p1.AddSignature(sig1, nfx.Fx.PrivVals[1].Signer.PubKey()))

		nvuChs[1] <- tmelink.NetworkViewUpdate{
			Voting: &tmconsensus.VersionedRoundView{
				RoundView: tmconsensus.RoundView{
					Height: 1, Round: 0,

					ValidatorSet: nfx.Fx.ValSet(),

					PrecommitProofs: map[string]gcrypto.CommonMessageSignatureProof{
						"": p1,
					},
				},
			},
		}

		// With that update sent, node 1 should receive the packet with the vote.
		// Upon receiving the vote packet, it writes to the consensus handler,
		// which in our case is the CHBuffer instance.
		var psp0 tmconsensus.PrecommitSparseProof
		select {
		case _ = <-chBufs[0].PrecommitSparseProofs:
			// Discard the self precommit like in the prevote case.
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for consensus handler call")
		}
		select {
		case psp0 = <-chBufs[0].PrecommitSparseProofs:
			// Assert outside of select.
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for consensus handler call")
		}

		pf0, err := psp0.ToFull(
			gcrypto.SimpleCommonMessageSignatureProofScheme{},
			sigScheme,
			nfx.Fx.ValSet().PubKeys,
			string(nfx.Fx.ValSet().PubKeyHash),
		)
		require.NoError(t, err)

		// And the received proof includes the signature for the first validator.
		var bs bitset.BitSet
		pf0.Proofs[""].SignatureBitSet(&bs)
		require.True(t, bs.Test(1))
	})
}

func TestNetworkAdapter_votesForNextHeight(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	const nNodes = 2

	// This time we do need network view update channels for each node.
	blockDataStores := make([]gdnatest.BlockDataStore, nNodes)
	for i := range blockDataStores {
		blockDataStores[i] = tmintegration.NewBlockDataMap()
	}
	nfx := gdnatest.NewFixture(t, ctx, blockDataStores)

	nvuChs, chBufs := nfx.StartWithBufferedConsensusHandlers()

	nw := nfx.Network
	require.NoError(t, nw.Nodes[0].Node.DialAndJoin(ctx, nw.Nodes[1].UDP.LocalAddr()))

	// Tell both nodes that we are at initial height.
	// Normally this would also include the next round view,
	// but it should be fine to omit that in test here.
	u := tmelink.NetworkViewUpdate{
		Voting: &tmconsensus.VersionedRoundView{
			RoundView: tmconsensus.RoundView{
				Height: 1, Round: 0,

				ValidatorSet: nfx.Fx.ValSet(),
			},
		},
		RoundSessionChanges: []tmelink.RoundSessionChange{
			{Height: 1, Round: 0, State: tmelink.RoundSessionStateActive},
		},
	}
	nvuChs[0] <- u
	nvuChs[1] <- u

	// Proposed block for 1/0.
	const dataID = "dataid1"
	ph := nfx.Fx.NextProposedHeader([]byte(dataID), 0)
	blockData := bytes.Repeat([]byte("abcdefg"), 8*1024)
	blockDataStores[0].PutData([]byte(dataID), blockData)

	// The node has to prepare an origination through the breathcast adapter,
	// in order to sign the correct data.
	// Normally this would happen through the engine and the ProposedHeaderInterceptor.
	nonce := []byte{2, 4, 8, 16, 32} // Arbitrary nonce for origination.
	po, err := nfx.GDBCAdapters[0].PrepareOrigination(gdbc.PrepareOriginationConfig{
		BlockData: blockData,

		ParityRatio: 0.1,

		HashNonce: nonce,

		Height: 1, Round: 0,
		ProposerIdx: 0,
	})
	require.NoError(t, err)

	ph.Annotations.Driver, err = json.Marshal(po.BroadcastDetails())
	require.NoError(t, err)

	nfx.Fx.SignProposal(ctx, &ph, 0)

	// Send as a network view update directly to both validators,
	// so we don't need to directly originate a block in this test.
	nvuChs[0] <- tmelink.NetworkViewUpdate{
		Voting: &tmconsensus.VersionedRoundView{
			RoundView: tmconsensus.RoundView{
				Height: 1, Round: 0,

				ValidatorSet: nfx.Fx.ValSet(),

				ProposedHeaders: []tmconsensus.ProposedHeader{ph},
			},
		},
		RoundSessionChanges: []tmelink.RoundSessionChange{
			{Height: 1, Round: 0, State: tmelink.RoundSessionStateActive},
		},
	}

	// Now, if the second validator makes a prevote for the next height,
	// the first validator should see it and accept it.
	nvuChs[1] <- tmelink.NetworkViewUpdate{
		Voting: &tmconsensus.VersionedRoundView{
			RoundView: tmconsensus.RoundView{
				Height: 2, Round: 0,

				ValidatorSet: nfx.Fx.ValSet(),

				PrevoteProofs: nfx.Fx.PrevoteProofMap(
					ctx, 2, 0, map[string][]int{
						"": {1},
					},
				),
			},
		},
		RoundSessionChanges: []tmelink.RoundSessionChange{
			{Height: 2, Round: 0, State: tmelink.RoundSessionStateActive},
		},
	}

	var psp tmconsensus.PrevoteSparseProof
	select {
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for prevote proof confirmation")
	case psp = <-chBufs[0].PrevoteSparseProofs:
		// Okay, finish assertions outside of block.
	}
	require.Equal(t, uint64(2), psp.Height)
	require.Zero(t, psp.Round)
	require.Equal(t, string(nfx.Fx.ValSet().PubKeyHash), psp.PubKeyHash)

	// Contains prevote for nil block.
	require.Contains(t, psp.Proofs, "")
	require.Len(t, psp.Proofs[""], 1) // Only one signature in the proof.
}
