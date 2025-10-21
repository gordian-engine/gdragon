package gdna_test

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/gordian-engine/gdragon/gdbc"
	"github.com/gordian-engine/gdragon/gdna"
	"github.com/gordian-engine/gdragon/gdna/gdnatest"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
	"github.com/gordian-engine/gordian/tm/tmengine/tmelink"
	"github.com/stretchr/testify/require"
)

func TestNetworkAdapter_applicationProtocolsExposed(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	nfx := gdnatest.NewFixture(t, ctx, 2)
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
		s01, err := cc0.Conn.QUIC.OpenStream()
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
		s10, err := cc1.Conn.QUIC.OpenUniStream()
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
	nvuChs := make([]chan tmelink.NetworkViewUpdate, nNodes)
	for i := range nvuChs {
		// Must be unbuffered so we confirm receipt on send.
		nvuChs[i] = make(chan tmelink.NetworkViewUpdate)
	}

	chBufs := make([]gdnatest.CHBuffer, nNodes)
	for i := range chBufs {
		chBufs[i] = gdnatest.NewCHBuffer(4)
	}

	nfx := gdnatest.NewFixture(t, ctx, nNodes)
	for i := range nNodes {
		nfx.NetworkAdapters[i].SetConsensusHandler(chBufs[i])
		nfx.NetworkAdapters[i].Start(nvuChs[i])
	}

	nw := nfx.Network
	require.NoError(t, nw.Nodes[0].Node.DialAndJoin(ctx, nw.Nodes[1].UDP.LocalAddr()))
	require.NoError(t, nw.Nodes[1].Node.DialAndJoin(ctx, nw.Nodes[2].UDP.LocalAddr()))

	// First, tell nodes 1 and 2 that we are at initial height.
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
	nvuChs[1] <- u
	nvuChs[2] <- u

	// Now, node 0 is going to make a proposed block.
	ph := nfx.Fx.NextProposedHeader([]byte("dataid0"), 0)

	// Make some random enough data for the block.
	blockData := []byte(strings.Repeat("abcdefghijklmnopqrstuv", 1024))

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

	phBytes, err := nfx.MarshalCodec.MarshalProposedHeader(ph)
	require.NoError(t, err)

	od := gdna.OriginationDetails{
		AppHeader:           phBytes,
		PreparedOrigination: po,
	}

	// This is for the outgoing broadcast only.
	nfx.RegisterOriginationDetails(ph.Header.Hash, od)

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

	t.Skip("TODO: confirm data ready on both other nodes")
}
