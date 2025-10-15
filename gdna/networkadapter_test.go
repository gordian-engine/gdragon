package gdna_test

import (
	"context"
	"io"
	"testing"

	"github.com/gordian-engine/gdragon/gdna/gdnatest"
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
