package gdbc_test

import (
	"context"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/dragon/breathcast/breathcasttest"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/gdragon/gdbc"
	"github.com/gordian-engine/gordian/gcrypto"
	"github.com/gordian-engine/gordian/tm/tmcodec/tmjson"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
	"github.com/gordian-engine/gordian/tm/tmconsensus/tmconsensustest"
	"github.com/neilotoole/slogt"
	"github.com/stretchr/testify/require"
)

func TestBreathcast_hop(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const protocolID byte = 0xa0 // Arbitrary for test.

	pfx := breathcasttest.NewProtocolFixture(t, ctx, breathcasttest.ProtocolFixtureConfig{
		Nodes: 3,

		ProtocolID: protocolID,

		BroadcastIDLength: 8 + 4 + 2,
	})

	log := slogt.New(t, slogt.Text())

	var reg gcrypto.Registry
	gcrypto.RegisterEd25519(&reg)
	codec := tmjson.MarshalCodec{
		CryptoRegistry: &reg,
	}

	as := make([]*gdbc.Adapter, 3)
	for i, p := range pfx.Protocols {
		var err error
		as[i], err = gdbc.NewAdapter(
			log.With("idx", i), gdbc.AdapterConfig{
				Protocol:   p,
				ProtocolID: protocolID,
				Marshaler:  codec,
			},
		)
		require.NoError(t, err)
	}

	seed := [32]byte{}
	_ = append(seed[:0], t.Name()...)
	rng := rand.NewChaCha8(seed)
	blockData0 := make([]byte, 16*1024)
	_, _ = rng.Read(blockData0)

	fx := tmconsensustest.NewEd25519Fixture(3)

	ph := fx.NextProposedHeader(blockData0, 0)

	/*
		ann := breathcastAnnotation{}
		var err error
		ph.Annotations.Driver, err = json.Marshal(ann)
		require.NoError(t, err)
	*/

	fx.SignProposal(ctx, &ph, 0)

	nonce := []byte("some nonce value")

	bop0, bi0, err := as[0].Originate(
		ctx,
		blockData0,
		ph,
		ph.Header.Height, ph.Round,
		0,    // Proposer index.
		0.25, // Parity ratio.
		nonce,
	)
	require.NoError(t, err)
	defer bop0.Wait()
	defer cancel()

	// Connect the nodes as 0 <--> 1 <--> 2.
	c01, c10 := pfx.ListenerSet.Dial(t, 0, 1)
	pfx.AddConnection(c01, 0, 1)
	pfx.AddConnection(c10, 1, 0)

	c12, c21 := pfx.ListenerSet.Dial(t, 1, 2)
	pfx.AddConnection(c12, 1, 2)
	pfx.AddConnection(c21, 2, 1)

	acceptCtx, acceptCancel := context.WithTimeout(ctx, time.Second)
	defer acceptCancel()

	s01, err := c10.AcceptStream(acceptCtx)
	require.NoError(t, err)

	// Read the protocol byte.
	var b1 [1]byte
	_, err = io.ReadFull(s01, b1[:])
	require.NoError(t, err)
	require.Equal(t, protocolID, b1[0])

	// Broadcast ID must match height, round, and proposer index.
	bid, err := pfx.Protocols[1].ExtractStreamBroadcastID(s01, nil)
	require.NoError(t, err)
	require.Equal(t, ph.Header.Height, binary.BigEndian.Uint64(bid))
	require.Equal(t, ph.Round, binary.BigEndian.Uint32(bid[8:]))
	require.Equal(t, uint16(0), binary.BigEndian.Uint16(bid[8+4:]))

	// Extract the application header.
	// Currently, gdbc just sets the entire application header
	// as the serialized proposed header.
	ah0, _, err := breathcast.ExtractStreamApplicationHeader(s01, nil)
	require.NoError(t, err)

	var gotPH0 tmconsensus.ProposedHeader
	require.NoError(t, codec.UnmarshalProposedHeader(ah0, &gotPH0))

	// First we agree on the broadcast operation.
	bop1, err := pfx.Protocols[1].NewIncomingBroadcast(ctx, breathcast.IncomingBroadcastConfig{
		BroadcastID: bid,

		AppHeader: ah0,

		NData:   bi0.NData,
		NParity: bi0.NParity,

		TotalDataSize: bi0.TotalDataSize,

		// Fixed values.
		Hasher:   bcsha256.Hasher{},
		HashSize: bcsha256.HashSize,

		HashNonce: bi0.Nonce,

		RootProofs: bi0.RootProofs,

		ChunkSize: bi0.ChunkSize,
	})
	require.NoError(t, err)

	// Before we accept the stream on node 1,
	// node 1 should already forward the broadcast headers to node 2.
	acceptCtx, acceptCancel = context.WithTimeout(ctx, time.Second)
	defer acceptCancel()

	s12, err := c21.AcceptStream(acceptCtx)
	require.NoError(t, err)

	// Read the protocol byte.
	_, err = io.ReadFull(s12, b1[:])
	require.NoError(t, err)
	require.Equal(t, protocolID, b1[0])

	// Broadcast ID must match height, round, and proposer index.
	bid, err = pfx.Protocols[1].ExtractStreamBroadcastID(s12, nil)
	require.NoError(t, err)
	require.Equal(t, ph.Header.Height, binary.BigEndian.Uint64(bid))
	require.Equal(t, ph.Round, binary.BigEndian.Uint32(bid[8:]))
	require.Equal(t, uint16(0), binary.BigEndian.Uint16(bid[8+4:]))

	ah1, _, err := breathcast.ExtractStreamApplicationHeader(s12, nil)
	require.NoError(t, err)

	var gotPH1 tmconsensus.ProposedHeader
	require.NoError(t, codec.UnmarshalProposedHeader(ah1, &gotPH1))

	// Then we agree on the relayed broadcast operation.
	bop2, err := pfx.Protocols[2].NewIncomingBroadcast(ctx, breathcast.IncomingBroadcastConfig{
		BroadcastID: bid,

		AppHeader: ah1,

		NData:   bi0.NData,
		NParity: bi0.NParity,

		TotalDataSize: bi0.TotalDataSize,

		// Fixed values.
		Hasher:   bcsha256.Hasher{},
		HashSize: bcsha256.HashSize,

		HashNonce: bi0.Nonce,

		RootProofs: bi0.RootProofs,

		ChunkSize: bi0.ChunkSize,
	})
	require.NoError(t, err)

	// Then we accept the particular streams.
	require.NoError(t, bop1.AcceptBroadcast(
		ctx,
		dconn.Conn{
			QUIC:  c10,
			Chain: pfx.ListenerSet.Leaves[1].Chain,
		},
		s01,
	))

	require.NoError(t, bop2.AcceptBroadcast(
		ctx,
		dconn.Conn{
			QUIC:  c21,
			Chain: pfx.ListenerSet.Leaves[2].Chain,
		},
		s12,
	))

	// Finally, both broadcast operations expose the full block data.
	readCtx, readCancel := context.WithTimeout(ctx, time.Second)
	defer readCancel()

	data1, err := io.ReadAll(bop1.Data(readCtx))
	require.NoError(t, err)
	require.Equal(t, blockData0, data1)

	data2, err := io.ReadAll(bop2.Data(readCtx))
	require.NoError(t, err)
	require.Equal(t, blockData0, data2)
}
