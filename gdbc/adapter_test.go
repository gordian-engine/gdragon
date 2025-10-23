package gdbc_test

import (
	"context"
	"encoding/json"
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

				Hasher:   bcsha256.Hasher{},
				HashSize: bcsha256.HashSize,
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

	// Make the incomplete proposal first.
	ph := fx.NextProposedHeader(blockData0, 0)

	// Now, using the block data generated,
	// prepare the origination.
	nonce := []byte("some nonce value")
	po, err := as[0].PrepareOrigination(gdbc.PrepareOriginationConfig{
		BlockData: blockData0,

		ParityRatio: 0.25,

		HashNonce: nonce,

		Height:      ph.Header.Height,
		Round:       ph.Round,
		ProposerIdx: 0,
	})
	require.NoError(t, err)

	// Add the broadcast details on the proposal header,
	// so the recipients can decode them and accept a broadcast.
	ph.Annotations.Driver, err = json.Marshal(po.BroadcastDetails())
	require.NoError(t, err)

	fx.SignProposal(ctx, &ph, 0)

	mph, err := codec.MarshalProposedHeader(ph)
	require.NoError(t, err)

	bop0, err := as[0].Originate(ctx, mph, po)
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
	bidBytes, err := as[1].ExtractStreamBroadcastID(s01, nil)
	require.NoError(t, err)

	var bid gdbc.BroadcastID
	require.NoError(t, bid.Parse(bidBytes))

	require.Equal(t, ph.Header.Height, bid.Height)
	require.Equal(t, ph.Round, bid.Round)
	require.Equal(t, uint16(0), bid.ProposerIdx)

	// Extract the application header.
	// Currently, gdbc just sets the entire application header
	// as the serialized proposed header.
	ah0, _, err := breathcast.ExtractStreamApplicationHeader(s01, nil)
	require.NoError(t, err)

	var gotPH0 tmconsensus.ProposedHeader
	require.NoError(t, codec.UnmarshalProposedHeader(ah0, &gotPH0))

	var gotBD0 gdbc.BroadcastDetails
	require.NoError(t, json.Unmarshal(gotPH0.Annotations.Driver, &gotBD0))

	// First we agree on the broadcast operation.
	bop1, err := as[1].NewIncomingBroadcast(ctx, gdbc.IncomingBroadcastConfig{
		BroadcastID: bid,
		AppHeader:   ah0,

		BroadcastDetails: gotBD0,
	})
	require.NoError(t, err)

	defer bop1.Wait()
	defer cancel()

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
	bidBytes, err = as[2].ExtractStreamBroadcastID(s12, nil)
	require.NoError(t, err)

	require.NoError(t, bid.Parse(bidBytes))

	require.Equal(t, ph.Header.Height, bid.Height)
	require.Equal(t, ph.Round, bid.Round)
	require.Equal(t, uint16(0), bid.ProposerIdx)

	ah1, _, err := breathcast.ExtractStreamApplicationHeader(s12, nil)
	require.NoError(t, err)

	var gotPH1 tmconsensus.ProposedHeader
	require.NoError(t, codec.UnmarshalProposedHeader(ah1, &gotPH1))

	var gotBD1 gdbc.BroadcastDetails
	require.NoError(t, json.Unmarshal(gotPH1.Annotations.Driver, &gotBD1))

	// Then we agree on the relayed broadcast operation.
	bop2, err := as[2].NewIncomingBroadcast(ctx, gdbc.IncomingBroadcastConfig{
		BroadcastID: bid,
		AppHeader:   ah1,

		BroadcastDetails: gotBD1,
	})
	require.NoError(t, err)

	defer bop2.Wait()
	defer cancel()

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
