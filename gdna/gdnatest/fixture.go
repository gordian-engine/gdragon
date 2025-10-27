package gdnatest

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/dragon/dcert/dcerttest"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/dragontest"
	"github.com/gordian-engine/dragon/wingspan"
	"github.com/gordian-engine/gdragon/gdbc"
	"github.com/gordian-engine/gdragon/gdna"
	"github.com/gordian-engine/gdragon/gdwsu"
	"github.com/gordian-engine/gordian/gcrypto"
	"github.com/gordian-engine/gordian/tm/tmcodec"
	"github.com/gordian-engine/gordian/tm/tmcodec/tmjson"
	"github.com/gordian-engine/gordian/tm/tmconsensus/tmconsensustest"
	"github.com/gordian-engine/gordian/tm/tmengine/tmelink"
	"github.com/stretchr/testify/require"
)

// Arbitrary protocol IDs; fixed values for tests.
const (
	BreathcastProtocolID = 0xA1
	WingspanProtocolID   = 0xA2
)

// Fixture allows creating a network of dragon nodes
// with network adapters on top of each node.
//
// This emulates the interface exposed by gdragon to gordian core,
// without supplying the core engine.
type Fixture struct {
	// The underlying test network.
	// After creating a fixture,
	// you will still need to call DialAndJoin on the underlying nodes.
	Network *dragontest.Network

	Fx *tmconsensustest.Fixture

	// Receive-only channels for non-gdna streams
	// accepted within the network adapter.
	// Indexed one-to-one with network nodes and network adapters.
	AcceptedStreamChs    []<-chan gdna.AcceptedStream
	AcceptedUniStreamChs []<-chan gdna.AcceptedUniStream

	// The set of channels that would normally be supplied to the engine
	// via the WithBlockDataArrivalChannel function.
	// Exposed directly here for consumption in test.
	BlockDataArrivalChs []<-chan tmelink.BlockDataArrival

	// The connection change streams used for the protocol instances
	// and supporting types.
	// Callers probably rarely, if ever, need to access this.
	ConnChangeStreams []*dpubsub.Stream[dconn.Change]

	// The low-level breathcast protocol instances.
	// Callers probably rarely, if ever, need to access this.
	BreathcastProtocols []*breathcast.Protocol

	// The gdbc package's adapters,
	// which abstract many details of the lower-level breathcast protocol.
	// Callers probably rarely, if ever, need to access this.
	GDBCAdapters []*gdbc.Adapter

	WingspanProtocols []*wingspan.Protocol[
		gdwsu.ParsedPacket, gdwsu.OutboundPacket,
		gdwsu.ReceivedFromPeer, gdwsu.UpdateFromCentral,
	]

	NetworkAdapters []*gdna.NetworkAdapter

	MarshalCodec tmcodec.MarshalCodec

	odMu sync.Mutex
	ods  map[string]gdna.OriginationDetails
}

// NewFixture returns a new Fixture.
func NewFixture(t *testing.T, ctx context.Context, nNodes int) *Fixture {
	configs := make([]dcerttest.CAConfig, nNodes)
	for i := range configs {
		configs[i] = dcerttest.FastConfig()
	}
	nw := dragontest.NewDefaultNetwork(t, ctx, configs...)
	t.Cleanup(nw.Wait)

	// There are several layers that we need to create here, to make a set of network adapters.
	// First we need the streams of connection changes.
	connChangeStreams := make([]*dpubsub.Stream[dconn.Change], nNodes)
	for i := range connChangeStreams {
		s, done := dpubsub.RunChannelToStream(ctx, nw.ConnectionChanges[i])
		connChangeStreams[i] = s
		t.Cleanup(func() { <-done })
	}

	// That allows us to make a raw breathcast protocol.
	breathcastProtocols := make([]*breathcast.Protocol, nNodes)
	for i := range breathcastProtocols {
		breathcastProtocols[i] = breathcast.NewProtocol(
			ctx, nw.Log.With("breathcastprotocol", i), breathcast.ProtocolConfig{
				// No initial connections.
				ConnectionChanges: connChangeStreams[i],
				ProtocolID:        BreathcastProtocolID,
				BroadcastIDLength: gdbc.BroadcastIDLen,
			},
		)
		t.Cleanup(breathcastProtocols[i].Wait)
	}

	// With the raw protocols, we can make gdragon breathcast adapters.
	gdbcAdapters := make([]*gdbc.Adapter, nNodes)
	for i := range gdbcAdapters {
		a, err := gdbc.NewAdapter(
			nw.Log.With("gdbc_adapter", i),
			gdbc.AdapterConfig{
				Protocol:   breathcastProtocols[i],
				ProtocolID: BreathcastProtocolID,

				Hasher:   bcsha256.Hasher{},
				HashSize: bcsha256.HashSize,
			},
		)
		require.NoError(t, err)
		gdbcAdapters[i] = a
	}

	// Now make the wingspan protocol instances.
	wingspanProtocols := make([]*wingspan.Protocol[
		gdwsu.ParsedPacket, gdwsu.OutboundPacket,
		gdwsu.ReceivedFromPeer, gdwsu.UpdateFromCentral,
	], nNodes)
	for i := range wingspanProtocols {
		wingspanProtocols[i] = wingspan.NewProtocol[
			gdwsu.ParsedPacket, gdwsu.OutboundPacket,
			gdwsu.ReceivedFromPeer, gdwsu.UpdateFromCentral,
		](
			ctx, nw.Log.With("wingspanprotocol", i),
			wingspan.ProtocolConfig{
				// No initial connections.
				ConnectionChanges: connChangeStreams[i],
				ProtocolID:        WingspanProtocolID,
				SessionIDLength:   12, // TODO: what constant should this be referencing?
			},
		)
		t.Cleanup(wingspanProtocols[i].Wait)
	}

	fx := tmconsensustest.NewEd25519Fixture(nNodes)

	// Finally we should have everything needed to make a network adapter.

	// A single codec can be shared among all the network adapters.
	codec := tmjson.MarshalCodec{CryptoRegistry: new(gcrypto.Registry)}
	gcrypto.RegisterEd25519(codec.CryptoRegistry)

	// And we need one set of hte
	var odMu sync.Mutex
	ods := map[string]gdna.OriginationDetails{}

	networkAdapters := make([]*gdna.NetworkAdapter, nNodes)

	acceptedStreamChs := make([]<-chan gdna.AcceptedStream, nNodes)
	acceptedUniStreamChs := make([]<-chan gdna.AcceptedUniStream, nNodes)
	blockDataArrivalChs := make([]<-chan tmelink.BlockDataArrival, nNodes)

	for i := range networkAdapters {
		// Arbitrary guess of size 8.
		asCh := make(chan gdna.AcceptedStream, 8)
		ausCh := make(chan gdna.AcceptedUniStream, 8)
		bdaCh := make(chan tmelink.BlockDataArrival, 8)

		acceptedStreamChs[i] = asCh
		acceptedUniStreamChs[i] = ausCh
		blockDataArrivalChs[i] = bdaCh

		networkAdapters[i] = gdna.NewNetworkAdapter(
			ctx, nw.Log.With("networkadapter", i),
			gdna.NetworkAdapterConfig{
				// No initial connections.
				ConnectionChanges: connChangeStreams[i],

				BreathcastAdapter: gdbcAdapters[i],

				Wingspan: wingspanProtocols[i],

				BreathcastProtocolID: BreathcastProtocolID,
				WingspanProtocolID:   WingspanProtocolID,

				OwnPubKey: fx.ValidatorPubKey(i),

				SignatureScheme: tmconsensustest.SimpleSignatureScheme{},

				SignatureLen: ed25519.SignatureSize,
				HashLen:      32, // TODO: this needs to be a constant from tmconsensustest.

				GetOriginationDetailsFunc: func(blockHash []byte) gdna.OriginationDetails {
					odMu.Lock()
					defer odMu.Unlock()

					od, ok := ods[string(blockHash)]
					if !ok {
						panic(fmt.Errorf(
							"attempted to get origination details for hash %x, but no entry existed",
							blockHash,
						))
					}

					return od
				},

				GetBroadcastDetailsFunc: func(proposalDriverAnnotation []byte) (gdbc.BroadcastDetails, error) {
					// Assuming for now that the proposal annotation is a simple JSON encoding.
					var d gdbc.BroadcastDetails
					if err := json.Unmarshal(proposalDriverAnnotation, &d); err != nil {
						return d, fmt.Errorf(
							"failed to json-unmarshal broadcast details: %w", err,
						)
					}

					return d, nil
				},

				AcceptedStreamCh:    asCh,
				AcceptedUniStreamCh: ausCh,
				BlockDataArrivalCh:  bdaCh,

				Unmarshaler: codec,
			},
		)
		t.Cleanup(networkAdapters[i].Wait)
	}

	return &Fixture{
		Network: nw,

		Fx: fx,

		AcceptedStreamChs:    acceptedStreamChs,
		AcceptedUniStreamChs: acceptedUniStreamChs,
		BlockDataArrivalChs:  blockDataArrivalChs,

		ConnChangeStreams: connChangeStreams,

		BreathcastProtocols: breathcastProtocols,
		GDBCAdapters:        gdbcAdapters,

		WingspanProtocols: wingspanProtocols,

		NetworkAdapters: networkAdapters,

		MarshalCodec: codec,

		ods: ods,
	}
}

// StartWithBufferedConsensusHandlers starts all the nodes in the fixture's network,
// with each node reading from writing to its own CHBuffer instance.
//
// It also sets write-only channels of network view updates,
// so the test can directly control the network view updates
// without a running engine.
// The network view updates are consumed directly by the [gdna.NetworkAdapter].
func (f *Fixture) StartWithBufferedConsensusHandlers() (
	[]chan<- tmelink.NetworkViewUpdate, []CHBuffer,
) {
	nNodes := len(f.Network.Nodes)
	nvuOut := make([]chan<- tmelink.NetworkViewUpdate, nNodes)

	chBufs := make([]CHBuffer, nNodes)
	for i := range chBufs {
		chBufs[i] = NewCHBuffer(4)

		// Must be unbuffered so we confirm receipt on send.
		nvuCh := make(chan tmelink.NetworkViewUpdate)

		nvuOut[i] = nvuCh

		f.NetworkAdapters[i].SetConsensusHandler(chBufs[i])
		f.NetworkAdapters[i].Start(nvuCh)
	}

	return nvuOut, chBufs
}

func (f *Fixture) RegisterOriginationDetails(blockHash []byte, od gdna.OriginationDetails) {
	f.odMu.Lock()
	defer f.odMu.Unlock()

	f.ods[string(blockHash)] = od
}
