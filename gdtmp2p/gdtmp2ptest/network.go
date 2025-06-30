package gdtmp2ptest

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gordian-engine/dragon"
	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dcert/dcerttest"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/dview/dviewrand"
	"github.com/gordian-engine/gdragon/gdtmp2p"
	"github.com/gordian-engine/gordian/tm/tmcodec"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
	"github.com/gordian-engine/gordian/tm/tmp2p"
	"github.com/gordian-engine/gordian/tm/tmp2p/tmp2ptest"
	"github.com/neilotoole/slogt"
)

var leafCounter uint32

// Network is an implementation of [tmp2ptest.Network] for [dragon].
//
// Note, this does not use the [github.com/gordian-engine/dragon/dragontest.Network] type
// which is intended for a static set of nodes.
type Network struct {
	t *testing.T

	log *slog.Logger

	unmarshaler           tmcodec.Unmarshaler
	originationConfigFunc gdtmp2p.OriginationConfigFunc

	udpConns []*net.UDPConn
	nodes    []*dragon.Node
	caCerts  []*x509.Certificate
	chains   []dcert.Chain
}

// NetworkConfig is the configuration for [NewNetwork].
type NetworkConfig struct {
	OriginationConfigFunc gdtmp2p.OriginationConfigFunc

	Unmarshaler tmcodec.Unmarshaler
}

func NewNetwork(t *testing.T, ctx context.Context, cfg NetworkConfig) (tmp2ptest.Network, error) {
	n := &Network{
		t: t,

		log: slogt.New(t, slogt.Text()),

		unmarshaler:           cfg.Unmarshaler,
		originationConfigFunc: cfg.OriginationConfigFunc,
	}
	return n, nil
}

const (
	// Arbitrary sizes that seem reasonable for most tests.
	activeViewSize  = 5
	passiveViewSize = 8

	// Arbitrary protocol IDs for test.
	BreathcastProtocolID = 0x90

	// TODO: this should be a non-constant,
	// derived from the hash scheme somehow.
	// For now it is uint64 height + uint32 round + 32-byte blake2b hash.
	broadcastIDLength = 8 + 4 + 32
)

func (n *Network) Connect(ctx context.Context) (tmp2p.Connection, error) {
	// First, create a new certificate for the new node.
	ca, err := dcerttest.GenerateCA(dcerttest.FastConfig())
	if err != nil {
		panic(err)
	}
	leafIdx := atomic.AddUint32(&leafCounter, 1)
	leaf, err := ca.CreateLeafCert(dcerttest.LeafConfig{
		DNSNames: []string{
			fmt.Sprintf("%d.leaf.example", leafIdx),
		},
	})

	n.caCerts = append(n.caCerts, ca.Cert)
	n.chains = append(n.chains, leaf.Chain)

	// Set up the listener.
	uc, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0,
	})
	if err != nil {
		panic(err)
	}
	n.t.Cleanup(func() {
		if err := uc.Close(); err != nil {
			n.t.Logf("Error closing UDP listener: %v", err)
		}
	})

	n.udpConns = append(n.udpConns, uc)

	tc := tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{leaf.Cert.Raw},
				PrivateKey:  leaf.PrivKey,

				Leaf: leaf.Cert,
			},
		},

		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	connChangesCh := make(chan dconn.Change, 8)
	nodeLog := n.log.With("global_node_idx", leafIdx)
	nc := dragon.NodeConfig{
		UDPConn: uc,
		QUIC:    dragon.DefaultQUICConfig(),
		TLS:     &tc,

		InitialTrustedCAs: n.caCerts,

		AdvertiseAddr: uc.LocalAddr().String(),

		ViewManager: dviewrand.New(
			nodeLog.With("node_sys", "view_manager"),
			dviewrand.Config{
				ActiveViewSize:  activeViewSize,
				PassiveViewSize: passiveViewSize,

				RNG: rand.New(rand.NewPCG(uint64(leafIdx), 0)),
			},
		),

		// Declared inline since it may not be nil.
		// Doesn't seem necessary for the integration tests,
		// at least not at this point in time.
		ShuffleSignal: make(chan struct{}),

		ConnectionChanges: connChangesCh,
	}

	nodeCtx, nodeCancel := context.WithCancel(ctx)

	connChangeStream, streamDone := dpubsub.RunChannelToStream(nodeCtx, connChangesCh)
	n.t.Cleanup(func() { <-streamDone })

	node, err := dragon.NewNode(nodeCtx, nodeLog, nc)
	if err != nil {
		panic(err)
	}
	n.t.Cleanup(node.Wait)

	for _, existingNode := range n.nodes {
		existingNode.UpdateCAs(n.caCerts)
	}

	if len(n.nodes) > 0 {
		targetAddr := n.udpConns[len(n.nodes)-1].LocalAddr()
		err := node.DialAndJoin(ctx, targetAddr)
		if err != nil {
			panic(err)
		}
	}

	n.nodes = append(n.nodes, node)

	bcProto := breathcast.NewProtocol(
		nodeCtx,
		nodeLog.With("protocol", "breathcast"),
		breathcast.ProtocolConfig{
			ConnectionChanges: connChangeStream,

			ProtocolID: BreathcastProtocolID,

			BroadcastIDLength: broadcastIDLength,
		},
	)

	cfg := gdtmp2p.ConnectionConfig{
		Node:   node,
		Cancel: nodeCancel,

		Breathcast: bcProto,

		BreathcastProtocolID: BreathcastProtocolID,

		Unmarshaler: n.unmarshaler,

		OriginationConfigFunc: n.originationConfigFunc,

		ConnChanges: connChangeStream,
	}
	return gdtmp2p.NewConnection(
		ctx, nodeLog.With("subsys", "conn"), cfg,
	), nil
}

func (n *Network) Wait() {
	for _, node := range n.nodes {
		node.Wait()
	}
}

func (n *Network) AddDriverAnnotations(
	ctx context.Context,
	c tmp2p.Connection,
	ph *tmconsensus.ProposedHeader,
) error {
	// This is a kind of weird setup.
	// The compliance test has to make the proposed header from a fixture,
	// and then that proposed header is sent directly to the Network instance.
	// Normally, the engine would set annotations on the proposed header,
	// but the network compliance tests circumvent the engine.
	// Therefore we have to add the annotations out of band.
	//
	// These annotations are critical to network communication
	// but are otherwise irrelevant to blockchain data,
	// so they are annotations on the ProposedHeader, not the Header.

	// First, recreate the deterministic data.
	po, _, err := PrepareOrigination(*ph)
	if err != nil {
		return fmt.Errorf("failed to prepare origination: %w", err)
	}

	a := gdtmp2p.BroadcastAnnotation{
		NData:   uint16(po.NumData),
		NParity: uint16(po.NumParity),

		TotalDataSize: 16 * 1024, // TODO: don't hardcode this value.

		HashNonce: nil, // TODO?

		RootProofs: po.RootProof,

		// TODO: does this need to account for broadcast ID length?
		ChunkSize: uint16(len(po.Packets[0])),
	}

	j, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("failed to marshal annotation: %w", err)
	}

	ph.Annotations.Driver = j
	return nil
}

func PrepareOrigination(ph tmconsensus.ProposedHeader) (
	breathcast.PreparedOrigination, []byte, error,
) {
	seed := sha256.Sum256(ph.Header.DataID)
	cc := rand.NewChaCha8(seed)
	blockData := make([]byte, 16*1024)
	_, err := io.ReadFull(cc, blockData)
	if err != nil {
		return breathcast.PreparedOrigination{}, nil, fmt.Errorf(
			"failed to generate random block data: %w", err,
		)
	}

	bid := make([]byte, 8+4+len(ph.Header.Hash))
	binary.BigEndian.PutUint64(bid, ph.Header.Height)
	binary.BigEndian.PutUint32(bid[8:], ph.Round)
	_ = copy(bid[8+4:], ph.Header.Hash)

	po, err := breathcast.PrepareOrigination(blockData, breathcast.PrepareOriginationConfig{
		// Doesn't matter much for test.
		MaxChunkSize: 1200,

		ProtocolID: BreathcastProtocolID,

		BroadcastID: bid,

		ParityRatio: 0.1,

		HeaderProofTier: 2,

		Hasher: bcsha256.Hasher{},

		HashSize: bcsha256.HashSize,
	})
	if err != nil {
		return breathcast.PreparedOrigination{}, nil, fmt.Errorf(
			"failed to prepare origination: %w", err,
		)
	}

	return po, bid, nil
}

func (n *Network) Stabilize(ctx context.Context) error {
	deadline := time.Now().Add(2 * time.Second)

	expActiveNodes := min(activeViewSize, len(n.nodes)-1)

	const waitDur = 20 * time.Millisecond

RETRY:
	for {
		if time.Now().After(deadline) {
			return errors.New("deadline exceeded while waiting for network to stabilize")
		}

		for _, node := range n.nodes {
			if node.ActiveViewSize() < expActiveNodes {
				time.Sleep(waitDur)
				continue RETRY
			}
		}

		return nil
	}
}
