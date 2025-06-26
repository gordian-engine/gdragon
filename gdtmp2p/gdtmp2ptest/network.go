package gdtmp2ptest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gordian-engine/dragon"
	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dcert/dcerttest"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dview/dviewrand"
	"github.com/gordian-engine/gdragon/gdtmp2p"
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

	udpConns []*net.UDPConn
	nodes    []*dragon.Node
	caCerts  []*x509.Certificate
	chains   []dcert.Chain
}

func NewNetwork(t *testing.T, ctx context.Context) (tmp2ptest.Network, error) {
	n := &Network{
		t: t,

		log: slogt.New(t, slogt.Text()),
	}
	return n, nil
}

const (
	// Arbitrary sizes that seem reasonable for most tests.
	activeViewSize  = 5
	passiveViewSize = 8
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

	connChanges := make(chan dconn.Change, 8)
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

		ConnectionChanges: connChanges,
	}

	nodeCtx, nodeCancel := context.WithCancel(ctx)

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

	return gdtmp2p.NewConnection(ctx, node, nodeCancel, connChanges), nil
}

func (n *Network) Wait() {
	for _, node := range n.nodes {
		node.Wait()
	}
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
