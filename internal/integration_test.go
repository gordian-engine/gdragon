package internal_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/gordian-engine/gdragon/gdbc"
	"github.com/gordian-engine/gdragon/gdna/gdnatest"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
	"github.com/gordian-engine/gordian/tm/tmconsensus/tmconsensustest"
	"github.com/gordian-engine/gordian/tm/tmengine/tmelink"
	"github.com/gordian-engine/gordian/tm/tmgossip"
	"github.com/gordian-engine/gordian/tm/tmintegration"
)

func GDragonFactory(
	t *testing.T,
	ctx context.Context,
	stores []tmintegration.BlockDataStore,
) (tmintegration.Network, tmintegration.StoreFactory) {
	// The gdnatest package is decoupled from tmintegration,
	// but the interfaces are equivalent,
	// so we just neeed a new slice of the right interface type.
	gdnaStores := make([]gdnatest.BlockDataStore, len(stores))
	for i, s := range stores {
		gdnaStores[i] = s
	}

	return &gdNetwork{
		nfx:    gdnatest.NewFixture(t, ctx, gdnaStores),
		stores: gdnaStores,
	}, tmintegration.InmemStoreNetwork{}
}

type gdNetwork struct {
	nfx *gdnatest.Fixture

	stores []gdnatest.BlockDataStore
}

func (n *gdNetwork) Fixture() *tmconsensustest.Fixture {
	return n.nfx.Fx
}

func (n *gdNetwork) GetGossipStrategy(ctx context.Context, idx int) tmgossip.Strategy {
	return n.nfx.NetworkAdapters[idx]
}

func (n *gdNetwork) GetBlockDataArrivalChannel(
	_ context.Context, idx int,
) <-chan tmelink.BlockDataArrival {
	return n.nfx.BlockDataArrivalChs[idx]
}

func (n *gdNetwork) GetProposedHeaderInterceptor(
	_ context.Context, idx int,
) tmelink.ProposedHeaderInterceptor {
	s := n.stores[idx]
	a := n.nfx.GDBCAdapters[idx]
	return tmelink.ProposedHeaderInterceptorFunc(
		func(ctx context.Context, ph *tmconsensus.ProposedHeader) error {
			blockData, ok := s.GetData(ph.Header.DataID)
			if !ok {
				// Panicking here because this is a fatal problem.
				panic(fmt.Errorf(
					"BUG: attempted to intercept proposed header for data id %x but it was missing",
					ph.Header.DataID,
				))
			}

			// Identify our proposer index.
			proposerIdx := -1
			proposerKey := ph.ProposerPubKey
			for i, k := range ph.Header.ValidatorSet.PubKeys {
				if proposerKey.Equal(k) {
					proposerIdx = i
					break
				}
			}

			if proposerIdx == -1 {
				panic(errors.New(
					"BUG: failed to find our proposer index on intercepted proposed header",
				))
			}

			po, err := a.PrepareOrigination(gdbc.PrepareOriginationConfig{
				BlockData: blockData,

				ParityRatio: 0.1,

				HashNonce: []byte("TODO"),

				Height:      ph.Header.Height,
				Round:       ph.Round,
				ProposerIdx: uint16(proposerIdx), // Assuming no chance of overflow here.
			})
			if err != nil {
				return fmt.Errorf("failed to prepare origination: %w", err)
			}

			ph.Annotations.Driver, err = json.Marshal(po.BroadcastDetails())
			if err != nil {
				panic(fmt.Errorf(
					"BUG: failed to JSON marshal broadcast details: %w", err,
				))
			}

			return nil
		},
	)
}

func (n *gdNetwork) Stabilize(ctx context.Context) {
	addr0 := n.nfx.Network.Nodes[0].UDP.LocalAddr()
	for i, node := range n.nfx.Network.Nodes {
		if i == 0 {
			continue
		}
		if err := node.Node.DialAndJoin(ctx, addr0); err != nil {
			panic(fmt.Errorf("failed to dial and join node zero: %w", err))
		}
	}
}

func (n *gdNetwork) Wait() {
	// The fixture already calls wait on everything via t.Cleanup.
	// Just waiting on the network value ought to suffice here.
	n.nfx.Network.Wait()
}

func TestGordianIntegration(t *testing.T) {
	t.Skip("TODO")
	t.Parallel()

	tmintegration.RunIntegrationTest(t, GDragonFactory)
}
