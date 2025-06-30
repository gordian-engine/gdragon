package gdtmp2ptest_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/gdragon/gdtmp2p/gdtmp2ptest"
	"github.com/gordian-engine/gordian/gcrypto"
	"github.com/gordian-engine/gordian/tm/tmcodec/tmjson"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
	"github.com/gordian-engine/gordian/tm/tmp2p/tmp2ptest"
)

func TestNetwork(t *testing.T) {
	t.Parallel()

	tmp2ptest.TestNetworkCompliance(t, networkConstructor)
}

func networkConstructor(t *testing.T, ctx context.Context) (tmp2ptest.Network, error) {
	var reg gcrypto.Registry
	gcrypto.RegisterEd25519(&reg)
	codec := tmjson.MarshalCodec{
		CryptoRegistry: &reg,
	}

	n, err := gdtmp2ptest.NewNetwork(t, ctx, gdtmp2ptest.NetworkConfig{
		Unmarshaler: codec,

		OriginationConfigFunc: func(
			ctx context.Context, ph tmconsensus.ProposedHeader,
		) (breathcast.OriginationConfig, error) {
			// These tests don't provide any application data.
			// So, we will produce some random block data
			// derived from the data ID on the proposed header.
			po, bid, err := gdtmp2ptest.PrepareOrigination(ph)
			if err != nil {
				return breathcast.OriginationConfig{}, fmt.Errorf(
					"failed to prepare origination: %w", err,
				)
			}

			ah, err := codec.MarshalProposedHeader(ph)
			if err != nil {
				return breathcast.OriginationConfig{}, fmt.Errorf(
					"failed to marshal proposed header: %w", err,
				)
			}

			cfg := breathcast.OriginationConfig{
				BroadcastID: bid,

				AppHeader: ah,
				Packets:   po.Packets,

				NData: uint16(po.NumData),

				TotalDataSize: 16 * 1024, // TODO: don't hardcode this value.

				ChunkSize: po.ChunkSize,
			}

			return cfg, nil
		},
	})

	if err != nil {
		return nil, err
	}

	return n, nil
}
