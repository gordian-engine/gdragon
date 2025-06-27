package gdtmp2ptest_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"testing"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
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
	return gdtmp2ptest.NewNetwork(t, ctx, gdtmp2ptest.NetworkConfig{
		OriginationConfigFunc: func(
			ctx context.Context, ph tmconsensus.ProposedHeader,
		) (breathcast.OriginationConfig, error) {
			// These tests don't provide any application data.
			// So, we will produce some random block data
			// derived from the data ID on the proposed header.
			seed := sha256.Sum256(ph.Header.DataID)
			cc := rand.NewChaCha8(seed)
			blockData := make([]byte, 16*1024)
			_, err := io.ReadFull(cc, blockData)
			if err != nil {
				return breathcast.OriginationConfig{}, fmt.Errorf(
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

				ProtocolID: gdtmp2ptest.BreathcastProtocolID,

				BroadcastID: bid,

				ParityRatio: 0.1,

				HeaderProofTier: 2,

				Hasher: bcsha256.Hasher{},

				HashSize: bcsha256.HashSize,
			})
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

				TotalDataSize: len(blockData),

				ChunkSize: po.ChunkSize,
			}

			return cfg, nil
		},
	})
}
