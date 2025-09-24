package gdbc

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle"
)

// The size of broadast IDs (64-bit height, 32-bit round, and 16-bit proposer ID).
// This is required for configuring the breathcast protocol instance.
const BroadcastIDLen = 8 + 4 + 2

// Adapter adapts a [*breathcast.Protocol] to more closely match
// the types that Gordian core wants to provide.
type Adapter struct {
	log *slog.Logger

	p *breathcast.Protocol

	hasher   bcmerkle.Hasher
	hashSize int

	protocolID byte

	done chan struct{}
}

// AdapterConfig is the configuration type for [NewAdapter].
type AdapterConfig struct {
	Protocol *breathcast.Protocol

	ProtocolID byte

	Hasher   bcmerkle.Hasher
	HashSize int
}

// NewAdapter returns a new Adapter instance based on the given config.
func NewAdapter(
	log *slog.Logger,
	cfg AdapterConfig,
) (*Adapter, error) {
	return &Adapter{
		log: log,

		p: cfg.Protocol,

		protocolID: cfg.ProtocolID,

		hasher:   cfg.Hasher,
		hashSize: cfg.HashSize,
	}, nil
}

// PrepareOriginationConfig is the configuration for [*Adapter.PrepareOrigination].
type PrepareOriginationConfig struct {
	BlockData []byte

	ParityRatio float32

	HashNonce []byte

	Height      uint64
	Round       uint32
	ProposerIdx uint16
}

// PreparedOrigination is the return value of [*Adapter.PrepareOrigination].
// It wraps a [breathcast.PreparedOrigination] and other values
// necessary to successfully call [*Adapter.Originate].
type PreparedOrigination struct {
	bc  breathcast.PreparedOrigination
	bid []byte

	hashNonce []byte

	totalDataSize uint32
}

// BroadcastDetails returns the broadcast details
// for the prepared origination.
//
// This value should be encoded in the proposed header's annotations,
// and the proposed header should be serialized as the app header value
// on a broadcast operation.
//
// This allows recipients to parse the app header
// and then have all necessary information
// to properly receive a broadcast.
func (po PreparedOrigination) BroadcastDetails() BroadcastDetails {
	return BroadcastDetails{
		NData:   uint16(po.bc.NumData),
		NParity: uint16(po.bc.NumParity),

		TotalDataSize: po.totalDataSize,

		ChunkSize: uint16(po.bc.ChunkSize),

		HashNonce: po.hashNonce,

		RootProofs: po.bc.RootProof,
	}
}

// BroadcastDetails contains the data necessary to accept an incoming broadcast.
// For block data, this should be encoded in the proposed header annotations.
type BroadcastDetails struct {
	NData, NParity uint16

	TotalDataSize uint32

	ChunkSize uint16

	HashNonce []byte

	RootProofs [][]byte
}

// PrepareOrigination returns an adapter-specific prepared origination type,
// to be passed to [*Adapter.Originate].
func (a *Adapter) PrepareOrigination(cfg PrepareOriginationConfig) (
	PreparedOrigination, error,
) {
	bid := make([]byte, BroadcastIDLen)
	binary.BigEndian.PutUint64(bid, cfg.Height)
	binary.BigEndian.PutUint32(bid[8:], cfg.Round)
	binary.BigEndian.PutUint16(bid[8+4:], cfg.ProposerIdx)

	bcpo, err := breathcast.PrepareOrigination(cfg.BlockData, breathcast.PrepareOriginationConfig{
		MaxChunkSize: 1100, // TODO: this value needs to be properly calculated.

		ProtocolID: a.protocolID,

		BroadcastID: bid,

		ParityRatio: cfg.ParityRatio,

		HeaderProofTier: 2, // TODO: this should be configurable.

		Hasher:   a.hasher,
		HashSize: a.hashSize,

		Nonce: cfg.HashNonce,
	})
	if err != nil {
		return PreparedOrigination{}, fmt.Errorf(
			"failed to prepare origination: %w", err,
		)
	}

	return PreparedOrigination{
		bc: bcpo,

		bid: bid,

		totalDataSize: uint32(len(cfg.BlockData)),

		hashNonce: cfg.HashNonce,
	}, nil
}

// Originate creates and returns a new broadcast operation.
//
// The typical flow for this is:
//  1. Produce block data
//  2. Pass the block data and other config to [*Adapter.PrepareOrigination]
//  3. On the returned [PreparedOrigination], gather the [PreparedOrigination.BroadcastDetails]
//     which contains the information for peers to decode the broadcast
//  4. Serialize the [BroadcastDetails] as part of the driver annotations on the [tmconsensus.ProposedHeader]
//  5. Sign the updated proposed header
//  6. Serialize the entire proposed header as the appHeader argument to this method
func (a *Adapter) Originate(
	ctx context.Context,
	appHeader []byte,
	po PreparedOrigination,
) (*breathcast.BroadcastOperation, error) {
	bop, err := a.p.NewOrigination(ctx, breathcast.OriginationConfig{
		BroadcastID: po.bid,

		AppHeader: appHeader,
		Packets:   po.bc.Packets,

		NData: uint16(po.bc.NumData),

		TotalDataSize: int(po.totalDataSize),

		ChunkSize: po.bc.ChunkSize,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create broadcast operation: %w", err,
		)
	}

	return bop, nil
}

// IncomingBroadcastConfig is the configuration type for [*Adapter.NewIncomingBroadcast].
type IncomingBroadcastConfig struct {
	// Necessary to relay the broadcast to other peers.
	BroadcastID []byte
	AppHeader   []byte

	BroadcastDetails BroadcastDetails
}

// NewIncomingBroadcast creates a new broadcast operation
// based on incoming data from a peer.
//
// Note that the caller must still call [*breathcast.BroadcastOperation.AcceptBroadcast]
// in order to actually read data from the underlying QUIC stream.
func (a *Adapter) NewIncomingBroadcast(
	ctx context.Context,
	cfg IncomingBroadcastConfig,
) (*breathcast.BroadcastOperation, error) {
	bd := cfg.BroadcastDetails
	bop, err := a.p.NewIncomingBroadcast(ctx, breathcast.IncomingBroadcastConfig{
		BroadcastID: cfg.BroadcastID,

		AppHeader: cfg.AppHeader,

		NData:   bd.NData,
		NParity: bd.NParity,

		TotalDataSize: int(bd.TotalDataSize),

		Hasher:   a.hasher,
		HashSize: a.hashSize,

		HashNonce: bd.HashNonce,

		RootProofs: bd.RootProofs,

		ChunkSize: bd.ChunkSize,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create incoming broadcast operation: %w", err,
		)
	}

	return bop, nil
}

// ExtractStreamBroadcastID extracts the broadcast ID from r
// (which should be a [quic.ReceiveStream]).
// The extracted data is appended to the given dst slice,
// which is permitted to be nil.
//
// The caller is responsible for setting any read deadlines.
//
// It is assumed that the caller has already consumed
// the protocol ID byte matching [ProtocolConfig.ProtocolID].
func (a *Adapter) ExtractStreamBroadcastID(r io.Reader, dst []byte) ([]byte, error) {
	return a.p.ExtractStreamBroadcastID(r, dst)
}
