package gdbc

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/gordian/tm/tmcodec"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
)

// The size of broadast IDs (64-bit height, 32-bit round, and 16-bit proposer ID).
// This is required for configuring the breathcast protocol instance.
const BroadcastIDLen = 8 + 4 + 2

// Adapter adapts a [*breathcast.Protocol] to more closely match
// the types that Gordian core wants to provide.
type Adapter struct {
	log *slog.Logger

	p *breathcast.Protocol

	marshaler tmcodec.Marshaler

	protocolID byte

	done chan struct{}
}

// AdapterConfig is the configuration type for [NewAdapter].
type AdapterConfig struct {
	Protocol *breathcast.Protocol

	ProtocolID byte

	Marshaler tmcodec.Marshaler
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

		marshaler: cfg.Marshaler,
	}, nil
}

// BroadcastInfo is a temporary struct indicating
// the configuration created inside [*Adapter.Originate].
//
// The API for Originate needs to change, and BroadcastInfo will go away.
type BroadcastInfo struct {
	NData, NParity uint16

	ChunkSize uint16

	TotalDataSize int

	RootProofs [][]byte

	Nonce []byte
}

// Originate creates and returns a new broadcast operation.
//
// TODO: this needs to be split into several discrete steps,
// likely at the caller's responsibility:
//  1. Prepare origination on blockData
//  2. Add an annotation to the proposed header with the breathcast configuration
//     so that receivers can set up the broadcast operation.
//  3. Sign the proposed header.
//  4. Marshal the proposed header and pass to a method like this Originate?
func (a *Adapter) Originate(
	ctx context.Context,
	blockData []byte,
	proposedHeader tmconsensus.ProposedHeader,
	height uint64,
	round uint32,
	proposerIdx uint16,
	parityRatio float32,
	hashNonce []byte,
) (*breathcast.BroadcastOperation, BroadcastInfo, error) {
	// We are currently serializing the proposed header internally here,
	// but it may be more appropriate to raise that out of this method
	// in order to allow the driver to add more data if needed.
	appHeader, err := a.marshaler.MarshalProposedHeader(proposedHeader)
	if err != nil {
		return nil, BroadcastInfo{}, fmt.Errorf(
			"failed to marshal proposed header: %w", err,
		)
	}

	bid := make([]byte, BroadcastIDLen)
	binary.BigEndian.PutUint64(bid, height)
	binary.BigEndian.PutUint32(bid[8:], round)
	binary.BigEndian.PutUint16(bid[8+4:], proposerIdx)

	po, err := breathcast.PrepareOrigination(blockData, breathcast.PrepareOriginationConfig{
		MaxChunkSize: 1100, // TODO: this value needs to be properly calculated.

		ProtocolID: a.protocolID,

		BroadcastID: bid,

		ParityRatio: parityRatio,

		HeaderProofTier: 2, // TODO: this should be configurable.

		Hasher: bcsha256.Hasher{}, // TODO: this should be configurable.

		HashSize: bcsha256.HashSize,

		Nonce: hashNonce,
	})
	if err != nil {
		return nil, BroadcastInfo{}, fmt.Errorf(
			"failed to prepare origination: %w", err,
		)
	}

	bop, err := a.p.NewOrigination(ctx, breathcast.OriginationConfig{
		BroadcastID: bid,

		AppHeader: appHeader,
		Packets:   po.Packets,

		NData: uint16(po.NumData),

		TotalDataSize: len(blockData),

		ChunkSize: po.ChunkSize,
	})
	if err != nil {
		return nil, BroadcastInfo{}, fmt.Errorf(
			"failed to create broadcast operation: %w", err,
		)
	}

	return bop, BroadcastInfo{
		NData:   uint16(po.NumData),
		NParity: uint16(po.NumParity),

		ChunkSize: uint16(po.ChunkSize),

		TotalDataSize: len(blockData),

		RootProofs: po.RootProof,

		Nonce: hashNonce,
	}, nil
}
