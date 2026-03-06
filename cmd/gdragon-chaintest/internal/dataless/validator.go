package dataless

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"

	"github.com/gordian-engine/gdragon/cmd/gdragon-chaintest/internal/validator"
)

// Temporary type alias until ValidatorConfig refactoring is ready.
type Peer = validator.Peer

// TODO: this is a partial clone of the internal/validator.Config,
// but it needs to be somehow extracted so we aren't halfway duplicating this.
type ValidatorConfig struct {
	Log *slog.Logger

	StoreMode string

	TrustedCAs []*x509.Certificate

	Peers []Peer

	PubKey  ed25519.PublicKey
	PrivKey ed25519.PrivateKey

	UDPConn *net.UDPConn

	P2PCert tls.Certificate
}

func RunValidator(
	ctx context.Context,
	cfg ValidatorConfig,
) error {
	bds := validator.NewBlockDataMap()
	return validator.Run(
		ctx,
		validator.Config{
			Log: cfg.Log,

			StoreMode: cfg.StoreMode,

			ConsensusStrategy: NewConsensusStrategy(
				cfg.Log.With("sys", "consensusstrategy"),
				bds,
				cfg.Peers[0].PubKey.Equal(cfg.PubKey),
			),

			BlockDataStore: bds,

			TrustedCAs: cfg.TrustedCAs,

			Peers: cfg.Peers,

			PubKey:  cfg.PubKey,
			PrivKey: cfg.PrivKey,

			UDPConn: cfg.UDPConn,

			P2PCert: cfg.P2PCert,
		},
	)
}
