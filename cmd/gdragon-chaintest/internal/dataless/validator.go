package dataless

import (
	"context"

	"github.com/gordian-engine/gdragon/cmd/gdragon-chaintest/internal/validator"
)

func RunValidator(
	ctx context.Context,
	vCfg validator.Config,
) error {
	bds := validator.NewBlockDataMap()
	return validator.Run(
		ctx,
		validator.App{
			ConsensusStrategy: NewConsensusStrategy(
				vCfg.Log.With("sys", "consensusstrategy"),
				bds,
				vCfg.Peers[0].PubKey.Equal(vCfg.PubKey),
			),
			BlockDataStore: bds,
		},
		vCfg,
	)
}
