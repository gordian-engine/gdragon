package randomdata

import (
	"context"

	"github.com/gordian-engine/gdragon/cmd/gdragon-chaintest/internal/validator"
)

func RunValidator(
	ctx context.Context,
	dataSize int,
	vCfg validator.Config,
) error {
	bds := validator.NewBlockDataMap()
	ownIdx := -1
	for i, p := range vCfg.Peers {
		if vCfg.PubKey.Equal(p.PubKey) {
			ownIdx = i
			break
		}
	}

	return validator.Run(
		ctx,
		validator.App{
			ConsensusStrategy: NewConsensusStrategy(
				vCfg.Log.With("sys", "consensusstrategy"),
				bds,
				ownIdx,
				len(vCfg.Peers),
				dataSize,
			),
			BlockDataStore: bds,
		},
		vCfg,
	)
}
