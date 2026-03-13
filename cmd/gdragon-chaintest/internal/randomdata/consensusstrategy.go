package randomdata

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"

	"github.com/gordian-engine/gdragon/cmd/gdragon-chaintest/internal/validator"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
)

type ConsensusStrategy struct {
	log *slog.Logger

	proposerIdx int
	nProposers  int

	rng      *rand.ChaCha8
	dataSize int

	bds validator.BlockDataStore

	mu   sync.Mutex
	curH uint64
	curR uint32
}

func NewConsensusStrategy(
	log *slog.Logger,
	bds validator.BlockDataStore,
	proposerIdx, nProposers int,
	dataSize int,
) *ConsensusStrategy {
	var seed [32]byte
	binary.BigEndian.PutUint64(seed[:], uint64(proposerIdx))
	binary.BigEndian.PutUint64(seed[15:], uint64(nProposers))
	rng := rand.NewChaCha8(seed)

	return &ConsensusStrategy{
		log: log,

		proposerIdx: proposerIdx,
		nProposers:  nProposers,

		rng:      rng,
		dataSize: dataSize,

		bds: bds,
	}
}

func (s *ConsensusStrategy) EnterRound(
	ctx context.Context,
	rv tmconsensus.RoundView,
	proposalOut chan<- tmconsensus.Proposal,
) error {
	s.mu.Lock()
	s.curH = rv.Height
	s.curR = rv.Round
	s.mu.Unlock()

	hr := rv.Height + uint64(rv.Round)
	isProposer := int(hr)%s.nProposers == s.proposerIdx

	if isProposer {
		data := make([]byte, s.dataSize)
		_, _ = s.rng.Read(data)
		dataID := sha256.Sum256(data)
		s.bds.PutData(dataID[:], data)

		proposalOut <- tmconsensus.Proposal{
			DataID: string(dataID[:]),
		}
	}

	return nil
}

func (s *ConsensusStrategy) ConsiderProposedBlocks(
	ctx context.Context,
	phs []tmconsensus.ProposedHeader,
	_ tmconsensus.ConsiderProposedBlocksReason,
) (string, error) {
	// Just vote for the first proposed block,
	// since we trust that other validators won't propose.
	for _, ph := range phs {
		d, ok := s.bds.GetData(ph.Header.DataID)
		if !ok {
			s.log.Info("Failed to get data for ID", "id", fmt.Sprintf("%x", ph.Header.DataID))
			continue
		}

		// The data ID must be the correct hash of the data.
		calcID := sha256.Sum256(d)
		if !bytes.Equal(ph.Header.Hash, calcID[:]) {
			s.log.Info("Hash mismatch for data")
			continue
		}

		return string(ph.Header.Hash), nil
	}

	return "", tmconsensus.ErrProposedBlockChoiceNotReady
}

func (s *ConsensusStrategy) ChooseProposedBlock(
	ctx context.Context,
	phs []tmconsensus.ProposedHeader,
) (string, error) {
	hash, err := s.ConsiderProposedBlocks(
		ctx, phs, tmconsensus.ConsiderProposedBlocksReason{},
	)
	if err == tmconsensus.ErrProposedBlockChoiceNotReady {
		s.mu.Lock()
		defer s.mu.Unlock()

		s.log.Warn(
			"Proposal timer elapsed with no proposed block; prevoting nil",
			"h", s.curH, "r", s.curR,
		)
		return "", nil
	}

	return hash, err
}

func (s *ConsensusStrategy) DecidePrecommit(
	ctx context.Context,
	vs tmconsensus.VoteSummary,
) (string, error) {
	maj := tmconsensus.ByzantineMajority(vs.AvailablePower)

	s.mu.Lock()
	defer s.mu.Unlock()

	if vs.PrevoteBlockPower[vs.MostVotedPrevoteHash] >= maj {
		s.log.Warn(
			"Precommitting block",
			"hash", fmt.Sprintf("%x", vs.MostVotedPrevoteHash),
			"h", s.curH, "r", s.curR,
		)
		return vs.MostVotedPrevoteHash, nil
	}

	s.log.Warn(
		"No supermajority prevote; precommitting nil",
		"h", s.curH, "r", s.curR,
	)
	return "", nil
}
