package dataless

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/gordian-engine/gordian/tm/tmconsensus"
)

type ConsensusStrategy struct {
	log *slog.Logger

	isSoleProposer bool

	mu   sync.Mutex
	curH uint64
	curR uint32
}

func NewConsensusStrategy(
	log *slog.Logger,
	isSoleProposer bool,
) *ConsensusStrategy {
	return &ConsensusStrategy{
		log: log,

		isSoleProposer: isSoleProposer,
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

	if s.isSoleProposer {
		proposalOut <- tmconsensus.Proposal{
			DataID: "",
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
