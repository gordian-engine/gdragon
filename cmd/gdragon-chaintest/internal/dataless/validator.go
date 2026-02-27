package dataless

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"

	"github.com/gordian-engine/dragon"
	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/dview/dviewrand"
	"github.com/gordian-engine/dragon/wingspan"
	"github.com/gordian-engine/gdragon/gdbc"
	"github.com/gordian-engine/gdragon/gdna"
	"github.com/gordian-engine/gdragon/gdwsu"
	"github.com/gordian-engine/gordian/gcrypto"
	"github.com/gordian-engine/gordian/gwatchdog"
	"github.com/gordian-engine/gordian/tm/tmcodec/tmjson"
	"github.com/gordian-engine/gordian/tm/tmconsensus"
	"github.com/gordian-engine/gordian/tm/tmconsensus/tmconsensustest"
	"github.com/gordian-engine/gordian/tm/tmdriver"
	"github.com/gordian-engine/gordian/tm/tmengine"
	"github.com/gordian-engine/gordian/tm/tmengine/tmelink"
	"github.com/gordian-engine/gordian/tm/tmstore/tmmemstore"
)

const (
	breathcastProtocolID = 0xa0
	wingspanProtocolID   = 0xa1
)

type Peer struct {
	PubKey ed25519.PublicKey
	Addr   string
}

type ValidatorConfig struct {
	Log *slog.Logger

	TrustedCAs []*x509.Certificate

	Peers []Peer

	PubKey  ed25519.PublicKey
	PrivKey ed25519.PrivateKey

	UDPConn *net.UDPConn

	P2PCert        *x509.Certificate
	P2PCertPrivKey any
}

func RunValidator(
	ctx context.Context,
	cfg ValidatorConfig,
) error {
	log := cfg.Log

	wd, wCtx := gwatchdog.NewWatchdog(ctx, log.With("sys", "watchdog"))

	// See notes on gwatchdog; waiting on this is probably inappropriate.
	// defer wd.Wait()

	vals := make([]tmconsensus.Validator, len(cfg.Peers))
	for i, p := range cfg.Peers {
		vals[i] = tmconsensus.Validator{
			PubKey: gcrypto.Ed25519PubKey(p.PubKey),
			Power:  1,
		}
	}

	hashScheme := tmconsensustest.SimpleHashScheme{}
	valSet, err := tmconsensus.NewValidatorSet(vals, hashScheme)
	if err != nil {
		return fmt.Errorf("failed to create validator set: %w", err)
	}

	signer := gcrypto.NewEd25519Signer(cfg.PrivKey)
	sigScheme := tmconsensustest.SimpleSignatureScheme{}

	cert := cfg.P2PCert
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{cert.Raw},
				PrivateKey:  cfg.P2PCertPrivKey,
				Leaf:        cert,
			},
		},
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	connChangesCh := make(chan dconn.Change, 16) // Arbitrarily sized.

	dNode, err := dragon.NewNode(
		wCtx,
		log.With("sys", "dragon"),
		dragon.NodeConfig{
			UDPConn: cfg.UDPConn,
			QUIC:    dragon.DefaultQUICConfig(),
			TLS:     tlsCfg,

			InitialTrustedCAs: cfg.TrustedCAs,

			AdvertiseAddr: cfg.UDPConn.LocalAddr().String(),

			ViewManager: dviewrand.New(
				log.With("sys", "viewmanager"),
				dviewrand.Config{
					ActiveViewSize:  len(cfg.Peers),
					PassiveViewSize: 2 * len(cfg.Peers),
					RNG:             rand.New(rand.NewPCG(rand.Uint64(), 0)),
				},
			),

			ConnectionChanges: connChangesCh,

			// Normally we would want some control over the shuffle signal,
			// but for this application we don't care about shuffling connections.
			ShuffleSignal: make(chan struct{}),
		},
	)
	if err != nil {
		return fmt.Errorf("creating dragon node: %w", err)
	}
	defer dNode.Wait()

	connChanges, connChangesDone := dpubsub.RunChannelToStream(
		wCtx, connChangesCh,
	)
	defer func() { <-connChangesDone }()

	bcProtocol := breathcast.NewProtocol(
		wCtx,
		log.With("sys", "breathcast"),
		breathcast.ProtocolConfig{
			// TODO: tracer provider.

			ConnectionChanges: connChanges,
			ProtocolID:        breathcastProtocolID,
			BroadcastIDLength: gdbc.BroadcastIDLen,
			Timing:            breathcast.DefaultProtocolTiming(),
		},
	)
	defer bcProtocol.Wait()

	gdbcAdapter, err := gdbc.NewAdapter(
		log.With("sys", "gdbc"),
		gdbc.AdapterConfig{
			Protocol:   bcProtocol,
			ProtocolID: breathcastProtocolID,
			Hasher:     bcsha256.Hasher{},
			HashSize:   bcsha256.HashSize,
		},
	)
	if err != nil {
		return fmt.Errorf("creating gdbc adapter: %w", err)
	}

	wsProtocol := wingspan.NewProtocol[
		gdwsu.ParsedPacket, gdwsu.OutboundPacket,
		gdwsu.ReceivedFromPeer, gdwsu.UpdateFromCentral,
	](
		wCtx,
		log.With("sys", "wingspan"),
		wingspan.ProtocolConfig{
			// TODO: tracer provider.

			ConnectionChanges: connChanges,
			ProtocolID:        wingspanProtocolID,
			SessionIDLength:   8 + 4, // uint64 height + uint32 round
			Timing:            wingspan.DefaultProtocolTiming(),
		},
	)
	defer wsProtocol.Wait()

	asCh := make(chan gdna.AcceptedStream, 8)
	ausCh := make(chan gdna.AcceptedUniStream, 8)
	bdaCh := make(chan tmelink.BlockDataArrival, 8)

	reg := new(gcrypto.Registry)
	gcrypto.RegisterEd25519(reg)
	codec := tmjson.MarshalCodec{CryptoRegistry: reg}

	bds := &blockDataMap{data: make(map[string][]byte)}

	na := gdna.NewNetworkAdapter(
		wCtx,
		log.With("sys", "networkadapter"),
		gdna.NetworkAdapterConfig{
			ConnectionChanges: connChanges,

			BreathcastAdapter:    gdbcAdapter,
			Wingspan:             wsProtocol,
			BreathcastProtocolID: breathcastProtocolID,
			WingspanProtocolID:   wingspanProtocolID,

			OwnPubKey:       gcrypto.Ed25519PubKey(cfg.PubKey),
			SignatureScheme: sigScheme,
			SignatureLen:    uint16(ed25519.SignatureSize),
			HashLen:         32, // TODO: don't hardcode this.

			GetOriginationDetailsFunc: func(
				ph tmconsensus.ProposedHeader,
			) gdna.OriginationDetails {
				po, err := gdbcAdapter.PrepareOrigination(gdbc.PrepareOriginationConfig{
					BlockData: []byte(":)"),

					ParityRatio: 0.1,
					Height:      ph.Header.Height,
					Round:       ph.Round,
					ProposerIdx: 0, // Hardcoded to the first validator in this app.
				})
				if err != nil {
					panic(fmt.Errorf(
						"failed to prepare origination: %w", err,
					))
				}

				ph.Annotations.Driver, err = json.Marshal(po.BroadcastDetails())
				if err != nil {
					panic(fmt.Errorf("marshal broadcast details: %w", err))
				}

				mph, err := codec.MarshalProposedHeader(ph)
				if err != nil {
					panic(fmt.Errorf("marshal proposed header: %w", err))
				}

				return gdna.OriginationDetails{
					AppHeader:           mph,
					PreparedOrigination: po,
				}
			},

			GetBroadcastDetailsFunc: func(
				driverAnnotation []byte,
			) (gdbc.BroadcastDetails, error) {
				var bd gdbc.BroadcastDetails
				if err := json.Unmarshal(driverAnnotation, &bd); err != nil {
					return bd, fmt.Errorf("unmarshal broadcast details: %w", err)
				}

				return bd, nil
			},

			OnDataReadyFunc: func(
				ctx context.Context,
				height uint64,
				round uint32,
				dataID []byte,
				r io.Reader,
			) {
				data, err := io.ReadAll(r)
				if err != nil {
					log.Warn(
						"Reading block data failed",
						"h", height, "r", round, "err", err,
					)
					return
				}

				bds.PutData(dataID, data)
			},

			AcceptedStreamCh:    asCh,
			AcceptedUniStreamCh: ausCh,
			BlockDataArrivalCh:  bdaCh,

			Unmarshaler: codec,
		},
	)
	defer na.Wait()

	consensusStrategy := NewConsensusStrategy(
		log.With("sys", "consensusstrategy"),
		cfg.Peers[0].PubKey.Equal(cfg.PubKey),
	)

	initChainCh := make(chan tmdriver.InitChainRequest, 1)
	finalizeBlockCh := make(chan tmdriver.FinalizeBlockRequest, 1)

	var engine *tmengine.Engine
	eReady := make(chan struct{})
	go func() {
		defer close(eReady)
		e, err := tmengine.New(
			wCtx,
			log.With("sys", "engine"),

			tmengine.WithGenesis(&tmconsensus.ExternalGenesis{
				ChainID:             "dataless",
				InitialHeight:       1,
				InitialAppState:     new(bytes.Buffer),
				GenesisValidatorSet: valSet,
			}),

			tmengine.WithHashScheme(hashScheme),
			tmengine.WithSignatureScheme(sigScheme),
			tmengine.WithCommonMessageSignatureProofScheme(gcrypto.SimpleCommonMessageSignatureProofScheme{}),

			tmengine.WithSigner(tmconsensus.PassthroughSigner{
				Signer:          signer,
				SignatureScheme: sigScheme,
			}),

			tmengine.WithActionStore(tmmemstore.NewActionStore()),
			tmengine.WithCommittedHeaderStore(tmmemstore.NewCommittedHeaderStore()),
			tmengine.WithFinalizationStore(tmmemstore.NewFinalizationStore()),
			tmengine.WithMirrorStore(tmmemstore.NewMirrorStore()),
			tmengine.WithRoundStore(tmmemstore.NewRoundStore()),
			tmengine.WithStateMachineStore(tmmemstore.NewStateMachineStore()),
			tmengine.WithValidatorStore(tmmemstore.NewValidatorStore(hashScheme)),

			tmengine.WithConsensusStrategy(consensusStrategy),
			tmengine.WithGossipStrategy(na),

			tmengine.WithInitChainChannel(initChainCh),
			tmengine.WithBlockFinalizationChannel(finalizeBlockCh),
			tmengine.WithBlockDataArrivalChannel(bdaCh),

			tmengine.WithTimeoutStrategy(wCtx, tmengine.LinearTimeoutStrategy{}),

			tmengine.WithWatchdog(wd),
		)
		if err != nil {
			panic(fmt.Errorf("create engine: %w", err))
		}
		engine = e
	}()

	var currentVals []tmconsensus.Validator
	select {
	case <-wCtx.Done():
		return fmt.Errorf("interrupted while waiting to initialize chain: %w", err)
	case req := <-initChainCh:
		currentVals = req.Genesis.GenesisValidatorSet.Validators
		appStateHash := sha256.Sum256([]byte("initial"))
		req.Resp <- tmdriver.InitChainResponse{
			AppStateHash: appStateHash[:],
		}
	}

	select {
	case <-wCtx.Done():
		return fmt.Errorf("interrupted while building engine: %w", context.Cause(ctx))
	case <-eReady:
		if engine == nil {
			return errors.New("failed to build engine")
		}
	}

	// Everyone dial peer 0.
	if cfg.UDPConn.LocalAddr().String() != cfg.Peers[0].Addr {
		udpAddr, err := net.ResolveUDPAddr("udp", cfg.Peers[0].Addr)
		if err == nil {
			if err := dNode.DialAndJoin(wCtx, udpAddr); err != nil {
				log.Error("Failed to join first peer", "err", err)
			}
		} else {
			log.Error("Failed to dial first peer", "err", err)
		}
	}

	for {
		select {
		case <-wCtx.Done():
			return fmt.Errorf("interrupted: %w", context.Cause(wCtx))

		case req := <-finalizeBlockCh:
			log.Info(
				"Finalizing block",
				"height", req.Header.Height,
				"round", req.Round,
				"hash", fmt.Sprintf("%x", req.Header.Hash),
			)

			appStateHash := sha256.Sum256(req.Header.DataID)
			req.Resp <- tmdriver.FinalizeBlockResponse{
				Height:       req.Header.Height,
				Round:        req.Round,
				BlockHash:    req.Header.Hash,
				Validators:   currentVals,
				AppStateHash: appStateHash[:],
			}
		}
	}
}

type blockDataMap struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func (m *blockDataMap) PutData(id, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[string(id)] = data
}

func (m *blockDataMap) GetData(id []byte) ([]byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	d, ok := m.data[string(id)]
	return d, ok
}
