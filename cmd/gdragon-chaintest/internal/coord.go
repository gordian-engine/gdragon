package internal

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"sync"
)

type Validator struct {
	Ed25519PubKey ed25519.PublicKey
	ListenAddr    string
	CACert        *x509.Certificate
}

type RegisterRequest struct {
	Ed25519PubKey ed25519.PublicKey
	ListenAddr    string
	CACert        []byte
}

type Genesis struct {
	Validators []Validator
}

type Coordinator struct {
	log *slog.Logger

	wg sync.WaitGroup

	startOnce sync.Once
	startCh   chan struct{}
	started   bool

	mu   sync.Mutex
	vals []Validator
}

func NewCoordinator(log *slog.Logger) *Coordinator {
	return &Coordinator{
		log: log,

		startCh: make(chan struct{}),
	}
}

func (c *Coordinator) Wait() {
	c.wg.Wait()
}

func (c *Coordinator) addValidator(v Validator) {
	if len(v.Ed25519PubKey) != ed25519.PublicKeySize {
		panic(fmt.Errorf(
			"illegal key size (need %d, got %d)",
			ed25519.PublicKeySize, len(v.Ed25519PubKey),
		))
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, have := range c.vals {
		if v.Ed25519PubKey.Equal(have.Ed25519PubKey) {
			panic(fmt.Errorf("key %x registered twice", v.Ed25519PubKey))
		}

		if v.CACert.Equal(have.CACert) {
			panic(fmt.Errorf("CA certificate with public key %x registered twice", v.CACert.PublicKey))
		}
	}

	c.vals = append(c.vals, v)
}

func (c *Coordinator) getGenesis() Genesis {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Genesis{
		Validators: slices.Clone(c.vals),
	}
}

func (c *Coordinator) Serve(ctx context.Context, ln net.Listener) {
	c.wg.Add(2)

	go c.serve(ln)
	go c.closeOnCancel(ctx, ln)
}

func (c *Coordinator) serve(ln net.Listener) {
	defer c.wg.Done()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", c.handleRegister)
	mux.HandleFunc("POST /start", c.handleStart)
	mux.HandleFunc("GET /genesis", c.handleGenesis)

	srv := &http.Server{Handler: mux}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
		c.log.Warn("Serve error", "err", err)
	}
}

func (c *Coordinator) closeOnCancel(ctx context.Context, ln net.Listener) {
	defer c.wg.Done()

	<-ctx.Done()
	c.startOnce.Do(func() {
		close(c.startCh)
	})
	if err := ln.Close(); err != nil {
		c.log.Warn("Error closing listener", "err", err)
	}
}

func (c *Coordinator) handleRegister(w http.ResponseWriter, r *http.Request) {
	select {
	case <-c.startCh:
		http.Error(w, "cannot register after service started", http.StatusConflict)
		return
	default:
		// Okay.
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	caCert, err := x509.ParseCertificate(req.CACert)
	if err != nil {
		http.Error(w, "parse CA cert failed: "+err.Error(), http.StatusBadRequest)
	}

	c.addValidator(Validator{
		Ed25519PubKey: req.Ed25519PubKey,
		ListenAddr:    req.ListenAddr,
		CACert:        caCert,
	})

	w.WriteHeader(http.StatusNoContent)

	c.log.Info(
		"Received registration",
		"pubkey", fmt.Sprintf("%x", req.Ed25519PubKey),
		"addr", req.ListenAddr,
	)
}

func (c *Coordinator) handleStart(w http.ResponseWriter, r *http.Request) {
	c.startOnce.Do(func() {
		c.started = true
		close(c.startCh)
	})

	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) handleGenesis(w http.ResponseWriter, r *http.Request) {
	select {
	case <-c.startCh:
		// Ready.
	case <-r.Context().Done():
		// Client disconnect.
		return
	}

	if !c.started {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	g := c.getGenesis()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(g); err != nil {
		c.log.Warn("Encoding genesis", "err", err)
	}
}
