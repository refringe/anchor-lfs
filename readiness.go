package main

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/refringe/anchor-lfs/config"
	"github.com/refringe/anchor-lfs/middleware"
	"github.com/refringe/anchor-lfs/storage"
)

// Time limits for the storage check at startup, the checks behind GET /ready, and the healthcheck subcommand.
const (
	storageCheckTimeout   = 30 * time.Second
	readinessCheckTimeout = 5 * time.Second
	healthcheckTimeout    = 10 * time.Second
)

// readinessCacheTTL is how long GET /ready reuses a result before running the checks again.
const readinessCacheTTL = 5 * time.Second

// statusResponse is the JSON body of GET /health and GET /ready.
type statusResponse struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
	Failed  string `json:"failed,omitempty"`
}

// readiness answers GET /ready by checking the data directory and the storage backend.
type readiness struct {
	store   storage.Adapter
	dataDir string
	ttl     time.Duration

	mu        sync.Mutex
	checkedAt time.Time
	failed    string
}

// newReadiness creates the GET /ready handler for store and the data directory.
func newReadiness(store storage.Adapter, dataDir string) *readiness {
	return &readiness{store: store, dataDir: dataDir, ttl: readinessCacheTTL}
}

// ServeHTTP answers 200 when every check passes, or 503 naming the check that failed.
func (rd *readiness) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if failed := rd.check(r.Context()); failed != "" {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.MarshalWrite(w, statusResponse{Status: "not ready", Failed: failed})
		return
	}
	_ = json.MarshalWrite(w, statusResponse{Status: "ready"})
}

// check returns the name of the failed check, or "" when all pass, reusing the last result until it expires.
func (rd *readiness) check(ctx context.Context) string {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	if !rd.checkedAt.IsZero() && time.Since(rd.checkedAt) < rd.ttl {
		return rd.failed
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), readinessCheckTimeout)
	defer cancel()
	rd.failed = ""
	if err := storage.CheckWritableDir(rd.dataDir); err != nil {
		middleware.Logger(ctx).Warn().Err(err).Msg("readiness check failed: data directory")
		rd.failed = "data_directory"
	} else if err := rd.store.Check(ctx); err != nil {
		middleware.Logger(ctx).Warn().Err(err).Msg("readiness check failed: storage")
		rd.failed = "storage"
	}
	rd.checkedAt = time.Now()
	return rd.failed
}

// runHealthcheck asks the local server's GET /ready whether it is ready and returns the process exit code.
func runHealthcheck() int {
	cfg, err := config.Load(config.DefaultConfigPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	url, err := readyURL(cfg.Options.ListenAddress)
	if err == nil {
		err = checkReady(url)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	fmt.Println("ready")
	return 0
}

// readyURL returns the loopback URL of GET /ready for a server listening on listenAddress.
func readyURL(listenAddress string) (string, error) {
	host, port, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return "", fmt.Errorf("parsing listen_address %q: %w", listenAddress, err)
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/ready", nil
}

// checkReady requests url and returns an error unless the server answers 200.
func checkReady(url string) error {
	ctx, cancel := context.WithTimeout(context.Background(), healthcheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("server not reachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s answered %d: %s", url, resp.StatusCode, bytes.TrimSpace(body))
	}
	return nil
}
