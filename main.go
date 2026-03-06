package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sethvargo/go-limiter/memorystore"

	"github.com/refringe/anchor-lfs/auth"
	"github.com/refringe/anchor-lfs/config"
	"github.com/refringe/anchor-lfs/lfs"
	"github.com/refringe/anchor-lfs/middleware"
	"github.com/refringe/anchor-lfs/storage"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	// Default: JSON to stderr.
	log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()

	cfg, err := config.Load(config.DefaultConfigPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load configuration")
	}

	if cfg.Options.AdditionalLogging {
		log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
			With().Timestamp().Logger()
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	log.Info().
		Str("version", version).
		Str("commit", commit).
		Str("built", date).
		Msg("starting anchor-lfs")

	var store storage.Adapter
	switch cfg.Storage.Backend {
	case config.StorageS3:
		s3Store, err := storage.NewS3(context.Background(), storage.S3Config{
			Bucket:          cfg.Storage.S3Bucket,
			Region:          cfg.Storage.S3Region,
			Endpoint:        cfg.Storage.S3Endpoint,
			AccessKeyID:     cfg.Storage.S3AccessKeyID,
			SecretAccessKey: cfg.Storage.S3SecretAccessKey,
			Prefix:          cfg.Storage.S3Prefix,
			PresignedURLs:   cfg.Storage.S3PresignedURLsEnabled(),
			ForcePathStyle:  cfg.Storage.S3ForcePathStyleEnabled(),
		})
		if err != nil {
			log.Fatal().Err(err).Msg("creating S3 storage adapter")
		}
		store = s3Store
		log.Info().
			Str("bucket", cfg.Storage.S3Bucket).
			Str("region", cfg.Storage.S3Region).
			Bool("presigned_urls", cfg.Storage.S3PresignedURLsEnabled()).
			Msg("using S3 storage backend")
	default:
		store = storage.NewLocal(cfg.Options.DataDirectory)
		log.Info().Str("path", cfg.Options.DataDirectory).Msg("using local storage backend")
	}
	lockStore := lfs.NewFileLockStore(cfg.Options.DataDirectory)

	rateLimitStore, err := memorystore.New(&memorystore.Config{
		Tokens:   cfg.Options.RateLimitTokens,
		Interval: cfg.Options.RateLimitInterval,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("creating rate limiter")
	}

	// Shared HTTP client for GitHub API calls (connection pooling).
	githubHTTPClient := &http.Client{Timeout: 10 * time.Second}

	mux := http.NewServeMux()

	if cfg.Options.BaseURL == "" {
		log.Warn().Msg("base_url is not set; action URLs will be derived from request headers — ensure a trusted reverse proxy sets X-Forwarded-Proto and X-Forwarded-Host, or set base_url in config")
	}

	signingKey := cfg.Options.SigningKeyBytes
	if len(signingKey) == 0 {
		var err error
		signingKey, err = loadOrGenerateSigningKey(cfg.Options.DataDirectory)
		if err != nil {
			log.Fatal().Err(err).Msg("setting up signing key")
		}
	}
	signer, err := lfs.NewURLSigner(signingKey, cfg.Options.URLExpiryDuration)
	if err != nil {
		clear(signingKey)
		log.Fatal().Err(err).Msg("creating URL signer")
	}

	// GitHub authenticators keyed by API base URL string. Endpoints pointing at the same GitHub instance share a single
	// authenticator for cache efficiency. The None authenticator is stateless, so sharing is free.
	githubAuths := make(map[string]*auth.GitHub)
	githubAuth := func(ep *config.Endpoint) *auth.GitHub {
		key := ""
		if ep.GitHubBaseURL != nil {
			key = ep.GitHubBaseURL.String()
		}
		if g, ok := githubAuths[key]; ok {
			return g
		}
		g := auth.NewGitHub(githubHTTPClient, cfg.Options.AuthCacheDuration, ep.GitHubBaseURL)
		githubAuths[key] = g
		return g
	}
	noneAuth := &auth.None{}

	for i := range cfg.Endpoints {
		ep := &cfg.Endpoints[i]
		var authenticator auth.Authenticator
		switch ep.AuthMethod() {
		case "github":
			authenticator = githubAuth(ep)
		default:
			authenticator = noneAuth
		}
		handler := lfs.NewHandler(lfs.HandlerConfig{
			Endpoint:      ep,
			Store:         store,
			Auth:          authenticator,
			BaseURL:       cfg.Options.BaseURL,
			MaxUploadSize: cfg.Options.MaxUploadSize,
			Signer:        signer,
			LockStore:     lockStore,
		})

		prefix := ep.Path

		// Batch API — rate limited.
		mux.Handle(fmt.Sprintf("POST %s/objects/batch", prefix), middleware.RateLimit(rateLimitStore, http.HandlerFunc(handler.BatchHandler)))

		// Download — rate limited.
		mux.Handle(fmt.Sprintf("GET %s/objects/{oid}", prefix), middleware.RateLimit(rateLimitStore, http.HandlerFunc(handler.DownloadHandler)))

		// Upload — not rate limited; uploads are authenticated and size-bounded,
		// and rate limiting could interfere with legitimate large transfers.
		mux.Handle(fmt.Sprintf("PUT %s/objects/{oid}", prefix), http.HandlerFunc(handler.UploadHandler))

		// Verify — rate limited.
		mux.Handle(fmt.Sprintf("POST %s/objects/verify", prefix), middleware.RateLimit(rateLimitStore, http.HandlerFunc(handler.VerifyHandler)))

		// File Locking API — rate limited.
		mux.Handle(fmt.Sprintf("POST %s/locks", prefix), middleware.RateLimit(rateLimitStore, http.HandlerFunc(handler.CreateLockHandler)))
		mux.Handle(fmt.Sprintf("GET %s/locks", prefix), middleware.RateLimit(rateLimitStore, http.HandlerFunc(handler.ListLocksHandler)))
		mux.Handle(fmt.Sprintf("POST %s/locks/verify", prefix), middleware.RateLimit(rateLimitStore, http.HandlerFunc(handler.VerifyLocksHandler)))
		mux.Handle(fmt.Sprintf("POST %s/locks/{id}/unlock", prefix), middleware.RateLimit(rateLimitStore, http.HandlerFunc(handler.UnlockHandler)))

		log.Info().
			Str("name", ep.Name).
			Str("path", prefix).
			Str("auth", ep.Authentication).
			Str("visibility", ep.Visibility).
			Msg("registered endpoint")
	}

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"version": version,
		})
	})

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"version": version})
	})

	var handler http.Handler = mux
	if cfg.Options.AdditionalLogging {
		handler = middleware.Logging(handler)
	}

	server := &http.Server{
		Addr:    cfg.Options.ListenAddress,
		Handler: handler,

		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,

		// WriteTimeout and ReadTimeout are intentionally omitted. LFS
		// transfers can be very large; a fixed timeout would kill legitimate
		// long-running uploads and downloads. ReadHeaderTimeout above
		// protects against slowloris-style attacks on the header phase.
	}

	// Graceful shutdown.
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Info().Str("address", cfg.Options.ListenAddress).Msg("listening")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("server error")
		}
	}()

	<-done
	log.Info().Msg("shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("shutdown error")
	}

	// Close authenticator background goroutines (e.g., cache sweeper).
	for _, g := range githubAuths {
		_ = g.Close()
	}

	// Zero signing key material in memory.
	_ = signer.Close()
}

// signingKeyFile is the name of the auto-generated signing key file within the data directory.
const signingKeyFile = "signing.key"

// loadOrGenerateSigningKey loads a signing key from <dataDir>/signing.key. If
// the file does not exist, a new 32-byte random key is generated, written to
// disk (hex-encoded), and returned. This ensures signed URLs survive server
// restarts without requiring manual configuration.
func loadOrGenerateSigningKey(dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, signingKeyFile)

	data, err := os.ReadFile(path) //nolint:gosec // path is constructed from operator-controlled data directory + constant filename
	if err == nil {
		key, decErr := hex.DecodeString(strings.TrimSpace(string(data)))
		if decErr != nil {
			return nil, fmt.Errorf("signing key file %q contains invalid hex: %w", path, decErr)
		}
		if len(key) < 32 {
			return nil, fmt.Errorf("signing key file %q contains only %d bytes (minimum 32)", path, len(key))
		}
		log.Info().Str("path", path).Msg("loaded signing key from disk")
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading signing key file: %w", err)
	}

	// Generate a new key.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating signing key: %w", err)
	}

	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("creating data directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("writing signing key file: %w", err)
	}

	log.Info().Str("path", path).Msg("generated and saved new signing key")
	return key, nil
}
