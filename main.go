package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
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
	"github.com/sethvargo/go-limiter"
	"github.com/sethvargo/go-limiter/memorystore"

	"github.com/refringe/anchor-lfs/auth"
	"github.com/refringe/anchor-lfs/config"
	"github.com/refringe/anchor-lfs/internal/sanitise"
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
	if invalid, ok := errors.AsType[*config.ValidationError](err); ok {
		log.Fatal().Errs("errors", invalid.Problems).Msg("failed to load configuration")
	}
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load configuration")
	}

	configureLogging(&cfg.Options)

	log.Info().
		Str("version", version).
		Str("commit", commit).
		Str("built", date).
		Msg("starting anchor-lfs")

	if err := ensureWritableDir(cfg.Options.DataDirectory); err != nil {
		log.Fatal().Err(err).Int("uid", os.Getuid()).Int("gid", os.Getgid()).Msg("checking data directory")
	}

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
		Tokens:        cfg.Options.RateLimitTokens,
		Interval:      cfg.Options.RateLimitInterval,
		SweepInterval: cfg.Options.RateLimitInterval,
		SweepMinTTL:   cfg.Options.RateLimitInterval,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("creating rate limiter")
	}

	proxyTrust, err := middleware.NewProxyTrust(cfg.Options.TrustedProxies)
	if err != nil {
		log.Fatal().Err(err).Msg("creating proxy trust")
	}
	log.Info().Strs("trusted_proxies", cfg.Options.TrustedProxies).Msg("trusting X-Forwarded-* headers from these peers")

	// Shared HTTP client for GitHub API calls (connection pooling).
	githubHTTPClient := &http.Client{Timeout: 10 * time.Second}

	mux := http.NewServeMux()

	if cfg.Options.BaseURL == "" {
		log.Warn().Msg("base_url is not set; action URLs will be derived from the Host header, or X-Forwarded-Host and X-Forwarded-Proto from trusted_proxies peers; set base_url in config")
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
		registerRoutes(mux, prefix, handler, rateLimitStore)
		if ep.AuthMethod() == "none" {
			log.Warn().Str("name", ep.Name).Str("path", prefix).Msg("endpoint has no authentication; anyone can read, write and release any lock")
		}

		log.Info().
			Str("name", ep.Name).
			Str("path", prefix).
			Str("directory", sanitise.Endpoint(prefix)).
			Str("auth", ep.Authentication).
			Str("visibility", ep.Visibility).
			Msg("registered endpoint")
	}

	registerServiceRoutes(mux)

	server := &http.Server{
		Addr:    cfg.Options.ListenAddress,
		Handler: serverHandler(mux, proxyTrust, cfg.Options.AccessLogEnabled()),

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

// serverHandler wraps mux with proxy trust, request IDs and, when accessLog is set, the access log.
func serverHandler(mux http.Handler, proxyTrust *middleware.ProxyTrust, accessLog bool) http.Handler {
	handler := mux
	if accessLog {
		handler = middleware.Logging(handler, "/health")
	}
	return proxyTrust.Handler(middleware.RequestID(handler))
}

// configureLogging applies the configured log format and level to the global logger.
func configureLogging(opts *config.Options) {
	if opts.LogFormat == config.LogFormatConsole {
		log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: !isTerminal(os.Stderr)}).
			With().Timestamp().Logger()
	}
	if level, err := zerolog.ParseLevel(opts.LogLevel); err == nil {
		zerolog.SetGlobalLevel(level)
	}
	if opts.AdditionalLogging {
		log.Warn().Msg(`additional_logging is deprecated; set log_format = "console" and log_level = "debug" instead`)
	}
}

// isTerminal reports whether f is a character device such as a terminal.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// registerServiceRoutes adds the health check, the version at the root, and a JSON 404 for every other path to mux.
func registerServiceRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, map[string]string{
			"status":  "ok",
			"version": version,
		})
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, map[string]string{"version": version})
	})
	mux.HandleFunc("/", lfs.NotFoundHandler)
}

// registerRoutes adds an endpoint's routes to mux, rate limiting the batch and lock routes but not signed transfers.
func registerRoutes(mux *http.ServeMux, prefix string, handler *lfs.Handler, rateLimitStore limiter.Store) {
	limited := func(h http.HandlerFunc) http.Handler { return middleware.RateLimit(rateLimitStore, h) }

	mux.Handle(fmt.Sprintf("POST %s/objects/batch", prefix), limited(handler.BatchHandler))
	mux.Handle(fmt.Sprintf("POST %s/locks", prefix), limited(handler.CreateLockHandler))
	mux.Handle(fmt.Sprintf("GET %s/locks", prefix), limited(handler.ListLocksHandler))
	mux.Handle(fmt.Sprintf("POST %s/locks/verify", prefix), limited(handler.VerifyLocksHandler))
	mux.Handle(fmt.Sprintf("POST %s/locks/{id}/unlock", prefix), limited(handler.UnlockHandler))

	mux.HandleFunc(fmt.Sprintf("GET %s/objects/{oid}", prefix), handler.DownloadHandler)
	mux.HandleFunc(fmt.Sprintf("PUT %s/objects/{oid}", prefix), handler.UploadHandler)
	mux.HandleFunc(fmt.Sprintf("POST %s/objects/verify", prefix), handler.VerifyHandler)
}

// ensureWritableDir creates dir if it is missing and confirms the current process can create files in it.
func ensureWritableDir(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating data directory %q: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".write-check-*")
	if err != nil {
		return fmt.Errorf("data directory %q is not writable: %w", dir, err)
	}
	name := f.Name()
	_ = f.Close()
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("removing write check file: %w", err)
	}
	return nil
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
