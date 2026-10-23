package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
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
	os.Exit(runCommand(os.Args[1:], os.Stdout, os.Stderr))
}

// serve runs the server with the configuration at configPath until SIGINT or SIGTERM and returns the exit code.
func serve(configPath string) int {
	// Default: JSON to stderr.
	log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()

	cfg, err := config.Load(configPath)
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
		Str("config", absolutePath(configPath)).
		Msg("starting anchor-lfs")
	log.Info().
		Str("listen_address", cfg.Options.ListenAddress).
		Int64("max_upload_size", cfg.Options.MaxUploadSize).
		Uint64("rate_limit_tokens", cfg.Options.RateLimitTokens).
		Str("rate_limit_window", cfg.Options.RateLimitWindow).
		Str("url_expiry", cfg.Options.URLExpiry).
		Str("auth_cache_ttl", cfg.Options.AuthCacheTTL).
		Str("upload_idle_timeout", cfg.Options.UploadIdleTimeout).
		Str("shutdown_timeout", cfg.Options.ShutdownTimeout).
		Msg("settings")

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
			MaxUploadSize:   cfg.Options.MaxUploadSize,
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
	checkCtx, cancelCheck := context.WithTimeout(context.Background(), storageCheckTimeout)
	err = store.Check(checkCtx)
	cancelCheck()
	if err != nil {
		log.Fatal().Err(err).Msg("checking storage")
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

	// Shared HTTP client for GitHub API calls, keeping up to 32 idle connections per host.
	githubTransport := http.DefaultTransport.(*http.Transport).Clone()
	githubTransport.MaxIdleConnsPerHost = 32
	githubHTTPClient := &http.Client{Timeout: 10 * time.Second, Transport: githubTransport}

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

			UploadIdleTimeout: cfg.Options.UploadIdleTimeoutDuration,
		})

		prefix := ep.Path
		registerRoutes(mux, prefix, handler, rateLimitStore)
		if ep.AuthMethod() == "none" {
			log.Warn().Str("name", ep.Name).Str("path", prefix).Msg("endpoint has no authentication; anyone can read, write and release any lock")
		}
		if ep.UnexpectedGitHubAPIHost() {
			log.Warn().Str("name", ep.Name).Str("path", prefix).Str("github_api_url", ep.GitHubBaseURL.String()).
				Msg("github_api_url is not api.github.com for a github.com repository; every client token for this endpoint is sent to it")
		}

		log.Info().
			Str("name", ep.Name).
			Str("path", prefix).
			Str("directory", sanitise.Endpoint(prefix)).
			Str("auth", ep.Authentication).
			Str("visibility", ep.Visibility).
			Msg("registered endpoint")
	}

	registerServiceRoutes(mux, newReadiness(store, cfg.Options.DataDirectory))

	server := &http.Server{
		Handler: serverHandler(mux, proxyTrust, cfg.Options.AccessLogEnabled()),

		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,

		// WriteTimeout and ReadTimeout are intentionally omitted. LFS
		// transfers can be very large; a fixed timeout would kill legitimate
		// long-running uploads and downloads. ReadHeaderTimeout above
		// protects against slowloris-style attacks on the header phase.
	}

	signalled, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(context.Background(), "tcp", cfg.Options.ListenAddress)
	if err != nil {
		log.Fatal().Err(err).Str("address", cfg.Options.ListenAddress).Msg("listening")
	}
	log.Info().Str("address", listener.Addr().String()).Msg("listening")

	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()

	sweepCtx, stopSweep := context.WithCancel(context.Background())
	go sweepTempFiles(sweepCtx, cfg.Options.DataDirectory)

	exitCode := 0
	select {
	case <-signalled.Done():
		stopSignals() // A second SIGINT or SIGTERM now ends the process at once.
		log.Info().Str("timeout", cfg.Options.ShutdownTimeout).Msg("shutting down; send the signal again to stop immediately")
	case err := <-served:
		log.Error().Err(err).Msg("server error")
		exitCode = 1
	}
	stopSweep()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Options.ShutdownTimeoutDuration)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("closing connections still open after shutdown_timeout")
		_ = server.Close()
		exitCode = 1
	}

	_ = rateLimitStore.Close(ctx)

	// Close authenticator background goroutines (e.g., cache sweeper).
	for _, g := range githubAuths {
		_ = g.Close()
	}

	// Zero signing key material in memory.
	_ = signer.Close()
	return exitCode
}

// serverHandler wraps mux with proxy trust, request IDs and, when accessLog is set, the access log.
func serverHandler(mux http.Handler, proxyTrust *middleware.ProxyTrust, accessLog bool) http.Handler {
	handler := mux
	if accessLog {
		handler = middleware.Logging(handler, "/health", "/ready")
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

// absolutePath returns path made absolute, or path itself when the working directory is unknown.
func absolutePath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// isTerminal reports whether f is a character device such as a terminal.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// registerServiceRoutes adds the health and readiness checks, the version at the root, and a JSON 404 for any other path.
func registerServiceRoutes(mux *http.ServeMux, ready http.Handler) {
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, statusResponse{Status: "ok", Version: version})
	})
	mux.Handle("GET /ready", ready)
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
	if err := storage.CheckWritableDir(dir); err != nil {
		return fmt.Errorf("data directory %w", err)
	}
	return nil
}

// Temporary files unmodified for tempFileMaxAge are removed at startup and then every tempSweepInterval.
const (
	tempFileMaxAge    = time.Hour
	tempSweepInterval = time.Hour
)

// sweepTempFiles removes stale temporary files from dataDir now and then every tempSweepInterval until ctx ends.
func sweepTempFiles(ctx context.Context, dataDir string) {
	ticker := time.NewTicker(tempSweepInterval)
	defer ticker.Stop()
	for {
		removed, err := storage.RemoveStaleTempFiles(dataDir, tempFileMaxAge)
		if err != nil {
			log.Warn().Err(err).Int("removed", removed).Msg("sweeping temporary files")
		} else if removed > 0 {
			log.Info().Int("removed", removed).Msg("removed stale temporary files")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
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
