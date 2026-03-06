// Package config handles TOML configuration parsing, environment variable overrides, and validation for Anchor LFS.
package config

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/refringe/anchor-lfs/internal/sanitise"
)

// DefaultConfigPath is the file path used when no override is provided.
const DefaultConfigPath = "config.toml"

// authGitHub is the normalised name for GitHub-based authentication.
const authGitHub = "github"

// Storage backend names.
const (
	StorageLocal = "local"
	StorageS3    = "s3"
)

// Config is the top-level configuration structure.
type Config struct {
	Options   Options    `toml:"options"`
	Storage   Storage    `toml:"storage"`
	Endpoints []Endpoint `toml:"endpoints"`
}

// Storage configures the object storage backend.
type Storage struct {
	Backend           string `toml:"backend"`
	S3Bucket          string `toml:"s3_bucket"`
	S3Region          string `toml:"s3_region"`
	S3Endpoint        string `toml:"s3_endpoint"`
	S3AccessKeyID     string `toml:"s3_access_key_id"`
	S3SecretAccessKey string `toml:"s3_secret_access_key"`
	S3Prefix          string `toml:"s3_prefix"`
	S3PresignedURLs   *bool  `toml:"s3_presigned_urls"`
	S3ForcePathStyle  *bool  `toml:"s3_force_path_style"`
}

// S3PresignedURLsEnabled returns whether presigned URLs are enabled, defaulting to true when unset.
func (s *Storage) S3PresignedURLsEnabled() bool {
	if s.S3PresignedURLs == nil {
		return true
	}
	return *s.S3PresignedURLs
}

// S3ForcePathStyleEnabled returns whether path-style addressing is enabled, defaulting to false when unset.
func (s *Storage) S3ForcePathStyleEnabled() bool {
	if s.S3ForcePathStyle == nil {
		return false
	}
	return *s.S3ForcePathStyle
}

// Options holds global server settings.
type Options struct {
	ListenAddress     string `toml:"listen_address"`
	DataDirectory     string `toml:"data_directory"`
	AdditionalLogging bool   `toml:"additional_logging"`
	BaseURL           string `toml:"base_url"`
	MaxUploadSize     int64  `toml:"max_upload_size"`

	// Rate limiting.
	RateLimitTokens   uint64        `toml:"rate_limit_tokens"`
	RateLimitInterval time.Duration `toml:"-"`
	RateLimitWindow   string        `toml:"rate_limit_window"`

	// Auth cache.
	AuthCacheTTL      string        `toml:"auth_cache_ttl"`
	AuthCacheDuration time.Duration `toml:"-"`

	// URL signing.
	SigningKey        string        `toml:"signing_key"`
	SigningKeyBytes   []byte        `toml:"-"`
	URLExpiry         string        `toml:"url_expiry"`
	URLExpiryDuration time.Duration `toml:"-"`
}

// Endpoint configures a single repository whose LFS objects will be served.
type Endpoint struct {
	Name           string `toml:"name"`
	URL            string `toml:"url"`
	Path           string `toml:"endpoint"` // "endpoint" in TOML for user clarity; "Path" in Go to avoid stuttering with the type name.
	Visibility     string `toml:"visibility"`
	Authentication string `toml:"authentication"`
	GitHubAPIURL   string `toml:"github_api_url"`

	// Parsed from URL at load time.
	GitHubOwner   string   `toml:"-"`
	GitHubRepo    string   `toml:"-"`
	GitHubBaseURL *url.URL `toml:"-"`
}

// IsPublic reports whether the endpoint is publicly readable.
func (e *Endpoint) IsPublic() bool {
	return strings.EqualFold(e.Visibility, "public")
}

// AuthMethod returns the normalised authentication method name.
func (e *Endpoint) AuthMethod() string {
	return strings.ToLower(e.Authentication)
}

// Load reads and validates the configuration file. The path can be overridden
// by the ANCHOR_LFS_CONFIG environment variable.
func Load(path string) (*Config, error) {
	if env := os.Getenv("ANCHOR_LFS_CONFIG"); env != "" {
		path = env
	}

	data, err := os.ReadFile(path) //nolint:gosec // path is operator-controlled (config file or ANCHOR_LFS_CONFIG env var)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	cfg.applyDefaults()
	cfg.applyEnvOverrides()

	if err := cfg.parseRateLimitWindow(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	if err := cfg.parseAuthCacheTTL(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	if err := cfg.parseURLExpiry(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	if err := cfg.parseSigningKey(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	for i := range cfg.Endpoints {
		if err := cfg.Endpoints[i].parseGitHubURL(); err != nil {
			return nil, fmt.Errorf("endpoint %q: %w", cfg.Endpoints[i].Name, err)
		}
	}

	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Options.ListenAddress == "" {
		c.Options.ListenAddress = ":5420"
	}
	if c.Options.DataDirectory == "" {
		c.Options.DataDirectory = "./data"
	}
	if c.Options.BaseURL != "" {
		c.Options.BaseURL = strings.TrimRight(c.Options.BaseURL, "/")
	}
	if c.Options.MaxUploadSize <= 0 {
		c.Options.MaxUploadSize = 5 << 30 // 5 GiB
	}
	if c.Options.RateLimitTokens == 0 {
		c.Options.RateLimitTokens = 10000
	}
	if c.Options.RateLimitWindow == "" {
		c.Options.RateLimitWindow = "24h"
	}
	if c.Options.AuthCacheTTL == "" {
		c.Options.AuthCacheTTL = "60s"
	}
	if c.Options.URLExpiry == "" {
		c.Options.URLExpiry = "10m"
	}
	if c.Storage.Backend == "" {
		c.Storage.Backend = StorageLocal
	}
	if c.Storage.S3Prefix == "" {
		c.Storage.S3Prefix = "lfs/"
	}
}

func (c *Config) applyEnvOverrides() {
	if v := os.Getenv("ANCHOR_LFS_LISTEN"); v != "" {
		c.Options.ListenAddress = v
	}
	if v := os.Getenv("ANCHOR_LFS_DATA_DIR"); v != "" {
		c.Options.DataDirectory = v
	}
	if v := os.Getenv("ANCHOR_LFS_BASE_URL"); v != "" {
		c.Options.BaseURL = strings.TrimRight(v, "/")
	}
	if v := os.Getenv("ANCHOR_LFS_SIGNING_KEY"); v != "" {
		c.Options.SigningKey = v
	}
	if v := os.Getenv("ANCHOR_LFS_MAX_UPLOAD_SIZE"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			c.Options.MaxUploadSize = n
		}
	}

	// Storage overrides.
	if v := os.Getenv("ANCHOR_LFS_STORAGE_BACKEND"); v != "" {
		c.Storage.Backend = v
	}
	if v := os.Getenv("ANCHOR_LFS_S3_BUCKET"); v != "" {
		c.Storage.S3Bucket = v
	}
	if v := os.Getenv("ANCHOR_LFS_S3_REGION"); v != "" {
		c.Storage.S3Region = v
	}
	if v := os.Getenv("ANCHOR_LFS_S3_ENDPOINT"); v != "" {
		c.Storage.S3Endpoint = v
	}
	if v := os.Getenv("ANCHOR_LFS_S3_ACCESS_KEY_ID"); v != "" {
		c.Storage.S3AccessKeyID = v
	}
	if v := os.Getenv("ANCHOR_LFS_S3_SECRET_ACCESS_KEY"); v != "" {
		c.Storage.S3SecretAccessKey = v
	}
	if v := os.Getenv("ANCHOR_LFS_S3_PREFIX"); v != "" {
		c.Storage.S3Prefix = v
	}
	if v := os.Getenv("ANCHOR_LFS_S3_PRESIGNED_URLS"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.Storage.S3PresignedURLs = &b
		}
	}
	if v := os.Getenv("ANCHOR_LFS_S3_FORCE_PATH_STYLE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.Storage.S3ForcePathStyle = &b
		}
	}
}

func (c *Config) parseRateLimitWindow() error {
	d, err := time.ParseDuration(c.Options.RateLimitWindow)
	if err != nil {
		return fmt.Errorf("invalid rate_limit_window %q: %w", c.Options.RateLimitWindow, err)
	}
	if d <= 0 {
		return fmt.Errorf("rate_limit_window must be positive")
	}
	c.Options.RateLimitInterval = d
	return nil
}

func (c *Config) parseAuthCacheTTL() error {
	d, err := time.ParseDuration(c.Options.AuthCacheTTL)
	if err != nil {
		return fmt.Errorf("invalid auth_cache_ttl %q: %w", c.Options.AuthCacheTTL, err)
	}
	if d < 0 {
		return fmt.Errorf("auth_cache_ttl must not be negative")
	}
	c.Options.AuthCacheDuration = d
	return nil
}

func (c *Config) parseURLExpiry() error {
	d, err := time.ParseDuration(c.Options.URLExpiry)
	if err != nil {
		return fmt.Errorf("invalid url_expiry %q: %w", c.Options.URLExpiry, err)
	}
	if d <= 0 {
		return fmt.Errorf("url_expiry must be positive")
	}
	c.Options.URLExpiryDuration = d
	return nil
}

func (c *Config) parseSigningKey() error {
	if c.Options.SigningKey == "" {
		return nil // Will be generated at runtime.
	}
	b, err := hex.DecodeString(c.Options.SigningKey)
	if err != nil {
		return fmt.Errorf("invalid signing_key (must be hex-encoded): %w", err)
	}
	if len(b) < 32 {
		return fmt.Errorf("signing_key must be at least 32 bytes (64 hex characters)")
	}
	c.Options.SigningKeyBytes = b
	return nil
}

func (c *Config) validateStorage() error {
	backend := strings.ToLower(c.Storage.Backend)
	c.Storage.Backend = backend

	switch backend {
	case StorageLocal, "":
		return nil
	case StorageS3:
		if c.Storage.S3Bucket == "" {
			return fmt.Errorf("storage backend %q requires s3_bucket", backend)
		}
		if c.Storage.S3Region == "" {
			return fmt.Errorf("storage backend %q requires s3_region", backend)
		}
		if c.Storage.S3Endpoint != "" {
			u, err := url.Parse(c.Storage.S3Endpoint)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return fmt.Errorf("s3_endpoint %q is not a valid URL", c.Storage.S3Endpoint)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown storage backend %q (must be %q or %q)", backend, StorageLocal, StorageS3)
	}
}

func (c *Config) validate() error {
	if err := c.validateStorage(); err != nil {
		return err
	}
	if c.Options.BaseURL != "" {
		u, err := url.Parse(c.Options.BaseURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("base_url %q is not a valid URL", c.Options.BaseURL)
		}
	}
	if len(c.Endpoints) == 0 {
		return fmt.Errorf("no endpoints configured")
	}

	reservedPaths := map[string]struct{}{
		"health": {},
	}
	paths := make(map[string]struct{}, len(c.Endpoints))
	for _, ep := range c.Endpoints {
		if ep.Name == "" {
			return fmt.Errorf("endpoint missing name")
		}
		if ep.Path == "" {
			return fmt.Errorf("endpoint %q: missing endpoint path", ep.Name)
		}
		if _, exists := paths[ep.Path]; exists {
			return fmt.Errorf("endpoint %q: duplicate endpoint path %q", ep.Name, ep.Path)
		}
		paths[ep.Path] = struct{}{}
		if _, reserved := reservedPaths[strings.TrimLeft(ep.Path, "/")]; reserved {
			return fmt.Errorf("endpoint %q: path %q is reserved", ep.Name, ep.Path)
		}
		if sanitise.Endpoint(ep.Path) == sanitise.InvalidEndpoint {
			return fmt.Errorf("endpoint %q: path %q contains characters that are unsafe for storage directories", ep.Name, ep.Path)
		}
		auth := strings.ToLower(ep.Authentication)
		if auth != authGitHub && auth != "none" {
			return fmt.Errorf("endpoint %q: unknown authentication %q", ep.Name, ep.Authentication)
		}
		if ep.GitHubAPIURL != "" && auth != authGitHub {
			return fmt.Errorf("endpoint %q: github_api_url is set but authentication is %q (must be \"github\")", ep.Name, auth)
		}
		vis := strings.ToLower(ep.Visibility)
		if vis != "public" && vis != "private" {
			return fmt.Errorf("endpoint %q: unknown visibility %q", ep.Name, ep.Visibility)
		}
	}
	return nil
}

func (e *Endpoint) parseGitHubURL() error {
	if e.AuthMethod() != authGitHub {
		return nil
	}
	if e.URL == "" {
		return fmt.Errorf("github authentication requires a repository URL")
	}
	u, err := url.Parse(e.URL)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", e.URL, err)
	}
	if !strings.EqualFold(u.Host, "github.com") && e.GitHubAPIURL == "" {
		return fmt.Errorf("URL %q is not a github.com URL; set github_api_url for GitHub Enterprise", e.URL)
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segments) != 2 || segments[0] == "" || segments[1] == "" {
		return fmt.Errorf("URL %q must contain exactly org/repo", e.URL)
	}
	e.GitHubOwner = segments[0]
	e.GitHubRepo = segments[1]

	if e.GitHubAPIURL != "" {
		apiURL, err := url.Parse(e.GitHubAPIURL)
		if err != nil || apiURL.Scheme == "" || apiURL.Host == "" {
			return fmt.Errorf("github_api_url %q is not a valid URL", e.GitHubAPIURL)
		}
		if !strings.HasSuffix(apiURL.Path, "/") {
			apiURL.Path += "/"
		}
		e.GitHubBaseURL = apiURL
	}

	return nil
}
