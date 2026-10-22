// Package config handles TOML configuration parsing, environment variable overrides, and validation for Anchor LFS.
package config

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/refringe/anchor-lfs/internal/sanitise"
)

// DefaultConfigPath is the file path used when no override is provided.
const DefaultConfigPath = "config.toml"

// DefaultTrustedProxies are the loopback and private ranges trusted to send X-Forwarded-* headers by default.
var DefaultTrustedProxies = []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}

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
	S3Bucket          string `toml:"s3_bucket,omitempty"`
	S3Region          string `toml:"s3_region,omitempty"`
	S3Endpoint        string `toml:"s3_endpoint,omitempty"`
	S3AccessKeyID     string `toml:"s3_access_key_id,omitempty"`
	S3SecretAccessKey string `toml:"s3_secret_access_key,omitempty"`
	S3Prefix          string `toml:"s3_prefix,omitempty"`
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

// Log formats.
const (
	LogFormatJSON    = "json"
	LogFormatConsole = "console"
)

// Options holds global server settings.
type Options struct {
	ListenAddress string `toml:"listen_address"`
	DataDirectory string `toml:"data_directory"`
	BaseURL       string `toml:"base_url,omitempty"`
	MaxUploadSize int64  `toml:"max_upload_size"`

	// Longest wait for more upload body data before the upload is abandoned; zero disables it.
	UploadIdleTimeout         string        `toml:"upload_idle_timeout"`
	UploadIdleTimeoutDuration time.Duration `toml:"-"`

	// Logging; AdditionalLogging is a deprecated alias for console format at debug level.
	LogFormat         string `toml:"log_format"`
	LogLevel          string `toml:"log_level"`
	AccessLog         *bool  `toml:"access_log"`
	AdditionalLogging bool   `toml:"additional_logging,omitempty"`

	// Peers allowed to set X-Forwarded-For, X-Forwarded-Host and X-Forwarded-Proto.
	TrustedProxies []string `toml:"trusted_proxies"`

	// Rate limiting.
	RateLimitTokens   uint64        `toml:"rate_limit_tokens"`
	RateLimitInterval time.Duration `toml:"-"`
	RateLimitWindow   string        `toml:"rate_limit_window"`

	// Auth cache.
	AuthCacheTTL      string        `toml:"auth_cache_ttl"`
	AuthCacheDuration time.Duration `toml:"-"`

	// URL signing.
	SigningKey        string        `toml:"signing_key,omitempty"`
	SigningKeyBytes   []byte        `toml:"-"`
	URLExpiry         string        `toml:"url_expiry"`
	URLExpiryDuration time.Duration `toml:"-"`

	// Graceful shutdown.
	ShutdownTimeout         string        `toml:"shutdown_timeout"`
	ShutdownTimeoutDuration time.Duration `toml:"-"`
}

// AccessLogEnabled returns whether every request is logged, defaulting to true when unset.
func (o *Options) AccessLogEnabled() bool {
	if o.AccessLog == nil {
		return true
	}
	return *o.AccessLog
}

// Endpoint configures a single repository whose LFS objects will be served.
type Endpoint struct {
	Name           string `toml:"name"`
	URL            string `toml:"url"`
	Path           string `toml:"endpoint"` // "endpoint" in TOML for user clarity; "Path" in Go to avoid stuttering with the type name.
	Visibility     string `toml:"visibility"`
	Authentication string `toml:"authentication"`
	GitHubAPIURL   string `toml:"github_api_url,omitempty"`

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

// label names the endpoint in error messages, using its position when it has no name.
func (e *Endpoint) label(i int) string {
	if e.Name == "" {
		return fmt.Sprintf("endpoint #%d", i+1)
	}
	return fmt.Sprintf("endpoint %q", e.Name)
}

// ResolvePath returns flagPath if set, otherwise ANCHOR_LFS_CONFIG if set, otherwise DefaultConfigPath.
func ResolvePath(flagPath string) string {
	if flagPath != "" {
		return flagPath
	}
	if env := os.Getenv("ANCHOR_LFS_CONFIG"); env != "" {
		return env
	}
	return DefaultConfigPath
}

// Load reads and validates the configuration file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is operator-controlled (--config flag or ANCHOR_LFS_CONFIG env var)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	md, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if unknown := unrecognisedKeys(md); len(unknown) > 0 {
		return nil, fmt.Errorf("parsing config: unrecognised keys %s (check the spelling against config.toml.example)",
			strings.Join(unknown, ", "))
	}

	cfg.applyDefaults()

	problems := cfg.applyEnvOverrides()
	problems = append(problems, cfg.parseRateLimitWindow(), cfg.parseAuthCacheTTL(), cfg.parseURLExpiry(), cfg.parseShutdownTimeout(),
		cfg.parseUploadIdleTimeout(), cfg.parseSigningKey())
	problems = append(problems, cfg.validate()...)
	for i := range cfg.Endpoints {
		if err := cfg.Endpoints[i].parseGitHubURL(); err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", cfg.Endpoints[i].label(i), err))
		}
	}

	problems = slices.DeleteFunc(problems, func(err error) bool { return err == nil })
	if len(problems) > 0 {
		return nil, &ValidationError{Problems: problems}
	}
	return &cfg, nil
}

// ValidationError lists every problem found in a configuration.
type ValidationError struct {
	Problems []error
}

// Error joins the problems into a single line.
func (e *ValidationError) Error() string {
	messages := make([]string, len(e.Problems))
	for i, err := range e.Problems {
		messages[i] = err.Error()
	}
	return "validating config: " + strings.Join(messages, "; ")
}

// Unwrap returns the individual problems.
func (e *ValidationError) Unwrap() []error {
	return e.Problems
}

// unrecognisedKeys lists each undecoded key once, leaving out tables whose own keys are listed.
func unrecognisedKeys(md toml.MetaData) []string {
	var keys []string
	for _, key := range md.Undecoded() {
		if name := key.String(); !slices.Contains(keys, name) {
			keys = append(keys, name)
		}
	}
	return slices.DeleteFunc(slices.Clone(keys), func(table string) bool {
		return slices.ContainsFunc(keys, func(key string) bool { return strings.HasPrefix(key, table+".") })
	})
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
	if c.Options.MaxUploadSize == 0 {
		c.Options.MaxUploadSize = 5 << 30 // 5 GiB
	}
	if c.Options.UploadIdleTimeout == "" {
		c.Options.UploadIdleTimeout = "60s"
	}
	if c.Options.LogFormat == "" {
		c.Options.LogFormat = LogFormatJSON
		if c.Options.AdditionalLogging {
			c.Options.LogFormat = LogFormatConsole
		}
	}
	if c.Options.LogLevel == "" {
		c.Options.LogLevel = "info"
		if c.Options.AdditionalLogging {
			c.Options.LogLevel = "debug"
		}
	}
	if c.Options.TrustedProxies == nil {
		c.Options.TrustedProxies = slices.Clone(DefaultTrustedProxies)
	}
	if c.Options.RateLimitTokens == 0 {
		c.Options.RateLimitTokens = 600
	}
	if c.Options.RateLimitWindow == "" {
		c.Options.RateLimitWindow = "1m"
	}
	if c.Options.AuthCacheTTL == "" {
		c.Options.AuthCacheTTL = "60s"
	}
	if c.Options.URLExpiry == "" {
		c.Options.URLExpiry = "10m"
	}
	if c.Options.ShutdownTimeout == "" {
		c.Options.ShutdownTimeout = "30s"
	}
	if c.Storage.Backend == "" {
		c.Storage.Backend = StorageLocal
	}
	if c.Storage.S3Prefix == "" {
		c.Storage.S3Prefix = "lfs/"
	}
}

func (c *Config) applyEnvOverrides() []error {
	var problems []error

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
	if v, ok := os.LookupEnv("ANCHOR_LFS_TRUSTED_PROXIES"); ok {
		c.Options.TrustedProxies = []string{}
		for entry := range strings.SplitSeq(v, ",") {
			if entry = strings.TrimSpace(entry); entry != "" {
				c.Options.TrustedProxies = append(c.Options.TrustedProxies, entry)
			}
		}
	}
	if v := os.Getenv("ANCHOR_LFS_MAX_UPLOAD_SIZE"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			c.Options.MaxUploadSize = n
		} else {
			problems = append(problems, fmt.Errorf("ANCHOR_LFS_MAX_UPLOAD_SIZE %q must be a positive number of bytes", v))
		}
	}
	if v := os.Getenv("ANCHOR_LFS_UPLOAD_IDLE_TIMEOUT"); v != "" {
		c.Options.UploadIdleTimeout = v
	}
	if v := os.Getenv("ANCHOR_LFS_RATE_LIMIT_TOKENS"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			c.Options.RateLimitTokens = n
		} else {
			problems = append(problems, fmt.Errorf("ANCHOR_LFS_RATE_LIMIT_TOKENS %q must be a positive whole number", v))
		}
	}
	if v := os.Getenv("ANCHOR_LFS_RATE_LIMIT_WINDOW"); v != "" {
		c.Options.RateLimitWindow = v
	}
	if v := os.Getenv("ANCHOR_LFS_AUTH_CACHE_TTL"); v != "" {
		c.Options.AuthCacheTTL = v
	}
	if v := os.Getenv("ANCHOR_LFS_URL_EXPIRY"); v != "" {
		c.Options.URLExpiry = v
	}
	if v := os.Getenv("ANCHOR_LFS_LOG_FORMAT"); v != "" {
		c.Options.LogFormat = v
	}
	if v := os.Getenv("ANCHOR_LFS_LOG_LEVEL"); v != "" {
		c.Options.LogLevel = v
	}
	if err := overrideBool("ANCHOR_LFS_ACCESS_LOG", &c.Options.AccessLog); err != nil {
		problems = append(problems, err)
	}
	if v := os.Getenv("ANCHOR_LFS_SHUTDOWN_TIMEOUT"); v != "" {
		c.Options.ShutdownTimeout = v
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
	if err := overrideBool("ANCHOR_LFS_S3_PRESIGNED_URLS", &c.Storage.S3PresignedURLs); err != nil {
		problems = append(problems, err)
	}
	if err := overrideBool("ANCHOR_LFS_S3_FORCE_PATH_STYLE", &c.Storage.S3ForcePathStyle); err != nil {
		problems = append(problems, err)
	}

	return problems
}

// overrideBool sets *target from the named environment variable when it is set.
func overrideBool(name string, target **bool) error {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fmt.Errorf("%s %q must be true or false", name, v)
	}
	*target = &b
	return nil
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

func (c *Config) parseShutdownTimeout() error {
	d, err := time.ParseDuration(c.Options.ShutdownTimeout)
	if err != nil {
		return fmt.Errorf("invalid shutdown_timeout %q: %w", c.Options.ShutdownTimeout, err)
	}
	if d <= 0 {
		return fmt.Errorf("shutdown_timeout must be positive")
	}
	c.Options.ShutdownTimeoutDuration = d
	return nil
}

func (c *Config) parseUploadIdleTimeout() error {
	d, err := time.ParseDuration(c.Options.UploadIdleTimeout)
	if err != nil {
		return fmt.Errorf("invalid upload_idle_timeout %q: %w", c.Options.UploadIdleTimeout, err)
	}
	if d < 0 {
		return fmt.Errorf("upload_idle_timeout must not be negative")
	}
	c.Options.UploadIdleTimeoutDuration = d
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

func (c *Config) validateStorage() []error {
	backend := strings.ToLower(c.Storage.Backend)
	c.Storage.Backend = backend

	switch backend {
	case StorageLocal, "":
		return nil
	case StorageS3:
		var problems []error
		if c.Storage.S3Bucket == "" {
			problems = append(problems, fmt.Errorf("storage backend %q requires s3_bucket", backend))
		}
		if c.Storage.S3Region == "" {
			problems = append(problems, fmt.Errorf("storage backend %q requires s3_region", backend))
		}
		if c.Storage.S3Endpoint != "" {
			u, err := url.Parse(c.Storage.S3Endpoint)
			if err != nil || u.Scheme == "" || u.Host == "" {
				problems = append(problems, fmt.Errorf("s3_endpoint %q is not a valid URL", c.Storage.S3Endpoint))
			}
		}
		return problems
	default:
		return []error{fmt.Errorf("unknown storage backend %q (must be %q or %q)", backend, StorageLocal, StorageS3)}
	}
}

func (c *Config) validate() []error {
	problems := c.validateStorage()
	if err := checkChoice("log_format", c.Options.LogFormat, LogFormatJSON, LogFormatConsole); err != nil {
		problems = append(problems, err)
	}
	if err := checkChoice("log_level", c.Options.LogLevel, "debug", "info", "warn", "error"); err != nil {
		problems = append(problems, err)
	}
	c.Options.LogFormat = strings.ToLower(c.Options.LogFormat)
	c.Options.LogLevel = strings.ToLower(c.Options.LogLevel)
	if c.Options.MaxUploadSize < 0 {
		problems = append(problems, fmt.Errorf("max_upload_size must be positive"))
	}
	if c.Options.BaseURL != "" {
		u, err := url.Parse(c.Options.BaseURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			problems = append(problems, fmt.Errorf("base_url %q is not a valid URL", c.Options.BaseURL))
		}
	}
	for _, proxy := range c.Options.TrustedProxies {
		if _, err := netip.ParsePrefix(proxy); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(proxy); err != nil {
			problems = append(problems, fmt.Errorf("trusted_proxies entry %q is not an IP address or CIDR range", proxy))
		}
	}
	if len(c.Endpoints) == 0 {
		return append(problems, fmt.Errorf("no endpoints configured; add an [[endpoints]] block (see config.toml.example)"))
	}

	paths := make(map[string]struct{}, len(c.Endpoints))
	dirs := make(map[string]string, len(c.Endpoints))
	for i := range c.Endpoints {
		ep := &c.Endpoints[i]
		label := ep.label(i)
		if ep.Name == "" {
			problems = append(problems, fmt.Errorf("%s: missing name", label))
		}
		if err := validateEndpointPath(ep.Path, label, paths, dirs); err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", label, err))
		}
		for _, err := range ep.validateAccess() {
			problems = append(problems, fmt.Errorf("%s: %w", label, err))
		}
	}
	return problems
}

// validateEndpointPath checks an endpoint path, then records the path and its storage directory as taken by label.
func validateEndpointPath(endpointPath, label string, paths map[string]struct{}, dirs map[string]string) error {
	reservedPaths := map[string]struct{}{
		"health": {},
		"ready":  {},
	}
	if endpointPath == "" {
		return fmt.Errorf("missing endpoint path")
	}
	if !strings.HasPrefix(endpointPath, "/") {
		return fmt.Errorf("path %q must start with \"/\"", endpointPath)
	}
	if clean := path.Clean(endpointPath); clean != endpointPath {
		return fmt.Errorf("path %q is not a clean path; use %q", endpointPath, clean)
	}
	if _, exists := paths[endpointPath]; exists {
		return fmt.Errorf("duplicate endpoint path %q", endpointPath)
	}
	paths[endpointPath] = struct{}{}
	if _, reserved := reservedPaths[strings.TrimLeft(endpointPath, "/")]; reserved {
		return fmt.Errorf("path %q is reserved", endpointPath)
	}
	dir := sanitise.Endpoint(endpointPath)
	if dir == sanitise.InvalidEndpoint {
		return fmt.Errorf("path %q contains characters that are unsafe for storage directories", endpointPath)
	}
	if other, taken := dirs[strings.ToLower(dir)]; taken {
		return fmt.Errorf("path %q uses the same storage directory %q as %s", endpointPath, dir, other)
	}
	dirs[strings.ToLower(dir)] = label
	return nil
}

// validateAccess checks the endpoint's authentication and visibility settings.
func (e *Endpoint) validateAccess() []error {
	var problems []error
	if err := checkChoice("authentication", e.Authentication, authGitHub, "none"); err != nil {
		problems = append(problems, err)
	}
	if e.GitHubAPIURL != "" && e.AuthMethod() == "none" {
		problems = append(problems, fmt.Errorf(`github_api_url is set but authentication is "none" (must be "github")`))
	}
	if err := checkChoice("visibility", e.Visibility, "public", "private"); err != nil {
		problems = append(problems, err)
	}
	if strings.EqualFold(e.Visibility, "private") && e.AuthMethod() == "none" {
		problems = append(problems, fmt.Errorf(`visibility "private" requires authentication "github"; "none" lets anyone read and write`))
	}
	return problems
}

// checkChoice reports a setting that is missing or is not one of the allowed lower-case values.
func checkChoice(setting, value string, allowed ...string) error {
	if slices.Contains(allowed, strings.ToLower(value)) {
		return nil
	}
	quoted := make([]string, len(allowed))
	for i, choice := range allowed {
		quoted[i] = strconv.Quote(choice)
	}
	choices := quoted[len(quoted)-1]
	if len(quoted) > 1 {
		choices = strings.Join(quoted[:len(quoted)-1], ", ") + " or " + choices
	}
	if value == "" {
		return fmt.Errorf("missing %s (must be %s)", setting, choices)
	}
	return fmt.Errorf("unknown %s %q (must be %s)", setting, value, choices)
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
