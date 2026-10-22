package config

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadValid(t *testing.T) {
	path := writeConfig(t, `
[options]
listen_address = ":8080"
data_directory = "/tmp/data"

[[endpoints]]
name = "Test Repo"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "github"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Options.ListenAddress != ":8080" {
		t.Errorf("ListenAddress = %q, want %q", cfg.Options.ListenAddress, ":8080")
	}
	if cfg.Options.DataDirectory != "/tmp/data" {
		t.Errorf("DataDirectory = %q, want %q", cfg.Options.DataDirectory, "/tmp/data")
	}
	if len(cfg.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(cfg.Endpoints))
	}

	ep := cfg.Endpoints[0]
	if ep.GitHubOwner != "org" {
		t.Errorf("GitHubOwner = %q, want %q", ep.GitHubOwner, "org")
	}
	if ep.GitHubRepo != "repo" {
		t.Errorf("GitHubRepo = %q, want %q", ep.GitHubRepo, "repo")
	}
}

func TestLoadUnrecognisedKeys(t *testing.T) {
	const endpoint = `
[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`
	const misspelledEndpoint = `
[[endpoints]]
name = "Other"
url = "https://github.com/org/other"
endpoint = "/org/other"
visibilty = "public"
authentication = "none"
`
	tests := []struct {
		name   string
		config string
		want   string
	}{
		{name: "misspelled section", config: "[option]\nlisten_addr = \":8080\"\n" + endpoint, want: "option.listen_addr"},
		{name: "options key", config: "[options]\ndata_dir = \"/data\"\n" + endpoint, want: "options.data_dir"},
		{name: "storage key", config: "[storage]\ns3_bukket = \"lfs\"\n" + endpoint, want: "storage.s3_bukket"},
		{name: "endpoint key", config: endpoint + misspelledEndpoint + misspelledEndpoint, want: "endpoints.visibilty"},
		{name: "empty table", config: "[extra]\n" + endpoint, want: "extra"},
		{name: "top-level key", config: "listen_address = \":8080\"\n" + endpoint, want: "listen_address"},
		{
			name:   "several keys",
			config: "[options]\ndata_dir = \"/data\"\n" + endpoint + misspelledEndpoint,
			want:   "options.data_dir, endpoints.visibilty",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tt.config))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), "unrecognised keys "+tt.want+" (") {
				t.Errorf("error %q does not list exactly %q", err, tt.want)
			}
		})
	}
}

func TestLoadExampleConfig(t *testing.T) {
	data, err := os.ReadFile("../config.toml.example")
	if err != nil {
		t.Fatal(err)
	}
	commentedSetting := regexp.MustCompile(`(?m)^#(\[|[a-z_]+ = )`)

	tests := []struct {
		name          string
		config        string
		wantEndpoints int
	}{
		{name: "as shipped", config: string(data), wantEndpoints: 1},
		{name: "every setting enabled", config: commentedSetting.ReplaceAllString(string(data), "$1"), wantEndpoints: 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(writeConfig(t, tt.config))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if len(cfg.Endpoints) != tt.wantEndpoints {
				t.Errorf("got %d endpoints, want %d", len(cfg.Endpoints), tt.wantEndpoints)
			}
		})
	}
}

func TestLoadRateLimitDefaults(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Options.RateLimitTokens != 600 {
		t.Errorf("default RateLimitTokens = %d, want 600", cfg.Options.RateLimitTokens)
	}
	if cfg.Options.RateLimitWindow != "1m" {
		t.Errorf("default RateLimitWindow = %q, want %q", cfg.Options.RateLimitWindow, "1m")
	}
	if cfg.Options.RateLimitInterval != time.Minute {
		t.Errorf("default RateLimitInterval = %v, want %v", cfg.Options.RateLimitInterval, time.Minute)
	}
}

func TestLoadVisibilityAndAuthentication(t *testing.T) {
	tests := []struct {
		visibility     string
		authentication string
		wantErr        bool
	}{
		{"public", "none", false},
		{"public", "github", false},
		{"private", "github", false},
		{"private", "none", true},
		{"Private", "None", true},
	}
	for _, tt := range tests {
		t.Run(tt.visibility+"+"+tt.authentication, func(t *testing.T) {
			path := writeConfig(t, `
[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "`+tt.visibility+`"
authentication = "`+tt.authentication+`"
`)
			_, err := Load(path)
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("Load error = %v, want error %t", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), "requires authentication") {
				t.Errorf("error %q does not explain the required authentication", err)
			}
		})
	}
}

func TestLoadTrustedProxies(t *testing.T) {
	tests := []struct {
		name    string
		options string
		env     string
		setEnv  bool
		want    []string
		wantErr bool
	}{
		{name: "default", want: DefaultTrustedProxies},
		{name: "explicit list", options: `trusted_proxies = ["192.168.1.2", "10.0.0.0/8"]`, want: []string{"192.168.1.2", "10.0.0.0/8"}},
		{name: "explicit empty", options: `trusted_proxies = []`, want: []string{}},
		{name: "env list", env: "192.168.1.2, 10.0.0.0/8", setEnv: true, want: []string{"192.168.1.2", "10.0.0.0/8"}},
		{name: "env empty", options: `trusted_proxies = ["10.0.0.0/8"]`, setEnv: true, want: []string{}},
		{name: "hostname rejected", options: `trusted_proxies = ["proxy.example.com"]`, wantErr: true},
		{name: "bad range rejected", options: `trusted_proxies = ["10.0.0.0/33"]`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv("ANCHOR_LFS_TRUSTED_PROXIES", tt.env)
			}
			path := writeConfig(t, `
[options]
`+tt.options+`

[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

			cfg, err := Load(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Options.TrustedProxies == nil || !slices.Equal(cfg.Options.TrustedProxies, tt.want) {
				t.Errorf("TrustedProxies = %#v, want %#v", cfg.Options.TrustedProxies, tt.want)
			}
		})
	}
}

func TestLoadLogging(t *testing.T) {
	tests := []struct {
		name          string
		options       string
		env           map[string]string
		wantFormat    string
		wantLevel     string
		wantAccessLog bool
	}{
		{name: "defaults", wantFormat: "json", wantLevel: "info", wantAccessLog: true},
		{
			name:       "explicit",
			options:    "log_format = \"Console\"\nlog_level = \"WARN\"\naccess_log = false",
			wantFormat: "console", wantLevel: "warn", wantAccessLog: false,
		},
		{
			name:       "deprecated alias",
			options:    "additional_logging = true",
			wantFormat: "console", wantLevel: "debug", wantAccessLog: true,
		},
		{
			name:       "deprecated alias with explicit level",
			options:    "additional_logging = true\nlog_level = \"error\"",
			wantFormat: "console", wantLevel: "error", wantAccessLog: true,
		},
		{
			name:       "env overrides",
			options:    "log_format = \"console\"",
			env:        map[string]string{"ANCHOR_LFS_LOG_FORMAT": "json", "ANCHOR_LFS_LOG_LEVEL": "debug", "ANCHOR_LFS_ACCESS_LOG": "false"},
			wantFormat: "json", wantLevel: "debug", wantAccessLog: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for key, value := range tt.env {
				t.Setenv(key, value)
			}
			path := writeConfig(t, `
[options]
`+tt.options+`

[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Options.LogFormat != tt.wantFormat {
				t.Errorf("LogFormat = %q, want %q", cfg.Options.LogFormat, tt.wantFormat)
			}
			if cfg.Options.LogLevel != tt.wantLevel {
				t.Errorf("LogLevel = %q, want %q", cfg.Options.LogLevel, tt.wantLevel)
			}
			if got := cfg.Options.AccessLogEnabled(); got != tt.wantAccessLog {
				t.Errorf("AccessLogEnabled() = %t, want %t", got, tt.wantAccessLog)
			}
		})
	}
}

func TestLoadMaxUploadSizeDefault(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Options.MaxUploadSize != 5<<30 {
		t.Errorf("default MaxUploadSize = %d, want %d", cfg.Options.MaxUploadSize, 5<<30)
	}
}

func TestLoadAuthCacheTTLDefault(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Options.AuthCacheTTL != "60s" {
		t.Errorf("default AuthCacheTTL = %q, want %q", cfg.Options.AuthCacheTTL, "60s")
	}
	if cfg.Options.AuthCacheDuration != 60*time.Second {
		t.Errorf("default AuthCacheDuration = %v, want %v", cfg.Options.AuthCacheDuration, 60*time.Second)
	}
}

func TestLoadAuthCacheTTLDisabled(t *testing.T) {
	path := writeConfig(t, `
[options]
auth_cache_ttl = "0s"

[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Options.AuthCacheDuration != 0 {
		t.Errorf("AuthCacheDuration = %v, want 0", cfg.Options.AuthCacheDuration)
	}
}

func TestLoadDefaults(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Options.ListenAddress != ":5420" {
		t.Errorf("default ListenAddress = %q, want %q", cfg.Options.ListenAddress, ":5420")
	}
	if cfg.Options.DataDirectory != "./data" {
		t.Errorf("default DataDirectory = %q, want %q", cfg.Options.DataDirectory, "./data")
	}
	if cfg.Options.ShutdownTimeoutDuration != 30*time.Second {
		t.Errorf("default ShutdownTimeoutDuration = %v, want %v", cfg.Options.ShutdownTimeoutDuration, 30*time.Second)
	}
	if cfg.Options.UploadIdleTimeoutDuration != time.Minute {
		t.Errorf("default UploadIdleTimeoutDuration = %v, want %v", cfg.Options.UploadIdleTimeoutDuration, time.Minute)
	}
}

func TestLoadProblemMessages(t *testing.T) {
	endpoint := func(settings string) string {
		return "[[endpoints]]\nurl = \"https://github.com/org/repo\"\nendpoint = \"/org/repo\"\n" + settings
	}
	tests := []struct {
		name   string
		config string
		want   string
	}{
		{
			name:   "no endpoints",
			config: "[options]\nlisten_address = \":5420\"\n",
			want:   "no endpoints configured; add an [[endpoints]] block (see config.toml.example)",
		},
		{
			name:   "missing name",
			config: endpoint("visibility = \"public\"\nauthentication = \"none\"\n"),
			want:   "endpoint #1: missing name",
		},
		{
			name:   "missing visibility",
			config: endpoint("name = \"Test\"\nauthentication = \"none\"\n"),
			want:   `endpoint "Test": missing visibility (must be "public" or "private")`,
		},
		{
			name:   "unknown visibility",
			config: endpoint("name = \"Test\"\nvisibility = \"secret\"\nauthentication = \"none\"\n"),
			want:   `endpoint "Test": unknown visibility "secret" (must be "public" or "private")`,
		},
		{
			name:   "missing authentication",
			config: endpoint("name = \"Test\"\nvisibility = \"public\"\n"),
			want:   `endpoint "Test": missing authentication (must be "github" or "none")`,
		},
		{
			name:   "unknown authentication",
			config: endpoint("name = \"Test\"\nvisibility = \"public\"\nauthentication = \"ldap\"\n"),
			want:   `endpoint "Test": unknown authentication "ldap" (must be "github" or "none")`,
		},
		{
			name:   "unknown log_format",
			config: "[options]\nlog_format = \"text\"\n\n" + endpoint("name = \"Test\"\nvisibility = \"public\"\nauthentication = \"none\"\n"),
			want:   `unknown log_format "text" (must be "json" or "console")`,
		},
		{
			name:   "unknown log_level",
			config: "[options]\nlog_level = \"verbose\"\n\n" + endpoint("name = \"Test\"\nvisibility = \"public\"\nauthentication = \"none\"\n"),
			want:   `unknown log_level "verbose" (must be "debug", "info", "warn" or "error")`,
		},
		{
			name:   "negative max_upload_size",
			config: "[options]\nmax_upload_size = -1\n\n" + endpoint("name = \"Test\"\nvisibility = \"public\"\nauthentication = \"none\"\n"),
			want:   "max_upload_size must be positive",
		},
		{
			name:   "zero shutdown_timeout",
			config: "[options]\nshutdown_timeout = \"0s\"\n\n" + endpoint("name = \"Test\"\nvisibility = \"public\"\nauthentication = \"none\"\n"),
			want:   "shutdown_timeout must be positive",
		},
		{
			name:   "negative upload_idle_timeout",
			config: "[options]\nupload_idle_timeout = \"-1s\"\n\n" + endpoint("name = \"Test\"\nvisibility = \"public\"\nauthentication = \"none\"\n"),
			want:   "upload_idle_timeout must not be negative",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tt.config))
			invalid, ok := errors.AsType[*ValidationError](err)
			if !ok {
				t.Fatalf("Load error = %v, want *ValidationError", err)
			}
			if len(invalid.Problems) != 1 || invalid.Problems[0].Error() != tt.want {
				t.Errorf("problems = %q, want only %q", invalid.Problems, tt.want)
			}
		})
	}
}

func TestLoadReportsEveryProblem(t *testing.T) {
	t.Setenv("ANCHOR_LFS_MAX_UPLOAD_SIZE", "abc")
	path := writeConfig(t, `
[options]
rate_limit_window = "1 day"
url_expiry = "soon"

[[endpoints]]
name = "Docs"
url = "https://github.com/org/docs"
endpoint = "/org/docs"
authentication = "github"

[[endpoints]]
url = "https://github.com/org/repo"
endpoint = "/org/docs"
visibility = "public"
authentication = "none"
`)

	_, err := Load(path)
	invalid, ok := errors.AsType[*ValidationError](err)
	if !ok {
		t.Fatalf("Load error = %v, want *ValidationError", err)
	}
	want := []string{
		`ANCHOR_LFS_MAX_UPLOAD_SIZE "abc" must be a positive number of bytes`,
		`invalid rate_limit_window "1 day"`,
		`invalid url_expiry "soon"`,
		`endpoint "Docs": missing visibility`,
		`endpoint #2: missing name`,
		`endpoint #2: duplicate endpoint path "/org/docs"`,
	}
	if len(invalid.Problems) != len(want) {
		t.Fatalf("got %d problems %q, want %d", len(invalid.Problems), invalid.Problems, len(want))
	}
	for i, prefix := range want {
		if !strings.HasPrefix(invalid.Problems[i].Error(), prefix) {
			t.Errorf("problem %d = %q, want prefix %q", i, invalid.Problems[i], prefix)
		}
	}
}

func TestEnvOverrideInvalidValues(t *testing.T) {
	tests := []struct {
		env   string
		value string
		want  string
	}{
		{"ANCHOR_LFS_MAX_UPLOAD_SIZE", "abc", `ANCHOR_LFS_MAX_UPLOAD_SIZE "abc" must be a positive number of bytes`},
		{"ANCHOR_LFS_MAX_UPLOAD_SIZE", "0", `ANCHOR_LFS_MAX_UPLOAD_SIZE "0" must be a positive number of bytes`},
		{"ANCHOR_LFS_MAX_UPLOAD_SIZE", "-5", `ANCHOR_LFS_MAX_UPLOAD_SIZE "-5" must be a positive number of bytes`},
		{"ANCHOR_LFS_RATE_LIMIT_TOKENS", "lots", `ANCHOR_LFS_RATE_LIMIT_TOKENS "lots" must be a positive whole number`},
		{"ANCHOR_LFS_RATE_LIMIT_TOKENS", "0", `ANCHOR_LFS_RATE_LIMIT_TOKENS "0" must be a positive whole number`},
		{"ANCHOR_LFS_URL_EXPIRY", "soon", `invalid url_expiry "soon": time: invalid duration "soon"`},
		{"ANCHOR_LFS_S3_PRESIGNED_URLS", "yes", `ANCHOR_LFS_S3_PRESIGNED_URLS "yes" must be true or false`},
		{"ANCHOR_LFS_S3_FORCE_PATH_STYLE", "on", `ANCHOR_LFS_S3_FORCE_PATH_STYLE "on" must be true or false`},
		{"ANCHOR_LFS_ACCESS_LOG", "off", `ANCHOR_LFS_ACCESS_LOG "off" must be true or false`},
		{"ANCHOR_LFS_LOG_LEVEL", "trace", `unknown log_level "trace" (must be "debug", "info", "warn" or "error")`},
	}
	for _, tt := range tests {
		t.Run(tt.env+"="+tt.value, func(t *testing.T) {
			t.Setenv(tt.env, tt.value)
			path := writeConfig(t, `
[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

			_, err := Load(path)
			invalid, ok := errors.AsType[*ValidationError](err)
			if !ok {
				t.Fatalf("Load error = %v, want *ValidationError", err)
			}
			if len(invalid.Problems) != 1 || invalid.Problems[0].Error() != tt.want {
				t.Errorf("problems = %q, want only %q", invalid.Problems, tt.want)
			}
		})
	}
}

func TestLoadGitHubURLExtraSegments(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "Test"
url = "https://github.com/org/repo/settings"
endpoint = "/org/repo"
visibility = "public"
authentication = "github"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for GitHub URL with extra path segments")
	}
}

func TestLoadInvalidGitHubURL(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "Test"
url = "https://gitlab.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "github"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for non-github URL with github auth")
	}
}

func TestEndpointIsPublic(t *testing.T) {
	ep := Endpoint{Visibility: "Public"}
	if !ep.IsPublic() {
		t.Error("expected IsPublic=true for Public visibility")
	}

	ep.Visibility = "private"
	if ep.IsPublic() {
		t.Error("expected IsPublic=false for private visibility")
	}
}

func TestLoadDuplicateEndpointPaths(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "First"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"

[[endpoints]]
name = "Second"
url = "https://github.com/org/other"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for duplicate endpoint paths")
	}
}

func TestEnvOverrides(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	t.Setenv("ANCHOR_LFS_LISTEN", ":9999")
	t.Setenv("ANCHOR_LFS_DATA_DIR", "/custom/data")
	t.Setenv("ANCHOR_LFS_SHUTDOWN_TIMEOUT", "2m")
	t.Setenv("ANCHOR_LFS_UPLOAD_IDLE_TIMEOUT", "0s")
	t.Setenv("ANCHOR_LFS_RATE_LIMIT_TOKENS", "50")
	t.Setenv("ANCHOR_LFS_RATE_LIMIT_WINDOW", "10s")
	t.Setenv("ANCHOR_LFS_AUTH_CACHE_TTL", "5m")
	t.Setenv("ANCHOR_LFS_URL_EXPIRY", "1h")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Options.ListenAddress != ":9999" {
		t.Errorf("env override ListenAddress = %q, want %q", cfg.Options.ListenAddress, ":9999")
	}
	if cfg.Options.DataDirectory != "/custom/data" {
		t.Errorf("env override DataDirectory = %q, want %q", cfg.Options.DataDirectory, "/custom/data")
	}
	if cfg.Options.ShutdownTimeoutDuration != 2*time.Minute {
		t.Errorf("env override ShutdownTimeoutDuration = %v, want %v", cfg.Options.ShutdownTimeoutDuration, 2*time.Minute)
	}
	if cfg.Options.UploadIdleTimeoutDuration != 0 {
		t.Errorf("env override UploadIdleTimeoutDuration = %v, want 0", cfg.Options.UploadIdleTimeoutDuration)
	}
	if cfg.Options.RateLimitTokens != 50 || cfg.Options.RateLimitInterval != 10*time.Second {
		t.Errorf("env override rate limit = %d per %v, want 50 per 10s", cfg.Options.RateLimitTokens, cfg.Options.RateLimitInterval)
	}
	if cfg.Options.AuthCacheDuration != 5*time.Minute || cfg.Options.URLExpiryDuration != time.Hour {
		t.Errorf("env override AuthCacheDuration = %v, URLExpiryDuration = %v, want 5m and 1h",
			cfg.Options.AuthCacheDuration, cfg.Options.URLExpiryDuration)
	}
}

func TestEnvOverrideBaseURL(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	t.Setenv("ANCHOR_LFS_BASE_URL", "https://lfs.example.com/")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Options.BaseURL != "https://lfs.example.com" {
		t.Errorf("env override BaseURL = %q, want trailing slash trimmed", cfg.Options.BaseURL)
	}
}

func TestEnvOverrideSigningKey(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	// 32 bytes = 64 hex characters.
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	t.Setenv("ANCHOR_LFS_SIGNING_KEY", key)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Options.SigningKeyBytes) != 32 {
		t.Errorf("env override SigningKeyBytes length = %d, want 32", len(cfg.Options.SigningKeyBytes))
	}
}

func TestEnvOverrideMaxUploadSize(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	t.Setenv("ANCHOR_LFS_MAX_UPLOAD_SIZE", "1073741824")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Options.MaxUploadSize != 1073741824 {
		t.Errorf("env override MaxUploadSize = %d, want 1073741824", cfg.Options.MaxUploadSize)
	}
}

func TestBaseURLTrailingSlashTrimmed(t *testing.T) {
	path := writeConfig(t, `
[options]
base_url = "https://lfs.example.com/"

[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Options.BaseURL != "https://lfs.example.com" {
		t.Errorf("BaseURL = %q, want trailing slash trimmed", cfg.Options.BaseURL)
	}
}

func TestLoadInvalidBaseURL(t *testing.T) {
	path := writeConfig(t, `
[options]
base_url = "not a url"

[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid base_url")
	}
}

func TestLoadReservedEndpointPath(t *testing.T) {
	for _, reserved := range []string{"/health", "/ready"} {
		t.Run(reserved, func(t *testing.T) {
			path := writeConfig(t, `
[[endpoints]]
name = "Collision"
url = "https://github.com/org/repo"
endpoint = "`+reserved+`"
visibility = "public"
authentication = "none"
`)

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), "is reserved") {
				t.Fatalf("Load error = %v, want a reserved path error", err)
			}
		})
	}
}

func TestLoadGitHubEnterprise(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "GHE Repo"
url = "https://github.example.com/org/repo"
endpoint = "/ghe/repo"
visibility = "private"
authentication = "github"
github_api_url = "https://github.example.com/api/v3/"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	ep := cfg.Endpoints[0]
	if ep.GitHubOwner != "org" {
		t.Errorf("GitHubOwner = %q, want %q", ep.GitHubOwner, "org")
	}
	if ep.GitHubRepo != "repo" {
		t.Errorf("GitHubRepo = %q, want %q", ep.GitHubRepo, "repo")
	}
	if ep.GitHubBaseURL == nil {
		t.Fatal("GitHubBaseURL is nil, want non-nil")
	}
	if got := ep.GitHubBaseURL.String(); got != "https://github.example.com/api/v3/" {
		t.Errorf("GitHubBaseURL = %q, want %q", got, "https://github.example.com/api/v3/")
	}
}

func TestLoadGitHubEnterpriseTrailingSlash(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "GHE Repo"
url = "https://github.example.com/org/repo"
endpoint = "/ghe/repo"
visibility = "private"
authentication = "github"
github_api_url = "https://github.example.com/api/v3"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	ep := cfg.Endpoints[0]
	if !strings.HasSuffix(ep.GitHubBaseURL.Path, "/") {
		t.Errorf("GitHubBaseURL.Path = %q, want trailing slash", ep.GitHubBaseURL.Path)
	}
}

func TestLoadGitHubEnterpriseWithoutAPIURL(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "GHE Repo"
url = "https://github.example.com/org/repo"
endpoint = "/ghe/repo"
visibility = "private"
authentication = "github"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for non-github.com URL without github_api_url")
	}
}

func TestLoadGitHubAPIURLInvalid(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "GHE Repo"
url = "https://github.example.com/org/repo"
endpoint = "/ghe/repo"
visibility = "private"
authentication = "github"
github_api_url = "not a url"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid github_api_url")
	}
}

func TestLoadGitHubAPIURLOnNonGitHubAuth(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
github_api_url = "https://github.example.com/api/v3/"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for github_api_url on non-github auth")
	}
}

func TestLoadGitHubDotComWithAPIURL(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "github"
github_api_url = "https://custom-proxy.example.com/github/api/"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	ep := cfg.Endpoints[0]
	if ep.GitHubBaseURL == nil {
		t.Fatal("GitHubBaseURL is nil, want non-nil")
	}
}

func TestLoadRejectsMalformedEndpointPath(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
	}{
		{"trailing slash", "/org/repo/"},
		{"missing leading slash", "org/repo"},
		{"empty segment", "/org//repo"},
		{"dot segment", "/org/./repo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, `
[[endpoints]]
name = "Malformed"
url = "https://github.com/org/repo"
endpoint = "`+tt.endpoint+`"
visibility = "public"
authentication = "none"
`)

			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error for endpoint path %q", tt.endpoint)
			}
			if !strings.Contains(err.Error(), `"`+tt.endpoint+`"`) {
				t.Errorf("error %q does not name the endpoint path %q", err, tt.endpoint)
			}
		})
	}
}

func TestLoadRejectsCollidingStorageDirectories(t *testing.T) {
	tests := []struct {
		name   string
		first  string
		second string
	}{
		{"slash and underscore", "/org/repo", "/org_repo"},
		{"case only", "/org/repo", "/Org/Repo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, `
[[endpoints]]
name = "First"
url = "https://github.com/org/repo"
endpoint = "`+tt.first+`"
visibility = "public"
authentication = "none"

[[endpoints]]
name = "Second"
url = "https://github.com/org/other"
endpoint = "`+tt.second+`"
visibility = "public"
authentication = "none"
`)

			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error for %q and %q sharing a storage directory", tt.first, tt.second)
			}
			if !strings.Contains(err.Error(), "same storage directory") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestLoadUnsafeEndpointPath(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "Dotted Org"
url = "https://github.com/org/repo"
endpoint = "/my.org/repo"
visibility = "public"
authentication = "none"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for endpoint path with unsafe characters")
	}
}

func TestStorageDefaultsToLocal(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Storage.Backend != StorageLocal {
		t.Errorf("Storage.Backend = %q, want %q", cfg.Storage.Backend, StorageLocal)
	}
	if cfg.Storage.S3Prefix != "lfs/" {
		t.Errorf("Storage.S3Prefix = %q, want %q", cfg.Storage.S3Prefix, "lfs/")
	}
}

func TestStorageS3Valid(t *testing.T) {
	path := writeConfig(t, `
[storage]
backend = "s3"
s3_bucket = "my-bucket"
s3_region = "us-east-1"

[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Storage.Backend != StorageS3 {
		t.Errorf("Storage.Backend = %q, want %q", cfg.Storage.Backend, StorageS3)
	}
	if cfg.Storage.S3Bucket != "my-bucket" {
		t.Errorf("Storage.S3Bucket = %q, want %q", cfg.Storage.S3Bucket, "my-bucket")
	}
	if cfg.Storage.S3Region != "us-east-1" {
		t.Errorf("Storage.S3Region = %q, want %q", cfg.Storage.S3Region, "us-east-1")
	}
}

func TestStorageS3MissingBucket(t *testing.T) {
	path := writeConfig(t, `
[storage]
backend = "s3"
s3_region = "us-east-1"

[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for S3 backend without bucket")
	}
	if !strings.Contains(err.Error(), "s3_bucket") {
		t.Errorf("error should mention s3_bucket, got: %v", err)
	}
}

func TestStorageS3MissingRegion(t *testing.T) {
	path := writeConfig(t, `
[storage]
backend = "s3"
s3_bucket = "my-bucket"

[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for S3 backend without region")
	}
	if !strings.Contains(err.Error(), "s3_region") {
		t.Errorf("error should mention s3_region, got: %v", err)
	}
}

func TestStorageS3InvalidEndpoint(t *testing.T) {
	path := writeConfig(t, `
[storage]
backend = "s3"
s3_bucket = "my-bucket"
s3_region = "us-east-1"
s3_endpoint = "not a url"

[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid S3 endpoint URL")
	}
}

func TestStorageUnknownBackend(t *testing.T) {
	path := writeConfig(t, `
[storage]
backend = "gcs"

[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unknown storage backend")
	}
}

func TestStorageS3PresignedURLsDefault(t *testing.T) {
	path := writeConfig(t, `
[storage]
backend = "s3"
s3_bucket = "my-bucket"
s3_region = "us-east-1"

[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !cfg.Storage.S3PresignedURLsEnabled() {
		t.Error("S3PresignedURLsEnabled() should default to true")
	}
	if cfg.Storage.S3ForcePathStyleEnabled() {
		t.Error("S3ForcePathStyleEnabled() should default to false")
	}
}

func TestStorageS3EnvOverrides(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`)

	t.Setenv("ANCHOR_LFS_STORAGE_BACKEND", "s3")
	t.Setenv("ANCHOR_LFS_S3_BUCKET", "env-bucket")
	t.Setenv("ANCHOR_LFS_S3_REGION", "eu-west-1")
	t.Setenv("ANCHOR_LFS_S3_ENDPOINT", "https://r2.example.com")
	t.Setenv("ANCHOR_LFS_S3_ACCESS_KEY_ID", "AKID")
	t.Setenv("ANCHOR_LFS_S3_SECRET_ACCESS_KEY", "secret")
	t.Setenv("ANCHOR_LFS_S3_PREFIX", "custom/")
	t.Setenv("ANCHOR_LFS_S3_PRESIGNED_URLS", "false")
	t.Setenv("ANCHOR_LFS_S3_FORCE_PATH_STYLE", "true")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Storage.Backend != StorageS3 {
		t.Errorf("Backend = %q, want %q", cfg.Storage.Backend, StorageS3)
	}
	if cfg.Storage.S3Bucket != "env-bucket" {
		t.Errorf("S3Bucket = %q, want %q", cfg.Storage.S3Bucket, "env-bucket")
	}
	if cfg.Storage.S3Region != "eu-west-1" {
		t.Errorf("S3Region = %q, want %q", cfg.Storage.S3Region, "eu-west-1")
	}
	if cfg.Storage.S3Endpoint != "https://r2.example.com" {
		t.Errorf("S3Endpoint = %q, want %q", cfg.Storage.S3Endpoint, "https://r2.example.com")
	}
	if cfg.Storage.S3AccessKeyID != "AKID" {
		t.Errorf("S3AccessKeyID = %q, want %q", cfg.Storage.S3AccessKeyID, "AKID")
	}
	if cfg.Storage.S3SecretAccessKey != "secret" {
		t.Errorf("S3SecretAccessKey = %q, want %q", cfg.Storage.S3SecretAccessKey, "secret")
	}
	if cfg.Storage.S3Prefix != "custom/" {
		t.Errorf("S3Prefix = %q, want %q", cfg.Storage.S3Prefix, "custom/")
	}
	if cfg.Storage.S3PresignedURLsEnabled() {
		t.Error("S3PresignedURLsEnabled() should be false after env override")
	}
	if !cfg.Storage.S3ForcePathStyleEnabled() {
		t.Error("S3ForcePathStyleEnabled() should be true after env override")
	}
}
