package config

import (
	"os"
	"path/filepath"
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

	if cfg.Options.RateLimitTokens != 10000 {
		t.Errorf("default RateLimitTokens = %d, want 10000", cfg.Options.RateLimitTokens)
	}
	if cfg.Options.RateLimitWindow != "24h" {
		t.Errorf("default RateLimitWindow = %q, want %q", cfg.Options.RateLimitWindow, "24h")
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
}

func TestLoadNoEndpoints(t *testing.T) {
	path := writeConfig(t, `
[options]
listen_address = ":5420"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for no endpoints")
	}
}

func TestLoadInvalidAuth(t *testing.T) {
	path := writeConfig(t, `
[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "ldap"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid auth method")
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
	path := writeConfig(t, `
[[endpoints]]
name = "Health Collision"
url = "https://github.com/org/repo"
endpoint = "/health"
visibility = "public"
authentication = "none"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for reserved endpoint path")
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
