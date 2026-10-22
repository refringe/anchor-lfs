package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/refringe/anchor-lfs/config"
)

// writeCLIConfig writes content to a config.toml in a temporary directory and returns its path.
func writeCLIConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const cliEndpoint = `
[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`

func TestRunCommand(t *testing.T) {
	versionLine := "anchor-lfs dev (commit unknown, built unknown)\n"
	tests := []struct {
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{args: []string{"version"}, wantStdout: versionLine},
		{args: []string{"--version"}, wantStdout: versionLine},
		{args: []string{"-version"}, wantStdout: versionLine},
		{args: []string{"help"}, wantStdout: usage},
		{args: []string{"-h"}, wantStdout: usage},
		{args: []string{"--help"}, wantStdout: usage},
		{args: []string{"check", "-h"}, wantStdout: usage},
		{args: []string{"version", "extra"}, wantCode: 2, wantStderr: "anchor-lfs: unexpected argument \"extra\"\n\n" + usage},
		{args: []string{"--bogus"}, wantCode: 2, wantStderr: "anchor-lfs: flag provided but not defined: -bogus\n\n" + usage},
		{args: []string{"--config"}, wantCode: 2, wantStderr: "anchor-lfs: flag needs an argument: -config\n\n" + usage},
		{args: []string{"bogus"}, wantCode: 2, wantStderr: "anchor-lfs: unknown command \"bogus\"\n\n" + usage},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runCommand(tt.args, &stdout, &stderr); code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if stdout.String() != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", stdout.String(), tt.wantStdout)
			}
			if stderr.String() != tt.wantStderr {
				t.Errorf("stderr = %q, want %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestRunCheckPrintsRedactedConfig(t *testing.T) {
	signingKey, secret := strings.Repeat("ab", 32), "s3-secret-value"
	path := writeCLIConfig(t, `
[options]
signing_key = "`+signingKey+`"

[storage]
backend = "s3"
s3_bucket = "lfs"
s3_region = "eu-west-1"
s3_secret_access_key = "`+secret+`"
`+cliEndpoint)

	for _, args := range [][]string{{"--config", path, "check"}, {"check", "--config", path}, {"-config=" + path, "check"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runCommand(args, &stdout, &stderr); code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr %q)", code, stderr.String())
			}
			out := stdout.String()
			if !strings.HasPrefix(out, "# "+path+" is valid.") {
				t.Errorf("output does not start with the validity line:\n%s", out)
			}
			for _, leaked := range []string{signingKey, secret} {
				if strings.Contains(out, leaked) {
					t.Errorf("output contains the secret %q:\n%s", leaked, out)
				}
			}
			for _, want := range []string{
				`signing_key = "<redacted>"`, `s3_secret_access_key = "<redacted>"`, "access_log = true", "s3_presigned_urls = true",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
			var printed config.Config
			if _, err := toml.Decode(out, &printed); err != nil {
				t.Errorf("output is not valid TOML: %v", err)
			}
		})
	}
}

func TestRunCheckUsesEnvironmentPath(t *testing.T) {
	t.Setenv("ANCHOR_LFS_CONFIG", writeCLIConfig(t, cliEndpoint))
	var stdout, stderr bytes.Buffer
	if code := runCommand([]string{"check"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr %q)", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "s3_") {
		t.Errorf("local backend output includes S3 settings:\n%s", stdout.String())
	}
}

func TestRunCheckListsProblems(t *testing.T) {
	path := writeCLIConfig(t, `
[options]
rate_limit_window = "soon"
`+strings.Replace(cliEndpoint, `"public"`, `"secret"`, 1))

	var stdout, stderr bytes.Buffer
	if code := runCommand([]string{"check", "--config", path}, &stdout, &stderr); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing", stdout.String())
	}
	if !strings.HasPrefix(stderr.String(), "anchor-lfs: "+path+" is invalid:\n") || strings.Count(stderr.String(), "\n  - ") != 2 {
		t.Errorf("stderr does not list both problems:\n%s", stderr.String())
	}
}

func TestRunCheckMissingFile(t *testing.T) {
	var stderr bytes.Buffer
	if code := runCommand([]string{"check", "--config", filepath.Join(t.TempDir(), "missing.toml")}, &bytes.Buffer{}, &stderr); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "reading config") {
		t.Errorf("stderr = %q, want a read error", stderr.String())
	}
}
