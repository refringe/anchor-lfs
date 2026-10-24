//go:build unix

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// serveTestConfigEnv names the variable that makes the test binary run the server with the config file it holds.
const serveTestConfigEnv = "SERVE_TEST_CONFIG_PATH"

func TestMain(m *testing.M) {
	if configPath := os.Getenv(serveTestConfigEnv); configPath != "" {
		os.Exit(runCommand([]string{"--config", configPath}, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// logEntry is the part of a server log line the shutdown tests read.
type logEntry struct {
	Message string `json:"message"`
	Address string `json:"address"`
}

// serverProcess is the server running in a child process.
type serverProcess struct {
	cmd         *exec.Cmd
	addr        string
	metricsAddr string
	entries     chan logEntry
	exited      chan struct{}
}

// startServer runs the server in a child process with shutdownTimeout and waits until it serves requests and metrics.
func startServer(t *testing.T, shutdownTimeout string) *serverProcess {
	t.Helper()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	if err := os.Mkdir(dataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.toml")
	configText := fmt.Sprintf(`[options]
listen_address = "127.0.0.1:0"
metrics_address = "127.0.0.1:0"
data_directory = %q
shutdown_timeout = %q
upload_idle_timeout = "60s"

[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`, dataDir, shutdownTimeout)
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.CommandContext(t.Context(), os.Args[0]) //nolint:gosec // re-runs this test binary as the server
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "ANCHOR_LFS_") {
			cmd.Env = append(cmd.Env, env)
		}
	}
	cmd.Env = append(cmd.Env, serveTestConfigEnv+"="+configPath)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	p := &serverProcess{cmd: cmd, entries: make(chan logEntry, 256), exited: make(chan struct{})}
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			var entry logEntry
			if json.Unmarshal(scanner.Bytes(), &entry) == nil {
				p.entries <- entry
			}
		}
		_ = cmd.Wait()
		close(p.exited)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-p.exited
	})

	p.addr = p.waitForLog(t, "listening").Address
	p.metricsAddr = p.waitForLog(t, "serving metrics").Address
	return p
}

// waitForLog returns the first log entry with message, failing the test if the server exits or takes too long.
func (p *serverProcess) waitForLog(t *testing.T, message string) logEntry {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case entry := <-p.entries:
			if entry.Message == message {
				return entry
			}
		case <-p.exited:
			t.Fatalf("server exited before logging %q", message)
		case <-timeout:
			t.Fatalf("server did not log %q within 10s", message)
		}
	}
}

// signal sends sig to the server.
func (p *serverProcess) signal(t *testing.T, sig os.Signal) {
	t.Helper()
	if err := p.cmd.Process.Signal(sig); err != nil {
		t.Fatal(err)
	}
}

// waitExit waits up to timeout for the server to exit and returns its wait status.
func (p *serverProcess) waitExit(t *testing.T, timeout time.Duration) syscall.WaitStatus {
	t.Helper()
	select {
	case <-p.exited:
	case <-time.After(timeout):
		t.Fatalf("server still running %v after the signal", timeout)
	}
	status, ok := p.cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("process state is a %T, want syscall.WaitStatus", p.cmd.ProcessState.Sys())
	}
	return status
}

// stallUpload starts an upload through a batch request and sends only part of its body, leaving the handler waiting.
func stallUpload(t *testing.T, addr string) {
	t.Helper()
	data := bytes.Repeat([]byte("x"), 1000)
	sum := sha256.Sum256(data)
	oid := hex.EncodeToString(sum[:])

	body := fmt.Sprintf(`{"operation":"upload","objects":[{"oid":%q,"size":%d}]}`, oid, len(data))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+addr+"/org/repo/objects/batch", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/vnd.git-lfs+json")
	req.Header.Set("Content-Type", "application/vnd.git-lfs+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var batch struct {
		Objects []struct {
			Actions map[string]struct {
				Href string `json:"href"`
			} `json:"actions"`
		} `json:"objects"`
	}
	if err := json.UnmarshalRead(resp.Body, &batch); err != nil || len(batch.Objects) != 1 {
		t.Fatalf("batch response: %v, %+v", err, batch)
	}
	href, err := url.Parse(batch.Objects[0].Actions["upload"].Href)
	if err != nil {
		t.Fatal(err)
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	request := "PUT " + href.RequestURI() + " HTTP/1.1\r\nHost: " + addr + "\r\nContent-Length: 1000\r\nExpect: 100-continue\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(status, "100 Continue") {
		t.Fatalf("waiting for 100 Continue: %q, %v", status, err)
	}
	if _, err := conn.Write(data[:10]); err != nil {
		t.Fatal(err)
	}
}

func TestServeStopsCleanlyOnSignal(t *testing.T) {
	p := startServer(t, "30s")

	p.signal(t, syscall.SIGTERM)
	p.waitForLog(t, "shutting down; send the signal again to stop immediately")
	if status := p.waitExit(t, 10*time.Second); status.ExitStatus() != 0 {
		t.Errorf("exit status = %d, want 0", status.ExitStatus())
	}
}

func TestServeExitsNonZeroWhenShutdownTimesOut(t *testing.T) {
	p := startServer(t, "1s")
	stallUpload(t, p.addr)

	start := time.Now()
	p.signal(t, syscall.SIGTERM)
	p.waitForLog(t, "closing connections still open after shutdown_timeout")
	if status := p.waitExit(t, 10*time.Second); status.ExitStatus() != 1 {
		t.Errorf("exit status = %d, want 1", status.ExitStatus())
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Errorf("server exited after %v, before shutdown_timeout", elapsed)
	}
}

func TestServeSecondSignalStopsImmediately(t *testing.T) {
	p := startServer(t, "30s")
	stallUpload(t, p.addr)

	p.signal(t, syscall.SIGINT)
	p.waitForLog(t, "shutting down; send the signal again to stop immediately")
	select {
	case <-p.exited:
		t.Fatal("server exited on the first signal while an upload was in flight")
	case <-time.After(200 * time.Millisecond):
	}

	p.signal(t, syscall.SIGINT)
	status := p.waitExit(t, 5*time.Second)
	if !status.Signaled() || status.Signal() != syscall.SIGINT { //nolint:misspell // stdlib method name uses American English
		t.Errorf("wait status = %v, want killed by SIGINT", status)
	}
}
