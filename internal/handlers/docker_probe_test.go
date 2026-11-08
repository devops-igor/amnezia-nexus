package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/manager/dns"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// issue724VersionFailProtocolOK is the offline reproduction of the observed
// DEV-onboarding result asymmetry: the unprivileged `docker --version` probe
// fails while every privileged protocol query succeeds.
//
// It reproduces the *observable* contradiction from the failing run, not a
// claimed root cause. The mock cannot say why the unprivileged CLI was
// unreachable on that host; it only proves this endpoint would report
// docker_installed=false in exactly that situation while still listing live
// protocol status from the sudo path.
func issue724VersionFailProtocolOK() func(ctx context.Context, cmd string) (string, string, int, error) {
	return func(ctx context.Context, cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker --version") {
			// Exit 127 with empty stdout: the classic "command not found" shape.
			// stderr would normally carry the shell's message; it is omitted here
			// because the probe's stderr must never influence the verdict.
			return "", "", 127, nil
		}
		// Privileged protocol observations succeed on the same host, which is
		// what made the failing response self-contradictory.
		if strings.Contains(cmd, "docker ps -a") && strings.Contains(cmd, "amnezia-awg") {
			return "amnezia-awg2\n", "", 0, nil
		}
		if strings.Contains(cmd, "docker ps") && strings.Contains(cmd, "amnezia-awg") {
			return "Up 5 minutes\n", "", 0, nil
		}
		if strings.Contains(cmd, "wg0.conf") || strings.Contains(cmd, "awg0.conf") {
			return "[Interface]\nListenPort = 51820\nPrivateKey = server-priv-key\n", "", 0, nil
		}
		if strings.Contains(cmd, "wireguard_server_public_key.key") {
			return "probe-public-key\n", "", 0, nil
		}
		if strings.Contains(cmd, "wireguard_psk.key") {
			return "probe-psk\n", "", 0, nil
		}
		return "", "", 0, nil
	}
}

func newDockerProbeServer(t *testing.T, cmdFunc func(ctx context.Context, cmd string) (string, string, int, error)) (*Handlers, int64) {
	t.Helper()
	mockSSH := &testMockSSHClient{cmdFunc: cmdFunc}
	h, db, _ := setupTestHandlersWithMockSSH(t, mockSSH)
	ctx := context.Background()
	srv := &models.Server{
		Name:      "Probe-Server",
		Host:      "192.168.1.170",
		SSHPort:   22,
		SSHUser:   "ubuntu",
		SSHPass:   "pass123",
		Protocols: map[string]any{},
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	mockSSH.serverID = &serverID
	return h, serverID
}

func postServerCheck(t *testing.T, h *Handlers, serverID int64) map[string]any {
	t.Helper()
	r := setupFullServerRouter(h)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/check", serverID), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from /check, got %d (body: %s)", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode /check body: %v", err)
	}
	return body
}

// TestServerCheckHandler_DockerProbeAsymmetry reproduces issue #724's observed
// response shape: docker_installed=false together with live privileged protocol
// status. It pins both the unchanged verdict and the fact that the contradiction
// is reachable, so a future "fix" cannot quiet the assertion by misreporting the
// privileged path while leaving the unprivileged probe broken.
func TestServerCheckHandler_DockerProbeAsymmetry(t *testing.T) {
	h, serverID := newDockerProbeServer(t, issue724VersionFailProtocolOK())

	var logBuf testSyncWriter
	origLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(origLogger) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))

	body := postServerCheck(t, h, serverID)

	// Verdict semantics preserved: a failing unprivileged probe is still false.
	if got := body["docker_installed"]; got != false {
		t.Fatalf("expected docker_installed=false, got %v", got)
	}
	if got := body["connection"]; got != "ok" {
		t.Fatalf("expected connection=ok, got %v", got)
	}

	// The asymmetry itself: the privileged path still observes the container.
	protocols, ok := body["protocols"].(map[string]any)
	if !ok {
		t.Fatalf("expected protocols map, got %T", body["protocols"])
	}
	awgStatus, ok := protocols["awg"].(map[string]any)
	if !ok {
		t.Fatalf("expected awg status present (the reported contradiction), got protocols=%+v", protocols)
	}
	if running, _ := awgStatus["container_running"].(bool); !running {
		t.Fatalf("expected awg.container_running=true from the privileged path, got %v", awgStatus["container_running"])
	}

	// The failure must now be diagnosable: bounded facts, no raw host output.
	logs := logBuf.String()
	if !strings.Contains(logs, "docker CLI probe failed") {
		t.Fatalf("expected a diagnostic log for the failed probe, got:\n%s", logs)
	}
	for _, want := range []string{
		"server_id", "exit_code=127", "transport_error=",
		"stdout_len=0", "stdout_state=empty", "stderr_len=0",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("expected probe log to include %q, got:\n%s", want, logs)
		}
	}
}

// TestServerCheckHandler_DockerProbeSuccess verifies the success path keeps the
// verdict true and stays silent: the lifecycle suite polls this endpoint every
// few seconds, so a healthy probe must not emit a warning.
func TestServerCheckHandler_DockerProbeSuccess(t *testing.T) {
	h, serverID := newDockerProbeServer(t, func(ctx context.Context, cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker --version") {
			return "Docker version 24.0.5, build cedb786\n", "", 0, nil
		}
		return "", "", 0, nil
	})

	var logBuf testSyncWriter
	origLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(origLogger) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))

	body := postServerCheck(t, h, serverID)
	if got := body["docker_installed"]; got != true {
		t.Fatalf("expected docker_installed=true, got %v", got)
	}
	if logs := logBuf.String(); strings.Contains(logs, "docker CLI probe failed") {
		t.Fatalf("healthy probe must not log a failure, got:\n%s", logs)
	}
}

// TestServerCheckHandler_DockerProbePrivacy is the negative privacy control:
// hostile or sensitive output from the managed host must never reach the log.
// Only bounded categories and lengths may be recorded.
func TestServerCheckHandler_DockerProbePrivacy(t *testing.T) {
	const (
		hostileStdout = "PRIVATE_KEY=-----BEGIN OPENSSH PRIVATE KEY-----\nroot@internal-host.example.com:/home/ubuntu/.ssh/id_ed25519\n"
		hostileStderr = "bash: docker: command not found at /usr/local/bin/docker user=ubuntu host=10.1.2.3\n"
	)
	h, serverID := newDockerProbeServer(t, func(ctx context.Context, cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker --version") {
			return hostileStdout, hostileStderr, 127, nil
		}
		return "", "", 0, nil
	})

	var logBuf testSyncWriter
	origLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(origLogger) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))

	body := postServerCheck(t, h, serverID)
	if got := body["docker_installed"]; got != false {
		t.Fatalf("expected docker_installed=false for a non-zero exit, got %v", got)
	}

	logs := logBuf.String()
	if !strings.Contains(logs, "docker CLI probe failed") {
		t.Fatalf("expected a diagnostic log, got:\n%s", logs)
	}
	for _, leaked := range []string{
		"PRIVATE KEY", "OPENSSH", "internal-host", "id_ed25519",
		"command not found", "/usr/local/bin", "10.1.2.3", "user=ubuntu",
		"ubuntu", "192.168.1.170",
	} {
		if strings.Contains(logs, leaked) {
			t.Errorf("probe log leaked %q; log was:\n%s", leaked, logs)
		}
	}
	// Lengths are recorded as facts, not content.
	if !strings.Contains(logs, fmt.Sprintf("stdout_len=%d", len(hostileStdout))) {
		t.Errorf("expected stdout_len=%d in log, got:\n%s", len(hostileStdout), logs)
	}
	if !strings.Contains(logs, fmt.Sprintf("stderr_len=%d", len(hostileStderr))) {
		t.Errorf("expected stderr_len=%d in log, got:\n%s", len(hostileStderr), logs)
	}
}

// TestServerCheckHandler_DockerProbeResponseUnchanged pins that the diagnostic
// work added no new response fields: the contract stays
// connection/docker_installed/protocols, so the E2E assertion surface is
// identical.
func TestServerCheckHandler_DockerProbeResponseUnchanged(t *testing.T) {
	h, serverID := newDockerProbeServer(t, issue724VersionFailProtocolOK())
	body := postServerCheck(t, h, serverID)

	allowed := map[string]bool{"connection": true, "docker_installed": true, "protocols": true}
	for key := range body {
		if !allowed[key] {
			t.Errorf("response gained unexpected field %q; body: %+v", key, body)
		}
	}
	for key := range allowed {
		if _, ok := body[key]; !ok {
			t.Errorf("response lost required field %q; body: %+v", key, body)
		}
	}
}

// TestProbeDockerPresence_Classification exercises the bounded classifiers
// directly, including transport-error categories that must not leak raw text.
func TestProbeDockerPresence_Classification(t *testing.T) {
	cases := []struct {
		name        string
		stdout      string
		stderr      string
		code        int
		err         error
		wantInstall bool
		wantOut     string
		wantErrCat  string
	}{
		{"success", "Docker version 24.0.5\n", "", 0, nil, true, probeOutDockerToken, probeErrNone},
		{"success uppercase", "DOCKER VERSION 24\n", "", 0, nil, true, probeOutDockerToken, probeErrNone},
		{"not found", "", "bash: docker: command not found\n", 127, nil, false, probeOutEmpty, probeErrNone},
		{"empty stdout exit0", "", "", 0, nil, false, probeOutEmpty, probeErrNone},
		{"non-docker text", "podman 4.9\n", "", 0, nil, false, probeOutOther, probeErrNone},
		{"timeout", "", "", -1, fmt.Errorf("wrap: %w", ssh.ErrCommandTimeout), false, probeOutEmpty, probeErrTimeout},
		{"canceled", "", "", -1, context.Canceled, false, probeOutEmpty, probeErrCanceled},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := &testMockSSHClient{cmdFunc: func(ctx context.Context, cmd string) (string, string, int, error) {
				return tc.stdout, tc.stderr, tc.code, tc.err
			}}
			got := probeDockerPresence(context.Background(), mock)
			if got.Installed != tc.wantInstall {
				t.Errorf("Installed = %v, want %v", got.Installed, tc.wantInstall)
			}
			if got.StdoutState != tc.wantOut {
				t.Errorf("StdoutState = %q, want %q", got.StdoutState, tc.wantOut)
			}
			if got.TransportError != tc.wantErrCat {
				t.Errorf("TransportError = %q, want %q", got.TransportError, tc.wantErrCat)
			}
			if got.StdoutLen != len(tc.stdout) {
				t.Errorf("StdoutLen = %d, want %d", got.StdoutLen, len(tc.stdout))
			}
			if got.StderrLen != len(tc.stderr) {
				t.Errorf("StderrLen = %d, want %d", got.StderrLen, len(tc.stderr))
			}
		})
	}
}

// TestDockerPresenceProbe_TransportErrorNeverLeaksRawText proves the classifier
// collapses arbitrary error text to a category, even when the wrapped error
// embeds host details.
func TestDockerPresenceProbe_TransportErrorNeverLeaksRawText(t *testing.T) {
	const secretish = "dial tcp 10.9.8.7:22: connect: no route to host (user=ubuntu)"
	got := classifyProbeError(fmt.Errorf("%s", secretish))
	if got == secretish || strings.Contains(got, "10.9.8.7") || strings.Contains(got, "ubuntu") {
		t.Fatalf("classifyProbeError leaked raw error text: %q", got)
	}
	if got != probeErrOther {
		t.Fatalf("expected probeErrOther for an unrecognised error, got %q", got)
	}
}

// TestDockerPresenceProbe_LogFailureSkipsSuccess pins the silence contract.
func TestDockerPresenceProbe_LogFailureSkipsSuccess(t *testing.T) {
	var logBuf testSyncWriter
	origLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(origLogger) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))

	dockerPresenceProbe{Installed: true}.logFailure(1)
	if logs := logBuf.String(); logs != "" {
		t.Fatalf("successful probe must log nothing, got:\n%s", logs)
	}
}

// Compile-time guards: the reproduction targets the same container names the
// production managers use, so a rename cannot silently make the asymmetry test
// vacuous.
var (
	_ = awg.AWGContainerNames
	_ = dns.DNSContainerName
)
