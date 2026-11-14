package xray

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// alwaysRunningMockSSHClient reports the container as running on every inspect,
// which is what the readiness loop sees on a slow host: the process is up, the
// listener is not.
type alwaysRunningMockSSHClient struct{ *mockXraySSHClient }

func (m *alwaysRunningMockSSHClient) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "docker inspect") && strings.Contains(cmd, XrayContainerName) {
		return "true false\n", "", 0, nil
	}
	return m.mockXraySSHClient.RunSudoCommand(ctx, cmd)
}

func readinessTestOptions() containerLaunchOptions {
	return containerLaunchOptions{
		server:        &models.Server{ID: 1, Host: "192.0.2.1"},
		portPrimary:   443,
		serverName:    "example.com",
		pubB64:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		shortID:       "0123456789abcdef",
		engineProfile: "legacy",
	}
}

func newReadinessManager() (*XrayManager, *alwaysRunningMockSSHClient) {
	mockSSH := &alwaysRunningMockSSHClient{mockXraySSHClient: newMockXraySSHClient()}
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	return mgr, mockSSH
}

// A container that is running but has not bound its port yet is a startup race,
// not a defect. Observed on the arm64 DEV runner as:
//
//	xray container failed REALITY handshake readiness probe:
//	vless: dial: dial tcp 172.17.0.1:443: connect: connection refused
func TestVerifyContainerReadiness_RetriesTransientListenerRefusal(t *testing.T) {
	mgr, mockSSH := newReadinessManager()

	attempts := 0
	mgr.SetVLESSProbeFunc(func(ctx context.Context, endpoint string, params models.VLESSRealityParams, timeout time.Duration) (int64, error) {
		attempts++
		if attempts < 3 {
			return 0, fmt.Errorf("vless: dial: dial tcp %s: connect: connection refused", endpoint)
		}
		return 7, nil
	})

	if err := mgr.verifyContainerReadiness(context.Background(), mockSSH, readinessTestOptions()); err != nil {
		t.Fatalf("expected readiness to succeed once the listener binds, got: %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 probe attempts (2 refusals then success), got %d", attempts)
	}
}

// The retry must be bounded: a listener that never binds still fails the install.
func TestVerifyContainerReadiness_RefusalIsBounded(t *testing.T) {
	mgr, mockSSH := newReadinessManager()

	attempts := 0
	mgr.SetVLESSProbeFunc(func(ctx context.Context, endpoint string, params models.VLESSRealityParams, timeout time.Duration) (int64, error) {
		attempts++
		return 0, fmt.Errorf("vless: dial: dial tcp %s: connect: connection refused", endpoint)
	})

	err := mgr.verifyContainerReadiness(context.Background(), mockSSH, readinessTestOptions())
	if err == nil {
		t.Fatal("expected readiness to fail when the listener never binds")
	}
	if !strings.Contains(err.Error(), "readiness probe") {
		t.Errorf("expected the error to name the readiness probe, got: %v", err)
	}
	if attempts < 2 {
		t.Errorf("expected more than one attempt before giving up, got %d", attempts)
	}
	if attempts > 100 {
		t.Errorf("retry loop is not bounded, made %d attempts", attempts)
	}
}

// A configuration defect must not be retried: repeating it only delays the
// failure and muddies the cause.
func TestVerifyContainerReadiness_VerificationFailureIsNotRetried(t *testing.T) {
	mgr, mockSSH := newReadinessManager()

	attempts := 0
	mgr.SetVLESSProbeFunc(func(ctx context.Context, endpoint string, params models.VLESSRealityParams, timeout time.Duration) (int64, error) {
		attempts++
		return 0, fmt.Errorf("vless: reality verification failed")
	})

	err := mgr.verifyContainerReadiness(context.Background(), mockSSH, readinessTestOptions())
	if err == nil {
		t.Fatal("expected readiness to fail on a verification error")
	}
	if attempts != 1 {
		t.Errorf("expected a verification failure to be reported on the first attempt, got %d", attempts)
	}
}
