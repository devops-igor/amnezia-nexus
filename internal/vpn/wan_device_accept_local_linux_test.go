//go:build linux

package vpn

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetAcceptLocal_ProcfsSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	procFile := filepath.Join(tmpDir, "accept_local")
	if err := os.WriteFile(procFile, []byte("0\n"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := setAcceptLocal(procFile, "net.ipv4.conf.test.accept_local"); err != nil {
		t.Fatalf("setAcceptLocal failed on writable file: %v", err)
	}

	data, err := os.ReadFile(procFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if strings.TrimSpace(string(data)) != "1" {
		t.Fatalf("expected accept_local=1, got %q", string(data))
	}
}

func TestSetAcceptLocal_ProcfsAlreadyOne(t *testing.T) {
	tmpDir := t.TempDir()
	procFile := filepath.Join(tmpDir, "accept_local")
	if err := os.WriteFile(procFile, []byte("1\n"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := setAcceptLocal(procFile, "net.ipv4.conf.test.accept_local"); err != nil {
		t.Fatalf("setAcceptLocal failed when already 1: %v", err)
	}
}

func TestSetAcceptLocal_FailureOnInvalidPath(t *testing.T) {
	err := setAcceptLocal("/proc/sys/net/ipv4/conf/nonexistent-device-xyz/accept_local", "net.ipv4.conf.nonexistent-xyz.accept_local")
	if err == nil {
		t.Fatal("expected error on nonexistent device accept_local configuration, got nil")
	}
}

func TestValidateKernelPrerequisites_AcceptLocalErrorDefined(t *testing.T) {
	if ErrAcceptLocalDisabled == nil {
		t.Fatal("ErrAcceptLocalDisabled must be non-nil")
	}
	if !strings.Contains(ErrAcceptLocalDisabled.Error(), "accept_local") {
		t.Fatalf("ErrAcceptLocalDisabled should describe accept_local requirement: %v", ErrAcceptLocalDisabled)
	}
}

func TestValidateKernelPrerequisites_Execution(t *testing.T) {
	err := ValidateKernelPrerequisites()
	if err != nil {
		t.Logf("ValidateKernelPrerequisites returned: %v", err)
		// If it failed on accept_local, it must be ErrAcceptLocalDisabled or a read error
		if errors.Is(err, ErrAcceptLocalDisabled) {
			t.Log("ValidateKernelPrerequisites correctly detected accept_local requirement")
		}
	}
}

func TestIsAllAcceptLocalEnabled(t *testing.T) {
	enabled := isAllAcceptLocalEnabled()
	t.Logf("isAllAcceptLocalEnabled returned %v", enabled)
}

func TestSetAcceptLocal_ReadOnlyFileFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permission bits; read-only test not meaningful as non-root")
	}
	tmpDir := t.TempDir()
	procFile := filepath.Join(tmpDir, "accept_local")
	if err := os.WriteFile(procFile, []byte("0\n"), 0400); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	err := setAcceptLocal(procFile, "net.ipv4.conf.test.accept_local")
	if err == nil {
		t.Fatal("expected setAcceptLocal to fail on read-only file, got nil")
	}
}
