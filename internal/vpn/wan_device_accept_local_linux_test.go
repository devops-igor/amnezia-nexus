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

func TestCheckAcceptLocalPrerequisite_AllStates(t *testing.T) {
	fakeErr := errors.New("read-only procfs: permission denied")

	// State 1: per-device succeeds, global disabled -> proceeds (nil)
	if err := checkAcceptLocalPrerequisite(nil, false, "nexus-wan0"); err != nil {
		t.Fatalf("expected nil when per-device succeeds, got %v", err)
	}

	// State 2: per-device fails, global enabled -> proceeds (nil, fallback logged)
	if err := checkAcceptLocalPrerequisite(fakeErr, true, "nexus-wan0"); err != nil {
		t.Fatalf("expected nil when global is enabled, got %v", err)
	}

	// State 3: per-device fails, global disabled -> fails closed with error
	err := checkAcceptLocalPrerequisite(fakeErr, false, "nexus-wan0")
	if err == nil {
		t.Fatal("expected error when both per-device and global are disabled/unconfigurable, got nil")
	}
	expectedSub := "wan prerequisites: accept_local is disabled on both all and nexus-wan0 (cannot inject SNAT packets without martian drop)"
	if !strings.Contains(err.Error(), expectedSub) {
		t.Fatalf("expected error containing %q, got %q", expectedSub, err.Error())
	}
	if !errors.Is(err, fakeErr) {
		t.Fatalf("expected wrapped error %v, got %v", fakeErr, err)
	}

	// State 4: per-device succeeds, global enabled -> proceeds (nil)
	if err := checkAcceptLocalPrerequisite(nil, true, "nexus-wan0"); err != nil {
		t.Fatalf("expected nil when both succeed, got %v", err)
	}
}
