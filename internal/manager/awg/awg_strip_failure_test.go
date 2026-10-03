package awg

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// stripFailureRecorder is a test double around mockAWGSSHClient that rejects the
// `awg-quick strip` operation (simulating the pinned AWG tools refusing a config
// that Go-side validation happily accepts) while counting how often syncconf is
// invoked.
type stripFailureRecorder struct {
	mock       *mockAWGSSHClient
	mu         sync.Mutex
	commands   []string
	syncconfs  int
	stripCalls int
	stripFails bool
}

func newStripFailureRecorder(stripFails bool) *stripFailureRecorder {
	r := &stripFailureRecorder{mock: newMockAWGSSHClient(), stripFails: stripFails}
	r.mock.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		r.mu.Lock()
		r.commands = append(r.commands, cmd)
		r.mu.Unlock()
		isStrip := strings.Contains(cmd, "awg-quick") && strings.Contains(cmd, "strip")
		isSyncconf := strings.Contains(cmd, "syncconf")
		switch {
		case isStrip && isSyncconf:
			// Fused `syncconf ... <(awg-quick strip ...)` compound. Model real
			// bash faithfully: the process substitution's producer failure is
			// discarded, syncconf receives an empty configuration (which the
			// pinned AWG tools apply as a zero private key) and the container
			// exits 0.
			r.mu.Lock()
			r.stripCalls++
			r.syncconfs++
			r.mu.Unlock()
			return "OK", "", 0, nil
		case isStrip:
			// Separately checked strip step: its exit status is visible.
			r.mu.Lock()
			r.stripCalls++
			r.mu.Unlock()
			if r.stripFails {
				return "", "Line 3: invalid SaveConfig value", 1, errors.New("exit status 1")
			}
			return "OK", "", 0, nil
		case isSyncconf:
			r.mu.Lock()
			r.syncconfs++
			r.mu.Unlock()
			return "OK", "", 0, nil
		}
		return r.mock.defaultRunSudo(cmd)
	}
	return r
}

func (r *stripFailureRecorder) counts() (stripCalls, syncconfs int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stripCalls, r.syncconfs
}

func (r *stripFailureRecorder) recordedCommands() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.commands))
	copy(out, r.commands)
	return out
}

// stripRejectedConfig is accepted by ParseServerConfig / ValidateAWGParams
// (unknown [Interface] keys are ignored on the Go side) but rejected by the
// container's awg-quick strip.
const stripRejectedConfig = `[Interface]
PrivateKey = serverPrivKey1234567890123456789012345=
Address = 10.8.1.1/24
ListenPort = 55424
MTU = 1280
Jc = 4
Jmin = 30
Jmax = 80
S1 = 40
S2 = 60
H1 = 12345
H2 = 67890
SaveConfig = false-but-not-a-valid-boolean

[Peer]
PublicKey = pubkey1
PresharedKey = pskKey12345678901234567889012345678901=
AllowedIPs = 10.8.1.2/32
`

const validServerConfig = `[Interface]
PrivateKey = serverPrivKey1234567890123456789012345=
Address = 10.8.1.1/24
ListenPort = 55424
MTU = 1280
Jc = 4
Jmin = 30
Jmax = 80
S1 = 40
S2 = 60
H1 = 12345
H2 = 67890

[Peer]
PublicKey = pubkey1
PresharedKey = pskKey12345678901234567889012345678901=
AllowedIPs = 10.8.1.2/32
`

// TestStripFailureNeverReachesSyncconf is the core regression: a config that Go
// accepts but awg-quick strip rejects must not be handed to syncconf at all, and
// must surface as an error so the caller rolls the disk configuration back.
func TestStripFailureNeverReachesSyncconf(t *testing.T) {
	ctx := context.Background()
	rec := newStripFailureRecorder(true)
	// Seed a persisted config that carries peer identity, so restoration is
	// checked against real interface identity rather than an empty section.
	rec.mock.files["/opt/amnezia/awg/awg0.conf"] = []byte(validServerConfig)
	original := string(rec.mock.files["/opt/amnezia/awg/awg0.conf"])

	mgr := NewAWGManager(&mockAWGSSHProvider{client: rec.mock})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	err := mgr.WriteConfiguration(ctx, server, stripRejectedConfig)
	if err == nil {
		t.Fatal("expected WriteConfiguration to fail when strip rejects the config, got nil")
	}
	if !strings.Contains(err.Error(), "strip") {
		t.Errorf("expected error to mention the failing strip, got: %v", err)
	}

	stripCalls, syncconfs := rec.counts()
	if stripCalls == 0 {
		t.Fatal("expected strip to be invoked as its own checked step")
	}
	if syncconfs != 0 {
		t.Errorf("syncconf must never run after a failed strip, got %d invocations; commands: %v", syncconfs, rec.recordedCommands())
	}

	// Identity preservation: the previously persisted configuration is restored.
	// WriteConfiguration restores through saveServerConfigTracked, which
	// normalises the interface table flag, so the restored bytes are the
	// pre-existing config with that (idempotent) normalisation applied - and
	// crucially never the rejected config that was written before the failure.
	want := EnsureInterfaceTableOff(original)
	got := string(rec.mock.files["/opt/amnezia/awg/awg0.conf"])
	if got != want {
		t.Errorf("expected the previous configuration to be restored after a rejected strip\n got: %q\nwant: %q", got, want)
	}
	if strings.Contains(got, "SaveConfig") {
		t.Errorf("rejected config leaked onto disk after a failed strip: %q", got)
	}
	if !strings.Contains(got, "PrivateKey = serverPrivKey1234567890123456789012345=") {
		t.Errorf("expected the original private key to survive a rejected strip, got: %q", got)
	}
	if !strings.Contains(got, "[Peer]") {
		t.Errorf("expected the original peer section to survive a rejected strip, got: %q", got)
	}
}

// TestStripAndSyncconfAreSeparateCheckedSteps asserts the command structure: the
// strip is a separate, exit-checked step that completes before syncconf runs, not
// a `syncconf ... <(strip ...)` process substitution.
func TestStripAndSyncconfAreSeparateCheckedSteps(t *testing.T) {
	ctx := context.Background()
	rec := newStripFailureRecorder(false)

	mgr := NewAWGManager(&mockAWGSSHProvider{client: rec.mock})
	if err := mgr.saveServerConfig(ctx, rec.mock, validServerConfig); err != nil {
		t.Fatalf("expected a valid config to save and sync, got: %v", err)
	}

	var stripIdx, syncIdx = -1, -1
	var stripCmd, syncCmd string
	for i, cmd := range rec.recordedCommands() {
		if strings.Contains(cmd, "awg-quick") && strings.Contains(cmd, "strip") && stripIdx == -1 {
			stripIdx, stripCmd = i, cmd
		}
		if strings.Contains(cmd, "syncconf") && syncIdx == -1 {
			syncIdx, syncCmd = i, cmd
		}
	}
	if stripIdx == -1 || syncIdx == -1 {
		t.Fatalf("expected both a strip and a syncconf command; stripIdx=%d syncIdx=%d commands=%v", stripIdx, syncIdx, rec.recordedCommands())
	}
	if stripIdx > syncIdx {
		t.Errorf("expected the checked strip to run before syncconf; stripIdx=%d syncIdx=%d", stripIdx, syncIdx)
	}
	if strings.Contains(syncCmd, "<(") {
		t.Errorf("syncconf must not consume strip via process substitution: %s", syncCmd)
	}
	if strings.Contains(syncCmd, "awg-quick") {
		t.Errorf("syncconf command must not embed a strip invocation: %s", syncCmd)
	}
	if !strings.Contains(stripCmd, "test -s") {
		t.Errorf("expected the strip step to check its own exit status / non-empty output: %s", stripCmd)
	}
	if !strings.Contains(syncCmd, ".awg-strip-") {
		t.Errorf("expected syncconf to read the checked stripped config, got: %s", syncCmd)
	}
}

// TestSyncconfFailureStillRetriesAfterRestore keeps the pre-existing retry
// semantics intact: a syncconf failure triggers restoreInterfaceIfDown and one
// retry.
func TestSyncconfFailureStillRetriesAfterRestore(t *testing.T) {
	ctx := context.Background()
	rec := newStripFailureRecorder(false)

	mgr := NewAWGManager(&mockAWGSSHProvider{client: rec.mock})
	attempts := 0
	restoreCalled := false
	base := rec.mock.sudoCmdHandler
	rec.mock.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		switch {
		case strings.Contains(cmd, "awg-quick") && strings.Contains(cmd, "strip"):
			return base(cmd)
		case strings.Contains(cmd, "syncconf"):
			attempts++
			if attempts == 1 {
				return "", "Unable to retrieve current interface configuration: Protocol not supported", 1, nil
			}
			return "OK", "", 0, nil
		case strings.Contains(cmd, "ip link show"):
			restoreCalled = true
			return "", "", 0, nil
		}
		return base(cmd)
	}

	if err := mgr.saveServerConfig(ctx, rec.mock, validServerConfig); err != nil {
		t.Fatalf("expected the retry after restore to succeed, got: %v", err)
	}
	if attempts != 2 {
		t.Errorf("expected exactly 2 syncconf attempts (initial + one retry), got %d", attempts)
	}
	if !restoreCalled {
		t.Error("expected restoreInterfaceIfDown to run after the first syncconf failure")
	}
}
