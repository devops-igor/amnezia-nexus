package awg

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// R3-2 ambiguous-recovery tests. Since the R3-2 routing change,
// writeConfigurationTransaction compensates EVERY attempted write: an
// ambiguous copy outcome (the SSH result lost to cancellation, timeout or
// transport failure after the copy was invoked) routes through the bounded
// detached restore exactly like a known disk write, and the transaction may
// only report success-path errors when disk, runtime and identity artifacts
// are ALL proven restored.
//
// The oracle is the container state at the SSH seam, modeled independently per
// layer (identity_fixture_test.go machinery):
//
//   - disk: files[r31DiskPath] (the docker cp destination, byte-compare),
//   - runtime: livePublicKey, updated only by a successful syncconf,
//   - artifacts: the private/public key files, updated only by
//     reconcileServerIdentity.
//
// The context proof: the seam records ctx.Err() == nil for every command. The
// candidate copy must observe the dead request context while every restore
// command must observe a LIVE one (the restore derives its bounded context
// from context.WithoutCancel), so passing the raw request context into the
// restore fails these tests.
//
// Determinism: all seams are synchronous command intercepts; there are no
// sleeps and no real SSH.

// r32CtxProbe records one intercepted command: which stage it belongs to and
// whether its context was still alive when the seam saw it.
type r32CtxProbe struct {
	kind  string // candidate-copy, restore-copy, strip, syncconf, artifact
	alive bool
}

// r32SeamSSHClient wraps the identity fixture and injects exactly one
// ambiguity or restore-stage failure at a time. Everything else — remote
// lock, container discovery, configuration read, uploads, cleanup — flows
// through to the fixture handlers, so the only behavioral levers are the
// compensation boundaries under test.
type r32SeamSSHClient struct {
	*identityFixture
	// copyErr, when non-nil, is the SSH-level error returned by the CANDIDATE
	// copy only (canceled / deadline / transport class). The compensation copy
	// flows through to the fixture.
	copyErr error
	// copyCode, when copyErr == nil and nonzero, is the candidate copy's exit
	// status (nonzero-exit ambiguity class).
	copyCode int
	// failRestoreCopy fails the compensation copy with a nonzero exit.
	failRestoreCopy bool
	// failRestoreStrip / failRestoreSync fail the restore's awg-quick strip /
	// syncconf step.
	failRestoreStrip bool
	failRestoreSync  bool
	// artifactErr, when non-nil, fails every artifact-refresh invocation
	// (apply-time and restore-time alike).
	artifactErr error

	copyInvocations int
	probes          []r32CtxProbe
}

func (c *r32SeamSSHClient) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	isCopy := strings.Contains(cmd, "docker cp") && strings.Contains(cmd, "_amnz_edit_config_")
	isStrip := strings.Contains(cmd, "awg-quick") && strings.Contains(cmd, " strip ")
	isSync := strings.Contains(cmd, "syncconf")
	isArtifact := strings.Contains(cmd, "bash -c") && strings.Contains(cmd, serverPublicKeyArtifactPath)

	if isCopy {
		c.copyInvocations++
		kind := "restore-copy"
		if c.copyInvocations == 1 {
			kind = "candidate-copy"
		}
		c.probes = append(c.probes, r32CtxProbe{kind: kind, alive: ctx.Err() == nil})
		// The ambiguity levers inject into the CANDIDATE copy only; the
		// compensation copy must reach the fixture so the restore can really
		// re-establish the original bytes.
		if c.copyInvocations == 1 {
			if c.copyErr != nil {
				// SSH-level error classes model the transport contract: the
				// copy COMPLETED inside the container and only its result was
				// lost, so the candidate bytes land in the container BEFORE
				// the error surfaces. A nonzero exit class is a known
				// server-side failure: nothing is applied.
				if _, _, _, applyErr := c.mockAWGSSHClient.RunSudoCommand(ctx, cmd); applyErr != nil {
					return "", "", -1, applyErr
				}
				return "", "", -1, c.copyErr
			}
			if c.copyCode != 0 {
				return "", "candidate copy failed", c.copyCode, nil
			}
		} else if c.failRestoreCopy {
			return "", "restore copy refused", 1, nil
		}
		return c.mockAWGSSHClient.RunSudoCommand(ctx, cmd)
	}
	if isStrip {
		c.probes = append(c.probes, r32CtxProbe{kind: "strip", alive: ctx.Err() == nil})
		if c.failRestoreStrip {
			return "", "restore strip refused", 1, nil
		}
	}
	if isSync {
		c.probes = append(c.probes, r32CtxProbe{kind: "syncconf", alive: ctx.Err() == nil})
		if c.failRestoreSync {
			return "", "restore syncconf refused", 1, nil
		}
	}
	if isArtifact {
		c.probes = append(c.probes, r32CtxProbe{kind: "artifact", alive: ctx.Err() == nil})
		if c.artifactErr != nil {
			return "", "artifact refresh refused", 1, c.artifactErr
		}
	}
	return c.mockAWGSSHClient.RunSudoCommand(ctx, cmd)
}

// r32SeamProvider returns the seam client from Get; the stock mockAWGSSHProvider
// hands back the concrete mock and cannot surface a wrapper.
type r32SeamProvider struct {
	client *r32SeamSSHClient
}

func (p *r32SeamProvider) Get(ctx context.Context, server *models.Server) (ssh.SSHClient, error) {
	return p.client, nil
}

// r32Harness wires the identity fixture behind the R3-2 seam. The server
// starts at the OLD identity (disk, runtime and artifacts coherent); the
// candidate write rotates it to the NEW identity, so every compensation must
// bring all three layers back to OLD.
type r32Harness struct {
	m      *AWGManager
	server *models.Server
	client *r32SeamSSHClient
	oldPriv,
	oldPub,
	newPriv,
	newPub string
}

func r32NewHarness(t *testing.T, configure func(*r32SeamSSHClient)) *r32Harness {
	t.Helper()
	oldPriv, oldPub := identityTestKeypair(t, 120)
	newPriv, newPub := identityTestKeypair(t, 121)
	fixture := newIdentityFixture(oldPriv, oldPub, true)
	c := &r32SeamSSHClient{identityFixture: fixture}
	if configure != nil {
		configure(c)
	}
	return &r32Harness{
		m:       NewAWGManager(&r32SeamProvider{client: c}),
		server:  identityServer(),
		client:  c,
		oldPriv: oldPriv,
		oldPub:  oldPub,
		newPriv: newPriv,
		newPub:  newPub,
	}
}

// r32RequireCoherentOriginalIdentity asserts the restored container state at
// the seam level: disk bytes, runtime interface identity and key artifacts all
// describe the ORIGINAL identity. Each layer is checked independently — a
// restored disk with a stale runtime or artifact cannot pass.
func r32RequireCoherentOriginalIdentity(t *testing.T, h *r32Harness) {
	t.Helper()
	if got := interfacePrivateKey(string(h.client.files[r31DiskPath])); got != h.oldPriv {
		t.Error("disk must hold the ORIGINAL configuration after compensation")
	}
	if got := string(h.client.files[serverPrivateKeyArtifactPath]); got != h.oldPriv {
		t.Error("private identity artifact must hold the ORIGINAL key after compensation")
	}
	if got := string(h.client.files[serverPublicKeyArtifactPath]); got != h.oldPub {
		t.Error("public identity artifact must hold the ORIGINAL key after compensation")
	}
	if got := h.client.livePublicKey; got != h.oldPub {
		t.Error("runtime interface must answer with the ORIGINAL public key after compensation")
	}
}

// r32RequireRestoreRan asserts the compensation was really issued at the seam:
// the candidate copy plus exactly one restore copy.
func r32RequireRestoreRan(t *testing.T, h *r32Harness) {
	t.Helper()
	if h.client.copyInvocations != 2 {
		t.Fatalf("expected candidate copy + restore copy (2), got %d copy invocations", h.client.copyInvocations)
	}
}

func r32ProbeKinds(c *r32SeamSSHClient, kind string) []bool {
	var alive []bool
	for _, p := range c.probes {
		if p.kind == kind {
			alive = append(alive, p.alive)
		}
	}
	return alive
}

// TestR32_AmbiguousCanceledCopyCompensates: the copy completed (or not) inside
// the container and the SSH result was lost to request cancellation. The
// transaction must compensate: restore attempted with the ORIGINAL bytes, all
// three layers back to OLD, and the ORIGINAL cause surfaced without a
// rollback-failed marker (the restore itself succeeded).
func TestR32_AmbiguousCanceledCopyCompensates(t *testing.T) {
	h := r32NewHarness(t, func(c *r32SeamSSHClient) {
		c.copyErr = context.Canceled
	})
	requestCtx, cancel := context.WithCancel(context.Background())
	cancel()

	err := h.m.WriteConfiguration(requestCtx, h.server, identityServerConfig(h.newPriv))

	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("the original cancellation must be preserved, got: %v", err)
	}
	if errors.Is(err, ErrConfigurationRollbackFailed) {
		t.Errorf("a successful compensation must not report ErrConfigurationRollbackFailed, got: %v", err)
	}
	r32RequireRestoreRan(t, h)
	r32RequireCoherentOriginalIdentity(t, h)
}

// TestR32_AmbiguousNonzeroCopyExitCompensates: the copy command was invoked
// and answered with a nonzero exit status (outcome known-mutated or
// ambiguous). Compensation must run exactly as for the SSH-error classes.
func TestR32_AmbiguousNonzeroCopyExitCompensates(t *testing.T) {
	h := r32NewHarness(t, func(c *r32SeamSSHClient) {
		c.copyCode = 7
	})

	err := h.m.WriteConfiguration(context.Background(), h.server, identityServerConfig(h.newPriv))

	if err == nil || !strings.Contains(err.Error(), "failed to copy config into container") {
		t.Fatalf("the original copy failure must be preserved, got: %v", err)
	}
	if errors.Is(err, ErrConfigurationRollbackFailed) {
		t.Errorf("a successful compensation must not report ErrConfigurationRollbackFailed, got: %v", err)
	}
	r32RequireRestoreRan(t, h)
	r32RequireCoherentOriginalIdentity(t, h)
}

// TestR32_RestoreRunsOnFreshContextWhenRequestContextDead is the fresh-context
// proof: the request context is already dead when the ambiguous outcome is
// classified, and the restore must still run — on its own bounded context.
// The seam records per-command context liveness: the candidate copy must see
// the dead request context, and EVERY restore command (restore copy, strip,
// syncconf, artifact refresh) must see a live one. Routing the restore on the
// raw request context fails this test.
func TestR32_RestoreRunsOnFreshContextWhenRequestContextDead(t *testing.T) {
	h := r32NewHarness(t, func(c *r32SeamSSHClient) {
		c.copyErr = context.DeadlineExceeded
	})
	requestCtx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-requestCtx.Done()

	err := h.m.WriteConfiguration(requestCtx, h.server, identityServerConfig(h.newPriv))

	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the original deadline must be preserved, got: %v", err)
	}
	r32RequireRestoreRan(t, h)

	candidate := r32ProbeKinds(h.client, "candidate-copy")
	if len(candidate) != 1 || candidate[0] {
		t.Errorf("candidate copy must observe the dead request context, got %v", candidate)
	}
	for _, kind := range []string{"restore-copy", "strip", "syncconf", "artifact"} {
		alive := r32ProbeKinds(h.client, kind)
		if len(alive) == 0 {
			t.Errorf("restore stage %s never reached the seam", kind)
			continue
		}
		for i, isAlive := range alive {
			if !isAlive {
				t.Errorf("restore stage %s invocation %d inherited the canceled request context", kind, i+1)
			}
		}
	}
	r32RequireCoherentOriginalIdentity(t, h)
}

// TestR32_RestoreCopyFailurePreservesCause: the compensation copy itself
// fails. The transaction reports the rollback failure WITH the original cause,
// and the stage evidence shows the restore never reached strip/syncconf or the
// artifacts: disk stays NEW, runtime and artifacts stay untouched.
func TestR32_RestoreCopyFailurePreservesCause(t *testing.T) {
	transportErr := errors.New("ssh: connection lost")
	h := r32NewHarness(t, func(c *r32SeamSSHClient) {
		c.copyErr = transportErr
		c.failRestoreCopy = true
	})

	err := h.m.WriteConfiguration(context.Background(), h.server, identityServerConfig(h.newPriv))

	if err == nil || !errors.Is(err, transportErr) {
		t.Fatalf("the original transport error must be preserved, got: %v", err)
	}
	if !errors.Is(err, ErrConfigurationRollbackFailed) {
		t.Errorf("a failed restore must report ErrConfigurationRollbackFailed, got: %v", err)
	}
	r32RequireRestoreRan(t, h)
	if got := interfacePrivateKey(string(h.client.files[r31DiskPath])); got != h.newPriv {
		t.Error("a failed restore copy must leave the NEW bytes on disk")
	}
	if got := len(r32ProbeKinds(h.client, "strip")); got != 0 {
		t.Errorf("restore must fail before the strip stage, got %d strip invocations", got)
	}
	if got := len(r32ProbeKinds(h.client, "artifact")); got != 0 {
		t.Errorf("restore must fail before the artifact stage, got %d artifact invocations", got)
	}
	if got := h.client.livePublicKey; got != h.oldPub {
		t.Error("runtime must stay at the OLD identity when the restore copy failed")
	}
}

// TestR32_RestoreStripFailurePreservesCause: the restore copy persisted the
// ORIGINAL bytes but the checked awg-quick strip rejected them. The restore is
// reported failed with the original cause preserved; syncconf and the
// artifacts were never reached.
func TestR32_RestoreStripFailurePreservesCause(t *testing.T) {
	h := r32NewHarness(t, func(c *r32SeamSSHClient) {
		c.copyErr = context.Canceled
		c.failRestoreStrip = true
	})

	err := h.m.WriteConfiguration(context.Background(), h.server, identityServerConfig(h.newPriv))

	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("the original cancellation must be preserved, got: %v", err)
	}
	if !errors.Is(err, ErrConfigurationRollbackFailed) {
		t.Errorf("a failed restore must report ErrConfigurationRollbackFailed, got: %v", err)
	}
	r32RequireRestoreRan(t, h)
	if got := interfacePrivateKey(string(h.client.files[r31DiskPath])); got != h.oldPriv {
		t.Error("the restore copy must already have persisted the ORIGINAL bytes")
	}
	if got := len(r32ProbeKinds(h.client, "strip")); got != 1 {
		t.Errorf("expected exactly one (failing) strip invocation, got %d", got)
	}
	if got := len(r32ProbeKinds(h.client, "syncconf")); got != 0 {
		t.Errorf("syncconf must be unreachable after a failed strip, got %d invocations", got)
	}
	if got := len(r32ProbeKinds(h.client, "artifact")); got != 0 {
		t.Errorf("restore must fail before the artifact stage, got %d artifact invocations", got)
	}
	if got := h.client.livePublicKey; got != h.oldPub {
		t.Error("runtime must stay at the OLD identity when the restore strip failed")
	}
}

// TestR32_RestoreSyncconfFailurePreservesCause: the restore copy and strip
// succeeded but syncconf failed (after its awg-quick-up retry). Disk and
// strip-stage evidence present, runtime unrestored, artifacts never reached.
func TestR32_RestoreSyncconfFailurePreservesCause(t *testing.T) {
	h := r32NewHarness(t, func(c *r32SeamSSHClient) {
		c.copyErr = context.Canceled
		c.failRestoreSync = true
	})

	err := h.m.WriteConfiguration(context.Background(), h.server, identityServerConfig(h.newPriv))

	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("the original cancellation must be preserved, got: %v", err)
	}
	if !errors.Is(err, ErrConfigurationRollbackFailed) {
		t.Errorf("a failed restore must report ErrConfigurationRollbackFailed, got: %v", err)
	}
	r32RequireRestoreRan(t, h)
	if got := interfacePrivateKey(string(h.client.files[r31DiskPath])); got != h.oldPriv {
		t.Error("the restore copy must already have persisted the ORIGINAL bytes")
	}
	// One failing syncconf + one retry after the interface-down rescue.
	if got := len(r32ProbeKinds(h.client, "syncconf")); got != 2 {
		t.Errorf("expected the failing syncconf and its single retry, got %d invocations", got)
	}
	if got := len(r32ProbeKinds(h.client, "artifact")); got != 0 {
		t.Errorf("restore must fail before the artifact stage, got %d artifact invocations", got)
	}
	if got := h.client.livePublicKey; got != h.oldPub {
		t.Error("runtime must stay at the OLD identity when the restore syncconf failed")
	}
}

// TestR32_RestoreArtifactFailurePreservesCause: the disk write failed
// ambiguously and the restore re-establishes disk and runtime successfully,
// but the restore-time identity artifact refresh fails. The transaction must
// still report failure with the original cause — success requires ALL three
// layers proven — and the evidence shows each layer's independent outcome:
// disk OLD, runtime OLD, artifacts never refreshed (OLD). The apply-time
// reconciliation never ran because the candidate write itself failed.
func TestR32_RestoreArtifactFailurePreservesCause(t *testing.T) {
	artifactErr := errors.New("artifact refresh fixture failure")
	h := r32NewHarness(t, func(c *r32SeamSSHClient) {
		c.copyErr = context.Canceled
		c.artifactErr = artifactErr
	})

	err := h.m.WriteConfiguration(context.Background(), h.server, identityServerConfig(h.newPriv))

	if err == nil || !errors.Is(err, artifactErr) || !errors.Is(err, context.Canceled) {
		t.Fatalf("the original cause and the artifact failure must both be preserved, got: %v", err)
	}
	if !errors.Is(err, ErrConfigurationRollbackFailed) {
		t.Errorf("a failed restore must report ErrConfigurationRollbackFailed, got: %v", err)
	}
	r32RequireRestoreRan(t, h)
	if got := interfacePrivateKey(string(h.client.files[r31DiskPath])); got != h.oldPriv {
		t.Error("disk must be restored to the ORIGINAL bytes")
	}
	if got := h.client.livePublicKey; got != h.oldPub {
		t.Error("runtime must be restored to the ORIGINAL identity independently of disk")
	}
	if got := string(h.client.files[serverPublicKeyArtifactPath]); got != h.oldPub {
		t.Error("the failed artifact refresh must leave the artifacts untouched (OLD)")
	}
	// Only the restore-time refresh runs: the apply-time reconciliation is
	// unreachable after a failed candidate write.
	if got := len(r32ProbeKinds(h.client, "artifact")); got != 1 {
		t.Errorf("expected exactly one (failing) restore-time artifact refresh, got %d", got)
	}
}

// TestR32_ApplyArtifactFailureStillRestoresAndPreservesCause keeps the
// historical non-ambiguous path honest: an apply-time artifact failure still
// compensates, and when the SAME stage fails during the restore, the reported
// error carries the original cause plus the rollback marker — without ever
// reaching postApply.
func TestR32_ApplyArtifactFailureStillRestoresAndPreservesCause(t *testing.T) {
	artifactErr := errors.New("artifact refresh fixture failure")
	h := r32NewHarness(t, func(c *r32SeamSSHClient) {
		c.artifactErr = artifactErr
	})
	postApplyRan := false

	err := h.m.WriteConfigurationWithPostApply(context.Background(), h.server, identityServerConfig(h.newPriv), func(context.Context) error {
		postApplyRan = true
		return nil
	})

	if postApplyRan {
		t.Error("postApply must never run after a failed apply-time reconciliation")
	}
	if err == nil || !errors.Is(err, artifactErr) {
		t.Fatalf("the original artifact failure must be preserved, got: %v", err)
	}
	if !errors.Is(err, ErrConfigurationRollbackFailed) {
		t.Errorf("a failed restore must report ErrConfigurationRollbackFailed, got: %v", err)
	}
	r32RequireRestoreRan(t, h)
	// The apply-time refresh failed (invocation 1) and the restore-time
	// refresh failed too (invocation 2).
	if got := len(r32ProbeKinds(h.client, "artifact")); got != 2 {
		t.Errorf("expected the apply-time and restore-time artifact refreshes, got %d", got)
	}
	r32RequireCoherentOriginalIdentity(t, h)
}

// TestR32_PostApplyFailureRestoresCoherentOriginalState: postApply owns
// caller-side state and failed; the remote compensation succeeds, so the
// transaction reports exactly the postApply cause (wrapped with
// ErrConfigurationPostApply, no rollback marker) and the container is fully
// back at the ORIGINAL identity — disk, runtime and artifacts, each asserted.
func TestR32_PostApplyFailureRestoresCoherentOriginalState(t *testing.T) {
	postApplyErr := errors.New("caller reconciliation failed")
	h := r32NewHarness(t, nil)
	called := false

	err := h.m.WriteConfigurationWithPostApply(context.Background(), h.server, identityServerConfig(h.newPriv), func(context.Context) error {
		called = true
		return postApplyErr
	})

	if !called {
		t.Error("postApply must run after a successful write")
	}
	if err == nil || !errors.Is(err, postApplyErr) || !errors.Is(err, ErrConfigurationPostApply) {
		t.Fatalf("the postApply cause must be preserved, got: %v", err)
	}
	if errors.Is(err, ErrConfigurationRollbackFailed) {
		t.Errorf("a successful compensation must not report ErrConfigurationRollbackFailed, got: %v", err)
	}
	r32RequireRestoreRan(t, h)
	r32RequireCoherentOriginalIdentity(t, h)
	// The identity was rotated by the candidate, so both the apply-time and
	// the restore-time reconciliation refresh the artifacts.
	if got := len(r32ProbeKinds(h.client, "artifact")); got != 2 {
		t.Errorf("expected apply-time and restore-time artifact refreshes, got %d", got)
	}
}

// TestR32_SuccessfulWriteLeavesNewIdentityCoherent pins the positive path the
// compensation must not disturb: a clean write leaves the NEW configuration on
// disk (normalized), the NEW runtime identity live, and the NEW artifacts in
// place, with exactly one copy invocation and no restore.
func TestR32_SuccessfulWriteLeavesNewIdentityCoherent(t *testing.T) {
	h := r32NewHarness(t, nil)

	err := h.m.WriteConfiguration(context.Background(), h.server, identityServerConfig(h.newPriv))

	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if h.client.copyInvocations != 1 {
		t.Errorf("a successful write must not compensate, got %d copy invocations", h.client.copyInvocations)
	}
	if got := interfacePrivateKey(string(h.client.files[r31DiskPath])); got != h.newPriv {
		t.Error("disk must hold the NEW configuration")
	}
	if want := EnsureInterfaceTableOff(identityServerConfig(h.newPriv)); string(h.client.files[r31DiskPath]) != want {
		t.Error("disk must hold the normalized NEW configuration bytes")
	}
	if got := h.client.livePublicKey; got != h.newPub {
		t.Error("runtime must answer with the NEW public key")
	}
	if got := string(h.client.files[serverPublicKeyArtifactPath]); got != h.newPub {
		t.Error("public artifact must hold the NEW public key")
	}
	if got := string(h.client.files[serverPrivateKeyArtifactPath]); got != h.newPriv {
		t.Error("private artifact must hold the NEW private key")
	}
}
