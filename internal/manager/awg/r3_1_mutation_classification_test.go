package awg

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// R3-1 classification tests. Every case drives the real manager transaction
// (WriteConfiguration / WriteConfigurationWithPostApply) over a fake SSH seam;
// no real SSH or containers are involved. The oracle is the classification
// exposed to the transaction, observed through routing:
//
//   - pre-copy failures (validation, path resolution, upload preparation) must
//     classify configMutationNotAttempted: no ambiguity, no compensation;
//   - every post-invocation error class (canceled context, deadline exceeded,
//     nonzero copy exit) must classify attempted/may-have-mutated — no SSH
//     error is proof of no side effect;
//   - post-copy strip/syncconf failure classifies disk-written and keeps the
//     historical compensation behavior;
//   - success classifies configMutationSucceeded.
//
// The compensation ROUTING for ambiguous classes is deliberately NOT changed
// here (that is R3-2; see the TODO-R3-2 markers in writeConfigurationTransaction):
// ambiguous outcomes still return without compensation, exactly as before.
// These tests pin the classification itself, so reverting the flag semantics
// (classifying post-invocation errors as not-attempted) makes them fail.

const r31DiskPath = "/opt/amnezia/awg/awg0.conf"

// r31SeamSSHClient is otherwise fully transparent and fails only the FIRST
// copy invocation of the uploaded candidate (/tmp/_amnz_edit_config_*), its
// SFTP upload, or the awg-quick strip step. Since R3-2 the transaction runs a
// second (compensation) copy on ambiguous outcomes; that copy must flow
// through to the mock so the restore really re-establishes the original
// bytes. Everything else — remote lock, container discovery, configuration
// read, cleanup rm -f — flows through to the embedded mock, so the only
// behavioral levers are exactly the classified boundaries.
type r31SeamSSHClient struct {
	*mockAWGSSHClient
	// copyErr, when non-nil, is the SSH-level error returned by the copy.
	copyErr error
	// copyCode, when copyErr == nil and nonzero, is the copy's exit status.
	copyCode int
	// uploadErr, when non-nil, fails the candidate upload (pre-copy).
	uploadErr error
	// failStrip rejects the awg-quick strip step (post-copy).
	failStrip bool

	copyInvoked     bool
	copyInvocations int
}

func (c *r31SeamSSHClient) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if c.failStrip && strings.Contains(cmd, "awg-quick") && strings.Contains(cmd, "strip") {
		return "", "strip rejected", 1, nil
	}
	if strings.Contains(cmd, "docker cp") && strings.Contains(cmd, "_amnz_edit_config_") {
		c.copyInvoked = true
		c.copyInvocations++
		if c.copyInvocations == 1 {
			if c.copyErr != nil {
				return "", "", -1, c.copyErr
			}
			if c.copyCode != 0 {
				return "", "copy failed", c.copyCode, nil
			}
		}
	}
	return c.mockAWGSSHClient.RunSudoCommand(ctx, cmd)
}

func (c *r31SeamSSHClient) UploadSudoFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	if c.uploadErr != nil && strings.Contains(remotePath, "_amnz_edit_config_") {
		return c.uploadErr
	}
	return c.mockAWGSSHClient.UploadSudoFile(ctx, remotePath, content, mode)
}

// r31SeamProvider returns the seam client from Get; the stock mockAWGSSHProvider
// hands back the concrete mock and cannot surface a wrapper.
type r31SeamProvider struct {
	client *r31SeamSSHClient
}

func (p *r31SeamProvider) Get(ctx context.Context, server *models.Server) (ssh.SSHClient, error) {
	return p.client, nil
}

func r31NewManager(client *r31SeamSSHClient) (*AWGManager, *models.Server) {
	m := NewAWGManager(&r31SeamProvider{client: client})
	server := &models.Server{ID: 4242, Host: "192.0.2.42"}
	return m, server
}

// r31RequireNotAttempted pins the pre-copy failure classes: the container was
// provably not touched — classification configMutationNotAttempted.
func r31RequireNotAttempted(t *testing.T, err error, client *r31SeamSSHClient, original string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected the transaction to fail")
	}
	if client.copyInvoked {
		t.Error("copy must never be invoked for a pre-copy failure")
	}
	if errors.Is(err, ErrConfigurationRollbackFailed) {
		t.Errorf("pre-copy failure must not be rollback-classified, got: %v", err)
	}
	if got := string(client.files[r31DiskPath]); got != original {
		t.Errorf("disk must stay OLD\nwant:\n%s\ngot:\n%s", original, got)
	}
}

// r31RequireAmbiguousAttempt pins the R3-1 classification for post-invocation
// SSH error classes: the copy WAS invoked and its result was lost, so the
// outcome is ambiguous (attempted/may-have-mutated). The original error must
// always be surfaced unchanged. Since R3-2, an ambiguous attempt is
// compensated exactly like a known write: the R3-2 restore runs with the
// original bytes (succeeding fully over this seam), so the error is NOT
// rollback-classified and the disk keeps the OLD bytes.
func r31RequireAmbiguousAttempt(t *testing.T, err error, client *r31SeamSSHClient, original string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected the transaction to fail with the copy error")
	}
	if !client.copyInvoked {
		t.Fatal("test precondition: the copy must have been invoked")
	}
	if client.copyErr != nil {
		if !errors.Is(err, client.copyErr) {
			t.Errorf("the copy error itself must be surfaced unchanged, got: %v", err)
		}
	} else {
		// Nonzero-exit class: the wrapped error is the copy failure message.
		if !strings.Contains(err.Error(), "failed to copy config into container") {
			t.Errorf("expected the copy failure message, got: %v", err)
		}
	}
	if errors.Is(err, ErrConfigurationRollbackFailed) {
		t.Errorf("the R3-2 restore must succeed over this seam, got rollback-failed: %v", err)
	}
	if client.copyInvocations != 2 {
		t.Errorf("expected candidate copy + R3-2 restore copy (2), got %d", client.copyInvocations)
	}
	if got := string(client.files[r31DiskPath]); got != original {
		t.Errorf("compensation must restore the OLD bytes\nwant:\n%s\ngot:\n%s", original, got)
	}
}

func TestR3_1_PreCopyValidationFailureClassifiesNotAttempted(t *testing.T) {
	client := &r31SeamSSHClient{mockAWGSSHClient: newMockAWGSSHClient()}
	m, server := r31NewManager(client)
	original := string(client.files[r31DiskPath])

	// Jc = 0 fails current Nexus front-door validation, so
	// saveServerConfigTracked rejects the content before any SSH mutation.
	invalid := strings.Replace(validServerConfig, "Jc = 4", "Jc = 0", 1)
	params, _, err := ParseServerConfig(invalid)
	if err != nil {
		t.Fatalf("test precondition: parse: %v", err)
	}
	if err := ValidateAWGParams(params); err == nil {
		t.Fatal("test precondition: Jc=0 must be rejected by validation")
	}

	err = m.WriteConfiguration(context.Background(), server, invalid)
	r31RequireNotAttempted(t, err, client, original)
}

func TestR3_1_PreCopyUploadFailureClassifiesNotAttempted(t *testing.T) {
	client := &r31SeamSSHClient{
		mockAWGSSHClient: newMockAWGSSHClient(),
		uploadErr:        errors.New("sftp write failed"),
	}
	m, server := r31NewManager(client)
	original := string(client.files[r31DiskPath])

	err := m.WriteConfiguration(context.Background(), server, validServerConfig)
	r31RequireNotAttempted(t, err, client, original)
}

func TestR3_1_CopyResultCanceledContextClassifiesAttempted(t *testing.T) {
	client := &r31SeamSSHClient{
		mockAWGSSHClient: newMockAWGSSHClient(),
		copyErr:          context.Canceled,
	}
	m, server := r31NewManager(client)
	original := string(client.files[r31DiskPath])

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := m.WriteConfiguration(ctx, server, validServerConfig)
	r31RequireAmbiguousAttempt(t, err, client, original)
}

func TestR3_1_CopyResultDeadlineExceededClassifiesAttempted(t *testing.T) {
	client := &r31SeamSSHClient{
		mockAWGSSHClient: newMockAWGSSHClient(),
		copyErr:          context.DeadlineExceeded,
	}
	m, server := r31NewManager(client)
	original := string(client.files[r31DiskPath])

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	err := m.WriteConfiguration(ctx, server, validServerConfig)
	r31RequireAmbiguousAttempt(t, err, client, original)
}

func TestR3_1_CopyResultNonzeroExitClassifiesAttempted(t *testing.T) {
	client := &r31SeamSSHClient{
		mockAWGSSHClient: newMockAWGSSHClient(),
		copyCode:         1,
	}
	m, server := r31NewManager(client)
	original := string(client.files[r31DiskPath])

	err := m.WriteConfiguration(context.Background(), server, validServerConfig)
	r31RequireAmbiguousAttempt(t, err, client, original)
}

func TestR3_1_PostCopyStripFailureStillCompensates(t *testing.T) {
	client := &r31SeamSSHClient{
		mockAWGSSHClient: newMockAWGSSHClient(),
		failStrip:        true,
	}
	m, server := r31NewManager(client)
	original := string(client.files[r31DiskPath])

	err := m.WriteConfiguration(context.Background(), server, validServerConfig)
	if err == nil {
		t.Fatal("expected the transaction to fail")
	}
	if !client.copyInvoked {
		t.Fatal("test precondition: the copy must have been invoked")
	}
	if client.copyInvocations < 2 {
		t.Errorf("known disk-written failure must still be compensated (copy invocations=%d)", client.copyInvocations)
	}
	if !errors.Is(err, ErrConfigurationRollbackFailed) {
		t.Errorf("expected the rollback failure marker, got: %v", err)
	}
	if got := string(client.files[r31DiskPath]); got != original {
		t.Errorf("rollback must restore the OLD bytes\nwant:\n%s\ngot:\n%s", original, got)
	}
}

// TestR3_1_ClassificationMatrix pins the classification exposed by
// saveServerConfigTracked itself, one cell per spec input class. This is the
// direct oracle: reverting the flag semantics (e.g. returning
// configMutationNotAttempted from a post-invocation SSH error, or collapsing
// the distinction between attempted and disk-written) fails these cells even
// where the transaction-level routing is temporarily identical.
func TestR3_1_ClassificationMatrix(t *testing.T) {
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	cells := []struct {
		name    string
		client  *r31SeamSSHClient
		ctx     func() context.Context
		content string
		want    configMutationClassification
	}{
		{
			name:    "pre-copy validation failure is not attempted",
			client:  &r31SeamSSHClient{mockAWGSSHClient: newMockAWGSSHClient()},
			ctx:     context.Background,
			content: strings.Replace(validServerConfig, "Jc = 4", "Jc = 0", 1),
			want:    configMutationNotAttempted,
		},
		{
			name: "pre-copy upload failure is not attempted",
			client: &r31SeamSSHClient{
				mockAWGSSHClient: newMockAWGSSHClient(),
				uploadErr:        errors.New("sftp write failed"),
			},
			ctx:     context.Background,
			content: validServerConfig,
			want:    configMutationNotAttempted,
		},
		{
			name: "canceled context after copy invocation is attempted",
			client: &r31SeamSSHClient{
				mockAWGSSHClient: newMockAWGSSHClient(),
				copyErr:          context.Canceled,
			},
			ctx:     func() context.Context { return canceledCtx },
			content: validServerConfig,
			want:    configMutationAttempted,
		},
		{
			name: "deadline exceeded after copy invocation is attempted",
			client: &r31SeamSSHClient{
				mockAWGSSHClient: newMockAWGSSHClient(),
				copyErr:          context.DeadlineExceeded,
			},
			ctx:     context.Background,
			content: validServerConfig,
			want:    configMutationAttempted,
		},
		{
			name: "nonzero copy exit is attempted",
			client: &r31SeamSSHClient{
				mockAWGSSHClient: newMockAWGSSHClient(),
				copyCode:         1,
			},
			ctx:     context.Background,
			content: validServerConfig,
			want:    configMutationAttempted,
		},
		{
			name: "post-copy strip failure is disk written",
			client: &r31SeamSSHClient{
				mockAWGSSHClient: newMockAWGSSHClient(),
				failStrip:        true,
			},
			ctx:     context.Background,
			content: validServerConfig,
			want:    configMutationDiskWritten,
		},
		{
			name:    "success is succeeded",
			client:  &r31SeamSSHClient{mockAWGSSHClient: newMockAWGSSHClient()},
			ctx:     context.Background,
			content: validServerConfig,
			want:    configMutationSucceeded,
		},
	}

	for _, tc := range cells {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := r31NewManager(tc.client)
			got, err := m.saveServerConfigTracked(tc.ctx(), tc.client, tc.content)
			if tc.want == configMutationSucceeded {
				if err != nil {
					t.Fatalf("success cell must not fail, got: %v", err)
				}
			} else if err == nil {
				t.Fatal("every failure cell must fail")
			}
			if got != tc.want {
				t.Errorf("classification = %d, want %d (err: %v)", got, tc.want, err)
			}
			// The R3-1 invariant: no post-invocation error class may classify
			// as no-mutation.
			if tc.want != configMutationNotAttempted && !got.configMutationAttemptedOrBeyond() {
				t.Errorf("classification %d must report attempted-or-beyond", got)
			}
		})
	}
}

func TestR3_1_SuccessClassifiesSucceeded(t *testing.T) {
	client := &r31SeamSSHClient{mockAWGSSHClient: newMockAWGSSHClient()}
	m, server := r31NewManager(client)
	original := string(client.files[r31DiskPath])
	if original == validServerConfig {
		t.Fatal("test precondition: the mock default must differ from the candidate")
	}

	postApplyRan := false
	err := m.WriteConfigurationWithPostApply(context.Background(), server, validServerConfig, func(context.Context) error {
		postApplyRan = true
		return nil
	})
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if !postApplyRan {
		t.Error("postApply must run after a successful (succeeded-class) write")
	}
	if client.copyInvocations != 1 {
		t.Errorf("expected exactly one copy invocation, got %d", client.copyInvocations)
	}
	// The write path normalizes the content (EnsureInterfaceTableOff) before
	// the copy, so the disk holds the normalized NEW configuration.
	wantOnDisk := EnsureInterfaceTableOff(validServerConfig)
	if got := string(client.files[r31DiskPath]); got != wantOnDisk {
		t.Errorf("disk must hold the NEW configuration\nwant:\n%s\ngot:\n%s", wantOnDisk, got)
	}
}
