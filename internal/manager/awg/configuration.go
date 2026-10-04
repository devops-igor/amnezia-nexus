package awg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ReadConfiguration reads the installed AWG container, the same configuration
// used by provisioning and peer changes. A missing config is an error.
func (m *AWGManager) ReadConfiguration(ctx context.Context, server *models.Server) (string, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}
	lock := m.getServerLock(server.ID)
	lock.Lock()
	defer lock.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getServerConfig(ctx, client)
}

var (
	// ErrConfigurationPostApply marks a failure in the caller-supplied reconciliation
	// step after the remote AWG configuration was successfully applied.
	ErrConfigurationPostApply = errors.New("AWG configuration post-apply reconciliation failed")

	// ErrConfigurationRollbackFailed means OLD remote disk/runtime or identity
	// artifacts could not be restored. The caller must quarantine the backend.
	ErrConfigurationRollbackFailed = errors.New("AWG configuration rollback failed")

	// ErrConfigurationPostApplyKeepApplied tells the transaction that caller-owned
	// reconciliation could not safely roll back to the previous identity. In this
	// state the already-applied remote configuration is the convergence target and
	// must NOT be compensated back to the old identity.
	ErrConfigurationPostApplyKeepApplied = errors.New("keep applied AWG configuration after post-apply rollback failure")
)

// WriteConfiguration serializes with peer operations and applies both disk and
// runtime changes. If runtime application fails after the disk write, restore
// the preceding configuration under the same lock with a bounded cleanup context.
//
// An edit that changes the server's [Interface] PrivateKey rotates the server's
// identity. Because the user-facing contract is to reconcile rather than reject
// such an edit, every derived artifact that carries the identity is refreshed
// from the newly written configuration before the write is reported successful,
// so a subsequent read from the running container describes the new identity.
// Interface-down reads can use the configuration or artifacts; a stopped
// container cannot answer docker exec.
func (m *AWGManager) WriteConfiguration(ctx context.Context, server *models.Server, content string) error {
	return m.writeConfigurationTransaction(ctx, server, content, nil)
}

// WriteConfigurationWithPostApply keeps the AWG server lock and remote lock held
// while postApply reconciles state outside the manager (for example the server
// database and active VPN backend). Ordinary post-apply failures restore the
// previous remote configuration before either lock is released. A caller that
// returns ErrConfigurationPostApplyKeepApplied explicitly selects the already-
// applied configuration as the safer convergence target instead.
func (m *AWGManager) WriteConfigurationWithPostApply(
	ctx context.Context,
	server *models.Server,
	content string,
	postApply func(context.Context) error,
) error {
	if postApply == nil {
		return m.WriteConfiguration(ctx, server, content)
	}
	return m.writeConfigurationTransaction(ctx, server, content, postApply)
}

func (m *AWGManager) writeConfigurationTransaction(
	ctx context.Context,
	server *models.Server,
	content string,
	postApply func(context.Context) error,
) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}
	lock := m.getServerLock(server.ID)
	lock.Lock()
	defer lock.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.acquireRemoteServerLock(ctx, client, server.ID)
	if err != nil {
		return err
	}
	defer unlock()

	original, err := m.getServerConfig(ctx, client)
	if err != nil {
		return err
	}
	written, err := m.saveServerConfigTracked(ctx, client, content)
	if err != nil {
		if written {
			return m.restoreConfigurationAfterFailure(ctx, client, server, content, original, err)
		}
		return err
	}
	if !written {
		return errors.New("AWG configuration write completed without persisting content")
	}

	// The disk and runtime write succeeded. Reconcile the derived identity
	// artifacts before any caller-owned state is committed.
	if err := m.reconcileServerIdentity(ctx, client, server, original, content); err != nil {
		return m.restoreConfigurationAfterFailure(ctx, client, server, content, original, err)
	}

	if postApply == nil {
		return nil
	}
	if err := postApply(ctx); err != nil {
		cause := errors.Join(ErrConfigurationPostApply, err)
		if errors.Is(err, ErrConfigurationPostApplyKeepApplied) {
			return cause
		}
		return m.restoreConfigurationAfterFailure(
			ctx,
			client,
			server,
			content,
			original,
			cause,
		)
	}
	return nil
}

func (m *AWGManager) restoreConfigurationAfterFailure(
	ctx context.Context,
	client ssh.SSHClient,
	server *models.Server,
	attempted string,
	original string,
	cause error,
) error {
	restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	written, restoreErr := m.restoreKnownServerConfigTracked(restoreCtx, client, original)
	if restoreErr != nil {
		return errors.Join(cause, ErrConfigurationRollbackFailed, fmt.Errorf("failed to restore previous AWG configuration: %w", restoreErr))
	}
	if !written {
		return errors.Join(cause, ErrConfigurationRollbackFailed, errors.New("failed to restore previous AWG configuration: write was not persisted"))
	}
	if identityErr := m.reconcileServerIdentity(restoreCtx, client, server, attempted, original); identityErr != nil {
		return errors.Join(cause, ErrConfigurationRollbackFailed, fmt.Errorf("failed to restore previous AWG identity artifacts: %w", identityErr))
	}
	return cause
}

// reconcileServerIdentity refreshes the derived identity artifacts so they match
// the configuration that was just written.
//
// The public-key artifact is written exactly once at provisioning time
// (initializeServerKeysAndConfig), so an identity-changing edit used to leave it
// describing the pre-rotation server forever. Reconciliation derives the public
// key from the written configuration's [Interface] PrivateKey and rewrites both
// the private- and public-key artifacts.
//
// It is a no-op when the write did not change the PrivateKey. Refresh errors
// fail the transaction so the preceding disk, runtime and artifacts are restored.
func (m *AWGManager) reconcileServerIdentity(ctx context.Context, client ssh.SSHClient, server *models.Server, original, written string) error {
	previousKey := interfacePrivateKey(original)
	newKey := interfacePrivateKey(written)
	if newKey == "" || newKey == previousKey {
		return nil
	}
	newPub, err := derivePublicKeyFromPrivate(newKey)
	if err != nil {
		return fmt.Errorf("derive changed AWG server identity: %w", err)
	}
	// Defense in depth for the two values interpolated below: neither may
	// contain a shell metacharacter even if a future caller builds them
	// differently.
	if !awgKeyPattern.MatchString(newKey) || !awgKeyPattern.MatchString(newPub) {
		return errors.New("refusing to write AWG identity artifacts: key does not match the expected base64 form")
	}

	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	if !IsValidContainerName(cName) {
		return errors.New("invalid container name")
	}

	// Restrict both new and existing private artifacts before writing secrets.
	// Checked shell steps prevent a successful public write masking a failed
	// private write. Command output can contain key material and is not returned.
	script := fmt.Sprintf("set -e\numask 077\nmkdir -p /opt/amnezia/awg\ntouch %s\nchmod 600 %s\nprintf '%%s' '%s' > %s\nprintf '%%s' '%s' > %s\n",
		serverPrivateKeyArtifactPath, serverPrivateKeyArtifactPath,
		newKey, serverPrivateKeyArtifactPath, newPub, serverPublicKeyArtifactPath)
	if _, _, code, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s bash -c %s",
		ssh.EscapeShellArg(cName), ssh.EscapeShellArg(script))); err != nil {
		return fmt.Errorf("refresh AWG identity artifacts: %w", err)
	} else if code != 0 {
		return fmt.Errorf("refresh AWG identity artifacts: exit code %d", code)
	}
	return nil
}

// ExtractServerPublicKey returns the Base64-encoded public key derived from
// the [Interface] PrivateKey in an AWG configuration string.
func ExtractServerPublicKey(content string) (string, error) {
	key := interfacePrivateKey(content)
	if key == "" {
		return "", errors.New("no [Interface] PrivateKey found in configuration")
	}
	return derivePublicKeyFromPrivate(key)
}
