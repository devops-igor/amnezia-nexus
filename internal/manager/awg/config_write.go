package awg

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
)

// configMutationClassification describes what is known about the remote
// container's configuration state after a tracked write attempt. The ordering
// is significant: values are linearly ordered from "nothing touched" to "fully
// applied", and the transaction's compensation gate compares against
// mutationDiskWritten (see writeConfigurationTransaction).
//
// R3-1 semantics (re-review resolution plan, section 4 item 1): a copy
// invocation can COMPLETE inside the container and only then have its SSH
// result lost to cancellation, timeout or transport failure. Therefore no SSH
// error observed after the copy command was issued is proof of "no mutation":
// every such outcome classifies as at least configMutationAttempted. Only
// failures strictly before the copy invocation (validation, path resolution,
// upload preparation) are known no-config-mutation cases.
type configMutationClassification int

const (
	// configMutationNotAttempted: the write failed before the copy command was
	// invoked. The container configuration was provably not touched.
	configMutationNotAttempted configMutationClassification = iota
	// configMutationAttempted: the copy command was invoked and returned an
	// SSH-level error (cancellation, timeout, transport failure). The copy may
	// have completed server-side; disk state is UNKNOWN, never "old".
	configMutationAttempted
	// configMutationDiskWritten: the copy returned a nonzero exit status, or a
	// later step (strip/syncconf) failed after a successful copy. The disk
	// bytes are NEW; runtime/artifacts may be OLD.
	configMutationDiskWritten
	// configMutationSucceeded: disk write, runtime sync (and any tracked
	// follow-up) all completed successfully.
	configMutationSucceeded
)

// configMutationAttemptedOrBeyond reports whether the container configuration
// was mutated, or may have been mutated, by the tracked write. It is the R3-1
// replacement for the old boolean "did the write succeed" reading: every
// post-invocation SSH error class must report true, because no SSH error is
// proof of no side effect.
func (c configMutationClassification) configMutationAttemptedOrBeyond() bool {
	return c >= configMutationAttempted
}

// asLegacyWriteSucceeded maps the classification onto the historical boolean
// contract (true == "disk write is known to have persisted"). Used ONLY at
// call sites whose compensation behavior is owned by other tasks: the R3-1
// transaction gate and AddClient's rollback bookkeeping. The routing change
// for ambiguous outcomes is R3-2 (see writeConfigurationTransaction).
func (c configMutationClassification) asLegacyWriteSucceeded() bool {
	return c >= configMutationDiskWritten
}

func (m *AWGManager) saveServerConfig(ctx context.Context, client ssh.SSHClient, content string) error {
	_, err := m.saveServerConfigTracked(ctx, client, content, true)
	return err
}

// saveServerConfigPreservingParams writes a peer-only edit without revalidating
// existing interface parameters against today's rules.
func (m *AWGManager) saveServerConfigPreservingParams(ctx context.Context, client ssh.SSHClient, content string) error {
	_, err := m.saveServerConfigTracked(ctx, client, content, false)
	return err
}

func (m *AWGManager) saveServerConfigTracked(ctx context.Context, client ssh.SSHClient, content string, validateParams bool) (configMutationClassification, error) {
	params, _, err := ParseServerConfig(content)
	if err != nil {
		return configMutationNotAttempted, fmt.Errorf("invalid server config: %w", err)
	}
	if validateParams && len(params) > 0 {
		if err := ValidateAWGParams(params); err != nil {
			return configMutationNotAttempted, fmt.Errorf("invalid AWG parameters: %w", err)
		}
	}

	return m.writeServerConfigTracked(ctx, client, EnsureInterfaceTableOff(content))
}

// restoreKnownServerConfigTracked restores bytes that were read from this same
// server immediately before a mutation. It deliberately bypasses Nexus's
// front-door ParseServerConfig/ValidateAWGParams policy and preserves the exact
// previous bytes: a running legacy config can be accepted by the installed AWG
// tools even when newer Nexus validation would reject it. The restore still
// uses the normal safe copy path, checked awg-quick strip, and checked syncconf.
func (m *AWGManager) restoreKnownServerConfigTracked(ctx context.Context, client ssh.SSHClient, content string) (configMutationClassification, error) {
	return m.writeServerConfigTracked(ctx, client, content)
}

// writeServerConfigTracked performs the remote configuration write and returns
// what is known about the container's configuration state (see
// configMutationClassification). The classification is advanced to
// configMutationAttempted immediately BEFORE the copy command is invoked: once
// the copy has been issued, its result can be lost (cancellation, timeout,
// transport failure) while the mutation still completed server-side, so no
// post-invocation SSH error may classify as "not attempted".
func (m *AWGManager) writeServerConfigTracked(ctx context.Context, client ssh.SSHClient, content string) (configMutationClassification, error) {
	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	if !IsValidContainerName(cName) {
		return configMutationNotAttempted, errors.New("invalid container name")
	}
	randBytes := make([]byte, 8)
	_, _ = rand.Read(randBytes)
	tmpPath := fmt.Sprintf("/tmp/_amnz_edit_config_%d_%x.conf", time.Now().UnixNano(), randBytes)
	if err := client.UploadSudoFile(ctx, tmpPath, []byte(content), 0600); err != nil {
		return configMutationNotAttempted, err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_, _, _, _ = client.RunSudoCommand(cleanupCtx, fmt.Sprintf("rm -f %s", ssh.EscapeShellArg(tmpPath)))
	}()

	cfgPath := m.resolveContainerConfigPath(ctx, client, cName)
	cpCmd := fmt.Sprintf("docker cp %s %s:%s", ssh.EscapeShellArg(tmpPath), ssh.EscapeShellArg(cName), ssh.EscapeShellArg(cfgPath))
	// R3-1: from this point on, every outcome is at least "attempted". A
	// canceled, timed-out or transport-failed result says nothing about whether
	// the copy completed inside the container.
	mutation := configMutationAttempted
	if _, errOut, code, err := client.RunSudoCommand(ctx, cpCmd); err != nil || code != 0 {
		return mutation, fmt.Errorf("failed to copy config into container (code %d): %s, %w", code, errOut, err)
	}

	// Copy confirmed: the disk bytes are NEW.
	mutation = configMutationDiskWritten

	if err := m.syncInterfaceConfig(ctx, client, cName, cfgPath); err != nil {
		return mutation, err
	}
	return configMutationSucceeded, nil
}

// strippedConfigPath returns the in-container path that holds the stripped
// configuration. It lives next to the real configuration so it inherits the
// same directory conventions, and it is unique per call so concurrent
// operations never share it.
func (m *AWGManager) strippedConfigPath(cfgPath string) string {
	randBytes := make([]byte, 8)
	_, _ = rand.Read(randBytes)
	return fmt.Sprintf("%s/.awg-strip-%d-%x.conf", path.Dir(cfgPath), time.Now().UnixNano(), randBytes)
}

// stripInterfaceConfig runs `awg-quick strip` as a separately checked operation
// and returns the in-container path of the stripped configuration.
//
// Stripping must never be fused into the syncconf command through a process
// substitution (`<(awg-quick strip ...)`). Bash does not propagate the exit
// status of a process substitution's producer, so a rejected configuration
// yielded an empty stream that syncconf happily applied — initializing the
// interface with a zero private key and peer-replacement flags — while the
// container exited 0 and the caller reported success. Checking strip on its own
// guarantees syncconf is unreachable whenever stripping fails, and additionally
// rejects an empty strip result.
func (m *AWGManager) stripInterfaceConfig(ctx context.Context, client ssh.SSHClient, cName, cfgPath string) (string, error) {
	stripPath := m.strippedConfigPath(cfgPath)
	stripCmd := fmt.Sprintf("docker exec -i %s bash -c %s",
		ssh.EscapeShellArg(cName),
		ssh.EscapeShellArg(fmt.Sprintf("(umask 077 && %s strip %s > %s) && test -s %s",
			ssh.EscapeShellArg(m.wgBinary()+"-quick"), ssh.EscapeShellArg(cfgPath),
			ssh.EscapeShellArg(stripPath), ssh.EscapeShellArg(stripPath))))
	out, errOut, code, err := client.RunSudoCommand(ctx, stripCmd)
	if err != nil || code != 0 {
		m.removeContainerFile(ctx, client, cName, stripPath)
		errMsg := strings.TrimSpace(errOut)
		if errMsg == "" {
			errMsg = strings.TrimSpace(out)
		}
		if err != nil {
			return "", fmt.Errorf("failed to strip AmneziaWG config in container %s (exit code %d): %s: %w", cName, code, errMsg, err)
		}
		return "", fmt.Errorf("failed to strip AmneziaWG config in container %s (exit code %d): %s", cName, code, errMsg)
	}
	return stripPath, nil
}

// removeContainerFile deletes a file created inside a container, best effort.
// It uses a bounded context detached from ctx so the removal still runs when the
// caller's context has already been canceled or timed out.
func (m *AWGManager) removeContainerFile(ctx context.Context, client ssh.SSHClient, cName, filePath string) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_, _, _, _ = client.RunSudoCommand(cleanupCtx, fmt.Sprintf("docker exec -i %s rm -f %s", ssh.EscapeShellArg(cName), ssh.EscapeShellArg(filePath)))
}
