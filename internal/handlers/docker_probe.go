package handlers

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
)

// dockerProbeCmd is the unprivileged command used to detect a Docker CLI on the
// managed host. It deliberately mirrors the probe used by
// awg.ensureDockerInstalled so both call sites answer the same question.
const dockerProbeCmd = "docker --version"

// dockerProbeToken is the (lowercased) substring a successful probe must emit.
const dockerProbeToken = "docker"

// Bounded categories for the transport error of a failed probe. Raw error text
// is never recorded: it can embed hostnames, paths or the SSH user.
const (
	probeErrNone         = ""
	probeErrNotConnected = "not_connected"
	probeErrTimeout      = "timeout"
	probeErrCanceled     = "canceled"
	probeErrOther        = "other"
)

// Bounded categories for the stdout of a probe. Only the shape is recorded,
// never the bytes: a managed host can emit arbitrary text.
const (
	probeOutEmpty       = "empty"
	probeOutDockerToken = "docker_token"
	probeOutOther       = "other_text"
)

// dockerPresenceProbe is the outcome of the unprivileged Docker CLI probe plus
// the bounded diagnostic facts needed to explain a negative verdict.
//
// Installed carries the unchanged production decision; every other field is
// diagnostic-only and is consulted solely when that decision was negative.
type dockerPresenceProbe struct {
	Installed      bool
	ExitCode       int
	TransportError string
	StdoutLen      int
	StdoutState    string
	StderrLen      int
}

// probeDockerPresence runs the unprivileged Docker CLI probe and classifies the
// result. The Installed decision is unchanged from the previous inline
// expression: exit code zero AND stdout containing the docker token.
//
// Reporting a documented defect: when the CLI is resolvable only through the
// privileged path used elsewhere in ServerCheckHandler (the protocol status
// queries run under sudo), this unprivileged probe answers false while the same
// response reports healthy protocol data. The probe records enough shape to
// tell those cases apart without capturing host output.
func probeDockerPresence(ctx context.Context, client ssh.SSHClient) dockerPresenceProbe {
	stdout, stderr, code, err := client.RunCommand(ctx, dockerProbeCmd)
	return dockerPresenceProbe{
		Installed:      code == 0 && strings.Contains(strings.ToLower(stdout), dockerProbeToken),
		ExitCode:       code,
		TransportError: classifyProbeError(err),
		StdoutLen:      len(stdout),
		StdoutState:    classifyProbeStdout(stdout),
		StderrLen:      len(stderr),
	}
}

// classifyProbeError maps a probe transport error onto a bounded category.
// Unknown errors collapse to probeErrOther so no arbitrary error text escapes.
func classifyProbeError(err error) string {
	switch {
	case err == nil:
		return probeErrNone
	case errors.Is(err, ssh.ErrCommandTimeout), errors.Is(err, context.DeadlineExceeded):
		return probeErrTimeout
	case errors.Is(err, context.Canceled):
		return probeErrCanceled
	case errors.Is(err, ssh.ErrNotConnected):
		return probeErrNotConnected
	default:
		return probeErrOther
	}
}

// classifyProbeStdout reduces probe stdout to a bounded shape category.
func classifyProbeStdout(stdout string) string {
	switch {
	case stdout == "":
		return probeOutEmpty
	case strings.Contains(strings.ToLower(stdout), dockerProbeToken):
		return probeOutDockerToken
	default:
		return probeOutOther
	}
}

// logFailure emits the bounded diagnostic facts for a negative probe verdict.
// Success is silent: ServerCheckHandler is polled every few seconds by the E2E
// lifecycle suite, so logging healthy probes would bury the failure signal.
func (p dockerPresenceProbe) logFailure(serverID int64) {
	if p.Installed {
		return
	}
	slog.Warn("ServerCheckHandler: docker CLI probe failed",
		"server_id", serverID,
		"exit_code", p.ExitCode,
		"transport_error", p.TransportError,
		"stdout_len", p.StdoutLen,
		"stdout_state", p.StdoutState,
		"stderr_len", p.StderrLen,
	)
}
