package handlers

// The detail-page measurement.
//
// The page polls the reachability endpoint every 30 seconds, so this is automatic
// work: it is split out of the handler so the decision (may this row be dialed?)
// reads separately from the measurement itself, and so the handler file stays
// within the repository's size rule.

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// measureServerReachability dials the server's SSH port and reports what it
// measured: whether the port answered, the latency, and the status that follows.
//
// It is the only place the detail-page poll opens a connection, and the caller
// decides whether it may be called at all (a server the provider no longer lists
// is never dialed). A failed measurement keeps the stored status unless nothing is
// known about it yet; a successful one records the new observation.
func (h *Handlers) measureServerReachability(
	ctx context.Context, server *models.Server, status models.ReachabilityStatus,
) (reachable bool, latencyMS int, measured models.ReachabilityStatus) {
	if server.ProviderAbsent() {
		// The refusal lives with the dial, not only with the handler that asks for
		// it: a future caller cannot open a socket to a server the provider's
		// inventory no longer lists by forgetting the response branch above.
		return false, 0, status
	}

	sshPort := server.SSHPort
	if sshPort <= 0 {
		sshPort = 22
	}

	dialFn := h.dialTimeout
	if dialFn == nil {
		dialFn = net.DialTimeout
	}

	start := time.Now()
	// #nosec G704 -- connecting to managed server host for latency probe
	serverHost := strings.Trim(strings.TrimSpace(server.Host), "[]")
	conn, err := dialFn("tcp", net.JoinHostPort(serverHost, strconv.Itoa(sshPort)), 3*time.Second)
	if err != nil {
		if status == models.ReachabilityUnknown {
			status = models.ReachabilityOffline
		}
		return false, 0, status
	}
	_ = conn.Close()

	latencyMS = int(time.Since(start).Milliseconds())
	if latencyMS <= 0 {
		latencyMS = 1
	}
	_ = h.db.UpdateServerReachability(ctx, server.ID, models.ReachabilityOnline)
	return true, latencyMS, models.ReachabilityOnline
}
