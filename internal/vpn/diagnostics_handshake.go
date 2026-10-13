package vpn

import (
	"sort"
	"time"
)

// collectHandshakeDiagnostics inspects upstream device status and checks for stale active sessions.
func collectHandshakeDiagnostics(s *Service) HandshakeFreshnessDiagnostics {
	return s.captureDiagnosticsInputs().collectHandshakeDiagnostics()
}

func (inputs diagnosticsInputs) collectHandshakeDiagnostics() HandshakeFreshnessDiagnostics {
	diag := HandshakeFreshnessDiagnostics{}
	if inputs.ingressEngine == nil || inputs.ingressEngine.Portal() == nil {
		return diag
	}

	portalStatus, err := inputs.ingressEngine.Portal().Status()
	if err != nil {
		return diag
	}

	now := time.Now()
	diag.TotalPeers = len(portalStatus.Peers)
	peerHandshakes := make(map[string]time.Time, len(portalStatus.Peers))

	for _, p := range portalStatus.Peers {
		peerHandshakes[p.PublicKey] = p.LastHandshake
		if p.LastHandshake.IsZero() {
			diag.NeverCount++
			continue
		}
		age := now.Sub(p.LastHandshake)
		if age < 2*time.Minute {
			diag.Under2mCount++
		} else if age <= 5*time.Minute {
			diag.Between2m5mCount++
		} else {
			diag.Over5mCount++
		}
	}

	// Check active live sessions for stale handshakes (> 3 minutes)
	if inputs.sessionMgr != nil {
		activeSessions := inputs.sessions
		for _, sess := range activeSessions {
			hs, ok := peerHandshakes[sess.PeerPublicKey]
			if !ok || hs.IsZero() || now.Sub(hs) > DefaultHealthThresholds.HandshakeStaleAge {
				// Collected raw, redacted after the sort below (issue #424
				// round 5, item 1b). This value reached /api/vpn/status
				// verbatim as handshake_freshness.stale_live_sessions.
				// ingress.RedactKey keeps the per-session correlation an
				// admin needs while keeping the full key out of the payload.
				diag.StaleLiveSessions = append(diag.StaleLiveSessions, sess.PeerPublicKey)
			}
		}
	}

	// Sort first, redact second, for the same reason as the routing invariant
	// slices: sort.Strings over the raw keys is a total order on the data,
	// whereas sorting the redacted values would order by the 8 character
	// prefix that redaction leaves behind, making the output order a property
	// of the masking scheme instead of the keys.
	sort.Strings(diag.StaleLiveSessions)
	redactKeySlice(diag.StaleLiveSessions)
	diag.PeerHandshakes = peerHandshakes
	return diag
}
