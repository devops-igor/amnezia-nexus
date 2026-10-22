package vpn

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

var externalIPDetector = detectExternalPublicIP

// outboundDial is the seam used by detectOutboundInterfaceIP; tests stub it
// to fake the container's local address without a real UDP dial.
var outboundDial = net.DialTimeout

// ipServiceEndpoints lists the public IP echo services consulted by
// detectExternalPublicIP (issue #71: ipify + icanhazip stay, no new
// external service dependencies).
var ipServiceEndpoints = []string{
	"https://api.ipify.org",
	"https://icanhazip.com",
}

// Detection retry budget (issue #71 requirement 2): up to ipServiceAttempts
// rounds over the endpoint list, 2s per-attempt timeout, short backoff
// between rounds. Worst case stays bounded (~13s) under the ~15s ceiling.
const (
	ipServiceAttempts     = 3
	ipServiceRetryBackoff = 300 * time.Millisecond
)

// Endpoint sources for observability (issue #71 requirement 4).
const (
	endpointSourceConfigured = "configured"
	endpointSourceEnv        = "env"
	endpointSourceIPService  = "detected(ip-service)"
	endpointSourceOutbound   = "detected(outbound-interface)"
	endpointSourceFallback   = "fallback(127.0.0.1)"
)

// sanitizeLogValue makes untrusted text safe for single-line logs: control
// characters (including CR/LF used to forge log lines) become visible
// escapes. Applied to response bodies and externally supplied endpoint
// values before they reach the log.
func sanitizeLogValue(s string) string {
	if s == "" {
		return s
	}
	replaced := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '\\'
		}
		return r
	}, s)
	if len(replaced) > 96 {
		replaced = replaced[:93] + "..."
	}
	return replaced
}

// vpnDebugf logs opt-in debug detail: emitted only when VPN_DEBUG is set.
// internal/vpn has no leveled logger; per-attempt detection noise stays
// behind this gate so default logs carry the single INFO source line.
func vpnDebugf(format string, args ...any) {
	if os.Getenv("VPN_DEBUG") == "" {
		return
	}
	// #nosec G706 -- format strings are compile-time constants inside this
	// file; variable arguments are validated IPs, fixed endpoint URLs, or
	// sanitized via sanitizeLogValue before reaching this wrapper.
	log.Printf(format, args...)
}

// logWriter returns the standard logger's current output writer so tests
// can capture endpoint-source log lines.
func logWriter() io.Writer {
	return log.Writer()
}

// detectPortalHostIPFallback runs the detection chain and reports which
// source produced the result (issue #71 observability). It returns "" with
// endpointSourceFallback when every stage fails; callers treat "" as
// failure and fall back to 127.0.0.1 without caching.
func detectPortalHostIPFallback(ctx context.Context) (string, string) {
	if externalIPDetector != nil {
		if ip := externalIPDetector(ctx); ip != "" {
			// Trust boundary: whatever the detector (or its test seam)
			// returns is only usable if it is a validated global-unicast
			// address; anything else counts as detection failure (issue #71).
			if isPublicIP(net.ParseIP(ip)) {
				return ip, endpointSourceIPService
			}
			vpnDebugf("[vpn] portal host detection: ip-service returned non-public %q; rejected", sanitizeLogValue(ip))
		}
	}
	if ip := detectOutboundInterfaceIP(); ip != "" {
		return ip, endpointSourceOutbound
	}
	return "", endpointSourceFallback
}

// isPublicIP reports whether ip is a validated global-unicast address:
// not loopback, unspecified, multicast/broadcast, link-local, private
// (RFC1918), or CGNAT 100.64.0.0/10 (issue #71 requirement 1).
func isPublicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return false
	}
	// net.IP.IsPrivate does not cover carrier-grade NAT 100.64.0.0/10;
	// the live incident showed container/network ranges in that space.
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] < 128 {
		return false
	}
	return true
}

func detectExternalPublicIP(ctx context.Context) string {
	endpoints := ipServiceEndpoints

	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	// Issue #71: the observed failure was both services failing once during
	// a boot window while egress came up seconds later. Retry the endpoint
	// list with a short backoff; total worst case stays bounded.
	for attempt := 1; attempt <= ipServiceAttempts; attempt++ {
		for _, ep := range endpoints {
			// Per-attempt timeout: 2s each, as before the retry loop.
			lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			req, err := http.NewRequestWithContext(lookupCtx, http.MethodGet, ep, nil)
			if err != nil {
				cancel()
				continue
			}
			// #nosec G107 -- fixed public IP detection endpoints
			resp, err := client.Do(req)
			if err != nil {
				cancel()
				vpnDebugf("[vpn] public IP detection: %s attempt %d failed: %v", ep, attempt, err)
				continue
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
			_ = resp.Body.Close()
			cancel()
			if err != nil {
				vpnDebugf("[vpn] public IP detection: %s attempt %d read failed: %v", ep, attempt, err)
				continue
			}
			ipStr := strings.TrimSpace(string(body))
			if parsed := net.ParseIP(ipStr); parsed != nil && isPublicIP(parsed) {
				return ipStr
			}
			vpnDebugf("[vpn] public IP detection: %s attempt %d returned unusable body %q", ep, attempt, sanitizeLogValue(ipStr))
		}
		if attempt < ipServiceAttempts {
			select {
			case <-ctx.Done():
				return ""
			case <-time.After(time.Duration(attempt) * ipServiceRetryBackoff):
			}
		}
	}
	return ""
}

func detectOutboundInterfaceIP() string {
	// Issue #71: the UDP dial to 8.8.8.8:80 returns the container's local
	// IP inside Docker (observed: 172.19.0.3). Only a validated global
	// unicast address may leave this function; anything else is treated
	// as detection failure.
	conn, err := outboundDial("udp", "8.8.8.8:80", 500*time.Millisecond)
	if err != nil {
		vpnDebugf("[vpn] outbound interface detection: UDP dial failed: %v", err)
		return ""
	}
	defer conn.Close()
	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr.IP == nil {
		return ""
	}
	localIP := udpAddr.IP
	if !isPublicIP(localIP) {
		vpnDebugf("[vpn] outbound interface detection: rejected non-public local address %s", localIP)
		return ""
	}
	return localIP.String()
}

func formatEndpoint(val string, defaultPort int) string {
	val = strings.TrimSpace(val)
	if val == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(val); err == nil {
		return val
	}
	return net.JoinHostPort(val, strconv.Itoa(defaultPort))
}

func resolveClientEndpointInternal(ctx context.Context, s *Service, cfg *models.VPNConfig, listenPort int) string {
	// 1. Configured cfg.PublicEndpoint
	if cfg != nil && strings.TrimSpace(cfg.PublicEndpoint) != "" {
		logEndpointSource(endpointSourceConfigured, cfg.PublicEndpoint)
		return formatEndpoint(cfg.PublicEndpoint, listenPort)
	}

	// 2. Environment variables: VPN_PUBLIC_ENDPOINT, PUBLIC_ENDPOINT, PUBLIC_IP
	for _, envKey := range []string{"VPN_PUBLIC_ENDPOINT", "PUBLIC_ENDPOINT", "PUBLIC_IP"} {
		if envVal := strings.TrimSpace(os.Getenv(envKey)); envVal != "" {
			logEndpointSource(endpointSourceEnv, envVal)
			return formatEndpoint(envVal, listenPort)
		}
	}

	// 3. Portal Host Auto-Detection (validated public IPs only; see #71)
	var hostIP, source string
	if s != nil {
		hostIP, source = s.detectPortalHostIP(ctx)
	} else {
		hostIP, source = detectPortalHostIPFallback(ctx)
	}
	if hostIP == "" {
		hostIP = "127.0.0.1"
	}
	logEndpointSource(source, hostIP)
	return net.JoinHostPort(hostIP, strconv.Itoa(listenPort))
}

// lastEndpointSource/lastEndpointValue back the issue #71 observability
// line: log once per source change, not per resolve (cache hits must not
// spam). atomic.Pointer[string] is swap-only, so no ABA hazard.
var (
	lastEndpointSource atomic.Pointer[string]
	lastEndpointValue  atomic.Pointer[string]
)

// logEndpointSource emits the observability line required by issue #71:
// one INFO line whenever the resolved (source, value) pair changes, and a
// debug line (VPN_DEBUG-gated) otherwise, so cache hits and steady-state
// fallback resolves don't spam the log.
func logEndpointSource(source, value string) {
	value = sanitizeLogValue(value)
	prevSrc := lastEndpointSource.Swap(&source)
	prevVal := lastEndpointValue.Swap(&value)
	unchanged := prevSrc != nil && *prevSrc == source && prevVal != nil && *prevVal == value
	if unchanged {
		vpnDebugf("[vpn] client endpoint source: %s (%s) (unchanged)", source, value)
		return
	}
	// #nosec G706 -- source is a compile-time endpointSource* constant and
	// value passed through sanitizeLogValue above (control characters
	// including CR/LF replaced with escapes), so log lines cannot be forged.
	log.Printf("[vpn] client endpoint source: %s (%s)", source, value)
}

func (s *Service) detectPortalHostIP(ctx context.Context) (string, string) {
	if s != nil {
		s.publicIPMu.RLock()
		cached := s.detectedPublicIP
		s.publicIPMu.RUnlock()
		if cached != "" {
			return cached, endpointSourceIPService
		}
	}

	detected, source := detectPortalHostIPFallback(ctx)

	// Issue #71: only validated global-unicast results are cached; a failed
	// or non-public detection must return "" uncached so the next call
	// retries detection instead of pinning the bad value for the process
	// lifetime. The isPublicIP re-check is defense in depth: the detector
	// itself already validates, but this gate is what the no-cache
	// guarantee rests on.
	if s != nil && isPublicIP(net.ParseIP(detected)) {
		s.publicIPMu.Lock()
		s.detectedPublicIP = detected
		s.publicIPMu.Unlock()
	}
	return detected, source
}

func (s *Service) resolveClientEndpoint(ctx context.Context, cfg *models.VPNConfig, listenPort int) string {
	return resolveClientEndpointInternal(ctx, s, cfg, listenPort)
}

// ResolveClientEndpoint resolves the public endpoint for the Load Balancer entry point.
func (s *Service) ResolveClientEndpoint(ctx context.Context) string {
	s.mu.RLock()
	cfg := s.cfg
	listenPort := 51820
	if cfg != nil && cfg.ListenPort > 0 {
		listenPort = cfg.ListenPort
	}
	s.mu.RUnlock()
	return s.resolveClientEndpoint(ctx, cfg, listenPort)
}
