package scanner

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultCandidateDomains contains well-known high-reputation TLS 1.3 / H2 endpoints.
var DefaultCandidateDomains = []string{
	"www.microsoft.com",
	"www.apple.com",
	"aws.amazon.com",
	"www.cloudflare.com",
	"fonts.googleapis.com",
	"www.cisco.com",
	"www.oracle.com",
	"www.samsung.com",
	"cdn.apple-mapkit.com",
}

// ScanResult contains diagnostic and compatibility information for a candidate domain.
type ScanResult struct {
	Domain          string `json:"domain"`
	Country         string `json:"country,omitempty"`
	ASN             uint32 `json:"asn,omitempty"`
	RTTMS           int64  `json:"rtt_ms,omitempty"`
	TLS13           bool   `json:"tls13"`
	Curve           string `json:"curve,omitempty"`
	X25519          bool   `json:"x25519,omitempty"`
	ALPN            string `json:"alpn,omitempty"`
	ALPNH2          bool   `json:"alpn_h2,omitempty"`
	PassedGeoFilter bool   `json:"passed_geo_filter"`
	ProximityScore  int    `json:"proximity_score,omitempty"`
	Status          string `json:"status"` // "ok", "rejected_geo_mismatch", "tls_failed", "dns_failed"
	Reason          string `json:"reason,omitempty"`
}

// ScanReport encapsulates scan results against a target server.
//
// Scope is "panel_side_proximity" when probes dial directly from the panel host, or
// "ssh_tunneled_proximity" when TCP is tunneled over SSH direct-tcpip while the TLS
// handshake still runs on the panel: RTTMS then includes panel<->SSH transport overhead
// and is not an isolated remote-server RTT. FallbackToPanel/Warning are set by callers
// that wanted the SSH tunnel but had to probe from the panel.
type ScanReport struct {
	Scope           string       `json:"scope,omitempty"`
	FallbackToPanel bool         `json:"fallback_to_panel,omitempty"`
	Warning         string       `json:"warning,omitempty"`
	ServerIP        string       `json:"server_ip"`
	ServerCountry   string       `json:"server_country,omitempty"`
	ServerASN       uint32       `json:"server_asn,omitempty"`
	Results         []ScanResult `json:"results"`
}

// ScannerOptions configures the worker pool and candidate selection.
//
//nolint:revive
type ScannerOptions struct {
	Concurrency int
	Timeout     time.Duration
	Domains     []string
	GeoDB       *GeoDB
	RootCAs     *x509.CertPool
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// calculateProximityScore ranks candidate domains by locality, treating Anycast CDNs as graceful fallback.
func calculateProximityScore(serverCountry string, serverASN uint32, candCountry string, candASN uint32) int {
	isCDN := IsMultiRegionCDNASN(candASN)
	sameASN := serverASN > 0 && candASN > 0 && serverASN == candASN
	sameCountry := serverCountry != "" && candCountry != "" && serverCountry == candCountry

	switch {
	case sameASN && sameCountry:
		return 100 // Same-ASN and same-country: optimal proximity
	case sameASN:
		return 90 // Same-ASN
	case sameCountry && !isCDN:
		return 80 // Same country local domain (non-CDN)
	case sameCountry && isCDN:
		return 60 // Same country CDN edge
	case isCDN:
		return 40 // Multi-region Anycast CDN fallback
	default:
		return 20 // Other allowed fallback
	}
}

// ScanSNI executes concurrent probing, compatibility filtering (TLS 1.3, X25519, H2),
// and geo/ASN-aligned ranking for candidate domains.
func ScanSNI(ctx context.Context, serverHost string, opts ScannerOptions) (*ScanReport, error) {
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	domains := opts.Domains
	if len(domains) == 0 {
		domains = DefaultCandidateDomains
	}

	geoDB := opts.GeoDB
	if geoDB == nil {
		var err error
		geoDB, err = DefaultGeoDB()
		if err != nil {
			return nil, fmt.Errorf("load default geodb: %w", err)
		}
	}

	// Resolve server IP
	var serverIP net.IP
	cleanHost := strings.TrimSpace(serverHost)
	if h, _, err := net.SplitHostPort(cleanHost); err == nil {
		cleanHost = h
	}
	serverIP = net.ParseIP(cleanHost)
	if serverIP == nil {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", cleanHost)
		if err != nil || len(ips) == 0 {
			// Fallback: dummy IP or report error
			return nil, fmt.Errorf("failed to resolve target server host %q: %w", cleanHost, err)
		}
		serverIP = ips[0]
	}

	serverASN, serverCountry, _ := geoDB.Lookup(serverIP)

	resultsChan := make(chan ScanResult, len(domains))
	jobsChan := make(chan string, len(domains))

	for _, d := range domains {
		jobsChan <- d
	}
	close(jobsChan)

	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobsChan {
				select {
				case <-ctx.Done():
					resultsChan <- ScanResult{
						Domain: domain,
						Status: "canceled",
						Reason: ctx.Err().Error(),
					}
					continue
				default:
				}

				res := scanCandidateDomain(ctx, domain, serverIP, serverCountry, serverASN, geoDB, timeout, opts.RootCAs, opts.DialContext)
				resultsChan <- res
			}
		}()
	}

	wg.Wait()
	close(resultsChan)

	results := make([]ScanResult, 0, len(domains))
	for res := range resultsChan {
		results = append(results, res)
	}

	// Rank results: "ok" first by proximity score descending, then latency ascending
	RankScanResults(results)

	scope := "panel_side_proximity"
	if opts.DialContext != nil {
		scope = "ssh_tunneled_proximity"
	}
	return &ScanReport{
		Scope:         scope,
		ServerIP:      serverIP.String(),
		ServerCountry: serverCountry,
		ServerASN:     serverASN,
		Results:       results,
	}, nil
}

// RankScanResults sorts scan results in-place per production ranking rules:
// "ok" status candidates appear first, ordered by ProximityScore descending,
// then RTTMS ascending. Non-"ok" results follow, ordered alphabetically by domain.
func RankScanResults(results []ScanResult) {
	sort.Slice(results, func(i, j int) bool {
		iOk := results[i].Status == "ok"
		jOk := results[j].Status == "ok"
		if iOk && jOk {
			if results[i].ProximityScore != results[j].ProximityScore {
				return results[i].ProximityScore > results[j].ProximityScore
			}
			return results[i].RTTMS < results[j].RTTMS
		}
		if iOk && !jOk {
			return true
		}
		if !iOk && jOk {
			return false
		}
		return results[i].Domain < results[j].Domain
	})
}

func scanCandidateDomain(
	ctx context.Context,
	domain string,
	serverIP net.IP,
	serverCountry string,
	serverASN uint32,
	geoDB *GeoDB,
	timeout time.Duration,
	rootCAs *x509.CertPool,
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error),
) ScanResult {
	// 0. Censor-target blacklist check
	if IsBlacklistedDecoyDomain(domain) {
		return ScanResult{
			Domain: domain,
			Status: "rejected_blacklisted",
			Reason: "censor-targeted circumvention domain",
		}
	}

	// 1. Resolve domain A record
	resolveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(resolveCtx, "ip4", domain)
	if err != nil || len(ips) == 0 {
		return ScanResult{
			Domain: domain,
			Status: "dns_failed",
			Reason: fmt.Sprintf("DNS resolution failed: %v", err),
		}
	}
	candIP := ips[0]

	// 2. Validate Geo / ASN proximity
	candASN, candCountry, _ := geoDB.Lookup(candIP)
	if candASN == 714 {
		return ScanResult{
			Domain:          domain,
			Country:         candCountry,
			ASN:             candASN,
			PassedGeoFilter: false,
			Status:          "rejected_blacklisted",
			Reason:          "resolves to Apple AS714 (censor-targeted Anycast)",
		}
	}

	passed, _, candCountry, _, candASN, geoReason := geoDB.ValidateGeoProximity(serverIP, candIP)
	if !passed {
		return ScanResult{
			Domain:          domain,
			Country:         candCountry,
			ASN:             candASN,
			PassedGeoFilter: false,
			Status:          "rejected_geo_mismatch",
			Reason:          geoReason,
		}
	}

	// 3. TLS 1.3 / X25519 / H2 Probe
	probeOpts := ProbeOptions{
		Timeout:     timeout,
		RootCAs:     rootCAs,
		TargetIP:    candIP,
		DialContext: dialContext,
	}
	probeRes := ProbeTLSH2(ctx, domain, probeOpts)
	if probeRes.Error != "" || !probeRes.TLS13 || !probeRes.X25519 || probeRes.ALPN != "h2" {
		failReason := probeRes.Error
		if failReason == "" {
			switch {
			case !probeRes.TLS13:
				failReason = "requires TLS 1.3"
			case !probeRes.X25519:
				failReason = "requires X25519 key exchange"
			case probeRes.ALPN != "h2":
				failReason = "requires ALPN h2 negotiation"
			default:
				failReason = "incompatible TLS configuration"
			}
		}
		return ScanResult{
			Domain:          domain,
			Country:         candCountry,
			ASN:             candASN,
			RTTMS:           probeRes.RTTMS,
			TLS13:           probeRes.TLS13,
			Curve:           probeRes.Curve,
			X25519:          probeRes.X25519,
			ALPN:            probeRes.ALPN,
			ALPNH2:          probeRes.ALPN == "h2",
			PassedGeoFilter: true,
			Status:          "tls_failed",
			Reason:          failReason,
		}
	}

	score := calculateProximityScore(serverCountry, serverASN, candCountry, candASN)

	return ScanResult{
		Domain:          domain,
		Country:         candCountry,
		ASN:             candASN,
		RTTMS:           probeRes.RTTMS,
		TLS13:           true,
		Curve:           probeRes.Curve,
		X25519:          true,
		ALPN:            probeRes.ALPN,
		ALPNH2:          true,
		PassedGeoFilter: true,
		ProximityScore:  score,
		Status:          "ok",
		Reason:          geoReason,
	}
}
