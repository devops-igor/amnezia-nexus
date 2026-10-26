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
	"gateway.icloud.com",
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
	ALPN            string `json:"alpn,omitempty"`
	ALPNH2          bool   `json:"alpn_h2,omitempty"`
	PassedGeoFilter bool   `json:"passed_geo_filter"`
	Status          string `json:"status"` // "ok", "rejected_geo_mismatch", "tls_failed", "dns_failed"
	Reason          string `json:"reason,omitempty"`
}

// ScanReport encapsulates scan results against a target server.
type ScanReport struct {
	ServerIP      string       `json:"server_ip"`
	ServerCountry string       `json:"server_country,omitempty"`
	ServerASN     uint32       `json:"server_asn,omitempty"`
	Results       []ScanResult `json:"results"`
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
}

// ScanSNI executes concurrent probing and ASN/geo proximity filtering for candidate domains.
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

				res := scanCandidateDomain(ctx, domain, serverIP, geoDB, timeout, opts.RootCAs)
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

	// Rank results: "ok" first by latency ascending, then non-ok
	sort.Slice(results, func(i, j int) bool {
		iOk := results[i].Status == "ok"
		jOk := results[j].Status == "ok"
		if iOk && jOk {
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

	return &ScanReport{
		ServerIP:      serverIP.String(),
		ServerCountry: serverCountry,
		ServerASN:     serverASN,
		Results:       results,
	}, nil
}

func scanCandidateDomain(
	ctx context.Context,
	domain string,
	serverIP net.IP,
	geoDB *GeoDB,
	timeout time.Duration,
	rootCAs *x509.CertPool,
) ScanResult {
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

	// 3. TLS 1.3 / H2 Probe
	probeOpts := ProbeOptions{
		Timeout: timeout,
		RootCAs: rootCAs,
	}
	probeRes := ProbeTLSH2(ctx, domain, probeOpts)
	if probeRes.Error != "" {
		return ScanResult{
			Domain:          domain,
			Country:         candCountry,
			ASN:             candASN,
			RTTMS:           probeRes.RTTMS,
			PassedGeoFilter: true,
			Status:          "tls_failed",
			Reason:          probeRes.Error,
		}
	}

	return ScanResult{
		Domain:          domain,
		Country:         candCountry,
		ASN:             candASN,
		RTTMS:           probeRes.RTTMS,
		TLS13:           true,
		ALPN:            probeRes.ALPN,
		ALPNH2:          probeRes.ALPN == "h2",
		PassedGeoFilter: true,
		Status:          "ok",
		Reason:          geoReason,
	}
}
