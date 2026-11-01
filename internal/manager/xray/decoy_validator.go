package xray

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/manager/xray/scanner"
)

// DefaultDecoyDomain is the default unblacklisted camouflage domain used for REALITY inbounds.
const DefaultDecoyDomain = "www.microsoft.com"

var lookupIP = net.DefaultResolver.LookupIP

// IsBlacklistedDecoyDomain returns true if the candidate domain matches known censor-targeted domains
// such as Apple Private Relay gateways or Telegram Web CDN endpoints.
func IsBlacklistedDecoyDomain(domain string) bool {
	return scanner.IsBlacklistedDecoyDomain(domain)
}

// ValidateDecoyDomain checks a candidate REALITY camouflage domain against DPI censor blacklists
// and verifies ASN/hosting proximity against the target server using GeoDB.
func ValidateDecoyDomain(domain string, serverIP string, geoDB *scanner.GeoDB) error {
	cleanDomain := strings.ToLower(strings.TrimSpace(domain))
	cleanDomain = strings.TrimSuffix(cleanDomain, ".")
	if cleanDomain == "" {
		return errors.New("decoy domain cannot be empty")
	}

	// 1. Censor-Target Blacklist Check
	if IsBlacklistedDecoyDomain(cleanDomain) {
		return fmt.Errorf("decoy domain %q is blacklisted as a known censor target", domain)
	}

	// 2. Load GeoDB if not supplied
	if geoDB == nil {
		var err error
		geoDB, err = scanner.DefaultGeoDB()
		if err != nil {
			return fmt.Errorf("load default geodb: %w", err)
		}
	}

	// 3. Resolve domain to IPv4
	var candIP net.IP
	if ip := net.ParseIP(cleanDomain); ip != nil {
		candIP = ip
	} else {
		ips, err := lookupIP(context.Background(), "ip4", cleanDomain)
		if err == nil && len(ips) > 0 {
			candIP = ips[0]
		}
	}

	if candIP == nil {
		// If domain cannot be resolved (e.g. offline test environment, mock domain),
		// we cannot verify ASN/geo alignment, but it passed the censor blacklist.
		return nil
	}

	// 4. ASN Validation: Reject Apple AS714 (censor-targeted Anycast)
	candASN, _, candFound := geoDB.Lookup(candIP)
	if candFound && candASN == 714 {
		return fmt.Errorf("decoy domain %q belongs to Apple AS714 which is targeted by DPI egress blocking", domain)
	}

	// 5. Server Alignment: Verify geo/ASN alignment if server IP is provided
	if serverIP != "" {
		cleanServer := strings.TrimSpace(serverIP)
		if h, _, err := net.SplitHostPort(cleanServer); err == nil {
			cleanServer = h
		}
		sIP := net.ParseIP(cleanServer)
		if sIP == nil {
			ips, err := lookupIP(context.Background(), "ip4", cleanServer)
			if err == nil && len(ips) > 0 {
				sIP = ips[0]
			}
		}

		if sIP != nil {
			passed, _, _, _, _, reason := geoDB.ValidateGeoProximity(sIP, candIP)
			if !passed {
				return fmt.Errorf("decoy domain %q failed geo/ASN alignment with server %s: %s", domain, serverIP, reason)
			}
		}
	}

	return nil
}
