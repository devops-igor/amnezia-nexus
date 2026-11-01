package scanner

import (
	"strings"
)

// IsBlacklistedDecoyDomain returns true if the domain matches censor-targeted DPI blacklists:
// - Apple Private Relay: gateway.icloud.com, mask.icloud.com, mask-h2.icloud.com, *.icloud.com, icloud.com, apple-relay.apple.com, *.apple-relay.apple.com
// - Telegram Web CDN / Circumvention domains: *.telegram.org, telegram.org, *.t.me, t.me
func IsBlacklistedDecoyDomain(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return false
	}

	// Apple Private Relay
	if d == "gateway.icloud.com" || d == "mask.icloud.com" || d == "mask-h2.icloud.com" {
		return true
	}
	if d == "icloud.com" || strings.HasSuffix(d, ".icloud.com") {
		return true
	}
	if d == "apple-relay.apple.com" || strings.HasSuffix(d, ".apple-relay.apple.com") {
		return true
	}

	// Telegram Web CDN
	if d == "telegram.org" || strings.HasSuffix(d, ".telegram.org") {
		return true
	}
	if d == "t.me" || strings.HasSuffix(d, ".t.me") {
		return true
	}

	return false
}
