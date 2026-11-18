package policy

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// This file defines the source-controlled aggregate manifest and the
// never-proxy guard from issue #883. The manifest is explicit: adding an
// upstream list is a reviewed code/change, never an automatic directory scan.

const aggregateBaseURL = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/"

// aggregateManifest is the 24 primary raw lists. Russia/outside-raw.lst is
// deliberately absent: it describes Russian egress destinations, not names this
// product should proxy. Converted transport variants and src/ derived files are
// also absent.
var aggregateManifest = []string{
	"Categories/anime.lst",
	"Categories/block.lst",
	"Categories/geoblock.lst",
	"Categories/hodca.lst",
	"Categories/news.lst",
	"Categories/porn.lst",
	"Russia/inside-raw.lst",
	"Ukraine/inside-raw.lst",
	"Services/cloudflare.lst",
	"Services/cloudfront.lst",
	"Services/digitalocean.lst",
	"Services/discord.lst",
	"Services/google_ai.lst",
	"Services/google_meet.lst",
	"Services/google_play.lst",
	"Services/hdrezka.lst",
	"Services/hetzner.lst",
	"Services/meta.lst",
	"Services/ovh.lst",
	"Services/roblox.lst",
	"Services/telegram.lst",
	"Services/tiktok.lst",
	"Services/twitter.lst",
	"Services/youtube.lst",
}

// AggregateSources returns the ordered aggregate sources. The IDs are stable and
// carry the manifest path, so per-component status is reviewable against the
// manifest without a second mapping.
func AggregateSources() []Source {
	out := make([]Source, 0, len(aggregateManifest))
	for _, path := range aggregateManifest {
		out = append(out, Source{
			ID:             "aggregate:" + path,
			URL:            aggregateBaseURL + path,
			Format:         FormatDomains,
			BareDomainMode: DomainModeInclusiveSuffix,
			IsPreset:       true,
		})
	}
	return out
}

// AggregateManifest returns a copy of the manifest paths.
func AggregateManifest() []string {
	out := make([]string, len(aggregateManifest))
	copy(out, aggregateManifest)
	return out
}

// neverProxyPatterns is the reviewed guard set. A rule whose base is equal to,
// a subdomain of, or an ancestor matching any pattern is removed from the PROXY
// set. Ancestor rules are included deliberately: a broad "ru" rule would proxy
// every listed government name even if the exact entry were removed.
var neverProxyPatterns = []string{
	// Russian state and government patterns.
	"gov.ru",
	"government.ru",
	"kremlin.ru",
	"mil.ru",
	"mvd.ru",
	"rkn.gov.ru",
	"mchs.gov.ru",
	"rospotrebnadzor.gov.ru",
	"rospotrebnadzor.ru",
	"roszdravnadzor.gov.ru",
	"roszdravnadzor.ru",
	"genproc.gov.ru",
	"sudrf.ru",
	"pravo.gov.ru",
	"gosuslugi.ru",
	"gu-st.ru",
	"mos.ru",
	"mosreg.ru",
	"nalog.ru",
	"rosreestr.gov.ru",
	"fssp.gov.ru",
	"rk.gov.ru",
	// Explicit internal-service denylist observed crossing other components.
	"ozon.ru",
	"rzd.ru",
	"showip.net",
	"yandex.net",
	// Every name from Russia/outside-raw.lst, the list excluded from the
	// aggregate. Some cross into other components; the guard keeps them direct.
	"1018213540.rsc.cdn77.org",
	"avtodor-tr.ru",
	"b2c-ticket-sentry.onelya.ru",
	"bitrix.info",
	"bkvet.ru",
	"cdn1.ozonusercontent.com",
	"cms1.dzvr.ru",
	"consultant.ru",
	"counter.yadro.ru",
	"dzvr.ru",
	"emex.ru",
	"fairplay-proxy.ott.yandex.ru",
	"gorzdrav.spb.ru",
	"graphql.kinopoisk.ru",
	"lemanapro.ru",
	"leroymerlin.ru",
	"magnit.ru",
	"mobileapp.russianpost.ru",
	"mosenergosbyt.ru",
	"pesc.ru",
	"pochta.ru",
	"reso.ru",
	"rzd-bonus.ru",
	"sys.refocus.ru",
	"vshark.ttk.ru",
	"widevine-proxy.ott.yandex.ru",
	"xn--90aijkdmaud0d.xn--p1ai",
}

// NeverProxyReason reports whether a canonical domain rule would proxy a guarded
// name. The returned reason names the guard for local-entry validation.
func NeverProxyReason(domain string) (string, bool) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return "", false
	}
	for _, pattern := range neverProxyPatterns {
		if domain == pattern || strings.HasSuffix(domain, "."+pattern) || strings.HasSuffix(pattern, "."+domain) {
			return fmt.Sprintf("never-proxy guard: %q is internal Russian infrastructure and must stay direct (pattern %q)", domain, pattern), true
		}
	}
	return "", false
}

// FilterNeverProxyDomains removes guarded DOMAIN rules and returns the number
// removed. The input is not modified.
//
// CIDR rules pass through unchanged, and that is the documented boundary of the
// guarantee: the guard works from names, while the forwarder matches a CIDR rule
// against the packet's destination address before it consults DNS evidence
// (forwarder.matchesProxyPolicy). A name-based guard therefore cannot promise
// DIRECT for an address covered by an operator-supplied CIDR. The aggregate
// manifest contains only FormatDomains lists, so the shipped aggregate has no
// CIDRs; an operator who adds one is choosing the address range to proxy.
func FilterNeverProxyDomains(rules ParsedRules) (ParsedRules, int) {
	out := ParsedRules{
		Domains: make(map[string]domainFlags, len(rules.Domains)),
		CIDRs:   rules.CIDRs,
	}
	excluded := 0
	for base, flags := range rules.Domains {
		if _, guarded := NeverProxyReason(base); guarded {
			excluded++
			continue
		}
		out.Domains[base] = flags
	}
	return out, excluded
}

// GenerationNeverProxyViolations returns the stored domain rules that the
// never-proxy guard forbids, sorted for stable reporting.
//
// A durable generation was filtered by the build that wrote it. After an upgrade
// that adds a guard pattern, or after a hand-edited or pre-guard cache is loaded,
// nothing in the generation itself proves it is clean. Baseline adoption must
// check this before publishing those rules, because an upstream outage must not
// turn a stale snapshot into a proxied government domain.
func GenerationNeverProxyViolations(gen *Generation) []string {
	if gen == nil || len(gen.Domains) == 0 {
		return nil
	}
	violations := make([]string, 0)
	for base := range gen.Domains {
		if _, guarded := NeverProxyReason(base); guarded {
			violations = append(violations, base)
		}
	}
	sort.Strings(violations)
	return violations
}

// filterNeverProxyFlags applies the guard to the durable/aggregate flag map.
func filterNeverProxyFlags(domains map[string]uint32) (map[string]uint32, int) {
	out := make(map[string]uint32, len(domains))
	excluded := 0
	for base, flags := range domains {
		if _, guarded := NeverProxyReason(base); guarded {
			excluded++
			continue
		}
		out[base] = flags
	}
	return out, excluded
}

// ParseLocalRules parses operator-supplied domain/CIDR entries with the same
// strict parser used for custom URLs, then applies the never-proxy guard.
func ParseLocalRules(lines []string) (ParsedRules, ParseReport, error) {
	dataLines := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isIgnoredLine(trimmed) {
			continue
		}
		dataLines = append(dataLines, trimmed)
	}
	if len(dataLines) == 0 {
		return ParsedRules{Domains: map[string]domainFlags{}}, ParseReport{}, nil
	}
	limits := DefaultParseLimits()
	limits.MaxLines = 4096
	limits.MaxRules = 4096
	src := Source{
		ID:             "local",
		Format:         FormatMixed,
		BareDomainMode: DomainModeInclusiveSuffix,
		IsPreset:       false,
	}
	parsed, report, err := Parse(context.Background(), strings.NewReader(strings.Join(dataLines, "\n")), src, limits)
	if err != nil {
		return ParsedRules{}, report, err
	}
	filtered, excluded := FilterNeverProxyDomains(parsed)
	if excluded > 0 {
		for base := range parsed.Domains {
			if reason, guarded := NeverProxyReason(base); guarded {
				return ParsedRules{}, report, fmt.Errorf("%s", reason)
			}
		}
	}
	return filtered, report, nil
}

// NeverProxyPatterns returns a copy for tests and documentation.
func NeverProxyPatterns() []string {
	out := make([]string, len(neverProxyPatterns))
	copy(out, neverProxyPatterns)
	return out
}
