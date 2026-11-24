package web

// The split-egress section and the per-client diagnosis beside it are the only
// surfaces where an operator reads how a route is chosen. This file pins what
// those strings are allowed to say, against the packet path itself:
//
//	internal/vpn/forwarder/routing_decision.go
//	    "The destination address is the only routing input. Retained DNS
//	    evidence is not consulted: the recorded evidence of a flow describes
//	    the decision, it does not decide one."
//	internal/policy/classify.go
//	    the classifier answers for an IPv4 destination only, and an address it
//	    cannot place is reported as unclassified.
//	internal/vpn/forwarder/pumps.go
//	    a flow that is not TCP or UDP cannot be NATed directly and takes the
//	    proxy path; without a classifier every destination stays unclassified
//	    and keeps the fail-safe proxy default.
//
// Prose that describes a mechanism the code does not implement is invisible to
// every other test here: the key resolves, the dictionary carries it, the page
// renders, and only the operator is misled. That is why the statements are
// pinned directly, and why the guarded key set is read from the shipped
// templates and controllers instead of being listed by hand.

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// policySurfaceFiles are the shipped sources whose translation keys reach the
// operator as policy text. A hint added to any of them is guarded without
// editing this test.
var policySurfaceFiles = []struct {
	path     string
	template bool
}{
	{path: "templates/settings_policy.html", template: true},
	{path: "templates/settings_policy_client.html", template: true},
	{path: "static/js/policy_routing.js"},
	{path: "static/js/policy_client_diag.js"},
	{path: "static/js/policy_client_diag_filter.js"},
}

var (
	// A template key is written as {{ _ "policy_…" }}.
	policyTemplateKey = regexp.MustCompile(`\{\{[^}]*?_\s+"(policy_[a-z0-9_]+)"`)
	// A controller key is the literal it passes to the translator, or a label
	// map value the translator resolves. Element ids the controllers also write
	// as string literals are not translation keys, so only these call forms are
	// read.
	policyScriptKeys = []*regexp.Regexp{
		regexp.MustCompile(`(?:policyText|clientText|label)\(\s*'(policy_[a-z0-9_]+)'`),
		regexp.MustCompile(`:\s*'(policy_client_decision_reason_[a-z0-9_]+)'`),
	}
)

// policyRetiredClaims are the statements the retired DNS-observation model made
// about how a destination is routed. Each fragment is wording the panel actually
// shipped, in the language it shipped it in, so restoring that model fails this
// test instead of quietly reaching an operator again. The fragments are the
// retired sentences' own words rather than a DNS keyword, because a hint about
// what the panel does *not* observe legitimately names DNS.
var policyRetiredClaims = []struct {
	locale string
	claim  string
	text   string
}{
	// Retired policy_limits_notice: "Encrypted DNS and direct-IP connections may
	// not be classified for direct routing; IPv6 PBR is unsupported in v1." No
	// part of the packet path observes a name to classify a destination.
	{locale: "en", claim: "DNS observation is what classifies a destination", text: "Encrypted DNS"},
	{locale: "en", claim: "DNS observation decides the direct route", text: "classified for direct routing"},
	{locale: "ru", claim: "DNS observation is what classifies a destination", text: "Зашифрованный DNS"},
	{locale: "ru", claim: "DNS observation decides the direct route", text: "классифицироваться для прямого маршрута"},
	{locale: "fr", claim: "DNS observation is what classifies a destination", text: "DNS chiffré"},
	{locale: "fr", claim: "DNS observation decides the direct route", text: "classés pour le routage direct"},
	{locale: "zh", claim: "DNS observation is what classifies a destination", text: "加密 DNS"},
	{locale: "zh", claim: "DNS observation decides the direct route", text: "无法归类为直连路由"},
	{locale: "fa", claim: "DNS observation is what classifies a destination", text: "DNS رمزنگاری"},
	{locale: "fa", claim: "DNS observation decides the direct route", text: "برای مسیریابی مستقیم طبقه‌بندی"},

	// Retired policy_inventory_unusable: "… while routing backed by retained DNS
	// evidence stays active." The packet path keeps no DNS evidence to route on;
	// an unusable inventory leaves every destination unclassified, which proxies.
	{locale: "en", claim: "retained DNS evidence still routes", text: "retained DNS evidence"},
	{locale: "ru", claim: "retained DNS evidence still routes", text: "свидетельствам DNS"},
	{locale: "fr", claim: "retained DNS evidence still routes", text: "preuves DNS"},
	{locale: "zh", claim: "retained DNS evidence still routes", text: "保留 DNS 证据"},
	{locale: "fa", claim: "retained DNS evidence still routes", text: "شواهد DNS نگهداری"},

	// An earlier notice on the same surface, kept refused so it cannot return in
	// a future rewrite of the hints above.
	{locale: "en", claim: "the gateway's DNS observation decides the route", text: "observed through the gateway DNS"},
}

// policyLocales is every bundle the panel ships.
var policyLocales = []string{"en", "ru", "fr", "zh", "fa"}

// TestPolicySurfaceDoesNotDescribeTheRetiredDnsModel fails when any string the
// policy surface renders asserts a routing mechanism the packet path does not
// implement.
func TestPolicySurfaceDoesNotDescribeTheRetiredDnsModel(t *testing.T) {
	surface := policySurfaceKeys(t)
	dictionaries := policyDictionaries(t)

	// A key extracted from a template or controller but absent from the bundle
	// would narrow the guard to nothing, so the guarded set is checked against
	// the dictionaries that render it.
	for _, key := range sortedPolicyKeys(surface) {
		if _, ok := dictionaries["en"][key]; !ok {
			t.Errorf("%s is referenced by %s but en.json does not define it", key, surface[key])
		}
	}
	if len(surface) < 40 {
		t.Fatalf("found only %d policy keys on the shipped surface; the extraction is wrong", len(surface))
	}

	for _, retired := range policyRetiredClaims {
		needle := strings.ToLower(retired.text)
		for _, key := range sortedPolicyKeys(surface) {
			if !strings.Contains(strings.ToLower(dictionaries[retired.locale][key]), needle) {
				continue
			}
			t.Errorf("%s.json %q still states that %s: restore what the packet path does\n  retired wording: %q\n  shipped value: %q",
				retired.locale, key, retired.claim, retired.text, dictionaries[retired.locale][key])
		}
	}
}

// policyHintClaim is one statement the operator relies on, with the technical
// token every bundle must keep for it.
type policyHintClaim struct {
	key    string
	claim  string
	tokens []string
}

// TestPolicyHintsNameTheRealRoutingInput pins what the two corrected hints keep
// saying, in every bundle. The retired sentences named neither IPv4 nor PROXY,
// so a bundle that reverts to the retired mechanism loses the token and fails
// here even when it was reworded rather than restored verbatim.
func TestPolicyHintsNameTheRealRoutingInput(t *testing.T) {
	surface := policySurfaceKeys(t)
	dictionaries := policyDictionaries(t)

	for _, want := range []policyHintClaim{
		{
			key:   "policy_limits_notice",
			claim: "the routing input is the IPv4 destination address, and DNS is not inspected",
			// The panel does read the destination address, and it never reads a
			// name: both halves are stated where the operator looks for limits.
			tokens: []string{"IPv4", "DNS"},
		},
		{
			key:   "policy_inventory_unusable",
			claim: "with no usable inventory every destination keeps the PROXY default",
			// The fail-safe default is the fact the retired sentence replaced with
			// a DNS fallback that does not exist.
			tokens: []string{"PROXY"},
		},
	} {
		assertPolicyHintClaim(t, surface, dictionaries, want)
	}
}

// assertPolicyHintClaim checks one claim against the shipped surface and every
// bundle.
func assertPolicyHintClaim(t *testing.T, surface map[string]string, dictionaries map[string]map[string]string, want policyHintClaim) {
	t.Helper()

	if _, ok := surface[want.key]; !ok {
		t.Errorf("%q is not referenced by any shipped policy source; the guard would pin a string nobody renders", want.key)
	}
	for _, locale := range policyLocales {
		value := strings.TrimSpace(dictionaries[locale][want.key])
		if value == "" {
			t.Errorf("%s.json %q is empty", locale, want.key)
			continue
		}
		if locale != "en" && value == dictionaries["en"][want.key] {
			t.Errorf("%s.json %q is the English text, not a translation", locale, want.key)
		}
		for _, token := range want.tokens {
			if !strings.Contains(value, token) {
				t.Errorf("%s.json %q must name %s in every locale: %s\n  shipped value: %q",
					locale, want.key, token, want.claim, value)
			}
		}
	}
}

// policySurfaceKeys reads every policy translation key the shipped policy
// templates and controllers reference, with the file that references it.
func policySurfaceKeys(t *testing.T) map[string]string {
	t.Helper()

	keys := make(map[string]string)
	for _, file := range policySurfaceFiles {
		source, err := readPolicySurfaceFile(file.path, file.template)
		if err != nil {
			t.Fatalf("read %s: %v", file.path, err)
		}
		patterns := policyScriptKeys
		if file.template {
			patterns = []*regexp.Regexp{policyTemplateKey}
		}
		for _, pattern := range patterns {
			for _, match := range pattern.FindAllStringSubmatch(source, -1) {
				if _, seen := keys[match[1]]; !seen {
					keys[match[1]] = file.path
				}
			}
		}
	}
	return keys
}

// readPolicySurfaceFile reads one policy source from the embedded assets, so the
// guard covers the files the binary serves rather than the working tree.
func readPolicySurfaceFile(path string, template bool) (string, error) {
	if template {
		raw, err := TemplatesFS.ReadFile(path)
		return string(raw), err
	}
	raw, err := StaticFS.ReadFile(path)
	return string(raw), err
}

// policyDictionaries decodes every shipped locale bundle.
func policyDictionaries(t *testing.T) map[string]map[string]string {
	t.Helper()

	dictionaries := make(map[string]map[string]string, len(policyLocales))
	for _, locale := range policyLocales {
		raw, err := TranslationsFS.ReadFile("translations/" + locale + ".json")
		if err != nil {
			t.Fatalf("read %s.json: %v", locale, err)
		}
		var dictionary map[string]string
		if err := json.Unmarshal(raw, &dictionary); err != nil {
			t.Fatalf("decode %s.json: %v", locale, err)
		}
		dictionaries[locale] = dictionary
	}
	return dictionaries
}

// sortedPolicyKeys orders the guarded keys so a failure lists them predictably.
func sortedPolicyKeys(keys map[string]string) []string {
	out := make([]string, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
