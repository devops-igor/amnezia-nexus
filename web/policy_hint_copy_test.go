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
//	    the packet is validated and an existing flow keeps its earlier decision
//	    before any list is matched, so the destination does not decide on its
//	    own; a flow that is not TCP or UDP cannot be NATed directly and takes the
//	    proxy path; a non-IPv4 packet is refused.
//	internal/vpn/vpn_pbr.go, internal/vpn/vpn_pbr_policy_snapshot.go
//	    activation refuses to start policy routing without an installed
//	    classifier, so an unusable inventory leaves policy routing off and the
//	    operator's traffic on the legacy proxy path.
//
// Prose that describes a mechanism the code does not implement, or that
// promises an outcome the code does not deliver in the state the operator is
// in, is invisible to every other test here: the key resolves, the dictionary
// carries it, the page renders, and only the operator is misled. That is why
// the statements are pinned directly, and why the guarded key set is read from
// the shipped templates and controllers instead of being listed by hand.

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
	{path: "static/js/policy_panels.js"},
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
		regexp.MustCompile(`(?:policyText|clientText|label|panelText)\(\s*'(policy_[a-z0-9_]+)'`),
		regexp.MustCompile(`:\s*'(policy_client_decision_reason_[a-z0-9_]+)'`),
	}
	// A translator call's whole argument list, so a label chosen inside a
	// conditional (`panelText(hasList ? 'a' : 'b')`) is guarded like a literal one.
	// A literal-call pattern misses it, and a miss is invisible: the key resolves
	// elsewhere and only the emptied translation reaches the operator.
	policyScriptCallEnv = regexp.MustCompile(`(?:policyText|clientText|label|panelText)\(([^()]*)\)`)
	// Any policy key literal inside such a call.
	policyScriptKeyLiteral = regexp.MustCompile(`'(policy_[a-z0-9_]+)'`)
)

// policyRefusedClaims are statements the policy surface must not make. Each
// fragment is wording the panel actually shipped, in the language it shipped it
// in, so restoring it fails this test instead of quietly reaching an operator
// again. The fragments are the refused sentences' own words rather than a DNS
// keyword, because a hint about what the panel does *not* observe legitimately
// names DNS.
//
// Two families are refused:
//
//   - "retired-dns" — the retired DNS-observation model.
//   - "rejected-r1" — the first-round wording a copy review rejected as partly
//     true: "the address only" overstates what an address match decides, "not
//     evaluated" hides that a non-IPv4 destination is refused, and "every
//     destination takes PROXY" promises a forwarder fallback in a state where
//     policy routing cannot start.
var policyRefusedClaims = []struct {
	id     string
	locale string
	claim  string
	text   string
}{
	// Retired policy_limits_notice: "Encrypted DNS and direct-IP connections may
	// not be classified for direct routing; IPv6 PBR is unsupported in v1." No
	// part of the packet path observes a name to classify a destination.
	{id: "retired-dns", locale: "en", claim: "DNS observation is what classifies a destination", text: "Encrypted DNS"},
	{id: "retired-dns", locale: "en", claim: "DNS observation decides the direct route", text: "classified for direct routing"},
	{id: "retired-dns", locale: "ru", claim: "DNS observation is what classifies a destination", text: "Зашифрованный DNS"},
	{id: "retired-dns", locale: "ru", claim: "DNS observation decides the direct route", text: "классифицироваться для прямого маршрута"},
	{id: "retired-dns", locale: "fr", claim: "DNS observation is what classifies a destination", text: "DNS chiffré"},
	{id: "retired-dns", locale: "fr", claim: "DNS observation decides the direct route", text: "classés pour le routage direct"},
	{id: "retired-dns", locale: "zh", claim: "DNS observation is what classifies a destination", text: "加密 DNS"},
	{id: "retired-dns", locale: "zh", claim: "DNS observation decides the direct route", text: "无法归类为直连路由"},
	{id: "retired-dns", locale: "fa", claim: "DNS observation is what classifies a destination", text: "DNS رمزنگاری"},
	{id: "retired-dns", locale: "fa", claim: "DNS observation decides the direct route", text: "برای مسیریابی مستقیم طبقه‌بندی"},

	// Retired policy_inventory_unusable: "… while routing backed by retained DNS
	// evidence stays active." The packet path keeps no DNS evidence to route on.
	{id: "retired-dns", locale: "en", claim: "retained DNS evidence still routes", text: "retained DNS evidence"},
	{id: "retired-dns", locale: "ru", claim: "retained DNS evidence still routes", text: "свидетельствам DNS"},
	{id: "retired-dns", locale: "fr", claim: "retained DNS evidence still routes", text: "preuves DNS"},
	{id: "retired-dns", locale: "zh", claim: "retained DNS evidence still routes", text: "保留 DNS 证据"},
	{id: "retired-dns", locale: "fa", claim: "retained DNS evidence still routes", text: "شواهد DNS نگهداری"},

	// An earlier notice on the same surface, kept refused so it cannot return in
	// a future rewrite of the hints above.
	{id: "retired-dns", locale: "en", claim: "the gateway's DNS observation decides the route", text: "observed through the gateway DNS"},

	// Rejected in the first round — the policy rules match the destination
	// address; the packet path also validates the packet, reuses an existing
	// flow's decision and sends a non-TCP/UDP flow to PROXY, so the address
	// match is not the whole decision.
	{id: "rejected-r1", locale: "en", claim: "address matching is the whole routing decision", text: "Routing reads the IPv4 destination address only"},
	{id: "rejected-r1", locale: "ru", claim: "address matching is the whole routing decision", text: "Маршрутизация читает только IPv4-адрес назначения"},
	{id: "rejected-r1", locale: "fr", claim: "address matching is the whole routing decision", text: "Le routage ne lit que l'adresse de destination IPv4"},
	{id: "rejected-r1", locale: "zh", claim: "address matching is the whole routing decision", text: "路由只依据 IPv4 目标地址判定"},
	{id: "rejected-r1", locale: "fa", claim: "address matching is the whole routing decision", text: "مسیریابی تنها نشانی مقصد IPv4 را می‌خواند"},

	// Rejected in the first round — a non-IPv4 client packet is refused on this
	// path, so "not evaluated" understates the limit: the policy path does not
	// support it.
	{id: "rejected-r1", locale: "en", claim: "an IPv6 destination is skipped rather than unsupported", text: "IPv6 destinations are not evaluated"},
	{id: "rejected-r1", locale: "ru", claim: "an IPv6 destination is skipped rather than unsupported", text: "IPv6-адреса не рассматриваются"},
	{id: "rejected-r1", locale: "fr", claim: "an IPv6 destination is skipped rather than unsupported", text: "les destinations IPv6 ne sont pas évaluées"},
	{id: "rejected-r1", locale: "zh", claim: "an IPv6 destination is skipped rather than unsupported", text: "IPv6 目标也不会被评估"},
	{id: "rejected-r1", locale: "fa", claim: "an IPv6 destination is skipped rather than unsupported", text: "مقصدهای IPv6 ارزیابی نمی‌شوند"},

	// Rejected in the first round — PROXY is what one decision falls back to; it
	// is not what an operator gets from a panel whose policy routing could not
	// start.
	{id: "rejected-r1", locale: "en", claim: "a broken inventory still routes every destination through PROXY", text: "every destination takes PROXY"},
	{id: "rejected-r1", locale: "ru", claim: "a broken inventory still routes every destination through PROXY", text: "все адреса идут через PROXY"},
	{id: "rejected-r1", locale: "fr", claim: "a broken inventory still routes every destination through PROXY", text: "toute destination passe par PROXY"},
	{id: "rejected-r1", locale: "zh", claim: "a broken inventory still routes every destination through PROXY", text: "所有目标都走 PROXY"},
	{id: "rejected-r1", locale: "fa", claim: "a broken inventory still routes every destination through PROXY", text: "همهٔ مقصدها از PROXY می‌روند"},
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

	for _, refused := range policyRefusedClaims {
		needle := strings.ToLower(refused.text)
		for _, key := range sortedPolicyKeys(surface) {
			if !strings.Contains(strings.ToLower(dictionaries[refused.locale][key]), needle) {
				continue
			}
			t.Errorf("(%s) %s.json %q still states that %s: state what this build does\n  refused wording: %q\n  shipped value: %q",
				refused.id, refused.locale, key, refused.claim, refused.text, dictionaries[refused.locale][key])
		}
	}
}

// policyHintClaim is one statement the operator relies on, with the technical
// token every bundle must keep for it.
type policyHintClaim struct {
	key    string
	claim  string
	tokens []string
	// tokensByLocale pins a claim whose words differ in every language: a shared
	// token cannot express "names the unusable list and points at the state
	// readout" in five languages, and pinning English words would fail four of them.
	tokensByLocale map[string][]string
}

// TestPolicyHintsNameTheRealRoutingInput pins what the two corrected hints keep
// saying, in every bundle: the terms that make each sentence true have to stay.
// The refused set above carries the corresponding negative direction, so a
// locale that reverts to the retired mechanism or to the rejected first-round
// wording fails there, and a locale that keeps the terms but loses the subject
// fails here.
func TestPolicyHintsNameTheRealRoutingInput(t *testing.T) {
	surface := policySurfaceKeys(t)
	dictionaries := policyDictionaries(t)

	for _, want := range []policyHintClaim{
		{
			key:   "policy_limits_notice",
			claim: "the policy rules match the destination's IPv4 address, DNS is named, and the IPv6 limit is stated",
			// Three terms carry the two clauses: the address the rules match,
			// the lookup they do not use, and the family they do not support.
			// A hint that drops any of them no longer states this limit.
			tokens: []string{"IPv4", "DNS", "IPv6"},
		},
		{
			// This key is the P2 answer body in this branch, not the free-standing
			// notice it was when the hint copy was written: the accepted design puts
			// "this build cannot read the list, check Policy status" in the panel and
			// states the mechanism limits in policy_limits_notice. The claim below is
			// therefore the one the panel actually makes; the mechanism sentence this
			// pin used to require is recorded as a handover disagreement, not silently
			// dropped — see the note in the R4 handover.
			key:   "policy_inventory_unusable",
			claim: "the unusable artifact is named, and the reader is sent to the Policy status readout",
			tokensByLocale: map[string][]string{
				"en": {"shipped address list", "Policy status"},
				"ru": {"список адресов", "политики"},
				"fr": {"liste d'adresses", "politique"},
				"zh": {"地址列表", "策略"},
				"fa": {"فهرست نشانی", "خط‌مشی"},
			},
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
		tokens := want.tokens
		if len(want.tokensByLocale) > 0 {
			tokens = want.tokensByLocale[locale]
		}
		for _, token := range tokens {
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
		if file.template {
			continue
		}
		for _, call := range policyScriptCallEnv.FindAllStringSubmatch(source, -1) {
			for _, literal := range policyScriptKeyLiteral.FindAllStringSubmatch(call[1], -1) {
				// A key ending in "_" is the base of a concatenation, not a key a
				// bundle can define; the composed forms are pinned below by name.
				if strings.HasSuffix(literal[1], "_") {
					continue
				}
				if _, seen := keys[literal[1]]; !seen {
					keys[literal[1]] = file.path
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
