package web

// A flow's recorded decision reason is rendered as one short label. Three facts
// have to agree for that to be true, and none of them may be restated as a second
// hand-written list:
//
//   - the tokens the packet path can record: the EgressReason declarations in
//     internal/vpn/forwarder/flow_evidence.go, every one of which the decision
//     contract in routing_decision.go assigns;
//   - the label each token renders: DECISION_REASON_LABELS in
//     static/js/policy_client_diag.js;
//   - the five bundles that carry those labels.
//
// The retired DNS-evidence tokens are why this exists. Two labels described a
// routing model the panel no longer implements, and every other test here passed
// while they sat in the dictionaries unused, because those tests check each
// bundle against the others: a key held by all five is indistinguishable from a
// key something renders. These tests check the vocabulary against its producer
// instead, in both directions — a token without a label and a label without a
// token both fail.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// forwarderSourceDir is the producing package, read as source so the vocabulary
// is derived from what the binary assigns rather than from a copy of it.
const forwarderSourceDir = "../internal/vpn/forwarder"

var (
	// A declared decision reason, in the form the producing package writes it:
	// EgressReasonX EgressReason = "token".
	egressReasonDeclaration = regexp.MustCompile(`^[ \t]*(EgressReason[A-Za-z0-9_]*)[ \t]+EgressReason[ \t]*=[ \t]*"([a-z0-9_]+)"`)
	// A declared drop reason. The drop table is the other half of this surface and
	// shares its token space, so the label map may carry one of these too.
	dropReasonDeclaration = regexp.MustCompile(`^[ \t]*(DropReason[A-Za-z0-9_]*)[ \t]*=[ \t]*"([a-z0-9_]+)"`)
	// A reason built from a literal instead of a declared constant. Such a token
	// would have no entry here and no label in any bundle, which is exactly the
	// class this guard refuses.
	rawReasonLiteral = regexp.MustCompile(`EgressReason\("[a-z0-9_]+"\)`)
	// One entry of the controller's label map: token: 'label key'.
	decisionReasonMapEntry = regexp.MustCompile(`^[ \t]*([a-z0-9_]+):[ \t]*'(policy_client_decision_reason_[a-z0-9_]+)'`)
	// Any decision-reason label key the controller resolves, which includes the
	// two its fallbacks return without a map entry.
	decisionReasonLabelLiteral = regexp.MustCompile(`'(policy_client_decision_reason_[a-z0-9_]+)'`)
	// The retired per-token label family. The controller never resolved these:
	// it selects a label from its map, not from a policy_client_reason_<token>
	// key, so the family described a rendering path that does not exist.
	retiredReasonLabelKey = regexp.MustCompile(`^policy_client_reason_[a-z0-9_]+$`)
)

// forwarderSource is one production file of the producing package.
type forwarderSource struct {
	name string
	body string
}

// egressReasonToken is one declared reason, its token and the file declaring it.
type egressReasonToken struct {
	name     string
	token    string
	declared string
}

// TestEveryDeclaredEgressReasonIsProduced fails when a reason this build declares
// cannot be recorded by any production code path, and when a production path
// builds a reason from a literal instead of a declaration. Either way the token
// is a value a diagnosis could only ever show as text nobody produced.
func TestEveryDeclaredEgressReasonIsProduced(t *testing.T) {
	reasons := declaredEgressReasons(t)
	sources := forwarderProductionSources(t)

	seen := make(map[string]string, len(reasons))
	for _, reason := range reasons {
		if first, duplicate := seen[reason.token]; duplicate {
			t.Errorf("%s and %s declare the same token %q", first, reason.name, reason.token)
			continue
		}
		seen[reason.token] = reason.name

		producer := ""
		for _, file := range sources {
			if file.name == reason.declared {
				continue
			}
			if codeMentions(file.body, reason.name) {
				producer = file.name
				break
			}
		}
		if producer == "" {
			t.Errorf("%s (%q) is declared in %s but no production file assigns it: "+
				"a reason this build cannot record must not be declared, because a label "+
				"for it is a sentence about a branch that does not exist",
				reason.name, reason.token, reason.declared)
		}
	}

	for _, file := range sources {
		for _, literal := range rawReasonLiteral.FindAllString(file.body, -1) {
			t.Errorf("%s builds %s from a literal instead of a declared reason: "+
				"that token has no label and no review, so it would reach the operator as "+
				"the generic label or as itself", file.name, literal)
		}
	}
}

// TestEveryDecisionReasonTokenHasALabel fails when a token the packet path can
// record has no entry in the controller's label map, when a map entry names a
// label no bundle defines, and when a map entry names a token nothing produces.
func TestEveryDecisionReasonTokenHasALabel(t *testing.T) {
	reasons := declaredEgressReasons(t)
	drops := declaredDropReasonTokens(t)
	labels := decisionReasonLabelMap(t)
	dictionaries := policyDictionaries(t)

	declared := make(map[string]bool, len(reasons))
	for _, reason := range reasons {
		declared[reason.token] = true
		key, labelled := labels[reason.token]
		if !labelled {
			t.Errorf("%s records %q, which DECISION_REASON_LABELS does not map: "+
				"the table would show the generic label instead of what decided",
				reason.name, reason.token)
			continue
		}
		for _, locale := range policyLocales {
			if _, defined := dictionaries[locale][key]; !defined {
				t.Errorf("%s.json does not define %q, the label %q is mapped to: "+
					"the cell would show the key itself", locale, key, reason.token)
			}
		}
	}

	// not_recorded is not a token: it is what the surface says about a flow whose
	// reason the producer did not record.
	for token := range labels {
		if token == "not_recorded" || declared[token] {
			continue
		}
		if _, refusal := drops[token]; refusal {
			continue
		}
		t.Errorf("%q is a label entry with no producer: no declared reason and no drop "+
			"reason carries that token, so the label describes nothing", token)
	}
}

// TestEveryDecisionReasonLabelHasAToken fails when a bundle carries a
// decision-reason label the controller never resolves (an orphan), when the
// controller resolves one no bundle defines, and when the retired per-token
// family survives anywhere. The locale-parity test cannot see any of these: it
// compares the bundles to each other, and a dead key held by all five passes.
func TestEveryDecisionReasonLabelHasAToken(t *testing.T) {
	consumed := decisionReasonLabelKeys(t)
	dictionaries := policyDictionaries(t)

	for _, locale := range policyLocales {
		dictionary := dictionaries[locale]
		bundled := decisionReasonKeysOf(dictionary)

		for key := range consumed {
			if !bundled[key] {
				t.Errorf("%s.json does not define %q, which the controller resolves", locale, key)
			}
		}
		orphans := make([]string, 0, len(bundled))
		for key := range bundled {
			if !consumed[key] {
				orphans = append(orphans, key)
			}
		}
		sort.Strings(orphans)
		for _, orphan := range orphans {
			t.Errorf("%s.json defines %q, which nothing resolves: an operator could not "+
				"see it, and the text describes a mechanism this build does not implement",
				locale, orphan)
		}

		retired := make([]string, 0)
		for key := range dictionary {
			if retiredReasonLabelKey.MatchString(key) {
				retired = append(retired, key)
			}
		}
		sort.Strings(retired)
		for _, key := range retired {
			t.Errorf("%s.json still carries %q: the controller renders a decision reason "+
				"from its own map, so this family labels no rendering path", locale, key)
		}
	}
}

// declaredEgressReasons reads the reason declarations out of the producing
// package. It fails rather than return an empty set, because an empty set would
// satisfy every other assertion in this file.
func declaredEgressReasons(t *testing.T) []egressReasonToken {
	t.Helper()

	var reasons []egressReasonToken
	for _, file := range forwarderProductionSources(t) {
		for _, line := range strings.Split(file.body, "\n") {
			match := egressReasonDeclaration.FindStringSubmatch(line)
			if match == nil {
				continue
			}
			reasons = append(reasons, egressReasonToken{
				name:     match[1],
				token:    match[2],
				declared: file.name,
			})
		}
	}
	if len(reasons) < 4 {
		t.Fatalf("found only %d declared egress reasons in %s; the extraction is wrong",
			len(reasons), forwarderSourceDir)
	}
	return reasons
}

// declaredDropReasonTokens reads the drop-reason declarations, keyed by token.
func declaredDropReasonTokens(t *testing.T) map[string]string {
	t.Helper()

	tokens := make(map[string]string)
	for _, file := range forwarderProductionSources(t) {
		for _, line := range strings.Split(file.body, "\n") {
			match := dropReasonDeclaration.FindStringSubmatch(line)
			if match == nil {
				continue
			}
			tokens[match[2]] = match[1]
		}
	}
	if len(tokens) == 0 {
		t.Fatalf("found no declared drop reasons in %s; the extraction is wrong", forwarderSourceDir)
	}
	return tokens
}

// forwarderProductionSources reads the producing package's non-test files, so the
// vocabulary is derived from what the binary is built from.
func forwarderProductionSources(t *testing.T) []forwarderSource {
	t.Helper()

	entries, err := os.ReadDir(forwarderSourceDir)
	if err != nil {
		t.Fatalf("read %s: %v", forwarderSourceDir, err)
	}
	var sources []forwarderSource
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(forwarderSourceDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		sources = append(sources, forwarderSource{name: name, body: string(body)})
	}
	if len(sources) < 20 {
		t.Fatalf("read only %d production files from %s; the extraction is wrong",
			len(sources), forwarderSourceDir)
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].name < sources[j].name })
	return sources
}

// codeMentions reports whether an identifier is used in executable source, not
// only named in a comment. A doc comment on a constant is not a producer.
func codeMentions(body, identifier string) bool {
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if strings.Contains(line, identifier) {
			return true
		}
	}
	return false
}

// decisionReasonLabelMap reads the controller's token-to-label mapping.
func decisionReasonLabelMap(t *testing.T) map[string]string {
	t.Helper()

	labels := make(map[string]string)
	for _, line := range strings.Split(policyClientDiagControllerSource(t), "\n") {
		match := decisionReasonMapEntry.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		labels[match[1]] = match[2]
	}
	if len(labels) == 0 {
		t.Fatal("found no DECISION_REASON_LABELS entries in the controller; the extraction is wrong")
	}
	return labels
}

// decisionReasonLabelKeys is every decision-reason label key the controller
// resolves, including the ones its fallbacks return without a map entry.
func decisionReasonLabelKeys(t *testing.T) map[string]bool {
	t.Helper()

	keys := make(map[string]bool)
	for _, match := range decisionReasonLabelLiteral.FindAllStringSubmatch(policyClientDiagControllerSource(t), -1) {
		keys[match[1]] = true
	}
	if len(keys) == 0 {
		t.Fatal("found no decision-reason label keys in the controller; the extraction is wrong")
	}
	return keys
}

// policyClientDiagControllerSource reads the shipped controller.
func policyClientDiagControllerSource(t *testing.T) string {
	t.Helper()

	raw, err := StaticFS.ReadFile("static/js/policy_client_diag.js")
	if err != nil {
		t.Fatalf("read static/js/policy_client_diag.js: %v", err)
	}
	return string(raw)
}

// decisionReasonKeysOf is the decision-reason label keys one bundle carries.
func decisionReasonKeysOf(dictionary map[string]string) map[string]bool {
	keys := make(map[string]bool)
	for key := range dictionary {
		if strings.HasPrefix(key, "policy_client_decision_reason_") {
			keys[key] = true
		}
	}
	return keys
}
