package web

// A flow's recorded decision reason is rendered as one short label. Three facts
// must agree, and none may be restated as a hand-kept list: the reasons this build
// can record (the string constants of type EgressReason in internal/vpn/forwarder
// that a write site assigns to a record's reason field), the label each token
// renders (DECISION_REASON_LABELS in the controller), and the five bundles carrying
// those labels.
//
// This exists because the retired DNS-evidence labels survived every other check:
// those compare the bundles to each other, and a dead key held by all five is
// indistinguishable from a key something renders. So the forwarding package is
// parsed as Go here — a declaration is a declaration and a write is a write. A name
// in a comment is not a producer; the token must be written into a reason field, or
// carried there from a field that was, and a raw token or a conversion from a
// string literal fails in the other direction.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// forwarderSourceDir is the package that creates and records a flow's reason. It is
// a variable so a fixture can point the analysis at an edited copy of those
// sources without touching the tree under review.
var forwarderSourceDir = "../internal/vpn/forwarder"

const (
	reasonTypeName     = "EgressReason" // the type whose string constants are reasons
	decisionRecordName = "egressDecision"
	dropReasonPrefix   = "DropReason" // drop tokens are untyped, so the name is the mark
)

var (
	// One entry of the controller's label map: token: 'label key'.
	decisionReasonMapEntry = regexp.MustCompile(`^[ \t]*([a-z0-9_]+):[ \t]*'(policy_client_decision_reason_[a-z0-9_]+)'`)
	// Any decision-reason label key the controller resolves, including the two its
	// fallbacks return without a map entry.
	decisionReasonLabelLiteral = regexp.MustCompile(`'(policy_client_decision_reason_[a-z0-9_]+)'`)
	// The retired per-token family: the controller selects a label from its map, not
	// from a policy_client_reason_<token> key, so it labelled no rendering path.
	retiredReasonLabelKey = regexp.MustCompile(`^policy_client_reason_[a-z0-9_]+$`)
)

// forwarderFile is one parsed production file of the forwarding package.
type forwarderFile struct {
	name string
	file *ast.File
}

// reasonConstant is one string constant declared by the forwarding package.
type reasonConstant struct {
	name  string // the Go identifier
	token string // the string value it holds
	typ   string // the declared type name, empty when untyped
	file  string // the file that declares it
}

// reasonVocabulary is what the forwarding package says about reasons.
type reasonVocabulary struct {
	declared []reasonConstant
	produced []reasonConstant
	consts   map[string]reasonConstant
	drops    map[string]string
	problems []string
}

// TestEveryDeclaredEgressReasonIsProduced fails when a reason this build declares
// cannot be written to a flow record, and when a write site names its reason as a
// literal instead of a declared constant.
func TestEveryDeclaredEgressReasonIsProduced(t *testing.T) {
	vocabulary := forwarderReasonVocabulary(t)
	for _, problem := range vocabulary.problems {
		t.Error(problem)
	}

	produced := make(map[string]bool, len(vocabulary.produced))
	for _, reason := range vocabulary.produced {
		produced[reason.token] = true
	}
	seen := make(map[string]string, len(vocabulary.declared))
	for _, reason := range vocabulary.declared {
		if first, duplicate := seen[reason.token]; duplicate {
			t.Errorf("%s and %s declare the same token %q", first, reason.name, reason.token)
			continue
		}
		seen[reason.token] = reason.name
		if produced[reason.token] {
			continue
		}
		t.Errorf("%s (%q) is declared in %s but no production file assigns it: a reason this build cannot record must not be declared, because a label for it is a sentence about a branch that does not exist",
			reason.name, reason.token, reason.file)
	}
}

// TestEveryDecisionReasonTokenHasALabel fails when a token a write site can record
// has no entry in the controller's label map, when an entry names a label no bundle
// defines, and when an entry names a token nothing can record.
func TestEveryDecisionReasonTokenHasALabel(t *testing.T) {
	vocabulary := forwarderReasonVocabulary(t)
	labels := decisionReasonLabelMap(t)
	dictionaries := policyDictionaries(t)

	produced := make(map[string]bool, len(vocabulary.produced))
	for _, reason := range vocabulary.produced {
		produced[reason.token] = true
		key, labelled := labels[reason.token]
		if !labelled {
			t.Errorf("%s records %q, which DECISION_REASON_LABELS does not map: the table would show the generic label instead of what decided",
				reason.name, reason.token)
			continue
		}
		for _, locale := range policyLocales {
			if _, defined := dictionaries[locale][key]; !defined {
				t.Errorf("%s.json does not define %q, the label %q is mapped to: the cell would show the key itself",
					locale, key, reason.token)
			}
		}
	}

	// not_recorded is not a token: it is what the surface says about a flow whose
	// reason was not recorded.
	for token := range labels {
		if token == "not_recorded" || produced[token] {
			continue
		}
		if _, refusal := vocabulary.drops[token]; refusal {
			continue
		}
		t.Errorf("%q is a label entry with no producer: no declared reason and no drop reason carries that token, so the label describes nothing", token)
	}
}

// TestEveryDecisionReasonLabelHasAToken fails when a bundle carries a label the
// controller never resolves, when the controller resolves one no bundle defines, and
// when the retired per-token family survives anywhere. Locale parity sees none of
// these: it compares the bundles to each other.
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
			t.Errorf("%s.json defines %q, which nothing resolves: an operator could not see it, and the text describes a mechanism this build does not implement", locale, orphan)
		}
		retired := make([]string, 0)
		for key := range dictionary {
			if retiredReasonLabelKey.MatchString(key) {
				retired = append(retired, key)
			}
		}
		sort.Strings(retired)
		for _, key := range retired {
			t.Errorf("%s.json still carries %q: the controller renders a decision reason from its own map, so this family labels no rendering path", locale, key)
		}
	}
}

// forwarderReasonVocabulary derives both sides from the forwarding package. It fails
// rather than return an empty set, because an empty set satisfies every assertion.
func forwarderReasonVocabulary(t *testing.T) reasonVocabulary {
	t.Helper()

	files := forwarderFiles(t)
	constants := stringConstants(files)
	vocabulary := reasonVocabulary{
		consts: make(map[string]reasonConstant, len(constants)),
		drops:  make(map[string]string),
	}
	for _, constant := range constants {
		vocabulary.consts[constant.name] = constant
		if constant.typ == reasonTypeName {
			vocabulary.declared = append(vocabulary.declared, constant)
		}
		if strings.HasPrefix(constant.name, dropReasonPrefix) {
			vocabulary.drops[constant.token] = constant.name
		}
	}
	if len(vocabulary.declared) < 4 {
		t.Fatalf("found only %d declared egress reasons in %s; the extraction is wrong", len(vocabulary.declared), forwarderSourceDir)
	}
	if len(vocabulary.drops) == 0 {
		t.Fatalf("found no declared drop reasons in %s; the extraction is wrong", forwarderSourceDir)
	}
	vocabulary.produced, vocabulary.problems = reasonWrites(files, vocabulary.consts)
	if len(vocabulary.produced) < 4 {
		t.Fatalf("found only %d recorded egress reasons in %s; the extraction is wrong", len(vocabulary.produced), forwarderSourceDir)
	}
	return vocabulary
}

// forwarderFiles parses the package's non-test files. A parse error is fatal: text that is not Go cannot be analysed, and an empty set would pass every assertion.
func forwarderFiles(t *testing.T) []forwarderFile {
	t.Helper()

	entries, err := os.ReadDir(forwarderSourceDir)
	if err != nil {
		t.Fatalf("read %s: %v", forwarderSourceDir, err)
	}
	fileSet := token.NewFileSet()
	var files []forwarderFile
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(forwarderSourceDir, name)
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		parsed, err := parser.ParseFile(fileSet, name, source, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		files = append(files, forwarderFile{name: name, file: parsed})
	}
	if len(files) < 20 {
		t.Fatalf("read only %d production files from %s; the extraction is wrong", len(files), forwarderSourceDir)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	return files
}

// stringConstants is every string constant the package declares, with the type it
// was declared with. A spec repeating neither type nor value keeps the type above it.
func stringConstants(files []forwarderFile) []reasonConstant {
	var constants []reasonConstant
	for _, file := range files {
		for _, declaration := range file.file.Decls {
			group, isConst := declaration.(*ast.GenDecl)
			if !isConst || group.Tok != token.CONST {
				continue
			}
			inherited := ""
			for _, entry := range group.Specs {
				spec, isValue := entry.(*ast.ValueSpec)
				if !isValue {
					continue
				}
				typ := inherited
				if spec.Type != nil {
					typ = exprName(spec.Type)
					inherited = typ
				}
				if len(spec.Names) != len(spec.Values) {
					continue
				}
				for index, name := range spec.Names {
					literal, isLiteral := spec.Values[index].(*ast.BasicLit)
					if !isLiteral || literal.Kind != token.STRING {
						continue
					}
					value, err := strconv.Unquote(literal.Value)
					if err != nil {
						continue
					}
					constants = append(constants, reasonConstant{name: name.Name, token: value, typ: typ, file: file.name})
				}
			}
		}
	}
	return constants
}

// reasonWrites is the recording boundary: every reason-bearing field of a record
// literal, every later assignment to one, and every conversion that would put a token
// on a record without a declaration.
func reasonWrites(files []forwarderFile, constants map[string]reasonConstant) ([]reasonConstant, []string) {
	scan := &reasonWriteScan{constants: constants, seen: make(map[string]bool)}
	for _, file := range files {
		ast.Inspect(file.file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.CompositeLit:
				scan.literal(file.name, typed)
			case *ast.AssignStmt:
				scan.assignment(file.name, typed)
			case *ast.GenDecl:
				scan.varDeclaration(file.name, typed)
			case *ast.CallExpr:
				scan.conversion(file.name, typed)
			}
			return true
		})
	}
	return scan.produced, scan.problems
}

// reasonWriteScan accumulates what the record literals and their assignments say.
type reasonWriteScan struct {
	constants map[string]reasonConstant
	produced  []reasonConstant
	problems  []string
	seen      map[string]bool
}

// literal inspects the reason field of one record literal.
func (scan *reasonWriteScan) literal(file string, literal *ast.CompositeLit) {
	record := exprName(literal.Type)
	if record == "" {
		record = "an untyped record literal"
	}
	for _, element := range literal.Elts {
		field, isField := element.(*ast.KeyValueExpr)
		if !isField || !isReasonField(exprName(field.Key)) {
			continue
		}
		scan.reason(file, record, field.Value, record == decisionRecordName)
	}
}

// assignment inspects a reason field set after the record was built; a local variable that happens to be called reason is not a field.
func (scan *reasonWriteScan) assignment(file string, statement *ast.AssignStmt) {
	for index, target := range statement.Lhs {
		_, isField := target.(*ast.SelectorExpr)
		if index >= len(statement.Rhs) || !isField || !isReasonField(exprName(target)) {
			continue
		}
		scan.reason(file, "an assignment to "+exprName(target), statement.Rhs[index], false)
	}
}

// varDeclaration refuses a token kept in a variable: the vocabulary only sees constants, so a var carries a reason no label can be derived for.
func (scan *reasonWriteScan) varDeclaration(file string, group *ast.GenDecl) {
	if group.Tok != token.VAR {
		return
	}
	for _, entry := range group.Specs {
		spec, isValue := entry.(*ast.ValueSpec)
		if !isValue || exprName(spec.Type) != reasonTypeName {
			continue
		}
		for _, value := range spec.Values {
			literal, isLiteral := value.(*ast.BasicLit)
			if !isLiteral || literal.Kind != token.STRING {
				continue
			}
			scan.problems = append(scan.problems, fmt.Sprintf("%s: declares the variable %s of type %s from a literal (%s); a reason must be a declared constant so the vocabulary can see it",
				file, spec.Names[0].Name, reasonTypeName, literal.Value))
		}
	}
}

// conversion catches a reason built through a type conversion, e.g. EgressReason("x").
func (scan *reasonWriteScan) conversion(file string, call *ast.CallExpr) {
	if _, isConverted := reasonConversionLiteral(call); !isConverted {
		return
	}
	scan.problems = append(scan.problems, fmt.Sprintf("%s: builds a reason from a literal instead of a declared reason: a converted string has no declaration to review and no label unless one is added by hand", file))
}

// reason classifies one expression written into a reason field. mustNameConstant is
// set where the writing construct is the decision contract itself, whose job is to
// name which branch decided; a variable or a carried field is left to its own site.
func (scan *reasonWriteScan) reason(file, site string, value ast.Expr, mustNameConstant bool) {
	switch typed := value.(type) {
	case *ast.Ident:
		constant, declared := scan.constants[typed.Name]
		if !declared {
			if mustNameConstant {
				scan.problems = append(scan.problems, fmt.Sprintf("%s: %s names %s as its reason, which is not a declared reason: the contract must name the constant that decided", file, site, typed.Name))
			}
			return
		}
		switch {
		case constant.typ == reasonTypeName:
			if !scan.seen[constant.name] {
				scan.seen[constant.name] = true
				scan.produced = append(scan.produced, constant)
			}
		case strings.HasPrefix(constant.name, dropReasonPrefix):
			// A refusal token. The surface renders it in its own table, and the label
			// map keeps it renderable should a diagnosis ever carry it as a reason.
		default:
			scan.problems = append(scan.problems, fmt.Sprintf("%s: %s writes the declared constant %s (%q) as a reason, but it is neither a decision reason nor a drop reason", file, site, constant.name, constant.token))
		}
	case *ast.SelectorExpr:
		// Carried across from another record, e.g. decision.reason. The site that
		// filled that field is scanned on its own.
	case *ast.BasicLit:
		if typed.Kind == token.STRING {
			scan.problems = append(scan.problems, fmt.Sprintf("%s: %s writes the reason as a literal instead of a declared reason (%s): that token has no declaration to review and no label to render", file, site, typed.Value))
		}
	case *ast.CallExpr:
		scan.problems = append(scan.problems, fmt.Sprintf("%s: %s builds its reason with a call instead of naming a declared constant: the resulting token cannot be checked against the label vocabulary", file, site))
	default:
		scan.problems = append(scan.problems, fmt.Sprintf("%s: %s writes a reason this guard cannot classify as a declared constant", file, site))
	}
}

// reasonConversionLiteral reports the string a conversion to EgressReason writes.
func reasonConversionLiteral(call *ast.CallExpr) (string, bool) {
	if exprName(call.Fun) != reasonTypeName || len(call.Args) != 1 {
		return "", false
	}
	if literal, isLiteral := call.Args[0].(*ast.BasicLit); isLiteral && literal.Kind == token.STRING {
		value, err := strconv.Unquote(literal.Value)
		return value, err == nil
	}
	return "", false
}

// isReasonField reports whether a field name carries a record's reason.
func isReasonField(name string) bool {
	return strings.EqualFold(name, "reason") || strings.EqualFold(name, "decisionreason")
}

// exprName is the identifier an expression names: a type, field key, target or function.
func exprName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	case *ast.IndexExpr:
		return exprName(typed.X)
	case *ast.StarExpr:
		return exprName(typed.X)
	}
	return ""
}

// decisionReasonLabelMap reads the controller's token-to-label mapping.
func decisionReasonLabelMap(t *testing.T) map[string]string {
	t.Helper()

	labels := make(map[string]string)
	for _, line := range strings.Split(policyClientDiagControllerSource(t), "\n") {
		if match := decisionReasonMapEntry.FindStringSubmatch(line); match != nil {
			labels[match[1]] = match[2]
		}
	}
	if len(labels) == 0 {
		t.Fatal("found no DECISION_REASON_LABELS entries in the controller; the extraction is wrong")
	}
	return labels
}

// decisionReasonLabelKeys is every decision-reason label key the controller resolves,
// including the two its fallbacks return without a map entry.
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
