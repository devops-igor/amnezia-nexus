package web

// A flow's recorded decision reason is rendered as one short label, and three facts
// must agree: the reasons this build can record, the label each token renders
// (DECISION_REASON_LABELS in the controller), and the five bundles carrying those
// labels. None may be restated as a hand-kept list; the retired DNS-evidence labels
// survived every other check because those compare the bundles to each other.
//
// Within the source forms this check recognizes, a struct field declared with
// type EgressReason is a governed reason field. A recognized write must name a
// declared EgressReason constant directly, or a selector on the closed transfer
// list below. Other values at those writes (a local, a literal, a call, a conversion,
// an expression it cannot read) are reported. This is a bounded source check, not a
// proof of every reason that can reach a recorder or of a transfer's runtime value.
// A string-typed reason field is not governed: the drop ledger aggregates refusals
// by its own token family, which this vocabulary never renders.
//
// This source check does not validate reasons introduced through type-elided
// positional record literals or trace whole-record copies, so use keyed reason
// fields with declared constants in new producers and add a focused recorder
// regression when changing how a reason reaches the recorder.

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
// a variable so a fixture can point the analysis at an edited copy of the sources.
var forwarderSourceDir = "../internal/vpn/forwarder"

const (
	reasonTypeName   = "EgressReason" // the type whose constants are decision reasons
	dropReasonPrefix = "DropReason"   // drop tokens are untyped, so the name is the mark
)

// decisionReasonTransfers is the closed list of selectors a recognized reason
// write may be filled from, each with the datum it is intended to carry. Checked in
// both directions: a listed transfer no recognized write uses fails the guard, and
// an unlisted selector at a recognized write is reported, so list entries cannot
// rot or widen silently. The source check judges recognized writes to reason fields;
// it does not trace whole-record copies or prove what an allowlisted selector holds.
var decisionReasonTransfers = map[string]string{
	"decision.reason": "the routing contract's answer, returned by decideEgress",
	"decision.Reason": "the decision handed to a recording call",
	"stats.reason":    "the stored flow's reason, copied from that decision",
	"evidence.reason": "the evidence snapshot, copied from the stored flow",
}

var (
	decisionReasonMapEntry     = regexp.MustCompile(`^[ \t]*([a-z0-9_]+):[ \t]*'(policy_client_decision_reason_[a-z0-9_]+)'`)
	decisionReasonLabelLiteral = regexp.MustCompile(`'(policy_client_decision_reason_[a-z0-9_]+)'`)
	// The retired per-token family: the controller selects a label from its map, so
	// a policy_client_reason_<token> key labelled no rendering path.
	retiredReasonLabelKey = regexp.MustCompile(`^policy_client_reason_[a-z0-9_]+$`)
)

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

// reasonVocabulary is what the package says about reasons, plus every write the
// guard could not resolve.
type reasonVocabulary struct {
	declared []reasonConstant
	produced []reasonConstant
	consts   map[string]reasonConstant
	drops    map[string]string
	governed map[string]bool
	problems []string
}

// TestEveryDeclaredEgressReasonIsProduced fails when a declared reason has no
// producer recognized by this bounded source check, and when a recognized reason
// write uses an unresolved value instead of a declared constant or allowlisted
// transfer. It does not prove runtime recordability; see the file-level limits.
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

// TestEveryDecisionReasonTokenHasALabel fails when a token from a recognized
// producer has no controller map entry, an entry names a label no bundle defines,
// or an entry has neither a recognized producer nor a declared drop reason. Producer
// discovery has the file-level limits; this is not runtime reachability analysis.
func TestEveryDecisionReasonTokenHasALabel(t *testing.T) {
	vocabulary := forwarderReasonVocabulary(t)
	labels, _ := controllerReasonLabels(t)
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
				t.Errorf("%s.json does not define %q, the label %q is mapped to: the cell would show the key itself", locale, key, reason.token)
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
	_, consumed := controllerReasonLabels(t)
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

// TestEveryDeclaredEgressReasonIsProducedWriteForms exercises the same traversal
// as the package guard. Targets must be judged before pairing their source values;
// a tuple call is one RHS expression even when it fills several destinations.
func TestEveryDeclaredEgressReasonIsProducedWriteForms(t *testing.T) {
	cases := []struct {
		name, body, problem string
		writes              int
	}{
		{"scalar constant", "decision.reason = EgressReasonKnown", "", 1},
		{"parallel constants", "decision.choice, decision.reason = 1, EgressReasonKnown", "", 1},
		{"parenthesized field", "((decision.reason)) = (EgressReasonKnown)", "", 1},
		{"checked transfer", "decision.reason = stats.reason", "", 0},
		{"keyed literal", "_ = egressDecision{reason: EgressReasonKnown}", "", 1},
		{"new storage copy", "_ = &egressDecision{reason: stats.reason}", "", 0},
		{"unrelated field", "decision.choice, other.choice = pair()", "", 0},
		{"tuple second result", "decision.choice, decision.reason = pair()", "cannot pair", 0},
		{"tuple first result", "decision.reason, decision.choice = pair()", "cannot pair", 0},
		{"tuple both results", "decision.reason, other.reason = pair()", "cannot pair", 0},
		{"tuple middle result", "decision.choice, decision.reason, other.choice = triple()", "cannot pair", 0},
		{"comma ok", "decision.reason, ok = reasons[0]", "cannot pair", 0},
		{"type assertion", "decision.reason, ok = unknown.(EgressReason)", "cannot pair", 0},
		{"channel receive", "decision.reason, ok = <-reasonsCh", "cannot pair", 0},
		{"parallel literal", "decision.choice, decision.reason = 1, \"unlabelled\"", "literal", 0},
		{"compound update", "decision.reason += EgressReasonKnown", "compound assignment", 0},
		{"parenthesized literal", "(decision.reason) = \"unlabelled\"", "literal", 0},
		{"indirect target", "*(&decision.reason) = EgressReasonKnown", "cannot resolve assignment target", 0},
		{"range value", "for _, decision.reason = range reasons {}", "range assignment", 0},
		{"range key", "for decision.reason = range reasonMap {}", "range assignment", 0},
		{"increment", "decision.reason++", "increment or decrement", 0},
		{"decrement", "decision.reason--", "increment or decrement", 0},
		{"address escape", "_ = &decision.reason", "address escape", 0},
		{"positional literal", "_ = egressDecision{\"unlabelled\", 0}", "positional literal", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Parsing, not execution: invalid typed mutations still must be refused
			// by the syntax boundary rather than disappear from the walk.
			file, err := parser.ParseFile(token.NewFileSet(), "writes.go", "package forwarder; func inspect() { "+tc.body+" }", 0)
			if err != nil {
				t.Fatal(err)
			}
			known := reasonConstant{name: "EgressReasonKnown", token: "known", typ: reasonTypeName}
			produced, transfers, problems := reasonWrites([]forwarderFile{{name: "writes.go", file: file}}, map[string]bool{"egressDecision.reason": true}, map[string]reasonConstant{known.name: known})
			if tc.problem == "" && len(problems) != 0 {
				t.Fatalf("resolvable write refused: %v", problems)
			}
			if tc.problem != "" && !strings.Contains(strings.Join(problems, "\n"), tc.problem) {
				t.Fatalf("governed target was not refused with %q: %v", tc.problem, problems)
			}
			if tc.name == "tuple both results" && len(problems) != 2 {
				t.Fatalf("must judge both governed targets, got %v", problems)
			}
			if len(produced) != tc.writes {
				t.Errorf("recordable constants = %v, want %d", produced, tc.writes)
			}
			if tc.name == "checked transfer" && !transfers["stats.reason"] {
				t.Error("resolvable transfer was not observed")
			}
		})
	}
}

// forwarderReasonVocabulary derives both sides from the forwarding package. It fails
// rather than return an empty set, because an empty set satisfies every assertion.
func forwarderReasonVocabulary(t *testing.T) reasonVocabulary {
	t.Helper()

	files := forwarderFiles(t)
	constants, problems := stringConstants(files)
	vocabulary := reasonVocabulary{
		consts:   make(map[string]reasonConstant, len(constants)),
		drops:    make(map[string]string),
		governed: reasonTypeFields(t, files),
		problems: problems,
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

	produced, transfers, writeProblems := reasonWrites(files, vocabulary.governed, vocabulary.consts)
	vocabulary.produced = produced
	vocabulary.problems = append(vocabulary.problems, writeProblems...)
	if len(produced) < 4 {
		t.Fatalf("found only %d recorded egress reasons in %s; the extraction is wrong", len(produced), forwarderSourceDir)
	}
	vocabulary.problems = append(vocabulary.problems, transferListProblems(vocabulary.governed, transfers)...)
	return vocabulary
}

// transferListProblems holds the transfer list to its own promise: an entry nothing
// uses is stale, and an entry naming a field that is not a reason cannot have a
// validated origin.
func transferListProblems(governed, observed map[string]bool) []string {
	transfers := make([]string, 0, len(decisionReasonTransfers))
	for transfer := range decisionReasonTransfers {
		transfers = append(transfers, transfer)
	}
	sort.Strings(transfers)

	var problems []string
	for _, transfer := range transfers {
		if !observed[transfer] {
			problems = append(problems, fmt.Sprintf("the allowlisted transfer %q (%s) is used by no write: remove it, or record why the writer changed", transfer, decisionReasonTransfers[transfer]))
		}
		if !carriesReason(governed, fieldNameOf(transfer)) {
			problems = append(problems, fmt.Sprintf("the allowlisted transfer %q does not name a field of type %s, so its origin is not a validated reason", transfer, reasonTypeName))
		}
	}
	return problems
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

// reasonTypeFields is the governed boundary: every struct field the package declares
// with type EgressReason, keyed "Type.field". The type itself must exist, or those
// declarations would be names without a meaning.
func reasonTypeFields(t *testing.T, files []forwarderFile) map[string]bool {
	t.Helper()

	fields := make(map[string]bool)
	declared := false
	for _, file := range files {
		for _, declaration := range file.file.Decls {
			group, isType := declaration.(*ast.GenDecl)
			if !isType || group.Tok != token.TYPE {
				continue
			}
			for _, entry := range group.Specs {
				spec, isSpec := entry.(*ast.TypeSpec)
				if !isSpec {
					continue
				}
				declared = declared || spec.Name.Name == reasonTypeName
				structure, isStruct := spec.Type.(*ast.StructType)
				if !isStruct || structure.Fields == nil {
					continue
				}
				for _, field := range structure.Fields.List {
					if exprName(field.Type) != reasonTypeName {
						continue
					}
					for _, name := range field.Names {
						fields[spec.Name.Name+"."+name.Name] = true
					}
				}
			}
		}
	}
	if !declared {
		t.Fatalf("found no %s type declaration in %s; the extraction is wrong", reasonTypeName, forwarderSourceDir)
	}
	if len(fields) == 0 {
		t.Fatalf("found no field of type %s in %s; the extraction is wrong", reasonTypeName, forwarderSourceDir)
	}
	return fields
}

// stringConstants is every string constant the package declares. A spec with no
// expression list repeats the one above it, type included, which is Go's rule; a
// reason-typed constant whose value is not a string token is reported, not dropped.
func stringConstants(files []forwarderFile) ([]reasonConstant, []string) {
	var constants []reasonConstant
	var problems []string
	for _, file := range files {
		for _, declaration := range file.file.Decls {
			group, isConst := declaration.(*ast.GenDecl)
			if !isConst || group.Tok != token.CONST {
				continue
			}
			var repeatedType string
			var repeatedValues []ast.Expr
			for _, entry := range group.Specs {
				spec, isValue := entry.(*ast.ValueSpec)
				if !isValue {
					continue
				}
				typ, values := "", spec.Values
				if len(values) == 0 {
					typ, values = repeatedType, repeatedValues
				} else if spec.Type != nil {
					typ = exprName(spec.Type)
				}
				if len(values) != 0 {
					repeatedType, repeatedValues = typ, values
				}
				if len(values) != len(spec.Names) {
					if typ == reasonTypeName {
						problems = append(problems, fmt.Sprintf("%s: %s is declared as %s from an expression list the guard cannot pair with its names", file.name, spec.Names[0].Name, reasonTypeName))
					}
					continue
				}
				for index, name := range spec.Names {
					literal, isLiteral := values[index].(*ast.BasicLit)
					readable := isLiteral && literal.Kind == token.STRING
					if typ == reasonTypeName && !readable {
						problems = append(problems, fmt.Sprintf("%s: %s is declared as %s from an expression the guard cannot read as a token, so the vocabulary cannot see it", file.name, name.Name, reasonTypeName))
						continue
					}
					if !readable {
						continue
					}
					if value, err := strconv.Unquote(literal.Value); err == nil {
						constants = append(constants, reasonConstant{name: name.Name, token: value, typ: typ, file: file.name})
					}
				}
			}
		}
	}
	return constants, problems
}

// reasonWrites judges writes recognized by the bounded source check and reports
// the declared reasons they name, not all reasons that can reach a recorder.
func reasonWrites(files []forwarderFile, governed map[string]bool, constants map[string]reasonConstant) ([]reasonConstant, map[string]bool, []string) {
	scan := &reasonScan{
		constants: constants,
		governed:  governed,
		seen:      make(map[string]bool),
		transfers: make(map[string]bool),
	}
	for _, file := range files {
		ast.Inspect(file.file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.CompositeLit:
				scan.literal(file.name, typed)
			case *ast.AssignStmt:
				scan.assignment(file.name, typed)
			case *ast.RangeStmt:
				scan.refuseTargets(file.name, typed.Key, "range assignment")
				scan.refuseTargets(file.name, typed.Value, "range assignment")
			case *ast.IncDecStmt:
				scan.refuseTargets(file.name, typed.X, "increment or decrement")
			case *ast.UnaryExpr:
				if typed.Op == token.AND {
					scan.refuseTargets(file.name, typed.X, "address escape")
				}
			case *ast.CallExpr:
				scan.conversion(file.name, typed)
			}
			return true
		})
	}
	return scan.produced, scan.transfers, scan.problems
}

// reasonScan accumulates what the governed writes say.
type reasonScan struct {
	constants map[string]reasonConstant
	governed  map[string]bool
	produced  []reasonConstant
	transfers map[string]bool
	problems  []string
	seen      map[string]bool
}

// literal inspects keyed reason fields, using field names alone when the type is
// elided. It refuses positional literals with an explicit governed type, but does
// not resolve type-elided positional literals from their enclosing context.
func (scan *reasonScan) literal(file string, literal *ast.CompositeLit) {
	record := exprName(literal.Type)
	for _, element := range literal.Elts {
		field, isField := element.(*ast.KeyValueExpr)
		if !isField {
			for governed := range scan.governed {
				if strings.HasPrefix(governed, record+".") {
					scan.problemf("%s: %s uses a positional literal whose reason field the guard cannot resolve", file, record)
					return
				}
			}
			continue
		}
		name := exprName(field.Key)
		governed := scan.governed[record+"."+name] || (record == "" && carriesReason(scan.governed, name))
		if !governed {
			continue
		}
		site := record + "." + name
		if record == "" {
			site = name
		}
		scan.write(file, site, field.Value)
	}
}

// assignment discovers governed targets independently of source arity. Go's
// multi-valued expressions cannot be paired positionally with the LHS syntax.
// Only a direct field under plain one-to-one assignment has a resolvable source.
func (scan *reasonScan) assignment(file string, statement *ast.AssignStmt) {
	for index, target := range statement.Lhs {
		for _, field := range scan.targets(target) {
			site := exprName(field.X) + "." + field.Sel.Name
			switch {
			case ast.Unparen(target) != field:
				scan.problemf("%s: %s: cannot resolve assignment target containing a governed field", file, site)
			case statement.Tok != token.ASSIGN:
				scan.problemf("%s: %s: compound assignment cannot resolve the resulting reason", file, site)
			case len(statement.Lhs) != len(statement.Rhs):
				scan.problemf("%s: %s: cannot pair %d assignment targets with %d source expressions; a multi-result write must name a declared reason explicitly", file, site, len(statement.Lhs), len(statement.Rhs))
			default:
				scan.write(file, site, statement.Rhs[index])
			}
		}
	}
}

// targets walks the complete destination expression, including parentheses,
// indirection and indices. A nested governed field is unresolved, never invisible.
// Matching by field name is deliberately conservative without Go type information.
func (scan *reasonScan) targets(target ast.Expr) []*ast.SelectorExpr {
	var fields []*ast.SelectorExpr
	if target == nil {
		return fields
	}
	ast.Inspect(target, func(node ast.Node) bool {
		// A literal creates new storage; selectors in its values are reads,
		// not destinations or escaped addresses of the existing fields.
		if _, literal := node.(*ast.CompositeLit); literal {
			return false
		}
		if field, ok := node.(*ast.SelectorExpr); ok && carriesReason(scan.governed, field.Sel.Name) {
			fields = append(fields, field)
		}
		return true
	})
	return fields
}

// refuseTargets covers implicit assignment by range, arithmetic updates and
// writable address escape. None supplies a constant/transfer value we can prove.
func (scan *reasonScan) refuseTargets(file string, target ast.Expr, operation string) {
	for _, field := range scan.targets(target) {
		scan.problemf("%s: %s.%s: %s cannot resolve the resulting reason", file, exprName(field.X), field.Sel.Name, operation)
	}
}

// write applies the value rule at recognized writes: a declared reason constant
// or an allowlisted transfer. Other expressions are reported as unresolved; accepting
// a selector by spelling does not prove its value after a whole-record copy.
func (scan *reasonScan) write(file, site string, value ast.Expr) {
	if paren, isParen := value.(*ast.ParenExpr); isParen {
		scan.write(file, site, paren.X)
		return
	}
	switch typed := value.(type) {
	case *ast.Ident:
		constant, declared := scan.constants[typed.Name]
		if !declared {
			scan.problemf("%s: %s is written from the identifier %s, which is not a declared reason: the guard cannot resolve what token that local or parameter carries, so an unlabelled value could reach the record", file, site, typed.Name)
			return
		}
		if constant.typ != reasonTypeName {
			scan.problemf("%s: %s is written from the constant %s (%q), which is not of type %s", file, site, constant.name, constant.token, reasonTypeName)
			return
		}
		if !scan.seen[constant.name] {
			scan.seen[constant.name] = true
			scan.produced = append(scan.produced, constant)
		}
	case *ast.SelectorExpr:
		transfer := exprName(typed.X) + "." + exprName(typed.Sel)
		if _, allowlisted := decisionReasonTransfers[transfer]; !allowlisted {
			scan.problemf("%s: %s is written from %s, which is not an allowlisted transfer: the guard cannot prove that selector carries a declared reason", file, site, transfer)
			return
		}
		scan.transfers[transfer] = true
	case *ast.BasicLit:
		scan.problemf("%s: %s is written as the literal %s instead of a declared reason: that token has no declaration to review and no label to render", file, site, typed.Value)
	case *ast.CallExpr:
		scan.problemf("%s: %s is written from a call, so the guard cannot resolve which token reaches the record", file, site)
	default:
		scan.problemf("%s: %s is written from an expression this guard cannot resolve as a declared reason or an allowlisted transfer", file, site)
	}
}

// conversion catches a reason built through a type conversion, e.g. EgressReason("x").
func (scan *reasonScan) conversion(file string, call *ast.CallExpr) {
	if _, isConverted := reasonConversionLiteral(call); !isConverted {
		return
	}
	scan.problemf("%s: builds a reason from a literal instead of a declared reason: a converted string has no declaration to review and no label unless one is added by hand", file)
}

// problemf records one unresolved write.
func (scan *reasonScan) problemf(format string, args ...any) {
	scan.problems = append(scan.problems, fmt.Sprintf(format, args...))
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

// carriesReason reports whether any governed record declares a field with this name.
func carriesReason(governed map[string]bool, name string) bool {
	for key := range governed {
		if fieldNameOf(key) == name {
			return true
		}
	}
	return false
}

// fieldNameOf is the field part of a "Type.field" key.
func fieldNameOf(key string) string {
	return key[strings.LastIndex(key, ".")+1:]
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

// controllerReasonLabels reads the controller once: the token-to-label map, and every
// decision-reason label key it resolves, including the two its fallbacks return
// without a map entry.
func controllerReasonLabels(t *testing.T) (map[string]string, map[string]bool) {
	t.Helper()

	source := policyClientDiagControllerSource(t)
	labels := make(map[string]string)
	for _, line := range strings.Split(source, "\n") {
		if match := decisionReasonMapEntry.FindStringSubmatch(line); match != nil {
			labels[match[1]] = match[2]
		}
	}
	keys := make(map[string]bool)
	for _, match := range decisionReasonLabelLiteral.FindAllStringSubmatch(source, -1) {
		keys[match[1]] = true
	}
	if len(labels) == 0 || len(keys) == 0 {
		t.Fatal("found no DECISION_REASON_LABELS entries in the controller; the extraction is wrong")
	}
	return labels, keys
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
