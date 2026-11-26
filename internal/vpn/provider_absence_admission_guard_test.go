package vpn

// Derived guard: every consumer of the active-tunnel snapshot must pass it through the
// provider-absence disqualification.
//
// The defect this pins was not a wrong predicate anywhere - it was a consumer that never
// asked the question. A per-function test cannot see a FUTURE consumer, and the earlier
// guards enumerated writers, not readers. So this guard reads the source: any call to
// Pool.GetActiveTunnels must appear as an argument of withoutProviderAbsent (or be the
// pool's own definition), and an exemption must be declared with a reason and be observed,
// so an exemption cannot outlive the consumer it was written for.

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// providerAbsenceSelectionExemptions lists the "file:function" consumers allowed to read
// the raw snapshot. It is empty on purpose: every current consumer assigns or migrates
// sessions, so none of them may see an absent backend. An entry needs a reason saying why
// reading the unfiltered list cannot place new work on a deleted server.
var providerAbsenceSelectionExemptions = map[string]string{}

const providerAbsencePoolDefinition = "tunnel/pool.go"

// providerAbsenceConsumer is one GetActiveTunnels call site.
type providerAbsenceConsumer struct {
	file     string
	function string
	line     int
	filtered bool // the call is an argument of withoutProviderAbsent
}

func TestActiveTunnelConsumersDisqualifyProviderAbsentBackends(t *testing.T) {
	fset := token.NewFileSet()
	var consumers []providerAbsenceConsumer

	err := filepath.Walk(".", func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(fset, guardSourcePath(path), nil, 0)
		if parseErr != nil {
			return parseErr
		}
		rel, relErr := filepath.Rel(".", path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)

		// Which GetActiveTunnels calls are arguments of a withoutProviderAbsent call?
		covered := make(map[token.Pos]bool)
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || !callsNamedFunc(call, "withoutProviderAbsent") {
				return true
			}
			for _, arg := range call.Args {
				ast.Inspect(arg, func(inner ast.Node) bool {
					if innerCall, ok := inner.(*ast.CallExpr); ok && callsNamedFunc(innerCall, "GetActiveTunnels") {
						covered[innerCall.Pos()] = true
					}
					return true
				})
			}
			return true
		})

		for _, decl := range file.Decls {
			fnDecl, ok := decl.(*ast.FuncDecl)
			if !ok || fnDecl.Body == nil {
				continue
			}
			walker := &providerAbsenceCallWalker{}
			ast.Walk(walker, fnDecl)
			for _, call := range walker.calls {
				consumers = append(consumers, providerAbsenceConsumer{
					file:     rel,
					function: funcName(fnDecl),
					line:     fset.Position(call.Pos()).Line,
					filtered: covered[call.Pos()],
				})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanning the package: %v", err)
	}

	observed := make(map[string]bool, len(consumers))
	for _, consumer := range consumers {
		key := consumer.file + ":" + consumer.function
		observed[key] = true

		if consumer.file == providerAbsencePoolDefinition && consumer.function == "Pool.GetActiveTunnels" {
			continue // the definition itself
		}
		if consumer.filtered {
			continue
		}
		if reason, exempt := providerAbsenceSelectionExemptions[key]; exempt {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s is exempt without a reason", key)
			}
			continue
		}
		t.Errorf("%s:%d (%s) consumes the active-tunnel snapshot without withoutProviderAbsent: a provider-confirmed deleted backend could receive new work",
			consumer.file, consumer.line, consumer.function)
	}

	// The guard must have seen the consumers it exists for, or a rename silently disables it.
	wantConsumers := []string{
		"vpn_ingress.go:Service.admissibleIngressCandidatesLocked",
		"backend_health_disable.go:Service.healthDisableTargets",
		"backend_lifecycle.go:Service.disableBackendLocked",
		"backend_lifecycle.go:Service.sweepLeftoverBackendLocked",
	}
	for _, key := range wantConsumers {
		if !observed[key] {
			t.Errorf("expected consumer %s was not found; the guard's coverage is stale", key)
		}
	}

	// An exemption that no consumer matches any more is dead and must be removed.
	keys := make([]string, 0, len(providerAbsenceSelectionExemptions))
	for key := range providerAbsenceSelectionExemptions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !observed[key] {
			t.Errorf("exemption %q matches no consumer and must be removed", key)
		}
	}
}

// guardSourcePath returns the path the guard should parse for a scanned file.
//
// A compiler overlay does not redirect a test's own filesystem reads, so a negative probe
// (a consumer with the filter removed) would leave this guard reading pristine bytes and
// passing for the wrong reason. VPN_GUARD_OVERLAY names the same JSON passed to -overlay,
// and the guard parses the replacement bytes so the probe is genuinely live.
func guardSourcePath(path string) string {
	overlay := os.Getenv("VPN_GUARD_OVERLAY")
	if overlay == "" {
		return path
	}
	data, err := os.ReadFile(overlay)
	if err != nil {
		return path
	}
	var mapping struct{ Replace map[string]string }
	if err := json.Unmarshal(data, &mapping); err != nil {
		return path
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	if replacement, ok := mapping.Replace[abs]; ok {
		return replacement
	}
	return path
}

// providerAbsenceCallWalker collects direct calls to GetActiveTunnels inside one function.
type providerAbsenceCallWalker struct {
	calls []*ast.CallExpr
}

func (w *providerAbsenceCallWalker) Visit(node ast.Node) ast.Visitor {
	if call, ok := node.(*ast.CallExpr); ok && callsNamedFunc(call, "GetActiveTunnels") {
		w.calls = append(w.calls, call)
	}
	return w
}

// callsNamedFunc matches both a plain function call (withoutProviderAbsent(...)) and a
// method call (pool.GetActiveTunnels()).
func callsNamedFunc(call *ast.CallExpr, name string) bool {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name == name
	case *ast.SelectorExpr:
		return fun.Sel != nil && fun.Sel.Name == name
	}
	return false
}

func funcName(decl *ast.FuncDecl) string {
	if decl.Recv != nil && len(decl.Recv.List) > 0 {
		return receiverTypeName(decl.Recv.List[0].Type) + "." + decl.Name.Name
	}
	return decl.Name.Name
}

func receiverTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return receiverTypeName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return receiverTypeName(t.X)
	}
	return "?"
}
