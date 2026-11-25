package destinationguard

// Derived guard: no code may move a session, create one, or repoint a route without the
// shared destination decision.
//
// The defect this replaces was answered twice by naming symbols: the first guard enumerated
// the writers of the absence mark, the second enumerated the callers of one pool accessor.
// Both were accurate and both were insufficient, because the missing consumer read a
// DIFFERENT source (the durable tunnel table) and never appeared in either list. So this
// guard inverts the enumeration: it does not list sources, it lists the EFFECTS that place
// work somewhere, and requires each one to be reached through the decision.
//
// The invariant is stated on the EFFECT, not on the sources: any function that can put a
// session somewhere must reach the destination decision (or be a declared exemption with a
// reason). That is the property the two earlier guards lacked - they enumerated sources, so a
// consumer reading a source nobody had listed was invisible to them.
//
// The gate is models.TunnelDestinationAllowed plus the entry points that consult it on behalf
// of their callers: the service's migration gate, the ingress candidate builder, the
// health-disable target list, the rebalance pass, and the DB-only fallback's own pre-write
// revalidation.

// The gate itself is models.TunnelDestinationAllowed plus the two entry points that consult
// it before their own write (Service.MigrateSession in the vpn package and the orchestrator's
// rebalance, whose DB-only fallback revalidates separately).

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

// placementEffects are the calls that put a session somewhere. A function containing one of
// these is a placer and must reach the destination gate.
var placementEffects = map[string]bool{
	"MigrateSession":                  true, // live migration (route + session + counters)
	"UpdateVPNSessionBackendTunnel":   true, // durable repoint, no migration service
	"MigrateVPNSessionBackend":        true, // rollback/persist half of a migration
	"MigrateVPNSessionToActiveTunnel": true, // predicate-guarded repoint
	"UpdateSessionBackend":            true, // in-memory session repoint
	"UpdateSessionBackendIfCurrent":   true,
	"CreateSessionWithDelta":          true, // fresh admission
	"CreateSessionWithDeltaAndSource": true,
	"CreateSession":                   true,
	"TransferConnectionsIfActive":     true, // the counter commit that finalises a move
}

// destinationGateSymbols are the functions that make the decision or consult it on behalf of
// their callers. Reaching any of them counts as reaching the gate.
var destinationGateSymbols = map[string]bool{
	"TunnelDestinationAllowed":          true,
	"EligibleTunnelDestinations":        true,
	"EligibleTunnelDestinationValues":   true,
	"withoutProviderAbsent":             true,
	"validateMigrationTarget":           true,
	"dbTargetEligible":                  true,
	"admissibleIngressCandidatesLocked": true,
	"healthDisableTargets":              true,
	"RebalanceVPNSessions":              true,
}

// guardExemptions declares a function allowed to contain a placement effect or a candidate
// source without reaching the gate. Every entry needs a reason that survives review: why this
// code cannot place work on a provider-confirmed deleted server.
var guardExemptions = map[string]string{
	// Restoring a session to the backend it came from, and counter accounting, are not
	// destination decisions: they can only ever move work AWAY from a destination.
	"vpn:(*Service).rollbackMigration": "rollback returns a session to the backend it was migrated from; it never selects a destination",
	"vpn:(*Service).DisconnectSession": "removes a session and decrements a counter; no destination is chosen",
	"vpn:(*Service).DisconnectUser":    "removes a session and decrements a counter; no destination is chosen",
	"vpn:(*Service).ReleaseClient":     "removes a session and decrements a counter; no destination is chosen",
	// The server-side plumbing that persists a placement: its caller owns eligibility.
	"database:(*DB).UpdateVPNSessionBackendTunnel":              "the durable write primitive; its callers own destination eligibility",
	"database:(*DB).MigrateVPNSessionBackend":                   "the durable write primitive used by migration and rollback",
	"database:(*DB).MigrateVPNSessionToActiveTunnel":            "the durable write primitive; it applies its own status predicate",
	"session:(*SessionManager).CreateSession":                   "the effect primitive; its caller owns destination eligibility",
	"session:(*SessionManager).CreateSessionWithDelta":          "the effect primitive; its caller owns destination eligibility",
	"session:(*SessionManager).CreateSessionWithDeltaAndSource": "the effect primitive; its caller owns destination eligibility",
	"session:(*SessionManager).UpdateSessionBackend":            "the effect primitive; its caller owns destination eligibility",
}

// scannedPackages are the roots the guard reads, relative to the repository root.
var scannedPackages = []string{"internal", "cmd"}

func TestEverySessionPlacementReachesTheDestinationGate(t *testing.T) {
	root := repositoryRoot(t)
	graph := buildCallGraph(t, root)

	var placements []functionInfo
	for _, fn := range graph.functions {
		if fn.packagePath == "internal/models" {
			continue // the gate itself lives here
		}
		if fn.reachesAny(placementEffects) {
			placements = append(placements, fn)
		}
	}

	if len(placements) < 3 {
		t.Fatalf("the guard found only %d placers; it is no longer scanning the code", len(placements))
	}

	seen := make(map[string]bool)
	for _, fn := range placements {
		key := fn.key()
		seen[key] = true
		if graph.reachesGate(fn) {
			continue
		}
		if _, exempt := guardExemptions[key]; exempt {
			continue
		}
		t.Errorf("%s (%s:%d) can place a session without the shared destination decision",
			key, fn.file, fn.line)
	}

	// The known writers and the known blind spot must still be discovered, so a rename
	// cannot silently empty the scan. The rebalancer is named here because it was the
	// consumer two earlier guards missed.
	for _, required := range []string{
		"orchestrator:(*Orchestrator).drainTunnelExcess",
		"orchestrator:(*Orchestrator).migrateDegradedTunnelSessions",
		"vpn:(*Service).MigrateSession",
		"vpn:(*Service).ensureBackendSessionForIngress",
		"vpn:(*Service).disableBackendLocked",
		"vpn:(*Service).migrateSessionsToHealthy",
	} {
		if !seen[required] {
			t.Errorf("expected placer %s was not found; the guard's coverage is stale", required)
		}
	}
	// And the destination sources themselves must still be reachable through the gate.
	for _, required := range []string{
		"orchestrator:(*Orchestrator).RebalanceVPNSessions",
		"vpn:(*Service).healthDisableTargets",
		"vpn:(*Service).admissibleIngressCandidatesLocked",
		"vpn:(*Service).validateMigrationTarget",
		"orchestrator:(*Orchestrator).dbTargetEligible",
	} {
		if !graph.has(required) {
			t.Errorf("expected destination consumer %s was not found; the guard's coverage is stale", required)
		}
	}

	// Reachability is necessary but not sufficient, and the difference is exactly what the
	// round-17 guard missed: a function can reach the gate through ONE path and still carry a
	// second, unguarded one. The two checks below assert the path itself, structurally, for
	// the two places where that distinction matters.
	//
	//   1. The rebalance's candidate list - the source that was never filtered - must be
	//      derived from the shared decision.
	//   2. Its DB-only write must sit inside the pre-write revalidation, because it is a
	//      second write path in the same function as the guarded live migrator.
	assertRebalanceCandidatesAreFiltered(t, root)
	assertFallbackWriteIsGuarded(t, root)

	// Exemptions must match a real function, and must carry a reason.
	keys := make([]string, 0, len(guardExemptions))
	for key := range guardExemptions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if strings.TrimSpace(guardExemptions[key]) == "" {
			t.Errorf("exemption %q has no reason", key)
		}
		if !graph.has(key) {
			t.Errorf("exemption %q matches no function and must be removed", key)
		}
	}
}

// functionInfo is one function the guard considered.
type functionInfo struct {
	packagePath string // "internal/vpn"
	packageName string // "vpn"
	receiver    string // "" or "Service"
	name        string
	file        string
	line        int
	calls       []string // callee names, receiver-elided
}

func (f functionInfo) key() string {
	if f.receiver != "" {
		return f.packageName + ":" + f.receiver + "." + f.name
	}
	return f.packageName + ":" + f.name
}

func (f functionInfo) reachesAny(set map[string]bool) bool {
	for _, call := range f.calls {
		if set[call] {
			return true
		}
	}
	return false
}

// callGraph is the resolved call graph of the scanned packages plus the resolver it came
// from, so reachability is computed on names rather than on source proximity.
type callGraph struct {
	functions  []functionInfo
	byName     map[string][]int // elided function name -> indices
	gateCache  map[string]bool
	inProgress map[string]bool
}

func (g *callGraph) has(key string) bool {
	for _, fn := range g.functions {
		if fn.key() == key {
			return true
		}
	}
	return false
}

// reachesGate reports whether fn invokes a destination-gate symbol, directly or through
// functions in the scanned packages.
//
// Reachability is memoised per function: the call graph over a real repository is dense, so
// an unmemoised walk revisits the same sub-graph exponentially often (and did: the first
// version of this guard did not finish).
func (g *callGraph) reachesGate(fn functionInfo) bool {
	key := fn.key()
	if reached, known := g.gateCache[key]; known {
		return reached
	}
	reached := g.reaches(fn, map[string]bool{})
	// A cycle that comes back to key must not be able to poison the memo: the result is only
	// cached once the walk has finished, via the in-progress marker below.
	if !g.inProgress[key] {
		g.gateCache[key] = reached
	}
	return reached
}

func (g *callGraph) reaches(fn functionInfo, visiting map[string]bool) bool {
	key := fn.key()
	if visiting[key] {
		return false // a cycle contributes nothing new
	}
	if reached, known := g.gateCache[key]; known {
		return reached
	}
	visiting[key] = true
	g.inProgress[key] = true
	defer delete(visiting, key)

	reached := false
	for _, call := range fn.calls {
		if destinationGateSymbols[call] {
			reached = true
			break
		}
		for _, index := range g.byName[call] {
			if g.reaches(g.functions[index], visiting) {
				reached = true
				break
			}
		}
		if reached {
			break
		}
	}
	delete(g.inProgress, key)
	g.gateCache[key] = reached
	return reached
}

// buildCallGraph parses the scanned packages, honouring the same overlay seam the other
// source guards use so a negative probe reads the mutated bytes rather than pristine ones.
func buildCallGraph(t *testing.T, root string) *callGraph {
	t.Helper()
	fset := token.NewFileSet()
	graph := &callGraph{byName: make(map[string][]int), gateCache: make(map[string]bool), inProgress: make(map[string]bool)}

	for _, dir := range scannedPackages {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, parseErr := parser.ParseFile(fset, overlayPath(path), nil, 0)
			if parseErr != nil {
				return parseErr
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			pkgPath := filepath.ToSlash(filepath.Dir(rel))

			for _, decl := range file.Decls {
				fnDecl, ok := decl.(*ast.FuncDecl)
				if !ok || fnDecl.Body == nil {
					continue
				}
				info := functionInfo{
					packagePath: pkgPath,
					packageName: file.Name.Name,
					receiver:    destGuardReceiver(fnDecl),
					name:        fnDecl.Name.Name,
					file:        filepath.ToSlash(rel),
					line:        fset.Position(fnDecl.Pos()).Line,
				}
				ast.Inspect(fnDecl.Body, func(node ast.Node) bool {
					if call, ok := node.(*ast.CallExpr); ok {
						if name := calledName(call); name != "" {
							info.calls = append(info.calls, name)
						}
					}
					return true
				})
				index := len(graph.functions)
				graph.functions = append(graph.functions, info)
				graph.byName[info.name] = append(graph.byName[info.name], index)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scanning %s: %v", dir, err)
		}
	}
	return graph
}

// destGuardReceiver renders the receiver type of a method, or "" for a plain function.
func destGuardReceiver(decl *ast.FuncDecl) string {
	if decl.Recv == nil || len(decl.Recv.List) == 0 {
		return ""
	}
	return receiverTypeText(decl.Recv.List[0].Type)
}

func receiverTypeText(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return "(*" + receiverTypeText(t.X) + ")"
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return receiverTypeText(t.X)
	}
	return "?"
}

// calledName returns the elided name of an invoked function or method.
func calledName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		if fun.Sel != nil {
			return fun.Sel.Name
		}
	}
	return ""
}

// overlayPath applies the same JSON replacement map the compiler overlay used, so a negative
// probe is genuinely live: the guard otherwise reads pristine bytes and passes for the wrong
// reason.
func overlayPath(path string) string {
	overlay := os.Getenv("DESTINATION_GUARD_OVERLAY")
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

// repositoryRoot walks up from the test's working directory to the module root.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate the module root")
		}
		dir = parent
	}
}

// assertFallbackWriteIsGuarded requires the rebalance's durable repoint to be decided by the
// pre-write revalidation rather than by the pass snapshot alone.
//
// The defect this covers is specific: two write paths live in one function, one of them goes
// through the migration gate and the other writes the row directly. A function-level
// reachability check is satisfied by the first and says nothing about the second.
func assertFallbackWriteIsGuarded(t *testing.T, root string) {
	t.Helper()
	const rel = "internal/service/orchestrator/vpn_tasks.go"

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, overlayPath(filepath.Join(root, rel)), nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", rel, err)
	}

	found := false
	for _, decl := range file.Decls {
		fnDecl, ok := decl.(*ast.FuncDecl)
		if !ok || fnDecl.Name.Name != "drainTunnelExcess" {
			continue
		}
		ast.Inspect(fnDecl.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || calledName(call) != "UpdateVPNSessionBackendTunnel" {
				return true
			}
			found = true
			if !conditionMentions(fnDecl.Body, call.Pos(), "dbTargetEligible") {
				t.Errorf("%s:%d writes a session's durable backend without the pre-write destination revalidation",
					rel, fset.Position(call.Pos()).Line)
			}
			return true
		})
	}
	if !found {
		t.Errorf("the rebalance fallback no longer writes a durable repoint in %s; this check is stale", rel)
	}
}

// conditionMentions reports whether the call at pos is enclosed by an if statement whose
// condition or body mentions the given symbol.
func conditionMentions(body *ast.BlockStmt, pos token.Pos, symbol string) bool {
	guarded := false
	var walk func(node ast.Node) bool
	walk = func(node ast.Node) bool {
		ifStmt, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		encloses := ifStmt.Pos() <= pos && pos <= ifStmt.End()
		if !encloses {
			return true
		}
		mentions := false
		for _, subtree := range []ast.Node{ifStmt.Cond, ifStmt.Body} {
			ast.Inspect(subtree, func(inner ast.Node) bool {
				if ident, ok := inner.(*ast.Ident); ok && ident.Name == symbol {
					mentions = true
				}
				return !mentions
			})
		}
		if mentions {
			guarded = true
			return false
		}
		return true
	}
	ast.Inspect(body, walk)
	return guarded
}

// assertRebalanceCandidatesAreFiltered requires the rebalance's destination candidates to be
// derived from the shared decision.
//
// The function it checks reads a source no snapshot filter can see (`GetBackendTunnels`), and
// it reaches the destination gate through the live migrator, so a reachability check is
// satisfied while the candidate list itself is unfiltered. That is precisely the round-17
// defect, so the path is asserted here instead of inferred.
func assertRebalanceCandidatesAreFiltered(t *testing.T, root string) {
	t.Helper()
	const rel = "internal/service/orchestrator/vpn_tasks.go"

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, overlayPath(filepath.Join(root, rel)), nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", rel, err)
	}

	foundFn := false
	for _, decl := range file.Decls {
		fnDecl, ok := decl.(*ast.FuncDecl)
		if !ok || fnDecl.Name.Name != "RebalanceVPNSessions" {
			continue
		}
		foundFn = true
		filtered := false
		readsDurableTunnels := false
		ast.Inspect(fnDecl.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch calledName(call) {
			case "GetBackendTunnels":
				readsDurableTunnels = true
			case "EligibleTunnelDestinationValues", "EligibleTunnelDestinations":
				filtered = true
			}
			return true
		})
		if !readsDurableTunnels {
			t.Errorf("%s: the rebalance no longer reads the durable tunnel table; this check is stale", rel)
		}
		if !filtered {
			t.Errorf("%s: the rebalance builds its destination candidates without the shared decision", rel)
		}
	}
	if !foundFn {
		t.Fatalf("%s no longer declares RebalanceVPNSessions; this check is stale", rel)
	}
}
