package dialguard

import (
	"go/ast"
	"go/token"
	"strconv"
	"testing"
)

// TestSSHAcquisitionCoverage pins the private construction graph, not identifier
// witnesses elsewhere in a file. Public Dial is a one-shot pool checkout;
// NewClient alone cannot connect. No other function may construct a transport.
func TestSSHAcquisitionCoverage(t *testing.T) {
	root := repoRoot(t)
	body := functionBody(t, root, sshPoolFile, "*SSHClientPool", "getOrCreate")
	if len(body.List) == 0 || !admissionGuard(body.List[0]) {
		t.Fatal("pool admission must be the first statement, before cached validation, dial and every client return")
	}
	for _, name := range []string{"Get", "GetWithConfig"} {
		body := functionBody(t, root, sshPoolFile, "*SSHClientPool", name)
		checkPoolWrapper(t, body, name)
	}
	if !mentions(functionBody(t, root, sshClientFile, "", "Dial"), "getOrCreate") {
		t.Error("one-shot Dial bypasses pool checkout")
	}
	for _, rel := range productionFiles(t, root) {
		file := parseFile(t, root, rel)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok {
				if rel == sshClientFile && fn.Name.Name == "Connect" {
					t.Error("exported Connect bypasses pool ownership")
				}
				checkSSHConstruction(t, rel, file, fn)
				continue
			}
			if global, ok := decl.(*ast.GenDecl); ok && global.Tok == token.VAR {
				for _, spec := range global.Specs {
					values := spec.(*ast.ValueSpec)
					for _, value := range values.Values {
						checkSSHConstruction(t, rel, file, &ast.FuncDecl{Name: ast.NewIdent("global"), Body: &ast.BlockStmt{List: []ast.Stmt{&ast.ExprStmt{X: value}}}})
					}
				}
			}
		}
	}
}

func checkPoolWrapper(t *testing.T, body *ast.BlockStmt, name string) {
	t.Helper()
	if len(body.List) < 3 {
		t.Fatalf("pool %s has no admitted return sequence", name)
	}
	last := body.List[len(body.List)-3:]
	assignment, ok := last[0].(*ast.AssignStmt)
	if !ok || len(assignment.Rhs) != 1 {
		t.Fatalf("pool %s must acquire before returning", name)
	}
	call, ok := assignment.Rhs[0].(*ast.CallExpr)
	if !ok {
		t.Fatalf("pool %s must call checkout", name)
	}
	callee, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || callee.Sel.Name != "getOrCreate" {
		t.Fatalf("pool %s bypasses checkout", name)
	}
	ret, ok := last[2].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 2 || !mentions(ret.Results[0], "client") {
		t.Fatalf("pool %s does not return admitted client", name)
	}
	var returns int
	ast.Inspect(body, func(node ast.Node) bool {
		if result, ok := node.(*ast.ReturnStmt); ok && len(result.Results) > 0 {
			returns++
			if !mentions(result.Results[0], "nil") && result != ret {
				t.Errorf("pool %s returns a client outside admitted return", name)
			}
		}
		return true
	})
	if returns == 0 {
		t.Fatal("pool wrapper contains no returns")
	}
}

func admissionGuard(stmt ast.Stmt) bool {
	guard, ok := stmt.(*ast.IfStmt)
	if !ok || guard.Else != nil {
		return false
	}
	init, ok := guard.Init.(*ast.AssignStmt)
	if !ok || init.Tok != token.DEFINE || len(init.Rhs) != 1 {
		return false
	}
	call, ok := init.Rhs[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	callee, ok := call.Fun.(*ast.Ident)
	if !ok || callee.Name != "checkProviderPresence" {
		return false
	}
	cond, ok := guard.Cond.(*ast.BinaryExpr)
	if !ok || cond.Op != token.NEQ {
		return false
	}
	left, lok := cond.X.(*ast.Ident)
	right, rok := cond.Y.(*ast.Ident)
	if !lok || !rok || left.Name != "err" || right.Name != "nil" {
		return false
	}
	if len(guard.Body.List) != 1 {
		return false
	}
	ret, ok := guard.Body.List[0].(*ast.ReturnStmt)
	return ok && len(ret.Results) == 2 && mentions(ret.Results[0], "nil") && mentions(ret.Results[1], "err")
}

// hasPresenceInitGuard reports an `if err := checkProviderPresence(…); err != nil { … return err }`,
// the form that consults the durable observation rather than only the config
// snapshot. Like hasPlainGuard it rejects a disabled condition and a body that
// drops the refusal.
func hasPresenceInitGuard(body *ast.BlockStmt, callee string) bool {
	for _, stmt := range ifStatements(body) {
		init, ok := stmt.Init.(*ast.AssignStmt)
		if !ok || len(init.Rhs) != 1 {
			continue
		}
		call, ok := init.Rhs[0].(*ast.CallExpr)
		if !ok {
			continue
		}
		name, ok := call.Fun.(*ast.Ident)
		if !ok || name.Name != callee {
			continue
		}
		cond, ok := stmt.Cond.(*ast.BinaryExpr)
		if !ok || cond.Op != token.NEQ || !mentions(cond.Y, "nil") {
			continue
		}
		if mentions(stmt.Body, "err") {
			return true
		}
	}
	return false
}

// refusesBeforeDial reports that the presence guard is a statement before the
// first TCP dial in the body, so the refusal cannot be reached after a socket.
func refusesBeforeDial(body *ast.BlockStmt) bool {
	guard, dial := -1, -1
	for i, stmt := range body.List {
		if guard < 0 && (mentions(stmt, "checkProviderPresence") || mentions(stmt, "ProviderAbsent")) {
			guard = i
		}
		if dial < 0 && mentions(stmt, "DialContext") {
			dial = i
		}
	}
	return guard >= 0 && dial >= 0 && guard < dial
}

// branches reports whether the body contains the given branch statement, which
// is how a skip is written (`continue`, `break`) without an identifier to read.
func branches(body *ast.BlockStmt, kind token.Token) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if branch, ok := node.(*ast.BranchStmt); ok && branch.Tok == kind {
			found = true
		}
		return !found
	})
	return found
}

// TestPoolMaintenanceNeverClosesInFlightWork pins the ordering rule, not a word:
// the retirement branch of a maintenance cycle must consult InUse and skip the
// entry before it deletes or closes anything. A dead verdict on a transport that
// is still carrying a command would otherwise take that command's exit status
// with it.
func TestPoolMaintenanceNeverClosesInFlightWork(t *testing.T) {
	root := repoRoot(t)
	body := functionBody(t, root, sshPoolFile, "*SSHClientPool", "pingAll")
	inUse, closed := token.NoPos, token.NoPos
	ast.Inspect(body, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.IfStmt:
			if inUse == token.NoPos && mentions(n.Cond, "InUse") && branches(n.Body, token.CONTINUE) {
				inUse = n.Pos()
			}
		case *ast.CallExpr:
			if closed == token.NoPos && mentions(n.Fun, "Close") {
				closed = n.Pos()
			}
		}
		return true
	})
	if inUse == token.NoPos {
		t.Fatal("maintenance no longer skips a connection with work in flight")
	}
	if closed == token.NoPos {
		t.Fatal("maintenance no longer retires dead connections")
	}
	if inUse > closed {
		t.Fatal("maintenance closes a connection before checking whether work is in flight")
	}
}

func checkSSHConstruction(t *testing.T, rel string, file *ast.File, fn *ast.FuncDecl) {
	t.Helper()
	aliases := map[string]string{}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		alias := "ssh"
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		if path == "golang.org/x/crypto/ssh" || path == "github.com/devops-igor/amnezia-nexus/internal/manager/ssh" {
			if alias == "." {
				t.Fatal("dot SSH import defeats acquisition ownership")
			}
			aliases[alias] = path
		}
	}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.SelectorExpr:
			if file.Name.Name == "ssh" && n.Sel.Name == "conns" {
				allowed := rel == sshPoolFile && (fn.Name.Name == "cachedClient" || fn.Name.Name == "publishClient" || fn.Name.Name == "Remove" || fn.Name.Name == "RemoveByKey" || fn.Name.Name == "Len" || fn.Name.Name == "Close" || fn.Name.Name == "pingAll" || fn.Name.Name == "sweepIdle")
				if !allowed {
					t.Errorf("%s:%s reads cached clients outside private pool ownership", rel, fn.Name.Name)
				}
			}
			if n.Sel.Name == "getOrCreate" {
				allowed := rel == sshClientFile && fn.Name.Name == "Dial" || rel == sshPoolFile && (fn.Name.Name == "Get" || fn.Name.Name == "GetWithConfig" || fn.Name.Name == "publishClient")
				if !allowed {
					t.Errorf("%s:%s adds an unreviewed checkout route", rel, fn.Name.Name)
				}
			}
			if n.Sel.Name == "connect" && (rel != "internal/manager/ssh/pool_presence.go" || fn.Name.Name != "dialClient") {
				t.Errorf("%s:%s bypasses pool transport construction", rel, fn.Name.Name)
			}
			pkg, ok := n.X.(*ast.Ident)
			if ok && aliases[pkg.Name] == "golang.org/x/crypto/ssh" && (n.Sel.Name == "Dial" || n.Sel.Name == "NewClient" || n.Sel.Name == "NewClientConn") {
				allowed := rel == sshClientFile && fn.Name.Name == "connect" && n.Sel.Name == "NewClient" || rel == sshHandshakeFile && fn.Name.Name == "handshake" && n.Sel.Name == "NewClientConn"
				if !allowed {
					t.Errorf("%s:%s obtains raw SSH client outside pool construction", rel, fn.Name.Name)
				}
			}
		case *ast.Ident:
			if n.Name == "dialClient" && rel != "internal/manager/ssh/pool_presence.go" && (rel != sshPoolFile || fn.Name.Name != "getOrCreate") {
				t.Errorf("%s:%s invokes private dial outside checkout", rel, fn.Name.Name)
			}
		case *ast.CompositeLit:
			if sel, ok := n.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Client" {
				if pkg, ok := sel.X.(*ast.Ident); ok && aliases[pkg.Name] != "" {
					t.Errorf("%s:%s constructs SSH Client outside pool ownership", rel, fn.Name.Name)
				}
			}
			if ident, ok := n.Type.(*ast.Ident); ok && ident.Name == "Client" && file.Name.Name == "ssh" && fn.Name.Name != "NewClient" {
				t.Errorf("%s:%s constructs SSH Client outside its constructor", rel, fn.Name.Name)
			}
		}
		return true
	})
}
