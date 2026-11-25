package dialguard

import (
	"go/ast"
	"go/token"
	"testing"
)

func TestOperationAndQualificationCoverage(t *testing.T) {
	root := repoRoot(t)
	channelFile := "internal/manager/ssh/client_channel.go"
	// New global requests have exactly one admission seam: SendGatedRequest
	// admits presence before it writes anything, and SendRequest may only delegate
	// to it, so neither a caller nor a retained method value can skip the gate.
	for _, name := range []string{"OpenChannel", "SendGatedRequest"} {
		body := functionBody(t, root, channelFile, "*presenceConn", name)
		if len(body.List) == 0 || !isPresenceAdmission(body.List[0]) {
			t.Errorf("%s must admit presence before issuing a new exchange", name)
		}
	}
	sendBody := functionBody(t, root, channelFile, "*presenceConn", "SendRequest")
	if !mentions(sendBody, "SendGatedRequest") {
		t.Error("SendRequest no longer delegates to the guarded admission seam")
	}
	if len(ifStatements(sendBody)) > 0 {
		t.Error("SendRequest re-implements the gate instead of delegating to SendGatedRequest")
	}
	channelBody := functionBody(t, root, channelFile, "*presenceChannel", "SendRequest")
	for _, stmt := range ifStatements(channelBody) {
		if !isPresenceAdmission(stmt) {
			t.Error("preopened session request must refuse before dispatch")
		}
	}
	if len(ifStatements(channelBody)) == 0 {
		t.Error("preopened session has no admission")
	}
	for _, request := range []string{`"exec"`, `"shell"`, `"subsystem"`} {
		found := false
		ast.Inspect(channelBody, func(node ast.Node) bool {
			if value, ok := node.(*ast.BasicLit); ok && value.Value == request {
				found = true
			}
			return true
		})
		if !found {
			t.Errorf("preopened session no longer fences %s", request)
		}
	}
	channel := functionBody(t, root, channelFile, "*presenceConn", "OpenChannel")
	if !mentions(channel, "presenceChannel") {
		t.Error("opened sessions must retain request admission")
	}
	body := functionBody(t, root, sshClientFile, "*Client", "connect")
	wrappers := map[string]bool{}
	ast.Inspect(body, func(node ast.Node) bool {
		if assignment, ok := node.(*ast.AssignStmt); ok && len(assignment.Lhs) == 1 && len(assignment.Rhs) == 1 {
			if name, ok := assignment.Lhs[0].(*ast.Ident); ok && mentions(assignment.Rhs[0], "presenceConn") {
				wrappers[name.Name] = true
			}
		}
		return true
	})
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && mentions(call.Fun, "NewClient") {
			if len(call.Args) == 0 {
				t.Error("raw SSH client must carry presenceConn, including retained method values")
				return true
			}
			guarded := mentions(call.Args[0], "presenceConn")
			if ident, ok := call.Args[0].(*ast.Ident); ok && wrappers[ident.Name] {
				guarded = true
			}
			if !guarded {
				t.Error("raw SSH client must carry presenceConn, including retained method values")
			}
		}
		return true
	})
	body = functionBody(t, root, "internal/vpn/tunnel/health_qualify.go", "*HealthProber", "QualifyProxyTraffic")
	if len(body.List) < 3 || !hasPlainCallGuard(&ast.BlockStmt{List: body.List[:3]}, "providerAbsent", "ErrProviderAbsent") {
		t.Error("qualification must refuse before hook or protocol network dispatch")
	}
	if !mentions(functionBody(t, root, "internal/vpn/backend_enable.go", "*Service", "finishEnableBackend"), "preparePresentNaiveCandidate") {
		t.Error("native readiness lost its provider-presence admission")
	}
	for _, rel := range productionFiles(t, root) {
		file := parseFile(t, root, rel)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				if globals, ok := decl.(*ast.GenDecl); ok && globals.Tok == token.VAR {
					for _, spec := range globals.Specs {
						for _, value := range spec.(*ast.ValueSpec).Values {
							checkNewExchangeRoutes(t, rel, &ast.FuncDecl{Name: ast.NewIdent("global"), Body: &ast.BlockStmt{List: []ast.Stmt{&ast.ExprStmt{X: value}}}})
						}
					}
				}
				continue
			}
			checkNewExchangeRoutes(t, rel, fn)
		}
	}
}

func isPresenceAdmission(stmt ast.Stmt) bool {
	guard, ok := stmt.(*ast.IfStmt)
	if !ok || guard.Init == nil || !mentions(guard.Init, "checkProviderPresence") {
		return false
	}
	cond, ok := guard.Cond.(*ast.BinaryExpr)
	if !ok || cond.Op != token.NEQ || !mentions(cond.X, "err") || !mentions(cond.Y, "nil") {
		return false
	}
	if len(guard.Body.List) != 1 {
		return false
	}
	ret, ok := guard.Body.List[0].(*ast.ReturnStmt)
	return ok && len(ret.Results) > 0 && mentions(ret.Results[len(ret.Results)-1], "err")
}

func checkNewExchangeRoutes(t *testing.T, rel string, fn *ast.FuncDecl) {
	t.Helper()
	allowed := map[string]bool{
		"internal/manager/ssh/client_channel.go:OpenChannel:OpenChannel":                              true,
		"internal/manager/ssh/client_channel.go:SendRequest:SendRequest":                              true,
		"internal/manager/ssh/client_channel.go:SendGatedRequest:SendRequest":                         true,
		"internal/manager/ssh/client_channel.go:SendRequest:SendGatedRequest":                         true,
		"internal/manager/ssh/client.go:alive:SendGatedRequest":                                       true,
		"internal/manager/ssh/client.go:alive:SendRequest":                                            true,
		"internal/manager/ssh/exec.go:RunSession:NewSession":                                          true,
		"internal/vpn/tunnel/health_qualify.go:QualifyProxyTraffic:qualifyProxyTraffic":               true,
		"internal/vpn/tunnel/health_qualify.go:qualifyProxyTraffic:qualifyVLESS":                      true,
		"internal/vpn/tunnel/health_qualify.go:qualifyVLESS:ProbeVLESSTraffic":                        true,
		"internal/vpn/tunnel/health_qualify.go:qualifyProxyTraffic:ProbeNaiveProxyTunnel":             true,
		"internal/vpn/backend_enable.go:prepareNaiveCandidateDevice:EnsureReady":                      true,
		"internal/vpn/tunnel/health_canary_proxy.go:probeVLESSViaEgress:ProbeVLESSTrafficViaDialerTo": true,
		"internal/vpn/tunnel/health_canary_proxy.go:probeVLESSViaEgress:ProbeVLESSTrafficViaDialer":   true,
		"internal/manager/xray/xray.go:NewXrayManager:ProbeVLESSTraffic":                              true,
	}
	watched := map[string]bool{"OpenChannel": true, "SendRequest": true, "SendGatedRequest": true, "NewSession": true, "ProbeVLESSTraffic": true, "ProbeVLESSTrafficWithTarget": true, "ProbeVLESSTrafficViaDialer": true, "ProbeVLESSTrafficViaDialerTo": true, "ProbeNaiveProxyTunnel": true, "EnsureReady": true, "qualifyProxyTraffic": true, "qualifyVLESS": true}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if ident, ok := node.(*ast.Ident); ok && (ident.Name == "qualifyVLESS" || ident.Name == "qualifyProxyTraffic") {
			if !allowed[rel+":"+fn.Name.Name+":"+ident.Name] {
				t.Errorf("%s:%s adds unreviewed qualification dispatch %s", rel, fn.Name.Name, ident.Name)
			}
		}
		sel, ok := node.(*ast.SelectorExpr)
		if ok && watched[sel.Sel.Name] && !allowed[rel+":"+fn.Name.Name+":"+sel.Sel.Name] {
			t.Errorf("%s:%s adds unreviewed new-exchange route %s", rel, fn.Name.Name, sel.Sel.Name)
		}
		return true
	})
}
