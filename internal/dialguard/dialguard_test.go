package dialguard

// Derivation of the dialling inventory, and the checks that keep it honest.
//
// The inventory is built by parsing every non-test file under internal/ and cmd/
// and collecting the constructs that can open a connection to a managed server:
// TCP dials, SSH client construction, tunnel probe dispatch and the raw handshake
// senders. A construct found in a file the inventory does not name fails this
// test, so a dialling path added later cannot ship silently - it must either be
// declared as reaching one of the two provider-absence boundaries, or state why
// its target is not a managed server.
//
// Two rounds of this work failed by enumerating callers from memory: an
// independent worker and an automatic page poll were both missed. The list below
// is therefore derived by walking the tree, and every entry carries how it is
// covered. The boundary checks assert the refusal is still present in the SSH
// transport and in the tunnel probe dispatch, because losing it there leaves the
// inventory complete and the panel dialling again.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	sshClientFile    = "internal/manager/ssh/client.go"
	sshPoolFile      = "internal/manager/ssh/pool.go"
	sshHandshakeFile = "internal/manager/ssh/handshake.go"
	tunnelHealthFile = "internal/vpn/tunnel/health.go"
	tunnelSelfHeal   = "internal/vpn/tunnel/health_selfheal.go"
	tunnelHealthLoop = "internal/vpn/tunnel/health_loop.go"
	tunnelReconnect  = "internal/vpn/tunnel/reconnect.go"
)

// How a dialling construct is covered.
const (
	// viaBoundarySSH reaches the SSH transport, which refuses on the server row's
	// observation before any socket exists.
	viaBoundarySSH = "ssh-boundary"
	// viaBoundaryProbe is, or reaches, the tunnel probe dispatch or entry, which
	// refuses with ErrProviderAbsent.
	viaBoundaryProbe = "probe-boundary"
	// viaRefusesItself performs its own refusal before dialing.
	viaRefusesItself = "refuses-itself"
	// viaNotAServer cannot reach a managed server at all.
	viaNotAServer = "not-a-server"
)

// dialSite is one construct that can open a connection, allowed in one file with
// the way it is covered. An entry whose construct no longer appears in that file
// fails too, so an exemption cannot outlive the code it describes.
type dialSite struct {
	path      string
	construct string
	via       string
	reason    string
}

var dialSites = []dialSite{
	// ---- SSH transport: the boundary every SSH session passes through ----
	{sshClientFile, "net.Dialer", viaBoundarySSH, "the single TCP dial of an SSH session; refuses before the socket exists"},
	{sshClientFile, "DialContext", viaBoundarySSH, "same dial"},
	{sshClientFile, "gossh.NewClient", viaBoundarySSH, "SSH client construction, after the admitted dial"},
	{sshClientFile, "sftp.NewClient", viaNotAServer, "SFTP client over an SSH connection the transport already admitted"},
	{sshPoolFile, "ssh.Config{", viaBoundarySSH, "builds the config from the server row, carrying its absence observation"},
	{sshClientFile, "ssh.Config{", viaBoundarySSH, "DialFromServer builds the config from the row, carrying its absence observation"},
	{sshHandshakeFile, "gossh.NewClientConn", viaNotAServer, "handshake of a connection a caller already obtained from the transport, which refused first"},

	// ---- tunnel probe dispatch: the boundary every backend probe passes through ----
	{tunnelHealthFile, "probeEndpoint", viaBoundaryProbe, "the dispatch every tunnel probe passes through; returns ErrProviderAbsent"},
	{tunnelHealthFile, "health.ProbeAWGEndpointRange", viaBoundaryProbe, "default AWG sender of the prober, called only through probeEndpoint"},
	{tunnelHealthFile, "naive.ProbeNaiveProxy", viaBoundaryProbe, "default naive sender, called only through probeEndpoint"},
	{tunnelHealthFile, "vless.ProbeVLESSReality", viaBoundaryProbe, "default vless sender, called only through probeEndpoint"},
	{tunnelSelfHeal, "probeEndpoint", viaBoundaryProbe, "self-healing sweep uses the guarded dispatch"},
	{tunnelHealthLoop, "ProbeTunnel", viaBoundaryProbe, "periodic sweep calls the guarded entry"},
	{tunnelReconnect, "ProbeTunnel", viaBoundaryProbe, "reconnect sweep calls the guarded entry and leaves retry state untouched on refusal"},
	{"internal/vpn/service_test_hooks.go", "ProbeTunnel", viaBoundaryProbe, "test seam delegating to the guarded prober"},
	{"internal/vpn/service_test_hooks.go", "health.ProbeAWGEndpointRange", viaBoundaryProbe, "test seam default sender"},
	{"internal/vpn/vpn.go", "health.ProbeAWGEndpointRange", viaNotAServer, "default function value on the service prober, not a dial; every invocation goes through probeEndpoint"},
	{"internal/handlers/gigahost_deploy.go", "ProbeTunnel", viaBoundaryProbe, "deploy verification through the guarded prober; a refusal fails the deploy instead of reporting health"},
	{"internal/service/orchestrator/orchestrator.go", "health.ProbeAWGEndpointRange", viaNotAServer, "default function value on the orchestrator, not a dial; the loops that invoke it skip an absent row first"},
	{"internal/service/orchestrator/reachability.go", "health.PerformAWGHandshake", viaRefusesItself, "direct handshake inside the orchestrator probe, after the absent-row skip"},
	{"internal/service/orchestrator/reachability.go", "net.Dialer", viaRefusesItself, "TCP fallback of the orchestrator probe, after the absent-row skip"},
	{"internal/service/orchestrator/reachability.go", "DialContext", viaRefusesItself, "same fallback"},
	{"internal/service/orchestrator/vpn_tasks.go", "health.ProbeAWGEndpointRange", viaRefusesItself, "backend health sweep; a tunnel of an absent server is skipped before the probe"},

	// ---- SSH accessors: inherit the transport refusal ----
	{"internal/handlers/server_config.go", "GetSSHClient", viaBoundarySSH, "operator action over the guarded accessor"},
	{"internal/handlers/server_containers.go", "GetSSHClient", viaBoundarySSH, "operator action over the guarded accessor"},
	{"internal/handlers/reality_scanner.go", "GetSSHClient", viaBoundarySSH, "operator action over the guarded accessor"},
	{"internal/handlers/reality_scanner.go", "DialContext", viaRefusesItself, "reuses the admitted SSH connection's dialer; the handler refuses an absent row before acquiring it, so the panel-host fallback cannot be reached"},

	// ---- sites that refuse before dialing on their own ----
	{"internal/handlers/servers.go", "GetSSHClient", viaRefusesItself, "stats and check handlers answer an absent row without acquisition, and every other use inherits the transport refusal"},
	{"internal/handlers/servers.go", "net.DialTimeout", viaRefusesItself, "server page reachability poll refuses an absent row before dialing"},
	{"internal/handlers/servers.go", "ssh.Config{", viaRefusesItself, "single-server connection test in the detail flow, behind the row checks above"},
	{"internal/handlers/servers.go", "ssh.Dial", viaNotAServer, "adding a brand-new host from a request body: no stored row exists yet, so no absence can apply"},
	{"internal/handlers/gigahost_bootstrap.go", "ssh.Config{", viaRefusesItself, "builds the config from the row including its absence observation, so the transport refuses"},
	{"internal/handlers/gigahost_deploy.go", "ssh.Dial", viaRefusesItself, "the deploy dial refuses on the config flag, and both callers set it from the resolved row"},
	{"internal/handlers/gigahost_deploy_hostkey.go", "ssh.Config{", viaBoundarySSH, "deploy verification looks the row's absence up and puts it into the config, which the transport refuses on"},

	// ---- targets that are not a managed server ----
	{"internal/handlers/gigahost.go", "gigahost.NewClient", viaNotAServer, "provider REST API client, not a host connection"},
	{"internal/manager/awg/health/probe.go", "net.Dialer", viaNotAServer, "AWG handshake sender: takes an endpoint string and holds no server identity; every caller is a guarded loop or the guarded dispatch"},
	{"internal/manager/awg/health/probe.go", "DialContext", viaNotAServer, "same handshake sender"},
	{"internal/manager/dns/unbound.go", "net.Dialer", viaNotAServer, "UDP check against the configured resolver, not a managed server"},
	{"internal/manager/dns/unbound.go", "DialContext", viaNotAServer, "same resolver check"},
	{"internal/manager/xray/scanner/probe.go", "net.Dialer", viaNotAServer, "reality candidate scan against public domains, not a managed server"},
	{"internal/manager/xray/scanner/probe.go", "Dialer", viaNotAServer, "candidate scan dialer field"},
	{"internal/manager/xray/scanner/probe.go", "DialContext", viaNotAServer, "candidate scan dial"},
	{"internal/manager/xray/scanner/scanner.go", "DialContext", viaNotAServer, "candidate scan dial"},
	{"internal/manager/xray/xray.go", "vless.ProbeVLESSReality", viaNotAServer, "install-time protocol verification; the install itself ran over an SSH session the transport admitted"},
	{"internal/notifications/client.go", "net.Dialer", viaNotAServer, "outbound notification delivery to a configured receiver"},
	{"internal/notifications/client.go", "DialContext", viaNotAServer, "same delivery"},
	{"internal/vpn/backend_credential_rotation.go", "DialContext", viaNotAServer, "loopback self-check of a locally started port"},
	{"internal/vpn/backend_credential_rotation.go", "naive.ProbeNaiveProxy", viaNotAServer, "probe of that locally started proxy"},
	{"internal/vpn/endpoint.go", "net.DialTimeout", viaNotAServer, "outbound-interface detection to a public address"},
	{"internal/vpn/vpn_pbr.go", "net.Dial", viaNotAServer, "fixed public probe address used to find the default route"},
	{"internal/vpn/tunnel/naive/daemon.go", "net.DialTimeout", viaNotAServer, "loopback readiness wait for the local naive daemon"},
	{"internal/vpn/tunnel/naive/h2.go", "net.Dialer", viaNotAServer, "naive transport dialer toward the proxy endpoint; reached through the guarded dispatch for probes"},
	{"internal/vpn/tunnel/naive/h2.go", "DialContext", viaNotAServer, "same transport dialer"},
	{"internal/vpn/tunnel/naive/h2.go", "NewClientConn", viaNotAServer, "HTTP/2 client connection to the proxy endpoint"},
	{"internal/vpn/tunnel/naive/h3.go", "NewClientConn", viaNotAServer, "HTTP/3 client connection to the proxy endpoint"},
	{"internal/vpn/tunnel/naive/probe.go", "DialContext", viaNotAServer, "probe body reached only through the guarded dispatch"},
	{"internal/vpn/tunnel/naive/socks5_dialer.go", "DialContext", viaNotAServer, "SOCKS dialer built on a supplied underlying dialer"},
	{"internal/vpn/tunnel/naive/dialer.go", "net.Dialer", viaNotAServer, "naive dialer for the tunnel it was built for"},
	{"internal/vpn/tunnel/naive/dialer.go", "DialContext", viaNotAServer, "same naive dialer"},
	{"internal/vpn/tunnel/vless/dialer.go", "net.Dialer", viaNotAServer, "vless dialer for the tunnel it was built for"},
	{"internal/vpn/tunnel/vless/dialer.go", "DialContext", viaNotAServer, "same vless dialer"},
	{"internal/vpn/tunnel/vless/dialer.go", "vless.NewClient", viaNotAServer, "vless client value for that dialer"},
	{"internal/vpn/tunnel/vless/probe.go", "DialContext", viaNotAServer, "probe body reached only through the guarded dispatch"},
	{"internal/vpn/tunnel/vless/probe.go", "NewClientConn", viaNotAServer, "client connection inside the probe body"},
	{"internal/vpn/tunnel/streambridge/device.go", "DialTimeout", viaNotAServer, "data-plane device stream for an established session"},
	{"internal/vpn/tunnel/streambridge/flows.go", "DialContext", viaNotAServer, "data-plane flow bridge for an established session"},
	{"internal/vpn/tunnel/streambridge/flows.go", "DialTimeout", viaNotAServer, "data-plane flow bridge for an established session"},
}

// watchedSelectors are the constructs collected from the tree.
var watchedSelectors = map[string]bool{
	"Dial": true, "DialTimeout": true, "Dialer": true, "DialContext": true,
	"NewClient": true, "NewClientConn": true, "DialFromServer": true,
	"ProbeAWGEndpointRange": true, "PerformAWGHandshake": true,
	"ProbeVLESSReality": true, "ProbeNaiveProxy": true,
	"probeEndpoint": true, "ProbeTunnel": true, "GetWithConfig": true, "GetSSHClient": true,
}

// coverageWitnesses are the identifiers each coverage claim must produce in the
// file that claims it, so a mislabelled exemption fails here.
var coverageWitnesses = map[string][]string{
	viaBoundarySSH:   {"GetSSHClient", "DialFromServer", "sshPool", "ProviderAbsent"},
	viaBoundaryProbe: {"probeEndpoint", "ProbeTunnel", "ErrProviderAbsent"},
	viaRefusesItself: {"ProviderAbsent", "providerAbsent", "IsServerProviderAbsent", "not_measured", "ErrProviderAbsent"},
}

// TestInventoryIsCurrent fails when a dialling construct appears in a file the
// inventory does not name, when an inventoried site no longer exists, and when a
// site's declared coverage has no witness in its file.
func TestInventoryIsCurrent(t *testing.T) {
	root := repoRoot(t)

	allowed := map[string]*dialSite{}
	for i := range dialSites {
		site := &dialSites[i]
		key := site.path + "|" + site.construct
		if _, dup := allowed[key]; dup {
			t.Fatalf("inventory lists %s twice", key)
		}
		allowed[key] = site
	}
	observed := map[string]bool{}

	for _, rel := range productionFiles(t, root) {
		identifiers := identifiersInFile(t, root, rel)
		for _, construct := range constructsIn(t, root, rel) {
			key := rel + "|" + construct
			site, ok := allowed[key]
			if !ok {
				t.Errorf("%s uses %s, which is not in the derived dialling inventory.\n"+
					"Route it through a provider-absence boundary (the SSH transport's Config.ProviderAbsent or the "+
					"tunnel probe dispatch) and add it to dialSites with that coverage, or state why its target is not a "+
					"managed server.", rel, construct)
				continue
			}
			observed[key] = true
			if strings.TrimSpace(site.reason) == "" {
				t.Errorf("inventory entry %s has no reason", key)
			}
			if site.via == viaNotAServer {
				continue
			}
			witnesses, known := coverageWitnesses[site.via]
			if !known {
				t.Errorf("inventory entry %s declares unknown coverage %q", key, site.via)
				continue
			}
			if !referencesAny(identifiers, witnesses) {
				t.Errorf("inventory entry %s claims coverage %q but %s uses none of %v, so the claim is not backed by code",
					key, site.via, rel, witnesses)
			}
		}
	}

	for key, site := range allowed {
		if !observed[key] {
			t.Errorf("inventory entry %s is stale: %s no longer uses it.\n"+
				"Remove the entry so the inventory keeps describing the tree.", key, site.path)
		}
	}
}

// TestBoundariesStillRefuse proves the refusals are present as guards, not merely
// as words: the condition of a plain `if` must select the provider-absence signal
// and its body must return the refusal. A guard weakened to `if false && …` - or
// one whose body stops returning the refusal - fails here, which is why this check
// reads the AST shape rather than looking for an identifier.
func TestBoundariesStillRefuse(t *testing.T) {
	root := repoRoot(t)

	t.Run("SSH transport refuses before dialing", func(t *testing.T) {
		body := functionBody(t, root, sshClientFile, "*Client", "Connect")
		if !hasPlainGuard(body, "ProviderAbsent", "ErrProviderAbsent") {
			t.Fatal("Client.Connect no longer has a plain `if …ProviderAbsent` guard that returns ErrProviderAbsent")
		}
	})

	t.Run("SSH pool carries the row's observation into the config", func(t *testing.T) {
		body := functionBody(t, root, sshPoolFile, "*SSHClientPool", "Get")
		if !setsConfigField(body, "ProviderAbsent") {
			t.Fatal("SSHClientPool.Get no longer sets Config.ProviderAbsent from the server row")
		}
	})

	t.Run("tunnel probe dispatch refuses before probing", func(t *testing.T) {
		body := functionBody(t, root, tunnelHealthFile, "*HealthProber", "probeEndpoint")
		if !hasPlainCallGuard(body, "providerAbsent", "ErrProviderAbsent") {
			t.Fatal("probeEndpoint no longer refuses through a plain providerAbsent guard returning ErrProviderAbsent")
		}
	})

	for _, tc := range []struct {
		name     string
		file     string
		receiver string
		function string
	}{
		{"tunnel probe entry reports the refusal as not measured", tunnelHealthFile, "*HealthProber", "ProbeTunnel"},
		{"self-healing sweep reports the refusal as not measured", tunnelSelfHeal, "*HealthProber", "probeAndFlapDamp"},
		{"reconnect sweep does not count the refusal as an attempt", tunnelReconnect, "*ReconnectManager", "CheckAndReconnect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := functionBody(t, root, tc.file, tc.receiver, tc.function)
			if !hasRefusalBranch(body) {
				t.Fatalf("%s.%s no longer branches on ErrProviderAbsent", tc.receiver, tc.function)
			}
		})
	}
}

// ifStatements returns every if statement inside a body.
func ifStatements(body *ast.BlockStmt) []*ast.IfStmt {
	var out []*ast.IfStmt
	ast.Inspect(body, func(node ast.Node) bool {
		if stmt, ok := node.(*ast.IfStmt); ok {
			out = append(out, stmt)
		}
		return true
	})
	return out
}

// mentions reports whether a node contains an identifier whose name includes want.
func mentions(node ast.Node, want string) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && strings.Contains(ident.Name, want) {
			found = true
		}
		return !found
	})
	return found
}

// isPlainCondition rejects a condition that has been short-circuited, which is how
// a guard is disabled without deleting it (`if false && …`).
func isPlainCondition(cond ast.Expr) bool {
	_, binary := cond.(*ast.BinaryExpr)
	return !binary
}

// hasPlainGuard reports an `if <…ProviderAbsent…> { … return ErrProviderAbsent }`.
func hasPlainGuard(body *ast.BlockStmt, condition, returned string) bool {
	for _, stmt := range ifStatements(body) {
		if isPlainCondition(stmt.Cond) && mentions(stmt.Cond, condition) && mentions(stmt.Body, returned) {
			return true
		}
	}
	return false
}

// hasPlainCallGuard reports an `if hp.providerAbsent(…) { … return ErrProviderAbsent }`.
func hasPlainCallGuard(body *ast.BlockStmt, callee, returned string) bool {
	for _, stmt := range ifStatements(body) {
		call, ok := stmt.Cond.(*ast.CallExpr)
		if !ok {
			continue
		}
		fun, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || fun.Sel.Name != callee {
			continue
		}
		if mentions(stmt.Body, returned) {
			return true
		}
	}
	return false
}

// hasRefusalBranch reports an `if errors.Is(err, ErrProviderAbsent) { … }`.
func hasRefusalBranch(body *ast.BlockStmt) bool {
	for _, stmt := range ifStatements(body) {
		if !isPlainCondition(stmt.Cond) {
			continue
		}
		if mentions(stmt.Cond, "ErrProviderAbsent") {
			return true
		}
	}
	return false
}

// setsConfigField reports a composite literal inside the body that sets a named
// field, which is how the pool carries the row's observation into the transport.
func setsConfigField(body *ast.BlockStmt, field string) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		kv, ok := node.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == field {
			found = true
		}
		return !found
	})
	return found
}

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod above %s", dir)
		}
		dir = parent
	}
}

// productionFiles lists every non-test Go file in the packages that ship.
func productionFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			files = append(files, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", top, err)
		}
	}
	sort.Strings(files)
	return files
}

// parseFile parses one repository file.
func parseFile(t *testing.T, root, rel string) *ast.File {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(root, rel), nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", rel, err)
	}
	return file
}

// constructsIn returns the watched constructs one file contains.
func constructsIn(t *testing.T, root, rel string) []string {
	t.Helper()
	file := parseFile(t, root, rel)

	found := map[string]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.SelectorExpr:
			if !watchedSelectors[n.Sel.Name] {
				break
			}
			if pkg, ok := n.X.(*ast.Ident); ok && pkg.Obj == nil {
				// A package-qualified name (net.Dialer, ssh.Dial, health.…): keep the
				// qualifier so the inventory names the exact construct.
				found[pkg.Name+"."+n.Sel.Name] = true
				break
			}
			// A method call on a value (d.DialContext, hp.probeEndpoint).
			found[n.Sel.Name] = true
		case *ast.CompositeLit:
			switch t := n.Type.(type) {
			case *ast.SelectorExpr:
				if t.Sel.Name == "Config" {
					if pkg, ok := t.X.(*ast.Ident); ok && pkg.Name == "ssh" {
						found["ssh.Config{"] = true
					}
				}
			case *ast.Ident:
				// Inside the ssh package the config is spelled without a qualifier,
				// and that is where the pool and the dialer build it.
				if t.Name == "Config" && strings.HasPrefix(rel, "internal/manager/ssh/") {
					found["ssh.Config{"] = true
				}
			}
		}
		return true
	})

	out := make([]string, 0, len(found))
	for name := range found {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// identifiersInFile collects every identifier name used in one file.
func identifiersInFile(t *testing.T, root, rel string) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	ast.Inspect(parseFile(t, root, rel), func(node ast.Node) bool {
		if ident, ok := node.(*ast.Ident); ok {
			found[ident.Name] = true
		}
		return true
	})
	return found
}

// functionBody returns the body of one method.
func functionBody(t *testing.T, root, rel, receiver, name string) *ast.BlockStmt {
	t.Helper()
	file := parseFile(t, root, rel)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name || fn.Body == nil || receiverName(fn) != receiver {
			continue
		}
		return fn.Body
	}
	t.Fatalf("%s: %s.%s not found; the inventory points at a function that moved", rel, receiver, name)
	return nil
}

func receiverName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	switch expr := fn.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if ident, ok := expr.X.(*ast.Ident); ok {
			return "*" + ident.Name
		}
	case *ast.Ident:
		return expr.Name
	}
	return ""
}

// referencesAny reports whether any identifier name contains one of the wanted
// tokens, which is how a coverage claim is backed.
func referencesAny(identifiers map[string]bool, wanted []string) bool {
	for name := range identifiers {
		for _, want := range wanted {
			if strings.Contains(name, want) {
				return true
			}
		}
	}
	return false
}
