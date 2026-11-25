package dialguard

// The class this issue kept reopening is "something concluded a server is gone
// without proof". Two rounds of repair moved that decision around; this guard pins
// where it may live, so a new writer cannot appear silently and cannot skip the
// gate:
//
//	the column provider_absent_at   -  touched only by the store and its migration
//	  <- DB.SetServerProviderAbsence  -  called only by writeProviderAbsence
//	    <- writeProviderAbsence       -  called only by writeDecidedRows
//	      <- writeDecidedRows         -  writes absence only behind the
//	                                     account-wide certification
//	        <- applyGigahostInventoryPresence (the only caller)
//	          <- ReconcileGigahostServerInventory (the only caller)
//
// gigahostInventoryAccountWide is the single place that certifies the inventory
// answer, and it is called only from gigahostInventoryAnswerFor.

import (
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const absenceInventoryFile = "internal/handlers/gigahost_inventory.go"

func TestProviderAbsenceHasOneGatedWriter(t *testing.T) {
	root := repoRoot(t)

	// 1. The store method is the only way into the column, and the inventory writer is
	//    its only caller.
	want := absenceInventoryFile + ":writeProviderAbsence"
	var callers []string
	for _, rel := range productionFiles(t, root) {
		file := parseFile(t, root, rel)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if mentions(fn.Body, "SetServerProviderAbsence") {
				callers = append(callers, rel+":"+fn.Name.Name)
			}
		}
	}
	sort.Strings(callers)
	if len(callers) != 1 || callers[0] != want {
		t.Fatalf("absence-mark writers = %v, want exactly [%s]", callers, want)
	}

	// 2. Nothing outside the store may touch the column itself: no UPDATE, INSERT or
	//    raw literal can write the mark around the method.
	for _, rel := range productionFiles(t, root) {
		switch rel {
		case "internal/models/models.go", "internal/database/migrations.go", "internal/database/servers.go":
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if strings.Contains(string(raw), "provider_absent_at") {
			t.Errorf("%s touches the absence column outside the store; the mark has one writer", rel)
		}
	}

	// 3. The writer chain has no second route.
	assertOnlyCallers(t, root, "writeProviderAbsence", absenceInventoryFile+":writeDecidedRows")
	assertOnlyCallers(t, root, "writeDecidedRows", absenceInventoryFile+":applyGigahostInventoryPresence")
	assertOnlyCallers(t, root, "applyGigahostInventoryPresence", absenceInventoryFile+":ReconcileGigahostServerInventory")

	// 4. The absence direction is gated before it is written.
	body := functionBody(t, root, absenceInventoryFile, "*Handlers", "writeDecidedRows")
	gate, write := token.NoPos, token.NoPos
	ast.Inspect(body, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.IfStmt:
			if gate == token.NoPos && mentions(n.Cond, "accountWide") && branches(n.Body, token.CONTINUE) {
				gate = n.Pos()
			}
		case *ast.CallExpr:
			if write == token.NoPos && mentions(n.Fun, "writeProviderAbsence") {
				write = n.Pos()
			}
		}
		return true
	})
	if gate == token.NoPos {
		t.Fatal("the absence write is no longer gated by the account-wide certification")
	}
	if write == token.NoPos {
		t.Fatal("the pass no longer writes an observation at all")
	}
	if gate > write {
		t.Fatal("the pass writes the observation before checking the certification")
	}

	// 5. Certification is computed in exactly one place, from the inventory answer, and
	//    its authority input is read in exactly one place.
	assertOnlyCallers(t, root, "gigahostInventoryCertified", absenceInventoryFile+":gigahostInventoryAnswerFor")
	assertOnlyCallers(t, root, "gigahostCredentialScope", absenceInventoryFile+":gigahostInventoryAnswerFor")
	assertOnlyCallers(t, root, "EnumeratesWholeAccount", absenceInventoryFile+":gigahostCredentialScope")

	// 5b. The credential's scope is checked before the count corroboration: the summary
	//     read may only confirm an answer whose authority is already established.
	certify := functionBody(t, root, absenceInventoryFile, "*Handlers", "gigahostInventoryCertified")
	scope, summary := token.NoPos, token.NoPos
	ast.Inspect(certify, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.IfStmt:
			if scope == token.NoPos && mentions(n.Cond, "scopeStated") && returns(n.Body) {
				scope = n.Pos()
			}
		case *ast.CallExpr:
			if summary == token.NoPos && mentions(n.Fun, "GetDashboard") {
				summary = n.Pos()
			}
		}
		return true
	})
	if scope == token.NoPos {
		t.Fatal("the certificate no longer checks the credential's stated scope")
	}
	if summary == token.NoPos {
		t.Fatal("the certificate no longer corroborates with the account summary")
	}
	if scope > summary {
		t.Fatal("the certificate reads the account summary before the credential's scope")
	}

	// 6. A detail read may only ask about presence. Nothing in the decision path may
	//    classify a provider status as absence.
	for _, rel := range []string{absenceInventoryFile} {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(raw)
		for _, forbidden := range []string{"ErrNotFound", "StatusNotFound", "apiErr.StatusCode"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s interprets a provider status (%s); a detail read may only report presence", rel, forbidden)
			}
		}
	}
}

// returns reports whether the body exits, which is how a guard refuses.
func returns(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if _, ok := node.(*ast.ReturnStmt); ok {
			found = true
		}
		return !found
	})
	return found
}

// assertOnlyCallers fails unless symbol is invoked from exactly one function.
func assertOnlyCallers(t *testing.T, root, symbol, want string) {
	t.Helper()
	var callers []string
	for _, rel := range productionFiles(t, root) {
		file := parseFile(t, root, rel)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Name.Name == symbol {
				continue
			}
			if mentions(fn.Body, symbol) {
				callers = append(callers, rel+":"+fn.Name.Name)
			}
		}
	}
	sort.Strings(callers)
	if len(callers) != 1 || callers[0] != want {
		t.Fatalf("%s callers = %v, want exactly [%s]", symbol, callers, want)
	}
}
