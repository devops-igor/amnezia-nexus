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

	// 4. The absence direction is gated before it is written, by the confirmation a
	//    repeated omission produced.
	body := functionBody(t, root, absenceInventoryFile, "*Handlers", "writeDecidedRows")
	gate, write := token.NoPos, token.NoPos
	ast.Inspect(body, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.IfStmt:
			if gate == token.NoPos && (mentions(n.Cond, "confirmed") || (n.Init != nil && mentions(n.Init, "confirmed"))) && branches(n.Body, token.CONTINUE) {
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
		t.Fatal("the absence write is no longer gated by the repeated-omission confirmation")
	}
	if write == token.NoPos {
		t.Fatal("the pass no longer writes an observation at all")
	}
	if gate > write {
		t.Fatal("the pass writes the observation before checking the certification")
	}

	// 5. The pass-to-pass confirmation is computed in exactly one place, from the two
	//    counts a pass read, and the account-wide count in one place.
	assertOnlyCallers(t, root, "confirmRepeatedOmissions", absenceInventoryFile+":applyGigahostInventoryPresence")
	assertOnlyCallers(t, root, "gigahostAccountServerCount", absenceInventoryFile+":gigahostInventoryAnswerFor")

	// 6. The certificate must not depend on a field the provider does not document for
	//    the credential the panel holds: the account payload's permissions object is
	//    admin-session-only and must not be read here.
	for _, rel := range []string{absenceInventoryFile,
		"internal/provider/gigahost/types.go",
		"internal/provider/gigahost/client.go",
		"internal/provider/gigahost/account_decode.go"} {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for _, forbidden := range []string{"EnumeratesWholeAccount", "AccountPermissions", "PermissionScope", `"permissions"`} {
			if strings.Contains(string(raw), forbidden) {
				t.Errorf("%s reads %s, which the provider does not document for this credential", rel, forbidden)
			}
		}
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
