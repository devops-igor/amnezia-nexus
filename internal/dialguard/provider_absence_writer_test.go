package dialguard

// The class this issue kept reopening is "something concluded a server is gone
// without proof". Two rounds of repair moved that decision around; this guard pins
// where it may live, so a new writer cannot appear silently and cannot skip the
// gate:
//
//	the columns provider_absent_at / provider_absent_account_id
//	                                -  touched only by the store and its migration
//	  <- DB.SetServerProviderAbsence  -  called only by writeProviderAbsence, which
//	                                     records the account the listing was read from
//	    <- writeProviderAbsence       -  called only by writeDecidedRows
//	      <- writeDecidedRows         -  writes from the decision alone: the owner
//	                                     decided one complete listing is authoritative,
//	                                     so no count or pass-to-pass condition may gate it
//	        <- applyGigahostInventoryPresence (the only caller)
//	          <- ReconcileGigahostServerInventory (the only caller)
//
// The account-wide count is a diagnostic: it is read in one place and may not appear as
// a condition in the writer.

import (
	"encoding/json"
	"go/ast"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
		source := readSource(t, root, rel)
		for _, column := range []string{"provider_absent_at", "provider_absent_account_id"} {
			if strings.Contains(source, column) {
				t.Errorf("%s touches %s outside the store; the mark has one writer", rel, column)
			}
		}
	}

	// 3. The writer chain has no second route.
	assertOnlyCallers(t, root, "writeProviderAbsence", absenceInventoryFile+":writeDecidedRows")
	assertOnlyCallers(t, root, "writeDecidedRows", absenceInventoryFile+":applyGigahostInventoryPresence")
	assertOnlyCallers(t, root, "applyGigahostInventoryPresence", absenceInventoryFile+":ReconcileGigahostServerInventory")

	// 4. The writer records which account the listing was read from, and applies no
	//    count or pass-to-pass condition: the owner's decision makes one complete listing
	//    authoritative.
	body := functionBody(t, root, absenceInventoryFile, "*Handlers", "writeDecidedRows")
	if !mentions(body, "accountID") {
		t.Fatal("the writer no longer records the account the listing was read from")
	}
	for _, forbidden := range []string{"accountServers", "counted", "confirmed", "credible"} {
		if mentions(body, forbidden) {
			t.Fatalf("the writer gates on %s; the count is a diagnostic and one listing decides", forbidden)
		}
	}
	assertOnlyCallers(t, root, "writeProviderAbsence", absenceInventoryFile+":writeDecidedRows")

	// 5. The diagnostic count is read in one place and the decision path keeps no
	//    pass-to-pass state.
	assertOnlyCallers(t, root, "gigahostAccountServerCount", absenceInventoryFile+":gigahostInventoryAnswerFor")
	for _, rel := range productionFiles(t, root) {
		source := readSource(t, root, rel)
		for _, forbidden := range []string{"confirmRepeatedOmissions", "absenceCandidate", "absenceCandidates", "absenceMu", "listingCredible"} {
			if strings.Contains(source, forbidden) {
				t.Errorf("%s still carries %s; one complete listing decides and no pass-to-pass gate may return", rel, forbidden)
			}
		}
	}

	// 6. The certificate must not depend on a field the provider does not document for
	//    the credential the panel holds: the account payload's permissions object is
	//    admin-session-only, so no struct may map it and no symbol may model it.
	for _, rel := range []string{absenceInventoryFile,
		"internal/provider/gigahost/types.go",
		"internal/provider/gigahost/client.go",
		"internal/provider/gigahost/account_decode.go"} {
		file := parseFile(t, root, rel)
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.Field:
				if n.Tag == nil {
					break
				}
				tag, err := strconv.Unquote(n.Tag.Value)
				if err != nil {
					t.Fatalf("%s: unreadable struct tag %s", rel, n.Tag.Value)
				}
				if strings.Contains(tag, "permissions") {
					t.Errorf("%s maps a permissions field (%s), which the provider does not document for this credential", rel, tag)
				}
			case *ast.Ident:
				switch n.Name {
				case "AccountPermissions", "PermissionScope", "EnumeratesWholeAccount":
					t.Errorf("%s models the credential's scope with %s, which the provider does not document for this credential", rel, n.Name)
				}
			}
			return true
		})
	}
}

// readSource returns a file's source, honouring SSH_GUARD_OVERLAY exactly as parseFile
// does so a negative probe can show a text check failing without dirtying the tree.
func readSource(t *testing.T, root, rel string) string {
	t.Helper()
	path := filepath.Join(root, rel)
	if overlay := os.Getenv("SSH_GUARD_OVERLAY"); overlay != "" {
		var mapping struct{ Replace map[string]string }
		data, err := os.ReadFile(overlay)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &mapping); err != nil {
			t.Fatal(err)
		}
		if replacement, ok := mapping.Replace[path]; ok {
			path = replacement
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(raw)
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
