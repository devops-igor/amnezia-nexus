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
	"go/token"
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

	// 2. Nothing outside the store may WRITE the column: no UPDATE or INSERT and no raw
	//    literal can set the mark around the method.
	//
	//    READING it elsewhere is allowed and is a different fact: a destination predicate has
	//    to consult the mark as part of a statement that decides whether a write may happen
	//    (see the durable session-move writers). Banning the name outright would forbid exactly
	//    the fence those writers need, so the rule is stated on assignment and tested as such.
	for _, rel := range productionFiles(t, root) {
		switch rel {
		case "internal/models/models.go", "internal/database/migrations.go", "internal/database/servers.go":
			continue
		}
		source := readSource(t, root, rel)
		for _, column := range []string{"provider_absent_at", "provider_absent_account_id"} {
			if writesColumn(source, column) {
				t.Errorf("%s assigns %s outside the store; the mark has one writer", rel, column)
			}
		}
	}

	// 2b. A read of the mark outside the store must be a predicate on a write, not a free
	//     lookup: the only permitted shape is the destination fence in the session-move
	//     writers, and it must appear in a NOT EXISTS/EXISTS clause rather than a bare select
	//     used to make a decision in Go and then write separately.
	for _, rel := range productionFiles(t, root) {
		if rel != "internal/database/vpn.go" {
			continue
		}
		source := readSource(t, root, rel)
		if !strings.Contains(source, "providerAbsentDestinationPredicate") {
			t.Errorf("%s reads the absence column without the shared destination predicate", rel)
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
	// The writer may skip a row only when it has no measurement at all. Any second skip is
	// a condition on acting - a pass counter, a count, a confirmation - which the owner's
	// decision removed.
	skips := 0
	for _, stmt := range ifStatements(body) {
		if branches(stmt.Body, token.CONTINUE) {
			skips++
		}
	}
	if skips != 1 {
		t.Fatalf("the writer has %d skip conditions, want exactly 1 (the unmeasured row)", skips)
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

// writesColumn reports whether source ASSIGNS the column, as opposed to merely reading it.
// The shapes counted are the ones that could set the mark: an UPDATE ... SET, an INSERT column
// list that names it, or an explicit assignment to the model field.
func writesColumn(source, column string) bool {
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, column) {
			continue
		}
		lower := strings.ToLower(trimmed)
		switch {
		case strings.Contains(lower, "set ") && strings.Contains(lower, column):
			return true
		case strings.Contains(lower, "insert into servers") && strings.Contains(lower, column):
			return true
		case strings.Contains(trimmed, "ProviderAbsentAt =") || strings.Contains(trimmed, "ProviderAbsentAccountID ="):
			return true
		}
	}
	return false
}
