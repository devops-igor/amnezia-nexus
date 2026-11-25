package decodeguard

// Derived guard: every pass that can turn provider JSON into a durable identifier uses the
// lossless decoder.
//
// The defect this pins was a decode pass that used `json.Unmarshal` into an `any` field: the
// JSON number became a float64, the strict identity reader refused that dynamic type, and an
// accepted purchase was recorded as an unknown order. Nothing failed to compile and no test
// covered that shape, so the only thing that can catch the next such pass is a check on the
// code itself.
//
// The rule is stated on the SHAPE, not on a list of call sites: a struct field declared as
// `any` that also carries a `json` tag is a place where a decoded value keeps whatever type
// encoding/json chose, so any function that unmarshals into such a struct must use
// decodeJSONUseNumber instead of json.Unmarshal. Fields whose exact value is not an identity
// (a status that may be a bool or a string, an id that is only echoed) are declared exempt
// WITH a reason, and an exemption must match a real field so it cannot outlive its code.

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// losslessDecoder is the only decoder a pass that can carry an identity may use.
const losslessDecoder = "decodeJSONUseNumber"

// toleratedDecodeFunctions are named functions where a plain decode cannot lose an
// identity, each with the reason it was accepted.
//
// The exemption is per FUNCTION, never per file. A file-level exemption is exactly how the
// lossless requirement was lost once before: `client.go` was exempted on the rationale that
// it "only extracts a human-readable message", while the same file held the partial-order
// reader that feeds order identity into tracking. An exemption keyed on a function cannot
// cover a reader added beside it later, and every entry must still name a real function.
var toleratedDecodeFunctions = map[string]string{
	// Empty, deliberately. Every pass that can carry an identity now decodes losslessly, and
	// the readers that genuinely carry none decode into typed fields (an account identifier
	// has its own raw-token parser; catalog prices and statuses are strings and floats), so
	// they are not loose at all and need no exemption. The map stays because a future reader
	// may have a real reason, and an entry has to name a function that actually needs it.
}

// toleratedIdentityFields are `any`-typed JSON fields the guard does not require to be exact,
// each with the reason. A server id, an order id and a deployment's server id are NOT here:
// they are durable identities and must decode exactly.
var toleratedIdentityFields = map[string]string{
	"RegionID":       "a region label, never a durable row identity",
	"PID":            "a product label used for a request parameter",
	"OrderStatus":    "a status that arrives as a bool or a string",
	"SrvStatus":      "a status that arrives as a bool or a string",
	"BwIsHourly":     "a flag",
	"DedicatedOnly":  "a flag",
	"LimitedSupport": "a flag",
	"MinRAMGB":       "a capacity number, not an identifier",
	"Page":           "pagination metadata",
	"TotalPages":     "pagination metadata",
	"PerPage":        "pagination metadata",
	"Total":          "pagination metadata",
	"OSID":           "a catalog label used for a request parameter",
	"DCID":           "a datacenter label used as a request parameter; never a stored identity",
	"DistID":         "a catalog label used for a request parameter",
	"OrderIDs":       "a list of order identifiers: decoded losslessly by the order decoder, checked below",
}

func TestIdentityDecodePassesAreLossless(t *testing.T) {
	root := repositoryRoot(t)
	fset := token.NewFileSet()

	providerDir := filepath.Join(root, "internal/provider/gigahost")
	entries, err := os.ReadDir(providerDir)
	if err != nil {
		t.Fatalf("reading the provider package: %v", err)
	}

	type parsedFile struct {
		rel  string
		file *ast.File
	}
	var parsed []parsedFile
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		rel := "internal/provider/gigahost/" + entry.Name()
		file, parseErr := parser.ParseFile(fset, overlayPath(filepath.Join(providerDir, entry.Name())), nil, 0)
		if parseErr != nil {
			t.Fatalf("parsing %s: %v", rel, parseErr)
		}
		parsed = append(parsed, parsedFile{rel: rel, file: file})
	}
	if len(parsed) == 0 {
		t.Fatal("the guard scanned no provider files")
	}

	// Pass 1: which struct types are LOOSE, i.e. carry an untyped JSON field (including a
	// slice of untyped values) anywhere in their own definition, directly or through a nested
	// struct field. Two details make this guard able to see the real defect:
	//
	//   - transitivity: the payload carrying the identity was an inner struct while the
	//     unchecked decode targeted the outer envelope that embeds it, so a direct-field
	//     check reports nothing and passes for the wrong reason;
	//   - scope: these payload types are declared INSIDE functions and the name `envelope` is
	//     reused in many of them, so a bare-name key would make unrelated types inherit each
	//     other's looseness and report a decode that cannot lose an identity.
	type scopeKey struct {
		file string
		fn   string // enclosing function including its receiver, "" for a package-level type
		name string
	}

	declarations := map[scopeKey]*ast.StructType{}
	looseField := map[scopeKey]string{}
	seenFields := make(map[string]bool)
	nested := map[scopeKey][]string{}

	for _, pf := range parsed {
		var walkScope func(fn string, node ast.Node)
		walkScope = func(fn string, node ast.Node) {
			ast.Inspect(node, func(child ast.Node) bool {
				switch n := child.(type) {
				case *ast.FuncDecl:
					if n.Body != nil && fn == "" {
						walkScope(scopeName(n), n.Body)
					}
					return false
				case *ast.TypeSpec:
					structType, ok := n.Type.(*ast.StructType)
					if !ok {
						return true
					}
					key := scopeKey{file: pf.rel, fn: fn, name: n.Name.Name}
					declarations[key] = structType
					// Do not descend into the struct's own nested literals here; they are
					// anonymous and cannot be named by a field type.
					return false
				}
				return true
			})
		}
		walkScope("", pf.file)

		for key, structType := range declarations {
			if key.file != pf.rel {
				continue
			}
			for _, field := range structType.Fields.List {
				if len(field.Names) == 0 || field.Tag == nil {
					continue // embedded, or not a JSON field
				}
				fieldName := field.Names[0].Name
				if isUntypedJSONField(field.Type) {
					seenFields[fieldName] = true
					if _, tolerated := toleratedIdentityFields[fieldName]; !tolerated {
						if _, already := looseField[key]; !already {
							looseField[key] = fieldName
						}
					}
					continue
				}
				if valueType := typeName(derefType(field.Type)); valueType != "" {
					nested[key] = append(nested[key], valueType)
					continue
				}
				// An ANONYMOUS nested struct cannot be named by another type, so its untyped
				// fields must be folded in here or they are invisible to the whole check. Every
				// one of them is recorded as declared, so a tolerance entry for a field that
				// only appears here is still observed.
				for _, anonymousName := range anonymousUntypedFields(field.Type) {
					seenFields[anonymousName] = true
				}
				if offender := anonymousLooseField(field.Type); offender != "" {
					if _, already := looseField[key]; !already {
						looseField[key] = fieldName + ".<anonymous>." + offender
					}
				}
			}
		}
	}

	// Resolve a nested field type in the nearest scope: same function, then the same file's
	// package level, then any package-level declaration with that name.
	resolve := func(key scopeKey, typeNameWanted string) (scopeKey, bool) {
		candidates := []scopeKey{
			{file: key.file, fn: key.fn, name: typeNameWanted},
			{file: key.file, fn: "", name: typeNameWanted},
		}
		for _, candidate := range candidates {
			if _, ok := declarations[candidate]; ok {
				return candidate, true
			}
		}
		for other := range declarations {
			if other.fn == "" && other.name == typeNameWanted {
				return other, true
			}
		}
		return scopeKey{}, false
	}

	for changed := true; changed; {
		changed = false
		for key, fieldTypes := range nested {
			if _, already := looseField[key]; already {
				continue
			}
			for _, wanted := range fieldTypes {
				target, found := resolve(key, wanted)
				if !found {
					continue
				}
				if via, isLoose := looseField[target]; isLoose {
					looseField[key] = wanted + "." + via
					changed = true
					break
				}
			}
		}
	}

	seenFunctions := make(map[string]bool)

	// Pass 2: every decode into a loose struct must use the lossless decoder. The target is
	// usually a local VARIABLE (`&env`), so its declared type has to be resolved first: a
	// guard that only understands `&SomeType{}` misses the exact shape this defect used.
	for _, pf := range parsed {
		var plainDecodes []string
		fnName := ""
		var walkDecodes func(fn string, node ast.Node)
		walkDecodes = func(fn string, node ast.Node) {
			// Local variable types, so `&env` can be resolved to `envelope`.
			localTypes := map[string]string{}
			ast.Inspect(node, func(child ast.Node) bool {
				switch n := child.(type) {
				case *ast.ValueSpec:
					for i, nameIdent := range n.Names {
						if n.Type == nil {
							continue
						}
						localTypes[nameIdent.Name] = typeName(derefType(n.Type))
						_ = i
					}
				case *ast.AssignStmt:
					if n.Tok != token.DEFINE || len(n.Lhs) != len(n.Rhs) {
						return true
					}
					for i, lhs := range n.Lhs {
						nameIdent, ok := lhs.(*ast.Ident)
						if !ok {
							continue
						}
						if composite, ok := n.Rhs[i].(*ast.CompositeLit); ok {
							localTypes[nameIdent.Name] = typeName(composite.Type)
						}
					}
				}
				return true
			})

			ast.Inspect(node, func(child ast.Node) bool {
				if fnDecl, ok := child.(*ast.FuncDecl); ok {
					if fnDecl.Body != nil && fn == "" {
						fnName = scopeName(fnDecl)
						walkDecodes(fnName, fnDecl.Body)
						fnName = ""
					}
					return false
				}
				call, ok := child.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch calledName(call) {
				case "Unmarshal", "NewDecoder":
				default:
					return true
				}
				for _, arg := range call.Args {
					wanted := decodeTargetType(arg)
					if wanted == "" {
						continue
					}
					if declared, ok := localTypes[wanted]; ok && declared != "" {
						wanted = declared
					}
					target, found := resolve(scopeKey{file: pf.rel, fn: fn, name: wanted}, wanted)
					if !found {
						continue
					}
					if offends, isLoose := looseField[target]; isLoose {
						plainDecodes = append(plainDecodes, fmt.Sprintf("%s:%d decodes %s (loose via %s)",
							fnName, fset.Position(call.Pos()).Line, wanted, offends))
						break
					}
				}
				return true
			})
		}
		fnName = ""
		walkDecodes("", pf.file)

		for _, detail := range plainDecodes {
			// detail is "<function>:<line> decodes <type> ..."; the exemption key is
			// "<file>:<function>", so a reader added beside an exempt one is still caught.
			fnPart, _, _ := strings.Cut(detail, ":")
			key := path.Base(pf.rel) + ":" + fnPart
			if reason, tolerated := toleratedDecodeFunctions[key]; tolerated {
				if strings.TrimSpace(reason) == "" {
					t.Errorf("%s is tolerated without a reason", key)
				}
				seenFunctions[key] = true
				continue
			}
			t.Errorf("%s: %s without %s: a numeric identity there becomes a float64 instead of its exact value",
				pf.rel, detail, losslessDecoder)
		}
	}

	// The fields the rule exists for must still be seen, or a rename disarms the guard.
	for _, required := range []string{"ServerID", "OrderID", "SrvID", "ID"} {
		if !seenFields[required] {
			t.Errorf("watch field %s was not found; the guard's coverage is stale", required)
		}
	}

	// Every exemption must match a real function that still needs it.
	keys := make([]string, 0, len(toleratedDecodeFunctions))
	for key := range toleratedDecodeFunctions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !seenFunctions[key] {
			t.Errorf("exemption %q matches no loose decode and must be removed", key)
		}
	}
	for fieldName, reason := range toleratedIdentityFields {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("tolerated field %s has no reason", fieldName)
		}
		if !seenFields[fieldName] {
			t.Errorf("tolerated field %s is no longer declared and must be removed from the list", fieldName)
		}
	}
}

// decodeTargetType names the type a decode writes into, following the pointer and composite
// shapes the decoder is called with.
func decodeTargetType(arg ast.Expr) string {
	switch expr := arg.(type) {
	case *ast.UnaryExpr:
		return decodeTargetType(expr.X)
	case *ast.CompositeLit:
		return typeName(expr.Type)
	case *ast.Ident:
		return expr.Name
	}
	return ""
}

// derefType strips a pointer from a field type so a nested struct pointer still counts.
func derefType(expr ast.Expr) ast.Expr {
	if star, ok := expr.(*ast.StarExpr); ok {
		return star.X
	}
	return expr
}

// scopeName identifies a function uniquely enough for scope resolution: a method's receiver
// matters, because a payload type declared inside `(*A).UnmarshalJSON` cannot be the one
// declared inside `(*B).UnmarshalJSON`.
func scopeName(decl *ast.FuncDecl) string {
	if decl.Recv == nil || len(decl.Recv.List) == 0 {
		return decl.Name.Name
	}
	return receiverText(decl.Recv.List[0].Type) + "." + decl.Name.Name
}

func receiverText(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return receiverText(t.X)
	case *ast.Ident:
		return t.Name
	}
	return "?"
}

// anonymousUntypedFields lists every untyped JSON field name inside an anonymous struct,
// whether or not it is tolerated.
func anonymousUntypedFields(expr ast.Expr) []string {
	var names []string
	switch t := expr.(type) {
	case *ast.StarExpr:
		return anonymousUntypedFields(t.X)
	case *ast.ArrayType:
		return anonymousUntypedFields(t.Elt)
	case *ast.StructType:
		for _, field := range t.Fields.List {
			if len(field.Names) == 0 || field.Tag == nil {
				continue
			}
			if isUntypedJSONField(field.Type) {
				names = append(names, field.Names[0].Name)
				continue
			}
			names = append(names, anonymousUntypedFields(field.Type)...)
		}
	}
	return names
}

// anonymousLooseField returns the first untyped JSON field inside an anonymous struct
// (possibly behind a pointer or a slice), or "" when there is none.
func anonymousLooseField(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return anonymousLooseField(t.X)
	case *ast.ArrayType:
		return anonymousLooseField(t.Elt)
	case *ast.StructType:
		for _, field := range t.Fields.List {
			if len(field.Names) == 0 || field.Tag == nil {
				continue
			}
			if isUntypedJSONField(field.Type) {
				name := field.Names[0].Name
				// A tolerated field is tolerated wherever it is declared: two copies of one
				// rule would drift the moment a field moves between structs.
				if _, tolerated := toleratedIdentityFields[name]; tolerated {
					continue
				}
				return name
			}
			if nested := anonymousLooseField(field.Type); nested != "" {
				return nested
			}
		}
	}
	return ""
}

// isUntypedJSONField reports whether a field's type is `any` or `[]any`, the two shapes where
// a decoded value keeps whatever type encoding/json chose.
func isUntypedJSONField(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name == "any"
	case *ast.ArrayType:
		if ident, ok := t.Elt.(*ast.Ident); ok {
			return ident.Name == "any"
		}
	case *ast.MapType:
		return false
	}
	return false
}

func typeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return typeName(t.X)
	}
	return ""
}

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

// overlayPath applies the compiler overlay's replacement map so a negative probe reads the
// mutated bytes.
func overlayPath(path string) string {
	overlay := os.Getenv("DECODE_GUARD_OVERLAY")
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
