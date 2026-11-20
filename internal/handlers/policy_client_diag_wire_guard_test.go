package handlers

// The route cell's failure handling is a mapping from wire fields to visible
// markers, and it has been maintained by hand. Three reviews each found one more
// counter the renderer never read - `return.failed`, then
// `forward.backend_write_failed`, then `return.dropped` - so a refusal the server
// recorded stayed invisible until someone looked. This guard closes that pattern:
// the failure surface is derived from the wire types, not from a list kept here,
// and every field on it must be read by the code that decides whether a row is
// marked. A counter added to the wire and forgotten in the renderer fails this
// test and is named in the failure.
//
// What counts as the renderer handling a field, and why the match is narrow:
//
//   - only the bodies of the functions that decide failure visibility are
//     searched - the markers, the detail builder and the predicates they use.
//     A field named elsewhere in a 1000-line controller proves nothing about
//     whether a refusal reaches the table.
//   - comments are removed before the search. Several of those functions describe
//     the wire in prose ("dropped: queue full, rate limited ..."), so a
//     comment-blind match would pass for a field the code never reads - the exact
//     false confidence this guard exists to remove.
//   - the field must be read by its JSON name: a quoted literal such as
//     'backend_write_failed' (how the counters are read) or a property access such
//     as .failure (how the strings are read). Prose, an identifier that merely
//     contains the word, or a name appearing in another function does not count.
//
// The companion test below feeds the same collector and the same check a structure
// with one extra failure-bearing field and requires the guard to name it, so a
// guard that silently matched everything cannot pass.

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/devops-igor/amnezia-nexus/web"
)

// wireFailureStructures are the flow-record structures the route cell decides on.
// A new producer that records refusals is added here, and its failure-bearing
// fields are then guarded without touching the collector.
func wireFailureStructures() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(vpn.ClientDiagnosisFlowDispatch{}),
		reflect.TypeOf(vpn.ClientDiagnosisFlowForward{}),
		reflect.TypeOf(vpn.ClientDiagnosisFlowReturn{}),
	}
}

// failureNameVocabulary is what gives a JSON name a failure meaning: a counter of
// refused, failed or dropped packets, or the reason/failure string that records
// why. It is a rule about names, not a list of fields, so a counter this build has
// not seen yet is still collected.
var failureNameVocabulary = []string{"fail", "drop", "refus", "reject", "reason"}

// failurePathFunctions are the controller functions that decide whether a route
// cell is marked and what its tooltip says. Only their bodies are searched.
var failurePathFunctions = []string{
	"appendFlowRoute",
	"dispatchState",
	"dispatchFailed",
	"routeFailureMarkers",
	"returnRefused",
	"routeFailureDetail",
	"appendFailureLabel",
	"recordedCount",
}

// wireFailureField is one field the guard expects the renderer to handle.
type wireFailureField struct {
	Structure string // e.g. "ClientDiagnosisFlowForward"
	Field     string // e.g. "BackendWriteFailed"
	JSONName  string // e.g. "backend_write_failed"
}

func (f wireFailureField) String() string {
	return f.Structure + "." + f.Field + ` (json:"` + f.JSONName + `")`
}

// collectFailureFields derives the failure surface from the wire types: every
// exported field with a JSON tag whose name carries a failure meaning, in
// declaration order.
func collectFailureFields(types ...reflect.Type) []wireFailureField {
	var fields []wireFailureField
	for _, typ := range types {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := jsonFieldName(field)
			if name == "" || !hasFailureMeaning(name) {
				continue
			}
			fields = append(fields, wireFailureField{
				Structure: typ.Name(),
				Field:     field.Name,
				JSONName:  name,
			})
		}
	}
	return fields
}

// jsonFieldName is the name the answer actually carries for a struct field.
func jsonFieldName(field reflect.StructField) string {
	tag := field.Tag.Get("json")
	if tag == "" || tag == "-" {
		return ""
	}
	name, _, _ := strings.Cut(tag, ",")
	return strings.TrimSpace(name)
}

// hasFailureMeaning reports whether a JSON name says the answer refused, failed,
// dropped or rejected something, or records why it did.
func hasFailureMeaning(name string) bool {
	lower := strings.ToLower(name)
	for _, word := range failureNameVocabulary {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

// controllerFailurePath is the executable text of the failure path, comments
// removed, so a field named only in prose cannot satisfy the guard.
func controllerFailurePath(t *testing.T) string {
	t.Helper()
	raw, err := web.StaticFS.ReadFile("static/js/policy_client_diag.js")
	if err != nil {
		t.Fatalf("read the controller: %v", err)
	}
	code := stripJSComments(string(raw))
	var path strings.Builder
	for _, name := range failurePathFunctions {
		body, ok := jsFunctionBody(code, name)
		if !ok {
			t.Fatalf("the controller no longer defines %s(); the guard cannot tell what the failure path is", name)
		}
		path.WriteString(body)
		path.WriteString("\n")
	}
	return path.String()
}

// unhandledFailureFields is the guard itself: the fields of the surface that the
// failure path never reads by their JSON name.
func unhandledFailureFields(path string, fields []wireFailureField) []string {
	var unhandled []string
	for _, field := range fields {
		if !referencesJSONName(path, field.JSONName) {
			unhandled = append(unhandled, field.String())
		}
	}
	return unhandled
}

// failureGuardMessage is the message the guard reports, so the companion test can
// show the exact text a forgotten field would produce.
func failureGuardMessage(unhandled []string) string {
	return "wire failure field(s) the route cell never reads, so the refusal they carry would be " +
		"invisible in the table: " + strings.Join(unhandled, "; ")
}

// referencesJSONName reports whether the failure path reads a wire field by its
// JSON name. Both forms the controller uses count - a quoted literal for a counter
// ('dropped') and a property access for a string (.failure) - and nothing else
// does.
func referencesJSONName(code, name string) bool {
	if strings.Contains(code, "'"+name+"'") || strings.Contains(code, `"`+name+`"`) {
		return true
	}
	property := regexp.MustCompile(`\.` + regexp.QuoteMeta(name) + `\b`)
	return property.MatchString(code)
}

// TestPolicyClientDiagWireFailureFieldsAreRendered is the guard: every
// failure-bearing field of the flow record types must be read by the code that
// decides failure visibility.
func TestPolicyClientDiagWireFailureFieldsAreRendered(t *testing.T) {
	types := wireFailureStructures()
	fields := collectFailureFields(types...)

	// An empty or one-sided surface would make the guard vacuous, so pin that it
	// covers all three producers and is large enough to be the real surface.
	if len(fields) < 6 {
		t.Fatalf("collected only %d failure-bearing wire fields (%v); the collection rule is wrong, not the renderer", len(fields), fields)
	}
	seen := map[string]bool{}
	for _, field := range fields {
		seen[field.Structure] = true
	}
	for _, typ := range types {
		if !seen[typ.Name()] {
			t.Fatalf("%s contributes no collected failure field; the vocabulary or the struct tags changed", typ.Name())
		}
	}

	t.Logf("collected failure surface (%d fields): %s", len(fields), joinFields(fields))
	t.Logf("non-failure fields the same path reads, for contrast: %s", strings.Join(nonFailureFieldsReadByPath(t, types, fields), ", "))

	path := controllerFailurePath(t)
	if unhandled := unhandledFailureFields(path, fields); len(unhandled) > 0 {
		t.Fatalf("%s", failureGuardMessage(unhandled))
	}
}

// TestPolicyClientDiagWireFailureGuardNoticesANewCounter proves the guard is not
// vacuous. The wire type is untouched: a copy is declared here with one extra
// failure-bearing field, and the same collector and check must name exactly that
// field.
func TestPolicyClientDiagWireFailureGuardNoticesANewCounter(t *testing.T) {
	// A shape the producer does not emit today: the same return record plus a new
	// refusal counter that no renderer code has ever seen.
	type returnWithUnhandledCounter struct {
		Dropped      uint64 `json:"dropped"`
		Failed       uint64 `json:"failed"`
		Failure      string `json:"failure,omitempty"`
		RefusedByQoS uint64 `json:"refused_by_qos"`
	}

	fields := collectFailureFields(reflect.TypeOf(returnWithUnhandledCounter{}))
	if len(fields) != 4 {
		t.Fatalf("collected %d fields from the control structure, want its four failure-bearing ones (%v)", len(fields), fields)
	}
	unhandled := unhandledFailureFields(controllerFailurePath(t), fields)
	t.Logf("control: %d of %d fields unhandled: %s", len(unhandled), len(fields), failureGuardMessage(unhandled))

	if len(unhandled) != 1 {
		t.Fatalf("the guard must flag exactly the one unread counter, flagged %d: %v", len(unhandled), unhandled)
	}
	if !strings.Contains(unhandled[0], `refused_by_qos`) || !strings.Contains(unhandled[0], "RefusedByQoS") {
		t.Fatalf("the guard must name the unread counter and its field, got %q", unhandled[0])
	}
}

// nonFailureFieldsReadByPath reports the fields the same code reads that carry no
// failure meaning, so a reader can see the guard is not counting every field.
func nonFailureFieldsReadByPath(t *testing.T, types []reflect.Type, failureFields []wireFailureField) []string {
	t.Helper()
	path := controllerFailurePath(t)
	guarded := map[string]bool{}
	for _, field := range failureFields {
		guarded[field.JSONName] = true
	}
	var names []string
	for _, typ := range types {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := jsonFieldName(field)
			if name == "" || guarded[name] || !referencesJSONName(path, name) {
				continue
			}
			names = append(names, typ.Name()+"."+field.Name+` (json:"`+name+`")`)
		}
	}
	return names
}

func joinFields(fields []wireFailureField) string {
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		parts = append(parts, field.String())
	}
	return strings.Join(parts, ", ")
}

// stripJSComments removes // and /* */ comments while keeping string literals
// intact, so prose about the wire can never satisfy a reference check.
func stripJSComments(src string) string {
	const (
		normal = iota
		lineComment
		blockComment
		singleQuote
		doubleQuote
		backtick
	)
	state := normal
	var out strings.Builder
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch state {
		case normal:
			switch {
			case c == '/' && i+1 < len(src) && src[i+1] == '/':
				state = lineComment
				i++
			case c == '/' && i+1 < len(src) && src[i+1] == '*':
				state = blockComment
				i++
			case c == '\'':
				state = singleQuote
				out.WriteByte(c)
			case c == '"':
				state = doubleQuote
				out.WriteByte(c)
			case c == '`':
				state = backtick
				out.WriteByte(c)
			default:
				out.WriteByte(c)
			}
		case lineComment:
			if c == '\n' {
				state = normal
				out.WriteByte(c)
			}
		case blockComment:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				state = normal
				i++
			}
		default:
			out.WriteByte(c)
			if c == '\\' && i+1 < len(src) {
				out.WriteByte(src[i+1])
				i++
				continue
			}
			if (state == singleQuote && c == '\'') || (state == doubleQuote && c == '"') || (state == backtick && c == '`') {
				state = normal
			}
		}
	}
	return out.String()
}

// jsFunctionBody returns the body of one function from comment-free source, using
// brace matching that skips string literals, so a brace inside a string cannot
// end the extraction early.
func jsFunctionBody(code, name string) (string, bool) {
	marker := "function " + name + "("
	start := strings.Index(code, marker)
	if start < 0 {
		return "", false
	}
	open := strings.IndexByte(code[start:], '{')
	if open < 0 {
		return "", false
	}
	open += start
	depth := 0
	var inString byte
	for i := open; i < len(code); i++ {
		c := code[i]
		if inString != 0 {
			if c == '\\' {
				i++
				continue
			}
			if c == inString {
				inString = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			inString = c
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return code[open : i+1], true
			}
		}
	}
	return "", false
}
