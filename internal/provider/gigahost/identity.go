package gigahost

// Account identifiers as the provider sends them.
//
// The provider documents `cust_id` as a JSON number on GET /account
// (https://docs.gigahost.no/api/account shows `"cust_id": 12345`) and sends the
// same identifier as text inside /servers entries (`"cust_id":"19998"`). Both
// shapes name one account, so both must decode to one opaque value; treating a
// documented shape as "no account" would silently disable every consumer.
//
// The value is kept verbatim as text. It names an account, it cannot
// authenticate anything, and nothing does arithmetic on it.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Identity is an account identifier that decodes from a JSON string or a JSON
// integer without losing a digit.
type Identity string

// UnmarshalJSON accepts the documented string and numeric shapes, and null.
func (i *Identity) UnmarshalJSON(data []byte) error {
	parsed, ok := parseIdentity(data)
	if !ok {
		return fmt.Errorf("invalid account identifier %s", strings.TrimSpace(string(data)))
	}
	*i = Identity(parsed)
	return nil
}

// String returns the identifier as text.
func (i Identity) String() string { return string(i) }

// parseIdentity reads a raw JSON token as an account identifier: a quoted string,
// an integer literal, or null (which names no account).
//
// The integer path works on the raw bytes rather than on a float64, so a large id
// cannot be rounded into a different account.
func parseIdentity(data []byte) (string, bool) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		return "", true
	}
	if trimmed[0] == '"' {
		var text string
		if err := json.Unmarshal(data, &text); err != nil {
			return "", false
		}
		return strings.TrimSpace(text), true
	}
	if _, err := strconv.ParseInt(trimmed, 10, 64); err != nil {
		return "", false
	}
	return trimmed, true
}
