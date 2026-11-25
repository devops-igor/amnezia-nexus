package gigahost

// Provider server identifiers.
//
// A provider server id is an identity, not a number: the panel writes it into its own
// record (`protocols["provider_server_id"]`) and the reconciliation pass compares a
// stored row against it before it records or clears durable absence. A lossy conversion
// therefore does not merely lose precision, it silently names a DIFFERENT server that
// the panel then acts on.
//
// JSON numbers decode into `any` as float64 by default, and int64(501.5) is 501, so an
// unusable id can pass every later guard and reach a durable write. Nothing here coerces:
// every numeric token is kept as its exact source text (decodeJSONUseNumber) and parsed
// as an exact rational (big.Rat), which accepts only a whole, in-range value.
//
// Accepted shapes: a JSON integer literal, an exact decimal or exponent spelling of a
// whole number ("501.0", "5.01e2"), and a decimal string. Rejected: a fractional value,
// a non-numeric string, a fraction such as "4/2", a value outside int64, a boolean,
// an object or an array. A JSON null or an absent field names no server; the decoders
// leave that at zero and the callers' identity gates refuse a non-positive id.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

// decodeJSONUseNumber decodes one JSON value keeping every number as its exact source
// text, so no numeric identity is ever routed through a float64.
func decodeJSONUseNumber(data []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(target); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected trailing data after the JSON value")
	}
	return nil
}

// decodeProviderServerID reads one provider server id from a decoded JSON value.
func decodeProviderServerID(val any) (int64, error) {
	switch v := val.(type) {
	case nil:
		// An absent or null id names no server; the caller's identity gate refuses it.
		return 0, nil
	case json.Number:
		return exactServerID(v.String())
	case string:
		return exactServerID(strings.TrimSpace(v))
	case int:
		return int64(v), nil
	case int64:
		return v, nil
	case float64:
		// Reachable only from a programmatic value: JSON numbers arrive as json.Number.
		if v != math.Trunc(v) || math.IsInf(v, 0) || math.IsNaN(v) {
			return 0, fmt.Errorf("server id %v is not a whole number", v)
		}
		if v < math.MinInt64 || v > math.MaxInt64 {
			return 0, fmt.Errorf("server id %v is out of range", v)
		}
		return int64(v), nil
	default:
		return 0, fmt.Errorf("server id %v is not a number", val)
	}
}

// exactServerID parses the exact decimal text of a server id.
//
// big.Rat reads the text itself, so "501.5" cannot become 501 and a 19-digit id cannot be
// rounded; a value the provider spelled as a whole number in another form ("501.0",
// "5.01e2") is still the same identity and is accepted.
func exactServerID(text string) (int64, error) {
	if text == "" {
		return 0, errors.New("server id is empty")
	}
	// big.Rat also reads shapes a server id never uses on this API: "a/b" fractions and
	// hexadecimal spellings. Only a plain decimal may name a server, so anything outside
	// that alphabet is refused before parsing.
	for _, r := range text {
		if (r < '0' || r > '9') && r != '-' && r != '+' && r != '.' && r != 'e' && r != 'E' {
			return 0, fmt.Errorf("server id %q is not a number", text)
		}
	}
	value, ok := new(big.Rat).SetString(text)
	if !ok {
		return 0, fmt.Errorf("server id %q is not a number", text)
	}
	if !value.IsInt() {
		return 0, fmt.Errorf("server id %s is not a whole number", value.RatString())
	}
	if !value.Num().IsInt64() {
		return 0, fmt.Errorf("server id %s is out of range", text)
	}
	return value.Num().Int64(), nil
}

// decodeFirstServerID reads the first present provider server id among the documented
// aliases a payload may use for the same identity.
func decodeFirstServerID(values ...any) (int64, error) {
	for _, value := range values {
		if value == nil {
			continue
		}
		return decodeProviderServerID(value)
	}
	return 0, nil
}
