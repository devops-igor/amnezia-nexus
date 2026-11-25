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
	"strconv"
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

// maxProviderServerIDTextLength bounds the text a server id may occupy: int64 needs at
// most 19 digits, and a decimal or exponent spelling adds a few characters.
const maxProviderServerIDTextLength = 32

// maxProviderServerIDExponent bounds the exponent an id may carry, so a token such as
// "1e999999999" is refused instead of being expanded into a huge digit string.
const maxProviderServerIDExponent = 40

// exactServerID parses the exact decimal text of a server id.
//
// The value is computed from the digits themselves - never through a float - so "501.5"
// cannot become 501 and a 19-digit id cannot be rounded. A whole number spelled in another
// form ("501.0", "5.01e2") is the same identity and is accepted; anything else is refused.
func exactServerID(text string) (int64, error) {
	if text == "" {
		return 0, errors.New("server id is empty")
	}
	if len(text) > maxProviderServerIDTextLength {
		return 0, errors.New("server id is too long to be an identifier")
	}
	digits, exponent, negative, err := splitServerIDText(text)
	if err != nil {
		return 0, err
	}
	scaled, err := scaleServerIDDigits(digits, exponent)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseInt(scaled, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("server id %s is out of range", text)
	}
	if negative {
		value = -value
	}
	return value, nil
}

// splitServerIDText separates a decimal spelling into its digits, exponent and sign, and
// refuses anything that is not that shape.
func splitServerIDText(text string) (digits string, exponent int, negative bool, err error) {
	body := text
	switch body[0] {
	case '-':
		negative = true
		body = body[1:]
	case '+':
		body = body[1:]
	}
	if body == "" {
		return "", 0, false, fmt.Errorf("server id %q is not a number", text)
	}

	if index := strings.IndexAny(body, "eE"); index >= 0 {
		exponentText := body[index+1:]
		body = body[:index]
		if exponentText == "" {
			return "", 0, false, fmt.Errorf("server id %q is not a number", text)
		}
		parsed, convErr := strconv.Atoi(exponentText)
		if convErr != nil || parsed < -maxProviderServerIDExponent || parsed > maxProviderServerIDExponent {
			return "", 0, false, fmt.Errorf("server id %s has an unusable exponent", text)
		}
		exponent = parsed
	}

	integerPart, fractionPart := body, ""
	if dot := strings.IndexByte(body, '.'); dot >= 0 {
		integerPart, fractionPart = body[:dot], body[dot+1:]
		if fractionPart == "" {
			return "", 0, false, fmt.Errorf("server id %q is not a number", text)
		}
	}
	digits = integerPart + fractionPart
	if digits == "" || !isASCIIDigits(digits) {
		return "", 0, false, fmt.Errorf("server id %q is not a number", text)
	}
	return digits, exponent - len(fractionPart), negative, nil
}

// scaleServerIDDigits applies a decimal exponent to a digit string, refusing a value whose
// fractional digits are not zeros: those are exactly the ids that cannot be represented
// without changing which server they name.
func scaleServerIDDigits(digits string, exponent int) (string, error) {
	switch {
	case exponent < 0:
		drop := -exponent
		if drop >= len(digits) {
			if strings.Trim(digits, "0") != "" {
				return "", fmt.Errorf("server id %s is not a whole number", digits)
			}
			return "0", nil
		}
		if strings.Trim(digits[len(digits)-drop:], "0") != "" {
			return "", fmt.Errorf("server id %s is not a whole number", digits)
		}
		digits = digits[:len(digits)-drop]
	case exponent > 0:
		digits += strings.Repeat("0", exponent)
	}
	trimmed := strings.TrimLeft(digits, "0")
	if trimmed == "" {
		return "0", nil
	}
	return trimmed, nil
}

// isASCIIDigits reports whether every byte is a decimal digit.
func isASCIIDigits(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return false
		}
	}
	return true
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
