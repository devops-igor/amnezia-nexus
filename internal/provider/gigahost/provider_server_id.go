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
//
// It is decodeExactInteger at an identity site: the name says what the value identifies, so
// a reader can tell a site that must be exact from a site that tolerates a string.
func decodeProviderServerID(val any) (int64, error) {
	return decodeExactInteger(val)
}

// decodeExactInteger reads a whole identifier from a decoded JSON value without coercing it.
//
// Every caller that turns provider JSON into a durable identifier uses this: a server id, an
// order id. The distinction that matters is not what the number means but that it must not
// silently change, so there is one implementation and no second convention.
func decodeExactInteger(val any) (int64, error) {
	switch v := val.(type) {
	case nil:
		// An absent or null id names no server; the caller's identity gate refuses it.
		return 0, nil
	case json.Number:
		return exactServerID(v.String())
	case string:
		return exactServerID(strings.TrimSpace(v))
	default:
		// Includes the plain Go numeric types: every value here comes from decoded JSON,
		// where a number is a json.Number, so anything else is not an identity.
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
	body, negative, err := stripServerIDSign(text)
	if err != nil {
		return "", 0, false, err
	}
	mantissa, exponent, err := splitServerIDExponent(text, body)
	if err != nil {
		return "", 0, false, err
	}
	digits, fractionLength, err := joinServerIDDigits(text, mantissa)
	if err != nil {
		return "", 0, false, err
	}
	return digits, exponent - fractionLength, negative, nil
}

// stripServerIDSign removes an optional sign.
func stripServerIDSign(text string) (string, bool, error) {
	switch text[0] {
	case '-':
		if len(text) == 1 {
			return "", false, fmt.Errorf("server id %q is not a number", text)
		}
		return text[1:], true, nil
	case '+':
		if len(text) == 1 {
			return "", false, fmt.Errorf("server id %q is not a number", text)
		}
		return text[1:], false, nil
	}
	return text, false, nil
}

// splitServerIDExponent separates a bounded decimal exponent from the mantissa.
func splitServerIDExponent(text, body string) (string, int, error) {
	index := strings.IndexAny(body, "eE")
	if index < 0 {
		return body, 0, nil
	}
	exponent, err := strconv.Atoi(body[index+1:])
	if err != nil || exponent < -maxProviderServerIDExponent || exponent > maxProviderServerIDExponent {
		return "", 0, fmt.Errorf("server id %s has an unusable exponent", text)
	}
	return body[:index], exponent, nil
}

// joinServerIDDigits concatenates the integer and fractional digits, reporting how many of
// them are fractional so the caller can place the decimal point exactly.
func joinServerIDDigits(text, mantissa string) (string, int, error) {
	integerPart, fractionPart := mantissa, ""
	if dot := strings.IndexByte(mantissa, '.'); dot >= 0 {
		integerPart, fractionPart = mantissa[:dot], mantissa[dot+1:]
		if fractionPart == "" {
			return "", 0, fmt.Errorf("server id %q is not a number", text)
		}
	}
	digits := integerPart + fractionPart
	if digits == "" || !isASCIIDigits(digits) {
		return "", 0, fmt.Errorf("server id %q is not a number", text)
	}
	return digits, len(fractionPart), nil
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
