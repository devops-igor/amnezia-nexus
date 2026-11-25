package gigahost

// Flexible field readers for the provider's variable JSON shapes.
//
// Several payload fields are documented as one type and observed as another (an order id as
// a string or a number, a flag as a bool or 0/1). These helpers read such a field from an
// `any` value. They are for fields whose exact value is not an identity: a provider SERVER
// ID goes through decodeProviderServerID instead, which never coerces.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func parseStringField(val any) string {
	if val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case int64:
		return strconv.FormatInt(v, 10)
	case int:
		return strconv.Itoa(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func parseInt64Field(val any) int64 {
	if val == nil {
		return 0
	}
	switch v := val.(type) {
	case json.Number:
		// Exact text; a non-integer spelling stays 0 rather than naming a rounded value.
		n, err := strconv.ParseInt(v.String(), 10, 64)
		if err != nil {
			return 0
		}
		return n
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	default:
		return 0
	}
}

func parseIntFieldStrict(val any) (int, bool) {
	if val == nil {
		return 0, false
	}
	switch v := val.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		if v != float64(int64(v)) {
			return 0, false
		}
		return int(v), true
	case json.Number:
		n, err := strconv.Atoi(v.String())
		if err != nil {
			return 0, false
		}
		return n, true
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return 0, false
		}
		n, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil {
			return 0, false
		}
		return int(n), true
	default:
		return 0, false
	}
}

func parseBoolFieldStrict(val any) (bool, bool) {
	if val == nil {
		return false, false
	}
	switch v := val.(type) {
	case bool:
		return v, true
	case json.Number:
		switch v.String() {
		case "1":
			return true, true
		case "0":
			return false, true
		}
		return false, false
	case int:
		if v == 1 {
			return true, true
		} else if v == 0 {
			return false, true
		}
		return false, false
	case int64:
		if v == 1 {
			return true, true
		} else if v == 0 {
			return false, true
		}
		return false, false
	case float64:
		if v == 1 {
			return true, true
		} else if v == 0 {
			return false, true
		}
		return false, false
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return false, false
		}
		b, err := strconv.ParseBool(trimmed)
		if err != nil {
			return false, false
		}
		return b, true
	default:
		return false, false
	}
}
