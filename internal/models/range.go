package models

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

// HeaderRange represents an AmneziaWG header parameter range [Lo, Hi] in the uint32 domain [0, MaxUint32].
// When Lo == Hi, it represents a degenerate range (a single value).
type HeaderRange struct {
	Lo uint32 `json:"lo"`
	Hi uint32 `json:"hi"`
}

// Uint32Range is an alias for HeaderRange for general uint32 range usage.
type Uint32Range = HeaderRange

// NewHeaderRange creates a new HeaderRange ensuring Lo <= Hi.
func NewHeaderRange(lo, hi uint32) HeaderRange {
	if hi < lo {
		lo, hi = hi, lo
	}
	return HeaderRange{Lo: lo, Hi: hi}
}

// DegenerateHeaderRange creates a new HeaderRange representing a single value (Lo == Hi).
func DegenerateHeaderRange(n uint32) HeaderRange {
	return HeaderRange{Lo: n, Hi: n}
}

// String returns "lo-hi" for true ranges, or "lo" for degenerate ranges.
func (r HeaderRange) String() string {
	if r.Lo == r.Hi {
		return strconv.FormatUint(uint64(r.Lo), 10)
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

// IsDegenerate returns true if the range represents a single value (Lo == Hi).
func (r HeaderRange) IsDegenerate() bool {
	return r.Lo == r.Hi
}

// IsZero returns true if the range is uninitialized (Lo == 0 && Hi == 0).
func (r HeaderRange) IsZero() bool {
	return r.Lo == 0 && r.Hi == 0
}

// Contains reports whether val falls within [Lo, Hi].
func (r HeaderRange) Contains(val uint32) bool {
	return r.Lo <= val && val <= r.Hi
}

// Overlap reports whether two ranges intersect.
func (r HeaderRange) Overlap(other HeaderRange) bool {
	return r.Lo <= other.Hi && other.Lo <= r.Hi
}

// PickOne selects a pseudo-random value within [Lo, Hi] using crypto/rand.
// If Lo == Hi, it returns Lo directly.
func (r HeaderRange) PickOne() uint32 {
	if r.Lo >= r.Hi {
		return r.Lo
	}
	// #nosec G115 -- r.Hi > r.Lo, so r.Hi - r.Lo + 1 is in [2, MaxUint32+1] which fits in int64
	diff := int64(r.Hi - r.Lo + 1)
	n, err := rand.Int(rand.Reader, big.NewInt(diff))
	if err != nil {
		return r.Lo
	}
	// #nosec G115 -- n.Uint64() is < diff <= MaxUint32+1, r.Lo + offset is <= r.Hi <= MaxUint32
	return r.Lo + uint32(n.Uint64())
}

// MarshalJSON marshals HeaderRange as a JSON string ("lo-hi" or "lo").
func (r HeaderRange) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

// UnmarshalJSON unmarshals a JSON bare number, a JSON string ("lo-hi" or "lo"),
// or a JSON object ({"lo": X, "hi": Y}) into HeaderRange.
// Rejects any values outside [0, math.MaxUint32].
func (r *HeaderRange) UnmarshalJSON(data []byte) error {
	s := strings.TrimSpace(string(data))
	if s == "" || s == "null" {
		*r = HeaderRange{}
		return nil
	}

	// 1. Quoted string: "100-140" or "125"
	if strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		parsed, err := ParseHeaderRange(str)
		if err != nil {
			return err
		}
		*r = parsed
		return nil
	}

	// 2. Bare integer or float number: 125 or 125.0
	// Upstream amneziawg-go parses header values as uint32. Anything outside [0, MaxUint32]
	// must be rejected, not silently wrapped.
	var n int64
	if err := json.Unmarshal(data, &n); err == nil {
		if n < 0 || n > math.MaxUint32 {
			return fmt.Errorf("header range value out of range: %d", n)
		}
		*r = HeaderRange{Lo: uint32(n), Hi: uint32(n)}
		return nil
	}
	var f float64
	if err := json.Unmarshal(data, &f); err == nil {
		if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > math.MaxUint32 {
			return fmt.Errorf("header range value out of range: %f", f)
		}
		*r = HeaderRange{Lo: uint32(f), Hi: uint32(f)}
		return nil
	}

	// 3. Object: {"lo": 100, "hi": 140}
	var obj struct {
		Lo int64 `json:"lo"`
		Hi int64 `json:"hi"`
	}
	if err := json.Unmarshal(data, &obj); err == nil && (obj.Lo != 0 || obj.Hi != 0) {
		if obj.Lo < 0 || obj.Lo > math.MaxUint32 || obj.Hi < 0 || obj.Hi > math.MaxUint32 {
			return fmt.Errorf("header range object bounds out of range: lo=%d, hi=%d", obj.Lo, obj.Hi)
		}
		if obj.Hi < obj.Lo {
			return fmt.Errorf("invalid header range object: hi (%d) < lo (%d)", obj.Hi, obj.Lo)
		}
		*r = HeaderRange{Lo: uint32(obj.Lo), Hi: uint32(obj.Hi)}
		return nil
	}

	// 4. Fallback: ParseHeaderRange on raw string
	parsed, err := ParseHeaderRange(s)
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

func parseStringHeaderRange(val string) (HeaderRange, error) {
	str := strings.TrimSpace(val)
	if str == "" {
		return HeaderRange{}, nil
	}
	str = strings.Trim(str, "\"")
	parts := strings.Split(str, "-")
	if len(parts) == 1 {
		part := strings.TrimSpace(parts[0])
		if part == "" {
			return HeaderRange{}, nil
		}
		num, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return HeaderRange{}, fmt.Errorf("invalid header range %q: %w", val, err)
		}
		return DegenerateHeaderRange(uint32(num)), nil
	} else if len(parts) == 2 {
		loStr := strings.TrimSpace(parts[0])
		hiStr := strings.TrimSpace(parts[1])
		lo, err := strconv.ParseUint(loStr, 10, 32)
		if err != nil {
			return HeaderRange{}, fmt.Errorf("invalid header range lo %q: %w", val, err)
		}
		hi, err := strconv.ParseUint(hiStr, 10, 32)
		if err != nil {
			return HeaderRange{}, fmt.Errorf("invalid header range hi %q: %w", val, err)
		}
		if hi < lo {
			return HeaderRange{}, fmt.Errorf("invalid header range %q: hi (%d) < lo (%d)", val, hi, lo)
		}
		return HeaderRange{Lo: uint32(lo), Hi: uint32(hi)}, nil
	}
	return HeaderRange{}, fmt.Errorf("invalid header range %q: too many hyphens", val)
}

func parseIntHeaderRange(val int64) (HeaderRange, error) {
	if val < 0 || val > math.MaxUint32 {
		return HeaderRange{}, fmt.Errorf("header range value out of range: %d", val)
	}
	return DegenerateHeaderRange(uint32(val)), nil
}

func parseUintHeaderRange(val uint64) (HeaderRange, error) {
	if val > math.MaxUint32 {
		return HeaderRange{}, fmt.Errorf("header range value out of range: %d", val)
	}
	return DegenerateHeaderRange(uint32(val)), nil
}

func parseFloatHeaderRange(val float64) (HeaderRange, error) {
	if math.IsNaN(val) || math.IsInf(val, 0) || val < 0 || val > math.MaxUint32 {
		return HeaderRange{}, fmt.Errorf("header range value out of range: %f", val)
	}
	return DegenerateHeaderRange(uint32(val)), nil
}

func parseNumericHeaderRange(v any) (HeaderRange, error) {
	switch val := v.(type) {
	case int:
		return parseIntHeaderRange(int64(val))
	case int32:
		return parseIntHeaderRange(int64(val))
	case int64:
		return parseIntHeaderRange(val)
	case uint:
		return parseUintHeaderRange(uint64(val))
	case uint32:
		return DegenerateHeaderRange(val), nil
	case uint64:
		return parseUintHeaderRange(val)
	case float64:
		return parseFloatHeaderRange(val)
	case float32:
		return parseFloatHeaderRange(float64(val))
	default:
		return HeaderRange{}, fmt.Errorf("unsupported type %T for header range", v)
	}
}

// ParseHeaderRange parses a HeaderRange from any supported type:
// string ("100-140" or "125"), int, int32, int64, uint, uint32, uint64, float32, float64, HeaderRange, *HeaderRange.
func ParseHeaderRange(v any) (HeaderRange, error) {
	if v == nil {
		return HeaderRange{}, nil
	}
	switch val := v.(type) {
	case HeaderRange:
		return val, nil
	case *HeaderRange:
		if val == nil {
			return HeaderRange{}, nil
		}
		return *val, nil
	case string:
		return parseStringHeaderRange(val)
	default:
		return parseNumericHeaderRange(v)
	}
}
