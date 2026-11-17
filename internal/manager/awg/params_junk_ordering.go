package awg

import (
	"fmt"
	"strconv"
)

// validateAWGParamRanges applies the numeric range checks followed by the
// junk-size ordering rule that the pinned upstream engine enforces.
func validateAWGParamRanges(params map[string]string) error {
	if err := validateNumericBounds(params); err != nil {
		return err
	}
	return validateJunkSizeOrdering(params)
}

// validateJunkSizeOrdering rejects an inverted junk-packet size pair. The
// pinned upstream engine (amneziawg-go v3.1.20261116) commits jc/jmin/jmax
// atomically and refuses jmin > jmax, so accepting the pair here would only
// fail later at awg-quick up inside the backend container. An absent side is
// the upstream default 0, which is what a freshly started device applies.
func validateJunkSizeOrdering(params map[string]string) error {
	minSize, err := junkSizeOrDefault(params, "junk_packet_min_size", "jmin")
	if err != nil {
		return err
	}
	maxSize, err := junkSizeOrDefault(params, "junk_packet_max_size", "jmax")
	if err != nil {
		return err
	}
	if minSize > maxSize {
		return fmt.Errorf("param junk_packet_min_size (%d) must not be greater than junk_packet_max_size (%d)", minSize, maxSize)
	}
	return nil
}

// junkSizeOrDefault parses one optional junk-size parameter, returning the
// upstream default 0 when the key is absent.
func junkSizeOrDefault(params map[string]string, keys ...string) (int, error) {
	val := getCaseInsensitiveParam(params, keys...)
	if val == "" {
		return 0, nil
	}
	size, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("param %s must be a numeric integer, got: %s", keys[0], val)
	}
	return size, nil
}
