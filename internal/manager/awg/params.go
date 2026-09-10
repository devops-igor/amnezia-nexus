package awg

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/cps"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"golang.org/x/crypto/curve25519"
)

// AWGDefaults holds standard default values for AmneziaWG protocol parameters.
var AWGDefaults = map[string]string{
	"port":                          "55424",
	"mtu":                           "1280",
	"subnet_address":                "10.8.1.0",
	"subnet_cidr":                   "24",
	"subnet_ip":                     "10.8.1.1",
	"dns1":                          "94.140.14.14",
	"dns2":                          "94.140.15.15",
	"junk_packet_count":             "3",
	"junk_packet_min_size":          "10",
	"junk_packet_max_size":          "30",
	"init_packet_junk_size":         "15",
	"response_packet_junk_size":     "18",
	"cookie_reply_packet_junk_size": "20",
	"transport_packet_junk_size":    "23",
	"init_packet_magic_header":      "1020325451",
	"response_packet_magic_header":  "3288052141",
	"transport_packet_magic_header": "2528465083",
	"underload_packet_magic_header": "1766607858",
}

// AWGParams encapsulates all parameters for server and client config generation.
//
//nolint:revive
type AWGParams struct {
	Port                       string `json:"port"`
	MTU                        string `json:"mtu"`
	SubnetAddress              string `json:"subnet_address"`
	SubnetCIDR                 string `json:"subnet_cidr"`
	SubnetIP                   string `json:"subnet_ip"`
	DNS1                       string `json:"dns1"`
	DNS2                       string `json:"dns2"`
	JunkPacketCount            string `json:"junk_packet_count"`
	JunkPacketMinSize          string `json:"junk_packet_min_size"`
	JunkPacketMaxSize          string `json:"junk_packet_max_size"`
	InitPacketJunkSize         string `json:"init_packet_junk_size"`
	ResponsePacketJunkSize     string `json:"response_packet_junk_size"`
	CookieReplyPacketJunkSize  string `json:"cookie_reply_packet_junk_size"`
	TransportPacketJunkSize    string `json:"transport_packet_junk_size"`
	InitPacketMagicHeader      string `json:"init_packet_magic_header"`
	ResponsePacketMagicHeader  string `json:"response_packet_magic_header"`
	UnderloadPacketMagicHeader string `json:"underload_packet_magic_header"`
	TransportPacketMagicHeader string `json:"transport_packet_magic_header"`
	I1                         string `json:"i1,omitempty"`
	I2                         string `json:"i2,omitempty"`
	I3                         string `json:"i3,omitempty"`
	I4                         string `json:"i4,omitempty"`
	I5                         string `json:"i5,omitempty"`
	HeaderProtectionKey        string `json:"header_protection_key,omitempty"`
}

// ToMap converts AWGParams to a map of string key-values.
func (p *AWGParams) ToMap() map[string]string {
	m := map[string]string{
		"port":                          p.Port,
		"mtu":                           p.MTU,
		"subnet_address":                p.SubnetAddress,
		"subnet_cidr":                   p.SubnetCIDR,
		"subnet_ip":                     p.SubnetIP,
		"dns1":                          p.DNS1,
		"dns2":                          p.DNS2,
		"junk_packet_count":             p.JunkPacketCount,
		"junk_packet_min_size":          p.JunkPacketMinSize,
		"junk_packet_max_size":          p.JunkPacketMaxSize,
		"init_packet_junk_size":         p.InitPacketJunkSize,
		"response_packet_junk_size":     p.ResponsePacketJunkSize,
		"cookie_reply_packet_junk_size": p.CookieReplyPacketJunkSize,
		"transport_packet_junk_size":    p.TransportPacketJunkSize,
		"init_packet_magic_header":      p.InitPacketMagicHeader,
		"response_packet_magic_header":  p.ResponsePacketMagicHeader,
		"underload_packet_magic_header": p.UnderloadPacketMagicHeader,
		"transport_packet_magic_header": p.TransportPacketMagicHeader,
		"i1":                            p.I1,
		"i2":                            p.I2,
		"i3":                            p.I3,
		"i4":                            p.I4,
		"i5":                            p.I5,
	}
	if p.HeaderProtectionKey != "" {
		m["header_protection_key"] = p.HeaderProtectionKey
	}
	return m
}

// AWGParamsFromMap populates AWGParams from a generic map.
//
//nolint:revive
func AWGParamsFromMap(m map[string]any) *AWGParams {
	p := &AWGParams{
		Port:                       AWGDefaults["port"],
		MTU:                        AWGDefaults["mtu"],
		SubnetAddress:              AWGDefaults["subnet_address"],
		SubnetCIDR:                 AWGDefaults["subnet_cidr"],
		SubnetIP:                   AWGDefaults["subnet_ip"],
		DNS1:                       AWGDefaults["dns1"],
		DNS2:                       AWGDefaults["dns2"],
		JunkPacketCount:            AWGDefaults["junk_packet_count"],
		JunkPacketMinSize:          AWGDefaults["junk_packet_min_size"],
		JunkPacketMaxSize:          AWGDefaults["junk_packet_max_size"],
		InitPacketJunkSize:         AWGDefaults["init_packet_junk_size"],
		ResponsePacketJunkSize:     AWGDefaults["response_packet_junk_size"],
		CookieReplyPacketJunkSize:  AWGDefaults["cookie_reply_packet_junk_size"],
		TransportPacketJunkSize:    AWGDefaults["transport_packet_junk_size"],
		InitPacketMagicHeader:      AWGDefaults["init_packet_magic_header"],
		ResponsePacketMagicHeader:  AWGDefaults["response_packet_magic_header"],
		UnderloadPacketMagicHeader: AWGDefaults["underload_packet_magic_header"],
		TransportPacketMagicHeader: AWGDefaults["transport_packet_magic_header"],
	}

	for k, v := range m {
		strVal := fmt.Sprint(v)
		switch strings.ToLower(k) {
		case "port", "listenport":
			p.Port = strVal
		case "mtu":
			p.MTU = strVal
		case "subnet_address":
			p.SubnetAddress = strVal
		case "subnet_cidr":
			p.SubnetCIDR = strVal
		case "subnet_ip":
			p.SubnetIP = strVal
		case "dns1":
			p.DNS1 = strVal
		case "dns2":
			p.DNS2 = strVal
		case "junk_packet_count", "jc":
			p.JunkPacketCount = strVal
		case "junk_packet_min_size", "jmin":
			p.JunkPacketMinSize = strVal
		case "junk_packet_max_size", "jmax":
			p.JunkPacketMaxSize = strVal
		case "init_packet_junk_size", "s1":
			p.InitPacketJunkSize = strVal
		case "response_packet_junk_size", "s2":
			p.ResponsePacketJunkSize = strVal
		case "cookie_reply_packet_junk_size", "s3":
			p.CookieReplyPacketJunkSize = strVal
		case "transport_packet_junk_size", "s4":
			p.TransportPacketJunkSize = strVal
		case "init_packet_magic_header", "h1":
			p.InitPacketMagicHeader = strVal
		case "response_packet_magic_header", "h2":
			p.ResponsePacketMagicHeader = strVal
		case "underload_packet_magic_header", "h3":
			p.UnderloadPacketMagicHeader = strVal
		case "transport_packet_magic_header", "h4":
			p.TransportPacketMagicHeader = strVal
		case "i1":
			p.I1 = strVal
		case "i2":
			p.I2 = strVal
		case "i3":
			p.I3 = strVal
		case "i4":
			p.I4 = strVal
		case "i5":
			p.I5 = strVal
		}
	}
	return p
}

// GenerateWGKeypair generates a Curve25519 keypair formatted as base64 strings.
func GenerateWGKeypair() (privateKeyBase64, publicKeyBase64 string, err error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return "", "", fmt.Errorf("failed to generate random private key: %w", err)
	}

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive public key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}

// GeneratePSK generates a 32-byte cryptographically secure preshared key as base64 string.
func GeneratePSK() (string, error) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		return "", fmt.Errorf("failed to generate random psk: %w", err)
	}
	return base64.StdEncoding.EncodeToString(psk), nil
}

func randIntBetween(min, max int) (int, error) {
	if min > max {
		min, max = max, min
	}
	diff := max - min + 1
	n, err := rand.Int(rand.Reader, big.NewInt(int64(diff)))
	if err != nil {
		return 0, err
	}
	return min + int(n.Int64()), nil
}

func randUint32Between(min, max uint32) (uint32, error) {
	if min > max {
		min, max = max, min
	}
	// #nosec G115
	diff := int64(max - min + 1)
	n, err := rand.Int(rand.Reader, big.NewInt(diff))
	if err != nil {
		return 0, err
	}
	// #nosec G115
	return min + uint32(n.Uint64()), nil
}

// HeaderRange is an alias for models.HeaderRange.
type HeaderRange = models.HeaderRange

// Uint32Range is an alias for models.Uint32Range.
type Uint32Range = models.Uint32Range

var (
	// NewHeaderRange is an alias for models.NewHeaderRange.
	NewHeaderRange = models.NewHeaderRange
	// DegenerateHeaderRange is an alias for models.DegenerateHeaderRange.
	DegenerateHeaderRange = models.DegenerateHeaderRange
	// ParseHeaderRange is an alias for models.ParseHeaderRange.
	ParseHeaderRange = models.ParseHeaderRange
)

const (
	maxQuadrantVal uint32 = math.MaxInt32      // 2147483647
	quadrantSize   uint32 = maxQuadrantVal / 4 // 536870911
)

// QuadrantBounds returns the [lo, hi] bounds for the 0-indexed quadrant (0 to 3).
func QuadrantBounds(q int) (lo, hi uint32) {
	switch q {
	case 0:
		return 5, quadrantSize
	case 1:
		return 5 + quadrantSize, 2 * quadrantSize
	case 2:
		return 5 + 2*quadrantSize, 3 * quadrantSize
	case 3:
		return 5 + 3*quadrantSize, maxQuadrantVal
	default:
		return 0, 0
	}
}

// GenerateQuadrantHeader generates a HeaderRange strictly within quadrant q (0 to 3) with span >= 1000.
func GenerateQuadrantHeader(q int) (HeaderRange, error) {
	qLo, qHi := QuadrantBounds(q)
	a, err := randUint32Between(qLo, qHi-1000)
	if err != nil {
		return HeaderRange{}, err
	}
	maxSpan := uint32(50000)
	if qHi-a < maxSpan {
		maxSpan = qHi - a
	}
	span, err := randUint32Between(1000, maxSpan)
	if err != nil {
		return HeaderRange{}, err
	}
	return NewHeaderRange(a, a+span), nil
}

// GenerateQuadrantHeaders generates H1-H4 across non-overlapping quadrants of [5, 2^31 - 1] with min span >= 1000.
func GenerateQuadrantHeaders() (h1, h2, h3, h4 HeaderRange, err error) {
	h1, err = GenerateQuadrantHeader(0)
	if err != nil {
		return HeaderRange{}, HeaderRange{}, HeaderRange{}, HeaderRange{}, err
	}
	h2, err = GenerateQuadrantHeader(1)
	if err != nil {
		return HeaderRange{}, HeaderRange{}, HeaderRange{}, HeaderRange{}, err
	}
	h3, err = GenerateQuadrantHeader(2)
	if err != nil {
		return HeaderRange{}, HeaderRange{}, HeaderRange{}, HeaderRange{}, err
	}
	h4, err = GenerateQuadrantHeader(3)
	if err != nil {
		return HeaderRange{}, HeaderRange{}, HeaderRange{}, HeaderRange{}, err
	}
	return h1, h2, h3, h4, nil
}

// ValidateQuadrantDisjointness verifies that all non-zero header ranges are mutually disjoint.
func ValidateQuadrantDisjointness(h1, h2, h3, h4 HeaderRange) error {
	headers := []struct {
		name string
		rng  HeaderRange
	}{
		{"H1", h1},
		{"H2", h2},
		{"H3", h3},
		{"H4", h4},
	}
	for i := 0; i < len(headers); i++ {
		if headers[i].rng.IsZero() {
			continue
		}
		for j := i + 1; j < len(headers); j++ {
			if headers[j].rng.IsZero() {
				continue
			}
			if headers[i].rng.Overlap(headers[j].rng) {
				return fmt.Errorf("header ranges %s (%s) and %s (%s) overlap",
					headers[i].name, headers[i].rng.String(),
					headers[j].name, headers[j].rng.String())
			}
		}
	}
	return nil
}

// AdjustGeneratedHeaderToAvoid adjusts newly generated range *gen to ensure it does not
// overlap with any of the existing ranges, without mutating any of the existing ranges.
func AdjustGeneratedHeaderToAvoid(gen *HeaderRange, existing ...HeaderRange) {
	if gen == nil || gen.IsZero() {
		return
	}
	for _, ext := range existing {
		if ext.IsZero() || !gen.Overlap(ext) {
			continue
		}
		// If gen overlaps ext:
		// Attempt shifting gen above ext.Hi if possible within uint32 domain
		if uint64(ext.Hi)+1001 <= uint64(math.MaxUint32) {
			newLo := ext.Hi + 1
			span := gen.Hi - gen.Lo
			if span < 1000 {
				span = 1000
			}
			if uint64(newLo)+uint64(span) <= uint64(math.MaxUint32) {
				gen.Lo = newLo
				gen.Hi = newLo + span
				continue
			}
		}
		// Otherwise attempt shifting gen below ext.Lo
		if ext.Lo > 1001 {
			newHi := ext.Lo - 1
			span := gen.Hi - gen.Lo
			if span < 1000 {
				span = 1000
			}
			if newHi >= span+5 {
				gen.Hi = newHi
				gen.Lo = newHi - span
			}
		}
	}
}

// NeedsHeaderUpgrade reports whether hr is uninitialized, degenerate (Lo == Hi), or has span < 1000.
func NeedsHeaderUpgrade(hr HeaderRange) bool {
	return hr.IsZero() || hr.IsDegenerate() || (hr.Hi-hr.Lo < 1000)
}

// ExpandDegenerateHeader expands a degenerate header value hr (or sub-1000 range)
// within its quadrant q (0..3) to a range [lo, hi] with span >= 1000 such that
// lo <= hr.Lo <= hr.Hi <= hi.
// If hr is zero, or if hr does not fall entirely within QuadrantBounds(q), an error is returned.
func ExpandDegenerateHeader(hr HeaderRange, q int) (HeaderRange, error) {
	if hr.IsZero() {
		return HeaderRange{}, errors.New("cannot expand zero header range")
	}
	qLo, qHi := QuadrantBounds(q)
	if hr.Lo < qLo || hr.Hi > qHi {
		return HeaderRange{}, fmt.Errorf("header %s outside quadrant %d [%d, %d]", hr.String(), q, qLo, qHi)
	}

	// If already a valid range with span >= 1000 within the quadrant, return as-is.
	if !hr.IsDegenerate() && hr.Hi-hr.Lo >= 1000 {
		return hr, nil
	}

	maxSpan := uint32(50000)
	if qHi-qLo < maxSpan {
		maxSpan = qHi - qLo
	}
	span, err := randUint32Between(1000, maxSpan)
	if err != nil {
		return HeaderRange{}, err
	}

	// We require:
	// 1. lo <= hr.Lo
	// 2. hr.Hi <= lo + span (i.e. lo >= hr.Hi - span)
	// 3. qLo <= lo
	// 4. lo + span <= qHi (i.e. lo <= qHi - span)
	minLo := qLo
	if hr.Hi > span && hr.Hi-span > minLo {
		minLo = hr.Hi - span
	}
	maxLo := hr.Lo
	if qHi-span < maxLo {
		maxLo = qHi - span
	}

	if minLo > maxLo {
		if hr.Lo+span <= qHi {
			return NewHeaderRange(hr.Lo, hr.Lo+span), nil
		}
		if hr.Hi >= span && hr.Hi-span >= qLo {
			return NewHeaderRange(hr.Hi-span, hr.Hi), nil
		}
		return HeaderRange{}, fmt.Errorf("unable to fit span %d around %s in quadrant %d", span, hr.String(), q)
	}

	lo, err := randUint32Between(minLo, maxLo)
	if err != nil {
		return HeaderRange{}, err
	}
	hi := lo + span
	return NewHeaderRange(lo, hi), nil
}

// UpgradeDegenerateHeaders checks if any of h1..h4 are degenerate or sub-1000 ranges,
// and upgrades them to ranges with span >= 1000 in their respective quadrants [0..3].
// If possible, each degenerate header is expanded in place within its quadrant so that
// the original value is contained in the new range (preserving backward compatibility
// for clients configured with the legacy single value).
// If any header cannot be safely expanded within its quadrant without overlap,
// fresh non-overlapping quadrant ranges are generated via GenerateQuadrantHeaders().
// Returns the resulting ranges, a boolean indicating whether any headers were changed, and any error.
func UpgradeDegenerateHeaders(h1, h2, h3, h4 HeaderRange) (HeaderRange, HeaderRange, HeaderRange, HeaderRange, bool, error) {
	if !NeedsHeaderUpgrade(h1) && !NeedsHeaderUpgrade(h2) && !NeedsHeaderUpgrade(h3) && !NeedsHeaderUpgrade(h4) {
		if err := ValidateQuadrantDisjointness(h1, h2, h3, h4); err == nil {
			return h1, h2, h3, h4, false, nil
		}
	}

	headers := []HeaderRange{h1, h2, h3, h4}
	newHeaders := make([]HeaderRange, 4)
	canExpandAll := true

	for q := 0; q < 4; q++ {
		hr := headers[q]
		if hr.IsZero() {
			gen, err := GenerateQuadrantHeader(q)
			if err != nil {
				canExpandAll = false
				break
			}
			newHeaders[q] = gen
		} else {
			expanded, err := ExpandDegenerateHeader(hr, q)
			if err != nil {
				canExpandAll = false
				break
			}
			newHeaders[q] = expanded
		}
	}

	if canExpandAll {
		if err := ValidateQuadrantDisjointness(newHeaders[0], newHeaders[1], newHeaders[2], newHeaders[3]); err == nil {
			return newHeaders[0], newHeaders[1], newHeaders[2], newHeaders[3], true, nil
		}
	}

	// Fallback: generate fresh non-overlapping quadrant ranges.
	genH1, genH2, genH3, genH4, err := GenerateQuadrantHeaders()
	if err != nil {
		return HeaderRange{}, HeaderRange{}, HeaderRange{}, HeaderRange{}, false, err
	}
	return genH1, genH2, genH3, genH4, true, nil
}

// GenerateStandardObfuscationValues generates standard-profile obfuscation parameters:
// H1-H4 across non-overlapping quadrants, and standard-profile S1-S4 satisfying |s1 - s2| >= 10.
func GenerateStandardObfuscationValues() (h1, h2, h3, h4 HeaderRange, s1, s2, s3, s4 int, err error) {
	h1, h2, h3, h4, err = GenerateQuadrantHeaders()
	if err != nil {
		return HeaderRange{}, HeaderRange{}, HeaderRange{}, HeaderRange{}, 0, 0, 0, 0, err
	}

	s1, err = randIntBetween(30, 80)
	if err != nil {
		return HeaderRange{}, HeaderRange{}, HeaderRange{}, HeaderRange{}, 0, 0, 0, 0, err
	}
	s2, err = randIntBetween(30, 80)
	if err != nil {
		return HeaderRange{}, HeaderRange{}, HeaderRange{}, HeaderRange{}, 0, 0, 0, 0, err
	}
	s3, err = randIntBetween(15, 32)
	if err != nil {
		return HeaderRange{}, HeaderRange{}, HeaderRange{}, HeaderRange{}, 0, 0, 0, 0, err
	}
	s4, err = randIntBetween(12, 24)
	if err != nil {
		return HeaderRange{}, HeaderRange{}, HeaderRange{}, HeaderRange{}, 0, 0, 0, 0, err
	}

	for attempts := 0; attempts < 100; attempts++ {
		diff := s1 - s2
		if diff < 0 {
			diff = -diff
		}
		if diff >= 10 {
			break
		}
		s2, _ = randIntBetween(30, 80)
	}
	diff := s1 - s2
	if diff < 0 {
		diff = -diff
	}
	if diff < 10 {
		if s1+10 <= 150 {
			s2 = s1 + 10
		} else {
			s2 = s1 - 10
		}
	}

	// Ensure S1, S2, S3, S4 >= 12 unconditionally to satisfy the upstream AmneziaWG header protection floor constraint.
	if s1 < 12 {
		s1 = 12
	}
	if s2 < 12 {
		s2 = 12
	}
	if s3 < 12 {
		s3 = 12
	}
	if s4 < 12 {
		s4 = 12
	}

	return h1, h2, h3, h4, s1, s2, s3, s4, nil
}

// AWGParamsFromVPNConfig converts stored models.VPNConfig parameters into *AWGParams.
//
//nolint:revive
func AWGParamsFromVPNConfig(cfg *models.VPNConfig) *AWGParams {
	p := AWGParamsFromMap(nil)
	if cfg == nil {
		return p
	}

	if !cfg.H1.IsZero() {
		p.InitPacketMagicHeader = cfg.H1.String()
	}
	if !cfg.H2.IsZero() {
		p.ResponsePacketMagicHeader = cfg.H2.String()
	}
	if !cfg.H3.IsZero() {
		p.UnderloadPacketMagicHeader = cfg.H3.String()
	}
	if !cfg.H4.IsZero() {
		p.TransportPacketMagicHeader = cfg.H4.String()
	}
	if cfg.S1 > 0 {
		p.InitPacketJunkSize = strconv.Itoa(cfg.S1)
	}
	if cfg.S2 > 0 {
		p.ResponsePacketJunkSize = strconv.Itoa(cfg.S2)
	}
	if cfg.S3 > 0 {
		p.CookieReplyPacketJunkSize = strconv.Itoa(cfg.S3)
	}
	if cfg.S4 > 0 {
		p.TransportPacketJunkSize = strconv.Itoa(cfg.S4)
	}

	if cfg.HeaderProtectionKey != "" {
		p.HeaderProtectionKey = cfg.HeaderProtectionKey
		ensureMinJunk := func(valStr *string, minVal int) {
			num, err := strconv.Atoi(*valStr)
			if err != nil || num < minVal {
				*valStr = strconv.Itoa(minVal)
			}
		}
		ensureMinJunk(&p.InitPacketJunkSize, 12)
		ensureMinJunk(&p.ResponsePacketJunkSize, 12)
		ensureMinJunk(&p.CookieReplyPacketJunkSize, 12)
		ensureMinJunk(&p.TransportPacketJunkSize, 12)
	}

	// Note: Pure AWG 3+ parameters (H1..H4, S1..S4, Jc, Jmin, Jmax) are used for Load Balancer.
	// CPS mimicry packets (I1..I5) are NOT used in LB mode because the Go noise endpoint
	// expects standard AWG 3+ initiation headers and does not implement CPS packet framing.
	return p
}

// GenerateAWGParams generates randomized AWG obfuscation parameters based on the given profile.
func GenerateAWGParams(profile string, headerProtection bool) (*AWGParams, error) {
	profile = strings.ToLower(strings.TrimSpace(profile))
	if profile == "" {
		profile = "standard"
	}

	var jc, jmin, jmax, s1, s2, s3, s4 int
	var err error

	switch profile {
	case "lite":
		jc, _ = randIntBetween(3, 5)
		jmin, _ = randIntBetween(5, 15)
		jmaxAddon, _ := randIntBetween(45, 55)
		jmax = jmin + jmaxAddon
		s1, _ = randIntBetween(97, 107)
		s2, _ = randIntBetween(17, 27)
		s3, _ = randIntBetween(16, 26)
		s4, _ = randIntBetween(4, 10)

	case "pro":
		jc, _ = randIntBetween(4, 16)
		jmin, _ = randIntBetween(50, 256)
		jmaxAddon, _ := randIntBetween(300, 1000)
		jmax = jmin + jmaxAddon
		s1, _ = randIntBetween(15, 150)
		s2, _ = randIntBetween(15, 150)
		s3, _ = randIntBetween(8, 64)
		s4, _ = randIntBetween(6, 31)

	default: // "standard"
		jc, _ = randIntBetween(5, 8)
		jmin, _ = randIntBetween(30, 80)
		jmaxAddon, _ := randIntBetween(100, 250)
		jmax = jmin + jmaxAddon
		s1, _ = randIntBetween(30, 80)
		s2, _ = randIntBetween(30, 80)
		s3, _ = randIntBetween(15, 32)
		s4, _ = randIntBetween(10, 20)
	}

	// Enforce |s1 - s2| >= 10 constraint
	for attempts := 0; attempts < 100; attempts++ {
		diff := s1 - s2
		if diff < 0 {
			diff = -diff
		}
		if diff >= 10 {
			break
		}
		switch profile {
		case "lite":
			s2, _ = randIntBetween(17, 27)
		case "pro":
			s2, _ = randIntBetween(15, 150)
		default:
			s2, _ = randIntBetween(30, 80)
		}
	}
	diff := s1 - s2
	if diff < 0 {
		diff = -diff
	}
	if diff < 10 {
		if s1+10 <= 150 {
			s2 = s1 + 10
		} else {
			s2 = s1 - 10
		}
	}

	h1, h2, h3, h4, err := GenerateQuadrantHeaders()
	if err != nil {
		return nil, err
	}

	mtu := "1280"
	if profile == "pro" {
		mtu = "1320"
	}

	cpsPackets, err := cps.GenerateCPSPackets(profile, "")
	if err != nil {
		return nil, err
	}

	params := &AWGParams{
		Port:                       AWGDefaults["port"],
		MTU:                        mtu,
		SubnetAddress:              AWGDefaults["subnet_address"],
		SubnetCIDR:                 AWGDefaults["subnet_cidr"],
		SubnetIP:                   AWGDefaults["subnet_ip"],
		DNS1:                       AWGDefaults["dns1"],
		DNS2:                       AWGDefaults["dns2"],
		JunkPacketCount:            strconv.Itoa(jc),
		JunkPacketMinSize:          strconv.Itoa(jmin),
		JunkPacketMaxSize:          strconv.Itoa(jmax),
		InitPacketJunkSize:         strconv.Itoa(s1),
		ResponsePacketJunkSize:     strconv.Itoa(s2),
		CookieReplyPacketJunkSize:  strconv.Itoa(s3),
		TransportPacketJunkSize:    strconv.Itoa(s4),
		InitPacketMagicHeader:      h1.String(),
		ResponsePacketMagicHeader:  h2.String(),
		UnderloadPacketMagicHeader: h3.String(),
		TransportPacketMagicHeader: h4.String(),
		I1:                         cpsPackets["i1"],
		I2:                         cpsPackets["i2"],
		I3:                         cpsPackets["i3"],
		I4:                         cpsPackets["i4"],
		I5:                         cpsPackets["i5"],
	}

	return params, nil
}

// TimingRange represents an AmneziaWG timing parameter range [Lo, Hi].
// When Lo == Hi, it represents a degenerate range (a single value).
type TimingRange struct {
	Lo int `json:"lo"`
	Hi int `json:"hi"`
}

// NewTimingRange creates a new TimingRange ensuring Lo <= Hi.
func NewTimingRange(lo, hi int) *TimingRange {
	if hi < lo {
		lo, hi = hi, lo
	}
	return &TimingRange{Lo: lo, Hi: hi}
}

// DegenerateTimingRange creates a new TimingRange representing a single value (Lo == Hi).
func DegenerateTimingRange(n int) *TimingRange {
	return &TimingRange{Lo: n, Hi: n}
}

// String returns "lo-hi" for true ranges, or "lo" for degenerate ranges.
func (r *TimingRange) String() string {
	if r == nil {
		return ""
	}
	if r.Lo == r.Hi {
		return strconv.Itoa(r.Lo)
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

// IsDegenerate returns true if the range represents a single value (Lo == Hi).
func (r *TimingRange) IsDegenerate() bool {
	if r == nil {
		return false
	}
	return r.Lo == r.Hi
}

// MarshalJSON marshals TimingRange as a JSON string ("lo-hi" or "lo").
func (r TimingRange) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

// UnmarshalJSON unmarshals a JSON number (bare int), a JSON string ("lo-hi" or "lo"),
// or a JSON object ({"lo": X, "hi": Y}) into TimingRange.
func (r *TimingRange) UnmarshalJSON(data []byte) error {
	s := strings.TrimSpace(string(data))
	if s == "" || s == "null" {
		return nil
	}

	// 1. Quoted string: "100-140" or "125"
	if strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		parsed, err := ParseTimingRange(str)
		if err != nil {
			return err
		}
		if parsed != nil {
			*r = *parsed
		}
		return nil
	}

	// 2. Bare integer or float number: 125 or 125.0
	// Upstream amneziawg-go parses timing values as uint32 (device/noise-types.go
	// FromString -> strconv.ParseUint(..., 32)), so anything outside [0, MaxUint32]
	// can never be consumed downstream and must be rejected here, not silently
	// wrapped by an int() conversion (e.g. float64 1e300 -> math.MinInt).
	var n int64
	if err := json.Unmarshal(data, &n); err == nil {
		if n < 0 || n > math.MaxUint32 {
			return fmt.Errorf("timing range value out of range: %d", n)
		}
		*r = TimingRange{Lo: int(n), Hi: int(n)}
		return nil
	}
	var f float64
	if err := json.Unmarshal(data, &f); err == nil {
		if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > math.MaxUint32 {
			return fmt.Errorf("timing range value out of range: %f", f)
		}
		*r = TimingRange{Lo: int(f), Hi: int(f)}
		return nil
	}

	// 3. Object: {"lo": 100, "hi": 140}
	var obj struct {
		Lo int `json:"lo"`
		Hi int `json:"hi"`
	}
	if err := json.Unmarshal(data, &obj); err == nil && (obj.Lo != 0 || obj.Hi != 0) {
		if obj.Hi < obj.Lo {
			obj.Lo, obj.Hi = obj.Hi, obj.Lo
		}
		*r = TimingRange{Lo: obj.Lo, Hi: obj.Hi}
		return nil
	}

	// 4. Fallback: ParseTimingRange on raw string
	parsed, err := ParseTimingRange(s)
	if err != nil {
		return err
	}
	if parsed != nil {
		*r = *parsed
	}
	return nil
}

func parseNumericTimingRange(v any) (*TimingRange, bool, error) {
	switch val := v.(type) {
	case int:
		if val < 0 {
			return nil, true, fmt.Errorf("timing range value must be non-negative: %d", val)
		}
		return DegenerateTimingRange(val), true, nil
	case int64:
		if val < 0 || val > math.MaxInt {
			return nil, true, fmt.Errorf("timing range value out of range: %d", val)
		}
		return DegenerateTimingRange(int(val)), true, nil
	case int32:
		if val < 0 {
			return nil, true, fmt.Errorf("timing range value must be non-negative: %d", val)
		}
		return DegenerateTimingRange(int(val)), true, nil
	case uint:
		if uint64(val) > math.MaxInt {
			return nil, true, fmt.Errorf("timing range value out of range: %d", val)
		}
		return DegenerateTimingRange(int(val)), true, nil
	case uint32:
		return DegenerateTimingRange(int(val)), true, nil
	case uint64:
		if val > math.MaxInt {
			return nil, true, fmt.Errorf("timing range value out of range: %d", val)
		}
		return DegenerateTimingRange(int(val)), true, nil
	case float64:
		if val < 0 || val > math.MaxInt {
			return nil, true, fmt.Errorf("timing range value out of range: %f", val)
		}
		return DegenerateTimingRange(int(val)), true, nil
	case float32:
		if val < 0 || float64(val) > math.MaxInt {
			return nil, true, fmt.Errorf("timing range value out of range: %f", val)
		}
		return DegenerateTimingRange(int(val)), true, nil
	default:
		return nil, false, nil
	}
}

func parseStringTimingRange(val string) (*TimingRange, error) {
	str := strings.TrimSpace(val)
	if str == "" {
		return nil, nil
	}
	str = strings.Trim(str, "\"")
	parts := strings.Split(str, "-")
	if len(parts) == 1 {
		n, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, fmt.Errorf("invalid timing range %q: %w", val, err)
		}
		if n < 0 {
			return nil, fmt.Errorf("timing range value must be non-negative, got %d", n)
		}
		return DegenerateTimingRange(n), nil
	} else if len(parts) == 2 {
		lo, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, fmt.Errorf("invalid timing range %q: %w", val, err)
		}
		hi, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid timing range %q: %w", val, err)
		}
		if lo < 0 || hi < 0 {
			return nil, fmt.Errorf("timing range values must be non-negative, got %q", val)
		}
		if hi < lo {
			return nil, fmt.Errorf("invalid timing range %q: hi (%d) < lo (%d)", val, hi, lo)
		}
		return &TimingRange{Lo: lo, Hi: hi}, nil
	}
	return nil, fmt.Errorf("invalid timing range %q: too many hyphens", val)
}

// ParseTimingRange parses a timing range from any supported type:
// string ("100-140" or "125"), int, int64, float64, *TimingRange, TimingRange.
func ParseTimingRange(v any) (*TimingRange, error) {
	if v == nil {
		return nil, nil
	}
	switch val := v.(type) {
	case TimingRange:
		return NewTimingRange(val.Lo, val.Hi), nil
	case *TimingRange:
		if val == nil {
			return nil, nil
		}
		return NewTimingRange(val.Lo, val.Hi), nil
	case string:
		return parseStringTimingRange(val)
	default:
		tr, handled, err := parseNumericTimingRange(v)
		if handled {
			return tr, err
		}
		return nil, fmt.Errorf("unsupported type %T for timing range", v)
	}
}

// GenerateRekeyAfterTime generates a randomized RekeyAfterTime range within AWG 3.1 floors [100, 140].
func GenerateRekeyAfterTime() *TimingRange {
	lo, _ := randIntBetween(100, 115)
	hi, _ := randIntBetween(125, 140)
	return &TimingRange{Lo: lo, Hi: hi}
}

// GenerateRekeyTimeout generates a randomized RekeyTimeout range within AWG 3.1 floors [4, 6].
func GenerateRekeyTimeout() *TimingRange {
	lo, _ := randIntBetween(4, 5)
	hi, _ := randIntBetween(5, 6)
	if lo >= hi {
		hi = lo + 1
		if hi > 6 {
			lo = 4
			hi = 6
		}
	}
	return &TimingRange{Lo: lo, Hi: hi}
}

// GenerateRejectAfterTime generates a randomized RejectAfterTime range within AWG 3.1 floors [160, 200].
func GenerateRejectAfterTime() *TimingRange {
	lo, _ := randIntBetween(160, 175)
	hi, _ := randIntBetween(185, 200)
	return &TimingRange{Lo: lo, Hi: hi}
}

// GenerateKeepaliveTimeout generates a randomized KeepaliveTimeout range within AWG 3.1 floors [8, 12].
func GenerateKeepaliveTimeout() *TimingRange {
	lo, _ := randIntBetween(8, 9)
	hi, _ := randIntBetween(11, 12)
	return &TimingRange{Lo: lo, Hi: hi}
}

// GenerateMaxHandshakeAttempts generates a randomized MaxHandshakeAttempts range within AWG 3.1 floors [4, 8].
func GenerateMaxHandshakeAttempts() *TimingRange {
	lo, _ := randIntBetween(4, 5)
	hi, _ := randIntBetween(7, 8)
	return &TimingRange{Lo: lo, Hi: hi}
}

// GeneratePersistentKeepalive generates a randomized PersistentKeepalive range within AWG 3.1 floors [22, 30].
func GeneratePersistentKeepalive() *TimingRange {
	lo, _ := randIntBetween(22, 25)
	hi, _ := randIntBetween(27, 30)
	return &TimingRange{Lo: lo, Hi: hi}
}

// EnforceTimingOrdering enforces strict ordering invariants between timing parameters:
// 1. rekey_timeout range must be strictly below rekey_after_time range (rt.Hi < rat.Lo, no overlap).
// 2. rekey_after_time range must be strictly below reject_after_time range (rat.Hi < rej.Lo).
func EnforceTimingOrdering(rt, rat, rej *TimingRange) {
	if rt != nil && rat != nil {
		if rt.Hi >= rat.Lo {
			if rat.Lo > 2 {
				rt.Hi = rat.Lo - 1
				if rt.Lo > rt.Hi {
					rt.Lo = rt.Hi
				}
			} else {
				rat.Lo = rt.Hi + 1
				if rat.Hi < rat.Lo {
					rat.Hi = rat.Lo
				}
			}
		}
	}
	if rat != nil && rej != nil {
		if rej.Lo <= rat.Hi {
			rej.Lo = rat.Hi + 1
			if rej.Hi < rej.Lo {
				rej.Hi = rej.Lo
			}
		}
	}
}

// GenerateClientTimingParams generates randomized timing params for a client as ranges
// with AWG 3.1-sane floors and strict ordering invariants enforced.
func GenerateClientTimingParams() (rekeyAfterTime, rekeyTimeout, rejectAfterTime, keepaliveTimeout, maxHandshakeAttempts, persistentKeepalive *TimingRange) {
	rat := GenerateRekeyAfterTime()
	rt := GenerateRekeyTimeout()
	rej := GenerateRejectAfterTime()
	kt := GenerateKeepaliveTimeout()
	mha := GenerateMaxHandshakeAttempts()
	pk := GeneratePersistentKeepalive()

	EnforceTimingOrdering(rt, rat, rej)

	return rat, rt, rej, kt, mha, pk
}

// ValidateAWGParams ensures all AWG parameters are numeric strings within safe ranges to prevent command injection.
func ValidateAWGParams(params map[string]string) error {
	numericBounds := map[string][2]int64{
		"junk_packet_count":             {1, 100},
		"junk_packet_min_size":          {1, 1000},
		"junk_packet_max_size":          {1, 1300},
		"init_packet_junk_size":         {1, 1000},
		"response_packet_junk_size":     {1, 1000},
		"cookie_reply_packet_junk_size": {1, 1000},
		"transport_packet_junk_size":    {1, 1000},
	}

	for k, bounds := range numericBounds {
		val, ok := params[k]
		if !ok || val == "" {
			continue
		}
		num, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return fmt.Errorf("param %s must be a numeric integer, got: %s", k, val)
		}
		if num < bounds[0] || num > bounds[1] {
			return fmt.Errorf("param %s must be between %d and %d, got: %d", k, bounds[0], bounds[1], num)
		}
	}

	magicHeaders := []string{
		"init_packet_magic_header",
		"response_packet_magic_header",
		"underload_packet_magic_header",
		"transport_packet_magic_header",
	}
	for _, k := range magicHeaders {
		val, ok := params[k]
		if !ok || val == "" {
			continue
		}
		hr, err := models.ParseHeaderRange(val)
		if err != nil {
			return fmt.Errorf("param %s must be a valid header range, got: %s: %w", k, val, err)
		}
		if hr.Lo < 5 || uint64(hr.Hi) > 4294967295 {
			return fmt.Errorf("param %s must be between 5 and 4294967295, got: %s", k, val)
		}
	}

	for _, k := range []string{"i1", "i2", "i3", "i4", "i5"} {
		val, ok := params[k]
		if !ok || val == "" {
			continue
		}
		if !strings.HasPrefix(val, "<") || !strings.HasSuffix(val, ">") {
			return fmt.Errorf("param %s must be in <b 0xHEX> or <r N><b 0xHEX> format, got: %s", k, val)
		}
	}

	if mtuStr, ok := params["mtu"]; ok && mtuStr != "" {
		mtu, err := strconv.Atoi(mtuStr)
		if err != nil || mtu < 1200 || mtu > 1500 {
			return fmt.Errorf("param mtu must be between 1200 and 1500, got: %s", mtuStr)
		}
	}

	return nil
}
