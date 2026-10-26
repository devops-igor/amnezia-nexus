package scanner

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
)

//go:embed ip2asn.bin.gz
var embeddedGeoDataGz []byte

// IPRange represents an IPv4 contiguous block with ASN and 2-letter ISO country code.
type IPRange struct {
	StartIP uint32
	EndIP   uint32
	ASN     uint32
	Country [2]byte
}

// GeoDB provides offline ASN and country lookups for IPv4 addresses.
type GeoDB struct {
	ranges []IPRange
}

var (
	defaultGeoDBInstance *GeoDB
	defaultGeoDBOnce     sync.Once
	defaultGeoDBErr      error
)

// KnownCDNASNs maps major multi-region Anycast CDN/cloud ASNs to their provider names.
var KnownCDNASNs = map[uint32]string{
	13335:  "Cloudflare",
	209242: "Cloudflare",
	54113:  "Fastly",
	20940:  "Akamai",
	16625:  "Akamai",
	35994:  "Akamai",
	16509:  "Amazon",
	14618:  "Amazon",
	15169:  "Google",
	8075:   "Microsoft",
}

// IsMultiRegionCDNASN checks if an ASN belongs to a known multi-region anycast provider.
func IsMultiRegionCDNASN(asn uint32) bool {
	_, ok := KnownCDNASNs[asn]
	return ok
}

// DefaultGeoDB returns the singleton embedded GeoDB instance.
func DefaultGeoDB() (*GeoDB, error) {
	defaultGeoDBOnce.Do(func() {
		defaultGeoDBInstance, defaultGeoDBErr = LoadGeoDBGz(embeddedGeoDataGz)
	})
	return defaultGeoDBInstance, defaultGeoDBErr
}

// LoadGeoDBGz decodes a gzip-compressed binary GeoDB table.
func LoadGeoDBGz(data []byte) (*GeoDB, error) {
	if len(data) == 0 {
		return nil, errors.New("empty geodb data")
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("open gzip reader: %w", err)
	}
	defer func() {
		_ = gz.Close()
	}()

	raw, err := io.ReadAll(gz)
	if err != nil {
		return nil, fmt.Errorf("read geodb gzip payload: %w", err)
	}

	const recordSize = 14
	if len(raw)%recordSize != 0 {
		return nil, fmt.Errorf("corrupted geodb: payload size %d not divisible by record size %d", len(raw), recordSize)
	}

	count := len(raw) / recordSize
	ranges := make([]IPRange, count)
	for i := 0; i < count; i++ {
		offset := i * recordSize
		ranges[i] = IPRange{
			StartIP: binary.BigEndian.Uint32(raw[offset : offset+4]),
			EndIP:   binary.BigEndian.Uint32(raw[offset+4 : offset+8]),
			ASN:     binary.BigEndian.Uint32(raw[offset+8 : offset+12]),
			Country: [2]byte{raw[offset+12], raw[offset+13]},
		}
	}

	return &GeoDB{ranges: ranges}, nil
}

// NewGeoDBFromRanges creates a GeoDB from a pre-sorted slice of IPRange (primarily for tests).
func NewGeoDBFromRanges(ranges []IPRange) *GeoDB {
	return &GeoDB{ranges: ranges}
}

// Lookup finds the ASN and ISO country code for an IPv4 address.
func (db *GeoDB) Lookup(ip net.IP) (asn uint32, country string, found bool) {
	if db == nil || len(db.ranges) == 0 {
		return 0, "", false
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, "", false
	}
	ipVal := binary.BigEndian.Uint32(ipv4)

	idx := sort.Search(len(db.ranges), func(i int) bool {
		return db.ranges[i].EndIP >= ipVal
	})

	if idx < len(db.ranges) && db.ranges[idx].StartIP <= ipVal && db.ranges[idx].EndIP >= ipVal {
		c := string(db.ranges[idx].Country[:])
		if c == "--" {
			c = ""
		}
		return db.ranges[idx].ASN, c, true
	}
	return 0, "", false
}

// ValidateGeoProximity checks if candidate IP matches target server's country or ASN,
// or if candidate resides on a known multi-region Anycast CDN.
func (db *GeoDB) ValidateGeoProximity(serverIP, candIP net.IP) (passed bool, serverCountry, candCountry string, serverASN, candASN uint32, reason string) {
	serverASN, serverCountry, sFound := db.Lookup(serverIP)
	candASN, candCountry, cFound := db.Lookup(candIP)

	// Check multi-region CDN exception first
	if IsMultiRegionCDNASN(candASN) {
		return true, serverCountry, candCountry, serverASN, candASN, fmt.Sprintf("allowed multi-region CDN (%s, AS%d)", KnownCDNASNs[candASN], candASN)
	}

	if !sFound {
		// Server IP not in DB (e.g. private test network) -> allow with note
		return true, serverCountry, candCountry, serverASN, candASN, "server IP not found in GeoDB, allowing candidate"
	}

	if !cFound {
		return false, serverCountry, candCountry, serverASN, candASN, "candidate IP not found in GeoDB"
	}

	if serverCountry != "" && candCountry != "" && serverCountry == candCountry {
		return true, serverCountry, candCountry, serverASN, candASN, fmt.Sprintf("country match (%s)", serverCountry)
	}

	if serverASN > 0 && candASN > 0 && serverASN == candASN {
		return true, serverCountry, candCountry, serverASN, candASN, fmt.Sprintf("ASN match (AS%d)", serverASN)
	}

	reason = fmt.Sprintf("server country=%s (AS%d), candidate country=%s (AS%d), non-CDN ASN", serverCountry, serverASN, candCountry, candASN)
	return false, serverCountry, candCountry, serverASN, candASN, reason
}
