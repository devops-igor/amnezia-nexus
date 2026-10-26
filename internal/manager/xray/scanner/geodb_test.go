package scanner

import (
	"net"
	"testing"
)

func TestGeoDB_Embedded(t *testing.T) {
	db, err := DefaultGeoDB()
	if err != nil {
		t.Fatalf("DefaultGeoDB failed: %v", err)
	}

	if len(db.ranges) < 300000 {
		t.Errorf("expected > 300,000 ranges in embedded GeoDB, got %d", len(db.ranges))
	}

	// 1.1.1.1 should be Cloudflare AS13335
	asn, country, found := db.Lookup(net.ParseIP("1.1.1.1"))
	if !found {
		t.Fatalf("failed to look up 1.1.1.1")
	}
	if asn != 13335 {
		t.Errorf("expected ASN 13335 for 1.1.1.1, got %d", asn)
	}
	if country == "" {
		t.Errorf("expected non-empty country for 1.1.1.1")
	}

	// 8.8.8.8 should be Google AS15169
	asnG, _, foundG := db.Lookup(net.ParseIP("8.8.8.8"))
	if !foundG || asnG != 15169 {
		t.Errorf("expected AS15169 for 8.8.8.8, got %d (found=%v)", asnG, foundG)
	}
}

func TestGeoDB_ValidateGeoProximity(t *testing.T) {
	ranges := []IPRange{
		{
			StartIP: 0x0A000000, // 10.0.0.0
			EndIP:   0x0A0000FF, // 10.0.0.255
			ASN:     100,
			Country: [2]byte{'D', 'E'},
		},
		{
			StartIP: 0x0A000100, // 10.0.1.0
			EndIP:   0x0A0001FF, // 10.0.1.255
			ASN:     200,
			Country: [2]byte{'D', 'E'},
		},
		{
			StartIP: 0x0A000200, // 10.0.2.0
			EndIP:   0x0A0002FF, // 10.0.2.255
			ASN:     300,
			Country: [2]byte{'S', 'E'},
		},
		{
			StartIP: 0x0A000300, // 10.0.3.0
			EndIP:   0x0A0003FF, // 10.0.3.255
			ASN:     13335,      // Cloudflare Anycast CDN
			Country: [2]byte{'U', 'S'},
		},
	}

	db := NewGeoDBFromRanges(ranges)
	serverIP := net.ParseIP("10.0.0.50") // DE, ASN 100

	// Case 1: Same country (DE), different ASN (200) -> PASS
	candSameCountry := net.ParseIP("10.0.1.50")
	passed, _, _, _, _, _ := db.ValidateGeoProximity(serverIP, candSameCountry)
	if !passed {
		t.Errorf("expected same country to pass")
	}

	// Case 2: Different country (SE), non-CDN ASN (300) -> FAIL
	candDiffCountry := net.ParseIP("10.0.2.50")
	passed, _, _, _, _, reason := db.ValidateGeoProximity(serverIP, candDiffCountry)
	if passed {
		t.Errorf("expected different country non-CDN to fail")
	}
	if reason == "" {
		t.Errorf("expected explanation reason on failure")
	}

	// Case 3: Different country (US), but Cloudflare CDN (AS13335) -> PASS
	candCloudflare := net.ParseIP("10.0.3.50")
	passed, _, _, _, _, _ = db.ValidateGeoProximity(serverIP, candCloudflare)
	if !passed {
		t.Errorf("expected Cloudflare CDN candidate to pass geo filter")
	}
}
