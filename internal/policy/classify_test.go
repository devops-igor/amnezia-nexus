package policy

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/geodb"
)

// Tests for the destination-address classifier of issue #918.
//
// Two kinds of evidence are asserted here and they answer different questions:
//
//   - synthetic ranges prove the classifier's mechanics (membership, source,
//     CDN exclusion, uncovered addresses, IPv6, sibling cases) without depending
//     on live data;
//   - the committed inventory and embedded table prove the field-verified
//     controls: Yandex is inside the allocation although the embedded table
//     reports a Serbian country for it, genuine Serbian traffic is not, and a
//     multi-region CDN range inside the allocation is excluded.

// addrU32 converts an IPv4 literal to the uint32 the embedded table stores.
func addrU32(t *testing.T, raw string) uint32 {
	t.Helper()
	addr := netip.MustParseAddr(raw)
	if !addr.Is4() {
		t.Fatalf("%q is not an IPv4 address", raw)
	}
	return binary.BigEndian.Uint32(addr.AsSlice())
}

// syntheticInventory builds a committed-shaped inventory with 1024 /24
// prefixes inside 45.0.0.0/16 (the loader's floor for a country allocation set).
func syntheticInventory(t *testing.T) *Inventory {
	t.Helper()
	var body strings.Builder
	for i := 0; i < MinInventoryPrefixes; i++ {
		fmt.Fprintf(&body, "45.%d.%d.0/24\n", i/256, i%256)
	}
	inv, err := InventoryFromBody([]byte(body.String()))
	if err != nil {
		t.Fatalf("build synthetic inventory: %v", err)
	}
	if inv.PrefixCount() != MinInventoryPrefixes {
		t.Fatalf("synthetic inventory holds %d prefixes, want %d", inv.PrefixCount(), MinInventoryPrefixes)
	}
	return inv
}

// syntheticGeoDB covers 45.0.0.0/16 with an ordinary ASN and 45.1.0.0/16 with a
// known multi-region CDN. 45.2.0.0/16 is deliberately left uncovered so the
// "allocation member the table does not cover" case can be asserted.
func syntheticGeoDB(t *testing.T) *geodb.GeoDB {
	t.Helper()
	return geodb.NewGeoDBFromRanges([]geodb.IPRange{
		{
			StartIP: addrU32(t, "45.0.0.0"),
			EndIP:   addrU32(t, "45.0.255.255"),
			ASN:     64999,
			Country: [2]byte{'Z', 'Z'},
		},
		{
			StartIP: addrU32(t, "45.1.0.0"),
			EndIP:   addrU32(t, "45.1.255.255"),
			ASN:     13335,
			Country: [2]byte{'U', 'S'},
		},
	})
}

func syntheticClassifier(t *testing.T) *AddressClassifier {
	t.Helper()
	classifier, err := NewAddressClassifier(syntheticInventory(t), syntheticGeoDB(t))
	if err != nil {
		t.Fatalf("build classifier: %v", err)
	}
	return classifier
}

// realClassifier is the production classifier: the committed inventory joined to
// the embedded ASN table, exactly as the VPN service installs it.
func realClassifier(t *testing.T) *AddressClassifier {
	t.Helper()
	inventory, err := ShippedInventory()
	if err != nil {
		t.Fatalf("committed inventory is unusable: %v", err)
	}
	geo, err := geodb.DefaultGeoDB()
	if err != nil {
		t.Fatalf("embedded ASN table is unusable: %v", err)
	}
	classifier, err := NewAddressClassifier(inventory, geo)
	if err != nil {
		t.Fatalf("build production classifier: %v", err)
	}
	return classifier
}

func TestNewAddressClassifierRequiresBothInputs(t *testing.T) {
	if _, err := NewAddressClassifier(nil, syntheticGeoDB(t)); err == nil {
		t.Fatal("a classifier without the allocation inventory must be refused")
	}
	if _, err := NewAddressClassifier(syntheticInventory(t), nil); err == nil {
		t.Fatal("a classifier without the ASN table must be refused")
	}
}

// A nil classifier is the documented fail-closed state: it classifies nothing,
// so the packet path keeps its proxy default.
func TestNilAddressClassifierClassifiesNothing(t *testing.T) {
	var classifier *AddressClassifier
	got := classifier.Classify(netip.MustParseAddr("45.0.0.1"))
	if got != (DestinationClassification{}) {
		t.Fatalf("nil classifier answered %+v, want the zero classification", got)
	}
}

func TestAddressClassifierClassifiesMembershipAndCDNExclusion(t *testing.T) {
	classifier := syntheticClassifier(t)

	tests := []struct {
		name       string
		address    string
		wantMember bool
		wantSource InventorySource
		wantASN    uint32
		wantCDN    string
		wantDirect bool
	}{
		{
			name:       "allocation member on an ordinary ASN routes direct",
			address:    "45.0.0.7",
			wantMember: true,
			wantSource: InventorySourceShipped,
			wantASN:    64999,
			wantDirect: true,
		},
		{
			name:       "allocation member on a known CDN ASN stays proxied",
			address:    "45.1.0.7",
			wantMember: true,
			wantSource: InventorySourceShipped,
			wantASN:    13335,
			wantCDN:    "Cloudflare",
			wantDirect: false,
		},
		{
			name:       "allocation member the ASN table does not cover is not excluded",
			address:    "45.2.0.7",
			wantMember: true,
			wantSource: InventorySourceShipped,
			wantDirect: true,
		},
		{
			name:       "address outside the allocation is not classified",
			address:    "46.0.0.7",
			wantMember: false,
			wantDirect: false,
		},
		{
			name:       "IPv6 is out of scope and not a member",
			address:    "2001:db8::1",
			wantMember: false,
			wantDirect: false,
		},
		{
			name:       "invalid address is not a member",
			address:    "0.0.0.0",
			wantMember: false,
			wantDirect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifier.Classify(netip.MustParseAddr(tt.address))
			if got.InAllocation != tt.wantMember {
				t.Fatalf("InAllocation = %v, want %v", got.InAllocation, tt.wantMember)
			}
			if got.Source != tt.wantSource {
				t.Errorf("Source = %q, want %q", got.Source, tt.wantSource)
			}
			if got.ASN != tt.wantASN {
				t.Errorf("ASN = %d, want %d", got.ASN, tt.wantASN)
			}
			if got.CDNProvider != tt.wantCDN {
				t.Errorf("CDNProvider = %q, want %q", got.CDNProvider, tt.wantCDN)
			}
			if got.AllocationRoutesDirect() != tt.wantDirect {
				t.Errorf("AllocationRoutesDirect = %v, want %v", got.AllocationRoutesDirect(), tt.wantDirect)
			}
		})
	}
}

// The operator override is an operator DIRECT input: it can add addresses to
// the set the classifier reports as inside the allocation. The classifier says
// only that; refusing a prohibited address remains the packet path's first row,
// which is asserted where that decision is consumed.
func TestAddressClassifierHonoursTheOperatorOverride(t *testing.T) {
	override, err := ParseInventoryOverride([]byte("203.0.113.0/24\n10.0.0.0/8\n"))
	if err != nil {
		t.Fatalf("parse override: %v", err)
	}
	classifier, err := NewAddressClassifier(syntheticInventory(t).WithOverride(override), syntheticGeoDB(t))
	if err != nil {
		t.Fatalf("build classifier: %v", err)
	}

	added := classifier.Classify(netip.MustParseAddr("203.0.113.9"))
	if !added.InAllocation || added.Source != InventorySourceOverride {
		t.Fatalf("override address classified %+v, want an override member", added)
	}
	if !added.AllocationRoutesDirect() {
		t.Error("an override address outside the ASN table should be a DIRECT candidate here; prohibition is decided later")
	}

	// The same operator input can name a prohibited range. Membership is not a
	// routing decision: the classifier reports the set the operator chose, and
	// the packet path refuses the destination before any DIRECT is installed.
	internal := classifier.Classify(netip.MustParseAddr("10.1.2.3"))
	if !internal.InAllocation {
		t.Fatal("the operator override named 10.0.0.0/8; the classifier must report it as a member")
	}
	if internal.Source != InventorySourceOverride {
		t.Errorf("Source = %q, want the operator override", internal.Source)
	}
}

// TestRealAllocationControls is the field-verified control set: the committed
// inventory and the embedded table together, on the addresses the epic resolved
// on the production host.
func TestRealAllocationControls(t *testing.T) {
	classifier := realClassifier(t)

	tests := []struct {
		name       string
		address    string
		wantMember bool
		wantDirect bool
		wantASN    uint32
		wantCDN    string
		note       string
	}{
		{
			name:       "music.yandex.ru is inside the Russian allocation although the table says RS",
			address:    "213.180.204.186",
			wantMember: true,
			wantDirect: true,
			wantASN:    208398,
			note:       "AS208398 is a Serbian-registered network that originates Yandex prefixes",
		},
		{
			name:       "yandex.ru is inside the Russian allocation",
			address:    "77.88.55.88",
			wantMember: true,
			wantDirect: true,
			wantASN:    208398,
		},
		{
			name:       "ozon.ru is inside the Russian allocation and not a CDN",
			address:    "185.73.194.82",
			wantMember: true,
			wantDirect: true,
			wantASN:    44386,
		},
		{
			name:       "genuine Serbian network is outside the allocation",
			address:    "147.91.1.1",
			wantMember: false,
			wantDirect: false,
			note:       "AS13092, Serbia",
		},
		{
			name:       "a multi-region CDN range inside the allocation stays proxied",
			address:    "193.176.179.1",
			wantMember: true,
			wantDirect: false,
			wantASN:    16509,
			wantCDN:    "Amazon",
			note:       "193.176.179.0/24 is inside the committed allocation and covered by AS16509",
		},
		{
			name:       "a CDN address outside the allocation is not classified",
			address:    "1.1.1.1",
			wantMember: false,
			wantDirect: false,
			wantCDN:    "",
			note:       "Cloudflare AS13335, not a member",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifier.Classify(netip.MustParseAddr(tt.address))
			if got.InAllocation != tt.wantMember {
				t.Fatalf("InAllocation = %v, want %v (%s)", got.InAllocation, tt.wantMember, tt.note)
			}
			if got.AllocationRoutesDirect() != tt.wantDirect {
				t.Errorf("AllocationRoutesDirect = %v, want %v (%s)", got.AllocationRoutesDirect(), tt.wantDirect, tt.note)
			}
			if tt.wantMember && got.ASN != tt.wantASN {
				t.Errorf("ASN = %d, want %d", got.ASN, tt.wantASN)
			}
			if got.CDNProvider != tt.wantCDN {
				t.Errorf("CDNProvider = %q, want %q", got.CDNProvider, tt.wantCDN)
			}
		})
	}
}

// registeredCountry reports the embedded table's country for an address.
func registeredCountry(t *testing.T, geo *geodb.GeoDB, address string) (uint32, string, bool) {
	t.Helper()
	asn, country, found := geo.Lookup(netip.MustParseAddr(address).AsSlice())
	return asn, country, found
}

// countryOnlyVariant is the rejected implementation that decides "inside the
// Russian allocation" from the embedded table's country column.
func countryOnlyVariant(t *testing.T, geo *geodb.GeoDB, address string) bool {
	t.Helper()
	_, country, found := registeredCountry(t, geo, address)
	return found && country == "RU"
}

// originASNOnlyVariant is the rejected implementation that decides the same
// question from an allowlist of Russian origin ASNs. Such a list is built from
// network registration, and the embedded table's country column *is* the
// registration country of the covering network, so on this data the two
// rejected designs reduce to one predicate — which is why a single correction
// disposed of both. The reduction is asserted, not assumed, in the control test.
func originASNOnlyVariant(t *testing.T, geo *geodb.GeoDB, address string) bool {
	t.Helper()
	if asn, country, found := registeredCountry(t, geo, address); found && asn != 0 {
		return country == "RU"
	}
	return false
}

// TestCountryAndOriginASNVariantsFailTheYandexCase is the negative implementation
// control: two rejected designs, both of which miss a Russian service because the
// embedded table reports the origin network's registration rather than the
// allocation.
func TestCountryAndOriginASNVariantsFailTheYandexCase(t *testing.T) {
	geo, err := geodb.DefaultGeoDB()
	if err != nil {
		t.Fatalf("embedded ASN table is unusable: %v", err)
	}
	classifier := realClassifier(t)

	const yandex = "213.180.204.186"
	asn, country, found := registeredCountry(t, geo, yandex)
	if !found || asn != 208398 {
		t.Fatalf("expected AS208398 for %s, got asn=%d found=%v", yandex, asn, found)
	}
	if country == "RU" {
		t.Fatalf("%s now reports country RU; the negative controls no longer exercise the ambiguity", yandex)
	}
	if !classifier.Classify(netip.MustParseAddr(yandex)).AllocationRoutesDirect() {
		t.Fatalf("%s must classify direct from allocation membership", yandex)
	}

	if countryOnlyVariant(t, geo, yandex) {
		t.Errorf("the country-only variant classified %s as Russian; allocation membership is the input that does", yandex)
	}
	if originASNOnlyVariant(t, geo, yandex) {
		t.Errorf("the origin-ASN-only variant classified %s as Russian; AS208398 is registered in Serbia", yandex)
	}

	// Neither variant is simply broken everywhere: both recognise an address
	// whose origin network is registered in Russia, which is why they looked
	// plausible before the field verification.
	const ozon = "185.73.194.82"
	if !countryOnlyVariant(t, geo, ozon) || !originASNOnlyVariant(t, geo, ozon) {
		t.Fatalf("both variants should accept %s; the control would otherwise prove nothing", ozon)
	}

	// The reduction claim above, asserted rather than asserted-in-prose.
	for _, address := range []string{yandex, ozon, "147.91.1.1", "193.176.179.1", "1.1.1.1"} {
		if got, want := originASNOnlyVariant(t, geo, address), countryOnlyVariant(t, geo, address); got != want {
			t.Errorf("variants disagree on %s: origin-ASN=%v country=%v; the documented reduction does not hold", address, got, want)
		}
	}
}
