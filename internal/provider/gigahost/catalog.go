package gigahost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// GetOperatingSystems returns the provider's installable images for
// GET /reinstall/distro plus one GET /reinstall/distro/{dist_id} per
// distribution, which is the documented way to discover os_id values. The
// distribution list is small and closed; an error from any distribution fails
// the whole call so a partial image list is never presented as complete.
func (c *client) GetOperatingSystems(ctx context.Context) ([]OperatingSystem, error) {
	var distroData []byte
	if err := c.doRequest(ctx, http.MethodGet, "/reinstall/distro", nil, &distroData); err != nil {
		return nil, fmt.Errorf("failed to fetch distributions: %w", err)
	}
	distros, err := parseDistros(distroData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode distributions: %w", err)
	}

	var systems []OperatingSystem
	for _, d := range distros {
		if d.Inactive() {
			continue
		}
		images, err := c.distributionImages(ctx, d)
		if err != nil {
			return nil, err
		}
		systems = append(systems, images...)
	}
	return systems, nil
}

// distributionImages reads and labels the images of one distribution.
func (c *client) distributionImages(ctx context.Context, d distrib) ([]OperatingSystem, error) {
	var pageData []byte
	if err := c.doRequest(ctx, http.MethodGet, fmt.Sprintf("/reinstall/distro/%d", d.ID), nil, &pageData); err != nil {
		return nil, fmt.Errorf("failed to fetch operating systems for distribution %d: %w", d.ID, err)
	}
	images, err := parseOperatingSystems(pageData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode operating systems for distribution %d: %w", d.ID, err)
	}
	for i := range images {
		if images[i].DistName == "" {
			images[i].DistName = d.Name
		}
		if images[i].DistID == 0 {
			images[i].DistID = d.ID
		}
	}
	return images, nil
}

// distrib is one entry from GET /reinstall/distro.
type distrib struct {
	ID     int    `json:"dist_id"`
	Name   string `json:"dist_name"`
	Value  string `json:"dist_value"`
	Active *bool  `json:"dist_active"`
}

// Inactive reports whether the provider explicitly marked the distribution
// inactive. An absent flag is not treated as inactive.
func (d distrib) Inactive() bool {
	return d.Active != nil && !*d.Active
}

// UnmarshalJSON decodes the documented string-encoded dist_id and dist_active.
func (d *distrib) UnmarshalJSON(data []byte) error {
	var raw struct {
		ID     any    `json:"dist_id"`
		Name   string `json:"dist_name"`
		Value  string `json:"dist_value"`
		Active any    `json:"dist_active"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	d.ID = int(parseInt64Field(raw.ID))
	d.Name = raw.Name
	d.Value = raw.Value
	if b, ok := parseBoolFieldStrict(raw.Active); ok {
		d.Active = &b
	}
	return nil
}

func parseDistros(data []byte) ([]distrib, error) {
	var doc struct {
		Data []distrib `json:"data"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc.Data, nil
}

func parseOperatingSystems(data []byte) ([]OperatingSystem, error) {
	var doc struct {
		Data []OperatingSystem `json:"data"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc.Data, nil
}

// GetProducts queries the raw product catalog from GET /deploy/servers.
func (c *client) GetProducts(ctx context.Context) ([]Product, error) {
	var respData []byte
	err := c.doRequest(ctx, http.MethodGet, "/deploy/servers", nil, &respData)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch products: %w", err)
	}

	products, elig, err := parseProducts(respData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode catalog products: %w", err)
	}
	c.mu.Lock()
	c.lastEligibility = elig
	c.mu.Unlock()
	return products, nil
}

// GetCatalog queries available products and filters those supporting hourly
// billing. Each plan carries the provider's own placement and image facts so
// the portal can offer only real choices and the handler can revalidate them.
func (c *client) GetCatalog(ctx context.Context) ([]HourlyPlan, error) {
	products, err := c.GetProducts(ctx)
	if err != nil {
		return nil, err
	}

	var hourlyPlans []HourlyPlan
	for _, p := range products {
		for _, price := range p.Prices {
			if strings.EqualFold(price.BillingPeriod, BillingPeriodHourly) {
				rate := price.HourlyRate
				if rate <= 0 && price.Amount > 0 {
					rate = price.Amount
				}
				currency := price.Currency
				if currency == "" {
					currency = "NOK"
				}

				plan := HourlyPlan{
					ProductID:      p.GetID(),
					Name:           p.Name,
					Description:    p.Description,
					Type:           p.Type,
					CPUCores:       p.CPUCores,
					RAMMB:          p.RAMMB,
					DiskGB:         p.DiskGB,
					BandwidthTB:    p.BandwidthTB,
					InStock:        p.InStock,
					BuiltToOrder:   p.BuiltToOrder,
					WaitlistOK:     p.WaitlistOK,
					PriceID:        price.ID,
					Currency:       currency,
					HourlyRateNOK:  rate,
					MonthlyCeiling: price.MonthlyCeiling,
					Regions:        p.Regions,
					Datacenters:    p.Datacenters,
					Eligibility:    p.Eligibility,
				}
				hourlyPlans = append(hourlyPlans, plan)
			}
		}
	}

	return hourlyPlans, nil
}

// GetCatalogEligibility returns the most recently decoded catalog eligibility.
func (c *client) GetCatalogEligibility() CatalogEligibility {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastEligibility
}

// GetCatalogResponse returns catalog plans and account eligibility.
func (c *client) GetCatalogResponse(ctx context.Context) (*CatalogResponse, error) {
	plans, err := c.GetCatalog(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	elig := c.lastEligibility
	c.mu.Unlock()
	if !elig.QualifiesArrears && elig.CreditNOK == 0 && len(plans) > 0 {
		elig = plans[0].Eligibility
	}
	return &CatalogResponse{
		Plans:       plans,
		Eligibility: elig,
	}, nil
}

type tierProductDTO struct {
	ProductID      int                `json:"product_id"`
	ProductName    string             `json:"product_name"`
	Type           string             `json:"type"`
	AllowHourly    bool               `json:"allow_hourly"`
	AllowRecurring bool               `json:"allow_recurring"`
	PriceID        int                `json:"price_id"`
	RateHourly     float64            `json:"rate_hourly"`
	RateMonthly    float64            `json:"rate_monthly"`
	RegionIDs      []any              `json:"region_ids"`
	DCIDs          []any              `json:"dc_ids"`
	DCStock        map[string]any     `json:"dc_stock"`
	InStock        bool               `json:"in_stock"`
	BuiltToOrder   bool               `json:"built_to_order"`
	WaitlistOK     bool               `json:"waitlist_eligible"`
	VMCores        string             `json:"vm_cores"`
	VMMemory       string             `json:"vm_memory"`
	VMStorage      string             `json:"vm_storage"`
	VMBW           string             `json:"vm_bw"`
	Eligibility    CatalogEligibility `json:"eligibility,omitempty"`
	Specs          struct {
		CPUCores int `json:"cpu_cores"`
		RAMGB    int `json:"ram_gb"`
		Disks    []struct {
			SizeGB int `json:"size_gb"`
		} `json:"disks"`
		BW float64 `json:"bw"`
	} `json:"specs"`
}

// dcPlacement is one datacenter the provider listed in the catalog.
type dcPlacement struct {
	ID       int
	Name     string
	RegionID int
	Location string
	Country  string
}

// productSpecs is the machine-readable spec set a catalog product documents.
type productSpecs struct {
	cores int
	ramMB int
	disk  int
	bw    float64
}

// firstPositiveInt returns primary when it carries a value, else the parsed
// fallback, else primary unchanged. The provider documents the machine-readable
// specs as authoritative and the legacy string fields as the older shape, so a
// value present in the structured object always wins.
func firstPositiveInt(primary int, fallback string) int {
	if primary > 0 {
		return primary
	}
	if v, err := strconv.Atoi(fallback); err == nil {
		return v
	}
	return primary
}

// firstPositiveFloat is firstPositiveInt for the bandwidth figure.
func firstPositiveFloat(primary float64, fallback string) float64 {
	if primary > 0 {
		return primary
	}
	if v, err := strconv.ParseFloat(fallback, 64); err == nil {
		return v
	}
	return primary
}

// resolveSpecs reads the structured specs object and falls back to the legacy
// string fields only when the structured value is absent.
func resolveSpecs(p tierProductDTO) productSpecs {
	disk := 0
	for _, d := range p.Specs.Disks {
		disk += d.SizeGB
	}
	return productSpecs{
		cores: firstPositiveInt(p.Specs.CPUCores, p.VMCores),
		ramMB: firstPositiveInt(p.Specs.RAMGB, p.VMMemory) * 1024,
		disk:  firstPositiveInt(disk, p.VMStorage),
		bw:    firstPositiveFloat(p.Specs.BW, p.VMBW),
	}
}

// hourlyPrices returns the price row the plan may be ordered at, or nothing when
// the provider does not offer the product hourly or has no hourly price id.
func hourlyPrices(p tierProductDTO, inStock bool, currency string) []Price {
	if !p.AllowHourly || p.PriceID <= 0 || !inStock {
		return nil
	}
	return []Price{{
		ID:             p.PriceID,
		BillingPeriod:  BillingPeriodHourly,
		Currency:       currency,
		HourlyRate:     p.RateHourly,
		MonthlyCeiling: p.RateMonthly,
	}}
}

// buildTierProduct converts one documented catalog product into the plan shape
// the portal and handler use, keeping every placement fact the provider
// documents: the region list, the per-product datacenters and their stock.
func buildTierProduct(p tierProductDTO, regionMap map[int]Region, dcMap map[int]dcPlacement, currency string, eligibility CatalogEligibility) Product {
	specs := resolveSpecs(p)
	datacenters, dcStockKnown := placementFor(p, dcMap)
	regions := regionsFor(p, regionMap, datacenters, dcStockKnown)

	if p.Eligibility.QualifiesArrears || p.Eligibility.CreditNOK > 0 {
		eligibility = p.Eligibility
	}

	return Product{
		ID:           p.ProductID,
		PID:          p.ProductID,
		Name:         p.ProductName,
		Type:         p.Type,
		CPUCores:     specs.cores,
		RAMMB:        specs.ramMB,
		DiskGB:       specs.disk,
		BandwidthTB:  specs.bw,
		InStock:      p.InStock,
		BuiltToOrder: p.BuiltToOrder,
		WaitlistOK:   p.WaitlistOK,
		Prices:       hourlyPrices(p, p.InStock, currency),
		Regions:      regions,
		Datacenters:  datacenters,
		Eligibility:  eligibility,
	}
}

// placementFor returns the product's own datacenters with the provider's stock
// fact for each. dcStockKnown reports whether the catalog carried dc_stock at
// all, so an absent fact is never read as "sold out".
//
// Two documented shapes are dropped rather than published:
//
//   - a dc_ids entry that is not a positive integer yields no usable identity, so
//     it lists nothing (an id of 0 would be indistinguishable from "unset");
//   - a dc_ids entry with no datacenter record keeps its id and no name, region
//     or stock. Its region relationship is unproven, so the handler can never
//     place a server there; it stays listed so a reader sees the provider
//     mentioned it, but it is never selectable.
func placementFor(p tierProductDTO, dcMap map[int]dcPlacement) ([]Datacenter, bool) {
	dcStockKnown := len(p.DCStock) > 0
	var datacenters []Datacenter
	for _, dcAny := range p.DCIDs {
		id := int(parseInt64Field(dcAny))
		if id <= 0 {
			continue
		}
		dc := Datacenter{ID: id}
		if known, ok := dcMap[id]; ok {
			dc.Name = known.Name
			dc.RegionID = known.RegionID
			dc.Location = known.Location
			dc.Country = known.Country
		}
		if inStock, ok := dcStockValue(p.DCStock, id); ok {
			dc.InStock = &inStock
		}
		datacenters = append(datacenters, dc)
	}
	return datacenters, dcStockKnown
}

// dcStockValue reads one dc_stock entry, whose key is a datacenter id and whose
// value may be a JSON boolean or a "0"/"1" string.
func dcStockValue(stock map[string]any, dcID int) (bool, bool) {
	if len(stock) == 0 {
		return false, false
	}
	raw, ok := stock[strconv.Itoa(dcID)]
	if !ok {
		return false, false
	}
	return parseBoolFieldStrict(raw)
}

// regionsFor builds the plan's region list. Availability comes from region_ids;
// the per-region stock is true when at least one of the product's datacenters in
// that region reports stock, false when every such datacenter reports none, and
// left unknown (nil) when the catalog carried no stock fact.
func regionsFor(p tierProductDTO, regionMap map[int]Region, datacenters []Datacenter, dcStockKnown bool) []Region {
	var regions []Region
	for _, ridAny := range p.RegionIDs {
		rid := int(parseInt64Field(ridAny))
		reg, known := regionMap[rid]
		if !known {
			reg = Region{ID: rid}
		}
		reg.Available = true
		reg.InStock = regionStock(rid, datacenters, dcStockKnown)
		regions = append(regions, reg)
	}
	return regions
}

// regionStock summarizes the product's datacenter stock inside one region: true
// when any of its datacenters in that region reports stock, false only when every
// datacenter that maps to the region reports no stock, and unknown (nil)
// otherwise.
//
// "Otherwise" covers two distinct cases that must not collapse into "sold out":
// the catalog carried no stock fact at all, and a region where some datacenters
// report no stock while others report nothing (an absent entry is not a
// sold-out entry).
func regionStock(regionID int, datacenters []Datacenter, dcStockKnown bool) *bool {
	if !dcStockKnown {
		return nil
	}
	matched, unknown := false, false
	for _, dc := range datacenters {
		if dc.RegionID != regionID {
			continue
		}
		matched = true
		if dc.Stocked() {
			inStock := true
			return &inStock
		}
		if dc.InStock == nil {
			unknown = true
		}
	}
	if !matched || unknown {
		return nil
	}
	inStock := false
	return &inStock
}

// tierDTO is one documented catalog tier: a named group of products.
type tierDTO struct {
	GroupID   int              `json:"group_id"`
	GroupName string           `json:"group_name"`
	InStock   bool             `json:"in_stock"`
	Products  []tierProductDTO `json:"products"`
}

// catalogDoc is the documented GET /deploy/servers body.
type catalogDoc struct {
	Meta struct {
		Status int `json:"status"`
	} `json:"meta"`
	Data struct {
		Tiers   []tierDTO `json:"tiers"`
		Regions []struct {
			RegionID   any    `json:"region_id"`
			RegionName string `json:"region_name"`
			Country    string `json:"region_country"`
		} `json:"regions"`
		Datacenters []struct {
			DCID           any    `json:"dc_id"`
			DCName         string `json:"dc_name"`
			RegionID       any    `json:"region_id"`
			RegionName     string `json:"region_name"`
			RegionLocation string `json:"region_location"`
			RegionCountry  string `json:"region_country"`
		} `json:"datacenters"`
		Currency    string             `json:"currency"`
		Eligibility CatalogEligibility `json:"eligibility"`
	} `json:"data"`
	Eligibility CatalogEligibility `json:"eligibility"`
}

// regionMap indexes the documented region list by provider region id.
func (d catalogDoc) regionMap() map[int]Region {
	regions := make(map[int]Region, len(d.Data.Regions))
	for _, r := range d.Data.Regions {
		rID := int(parseInt64Field(r.RegionID))
		regions[rID] = Region{
			ID:        rID,
			Name:      r.RegionName,
			Country:   r.Country,
			Available: true,
		}
	}
	return regions
}

// dcMap indexes the documented datacenter list by provider datacenter id. A
// datacenter whose region the catalog left out keeps region 0, which no
// documented region matches, so it never contributes stock to a region by
// accident.
func (d catalogDoc) dcMap() map[int]dcPlacement {
	datacenters := make(map[int]dcPlacement, len(d.Data.Datacenters))
	for _, dc := range d.Data.Datacenters {
		id := int(parseInt64Field(dc.DCID))
		datacenters[id] = dcPlacement{
			ID:       id,
			Name:     dc.DCName,
			RegionID: int(parseInt64Field(dc.RegionID)),
			Location: dc.RegionLocation,
			Country:  dc.RegionCountry,
		}
	}
	return datacenters
}

// eligibility prefers whichever source reports a qualifying fact, so a plan set
// is never published as ineligible on the strength of one absent field.
func (d catalogDoc) eligibility() CatalogEligibility {
	eligibility := d.Data.Eligibility
	if !eligibility.QualifiesArrears && eligibility.CreditNOK == 0 &&
		(d.Eligibility.QualifiesArrears || d.Eligibility.CreditNOK > 0) {
		eligibility = d.Eligibility
	}
	return eligibility
}

// currency reports the documented catalog currency, defaulting to the provider's
// billing currency when the field is absent.
func (d catalogDoc) currency() string {
	if d.Data.Currency == "" {
		return "NOK"
	}
	return d.Data.Currency
}

// productsFromTiers flattens the documented tiers into plans.
func productsFromTiers(tiers []tierDTO, regionMap map[int]Region, dcMap map[int]dcPlacement, currency string, eligibility CatalogEligibility) []Product {
	var products []Product
	for _, tier := range tiers {
		for _, p := range tier.Products {
			products = append(products, buildTierProduct(p, regionMap, dcMap, currency, eligibility))
		}
	}
	return products
}

// productsFromDocument reads the documented tiered catalog body. It reports a
// nil slice when the body is not that shape, so the caller can fall through to
// the legacy shapes.
func productsFromDocument(data []byte) ([]Product, CatalogEligibility, bool) {
	var doc catalogDoc
	if err := json.Unmarshal(data, &doc); err != nil || len(doc.Data.Tiers) == 0 {
		return nil, CatalogEligibility{}, false
	}
	eligibility := doc.eligibility()
	products := productsFromTiers(doc.Data.Tiers, doc.regionMap(), doc.dcMap(), doc.currency(), eligibility)
	if len(products) == 0 {
		return nil, CatalogEligibility{}, false
	}
	return products, eligibility, true
}

// productsFromLegacyShape reads the two older documented catalog wrappers.
// Neither shape carries eligibility, so the caller keeps the zero value it has.
func productsFromLegacyShape(data []byte) ([]Product, bool) {
	var direct []Product
	if err := json.Unmarshal(data, &direct); err == nil && direct != nil {
		return direct, true
	}
	var wrapped struct {
		Products []Product `json:"products"`
		Data     []Product `json:"data"`
		Servers  []Product `json:"servers"`
	}
	if err := json.Unmarshal(data, &wrapped); err != nil {
		return nil, false
	}
	for _, candidate := range [][]Product{wrapped.Products, wrapped.Data, wrapped.Servers} {
		if candidate != nil {
			return candidate, true
		}
	}
	return nil, false
}

func parseProducts(data []byte) ([]Product, CatalogEligibility, error) {
	if products, eligibility, ok := productsFromDocument(data); ok {
		return products, eligibility, nil
	}
	if products, ok := productsFromLegacyShape(data); ok {
		return products, CatalogEligibility{}, nil
	}
	return nil, CatalogEligibility{}, errors.New("unable to parse products response format")
}
