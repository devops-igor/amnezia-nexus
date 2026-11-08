package models

import "time"

// GigahostOrder is one persisted Gigahost hourly order attempt.
//
// It is the durable ledger the monthly budget is computed from, so it keeps the
// price identity the provider contracted for the order (price id, monthly cap,
// hourly rate, currency). A record created before that identity was persisted
// has zero values there, and the budget treats those as explicitly unknown
// rather than guessing.
//
// Records are never deleted. Releasing a reservation writes ReleasedAt and
// ReleaseReason and leaves the original Status intact, so the accounting
// history stays readable.
type GigahostOrder struct {
	ID             int64     `json:"id"`
	OrderID        string    `json:"order_id"`
	ServerID       int64     `json:"server_id"`
	Status         string    `json:"status"` // pending, deploying, ready, failed, unknown
	PlanID         int       `json:"plan_id"`
	RegionID       int       `json:"region_id"`
	HourlyPriceNOK float64   `json:"hourly_price_nok"`
	AssignedIP     string    `json:"assigned_ip"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`

	// PriceID is the catalog price id the order was placed with. It is the
	// order-time selection key and is preserved because the provider does not
	// return it on later reads.
	PriceID int `json:"price_id"`
	// MonthlyCapNOK is the monthly cap the provider contracted at order time.
	// Zero means "not recorded", never "zero cost".
	MonthlyCapNOK float64 `json:"monthly_cap_nok"`
	// Currency is the order's billing currency. Empty means "not recorded"
	// and is treated as NOK, the pre-existing assumption.
	Currency string `json:"currency"`

	// ReleasedAt marks a reservation removed from the committed total with
	// conclusive evidence. Empty means not released.
	ReleasedAt    string `json:"released_at,omitempty"`
	ReleaseReason string `json:"release_reason,omitempty"`
}
