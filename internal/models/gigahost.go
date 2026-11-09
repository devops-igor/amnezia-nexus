package models

import "time"

// GigahostOrder is one persisted Gigahost hourly order attempt.
//
// It is the durable record of an order and of the price the provider
// contracted for it (price id, provider monthly ceiling, hourly rate,
// currency). Those price fields are recorded history: nothing in the panel
// compares them against a configured spending limit. A record created before
// that identity was persisted has zero values there, which means "not
// recorded", never "zero cost".
//
// Records are never deleted.
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
	// MonthlyCapNOK is the monthly ceiling the provider reported for the
	// ordered product. Zero means "not recorded", never "a zero ceiling".
	MonthlyCapNOK float64 `json:"monthly_cap_nok"`
	// Currency is the order's billing currency. Empty means "not recorded"
	// and is treated as NOK, the pre-existing assumption.
	Currency string `json:"currency"`
}
