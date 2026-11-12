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

	// PurchaseOrigin records who created this row, and is the only evidence the
	// setup pipeline accepts that this panel actually purchased the order. See
	// PurchaseOrigin*: only the pre-purchase intent writer stamps it, so a row the
	// deploy-status mirror created - however plausible its plan and credential
	// happen to look - reads as PurchaseOriginNone forever.
	PurchaseOrigin string `json:"purchase_origin,omitempty"`
	// PurchaseRecordedAt is when the purchase intent was committed. It is recorded
	// with the stamp in the same INSERT so the two cannot disagree.
	PurchaseRecordedAt time.Time `json:"purchase_recorded_at,omitempty"`
}

// GigahostOrderCredential is the managed SSH credential attached to one order
// attempt.
//
// It exists so a purchase and the access to the purchased server are one
// durable unit: the public key is registered with the provider before the order,
// and the private material needed to log in afterwards is stored against the same
// order. PrivateKey holds plaintext in memory only; the database layer encrypts
// it on write and decrypts it on read, exactly as it does for the server table.
type GigahostOrderCredential struct {
	OrderID       string
	PrivateKey    string
	PublicKey     string
	ProviderKeyID int64
}
