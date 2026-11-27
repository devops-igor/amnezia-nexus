package models

import (
	"strings"
	"time"
)

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

	// LiveRepairedAt is the affirmative inventory observation that contradicted a
	// recorded deletion, recorded as the instant that observation was requested - never
	// the moment an answer was processed, which the listing cannot speak for.
	// Nil means no repair is known, not an inferred repair.
	// It is internal evidence, independent of the onboarding journal and provider spelling.
	LiveRepairedAt *time.Time `json:"-"`

	// NexusServerID is the panel server this order registered, as mirrored onto the
	// ledger by the onboarding journal. A saved setup can journal it on the intent
	// instead, so zero means "not mirrored here", never "registered nothing".
	// It is read for identity resolution - an existence question has to name the row
	// it is about - and is not part of the response shape.
	NexusServerID int64 `json:"-"`

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
	// Step is the onboarding journal's last recorded step for this order, as the
	// journal writer stored it. It is the panel's own execution record, never a
	// provider observation, and it is served so a row whose status is no longer
	// asked about still shows the step that was reached.
	Step string `json:"step,omitempty"`

	// PurchaseOrigin records who created this row, and is the only evidence the
	// setup pipeline accepts that this panel actually purchased the order. See
	// PurchaseOrigin*: only the pre-purchase intent writer stamps it, so a row the
	// deploy-status mirror created - however plausible its plan and credential
	// happen to look - reads as PurchaseOriginNone forever.
	PurchaseOrigin string `json:"purchase_origin,omitempty"`
	// PurchaseRecordedAt is when the purchase intent was committed. It is recorded
	// with the stamp in the same INSERT so the two cannot disagree.
	PurchaseRecordedAt time.Time `json:"purchase_recorded_at,omitempty"`

	// ProviderAccountID is the provider account the order was observed under: the
	// account whose own answer named this order or the server it registered. Empty
	// means unknown, and an unknown association may never justify a durable absence,
	// because one account's listing says nothing about another account's orders.
	ProviderAccountID string `json:"-"`

	// ProviderAbsentAt records when a successful, complete provider inventory read
	// omitted this order, as an RFC3339 UTC timestamp. Empty means no such
	// observation: the provider still lists it, or no successful read has judged it.
	// It is an observation about the provider's view of one order, never a deletion
	// of the ledger row, and it is what lets an order that never registered a panel
	// server be retired rather than polled forever.
	ProviderAbsentAt string `json:"-"`

	// ProviderAbsentAccountID records which provider account the listing that
	// produced the absence observation answered for. It is written and cleared with
	// the observation, so a later credential change is visible rather than silent.
	ProviderAbsentAccountID string `json:"-"`
}

// ProviderAbsent reports whether a successful provider inventory read has
// recorded that this order is gone. A failed or unanswered read never writes the
// column, so an empty value is the only "not absent" answer the panel holds.
func (o GigahostOrder) ProviderAbsent() bool {
	return strings.TrimSpace(o.ProviderAbsentAt) != ""
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
