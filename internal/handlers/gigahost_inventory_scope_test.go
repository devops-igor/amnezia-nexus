package handlers

// F989-05 (remaining): the certificate's authority comes from the credential's own
// scope, stated in the account payload's documented permissions object. The count
// comparison may only corroborate it.
//
// The review's case: a filtered key's listing is stable, an unrelated server of the
// same account is deleted, and the older listing's size then equals the newer
// account-wide count. Comparing counts across two reads certifies a partial list that
// never enumerated the account. With the certificate tied to the credential's scope,
// that input certifies nothing - whether the hidden row's detail read answers 403 or
// 404 - while a credential whose payload states all:true, with an honest listing,
// still records a genuinely absent server.

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// The review's replay, with both detail answers. Neither may certify, because the
// credential's payload states that it is limited to specific server ids.
func TestReconcileGigahostInventory_MatchingCountsDoNotCertifyARestrictedKey(t *testing.T) {
	for _, tc := range []struct {
		name         string
		detailStatus int
	}{
		{name: "detail answers 403", detailStatus: http.StatusForbidden},
		{name: "detail answers 404", detailStatus: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInventoryFixture(t)
			listed := f.seedServer("Listed", providerProtocols(501))
			hidden := f.seedServer("Working but hidden", providerProtocols(502))

			// The credential is limited to 501, so its listing is complete for the key
			// and incomplete for the account.
			f.provider.setAccountScopeRestricted(501)
			f.provider.set(inventoryJSON(501))
			// An unrelated server of the account was deleted since an older read, so the
			// account-wide count now equals the filtered listing's size. The two numbers
			// agree; the listing still never enumerated the account.
			f.provider.setAccountServers(1)
			f.provider.answerPerServer(502, tc.detailStatus)

			if err := f.reconcile(context.Background()); err != nil {
				t.Fatalf("reconciliation pass failed: %v", err)
			}
			if f.row(hidden).ProviderAbsent() {
				t.Fatal("matching counts certified a restricted key's list and hid a working server")
			}
			if f.row(listed).ProviderAbsent() {
				t.Fatal("a listed server was marked absent")
			}

			// The prior observation of the hidden row is untouched, not merely unmarked.
			recorded := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
			if err := f.db.SetServerProviderAbsence(context.Background(), hidden, recorded); err != nil {
				t.Fatalf("failed to seed the mark: %v", err)
			}
			before := f.row(hidden).ProviderAbsentAt
			if err := f.reconcile(context.Background()); err != nil {
				t.Fatalf("second reconciliation pass failed: %v", err)
			}
			if got := f.row(hidden).ProviderAbsentAt; got != before {
				t.Fatalf("a restricted credential's pass rewrote the observation: %q, want %q", got, before)
			}

			// Live control in the same run: the same fixture with a credential whose
			// payload states account-wide scope, and an honest listing whose size matches
			// the account, records the genuinely absent server.
			f.provider.setAccountScopeAccountWide()
			f.provider.set(inventoryJSON(501))
			f.provider.answerPerServer(502, http.StatusNotFound)
			if err := f.reconcile(context.Background()); err != nil {
				t.Fatalf("control pass failed: %v", err)
			}
			if !f.row(hidden).ProviderAbsent() {
				t.Fatal("a full-scope credential with an honest listing did not record an absent server")
			}
			if f.row(listed).ProviderAbsent() {
				t.Fatal("the control pass marked a listed server absent")
			}
		})
	}
}

// The authority dimension on its own: with the counts corroborating (equal), only a
// payload that states account-wide scope may certify.
func TestReconcileGigahostInventory_ScopeAuthorityIsTheCertificate(t *testing.T) {
	cases := []struct {
		name       string
		scope      func(f *inventoryFixture)
		wantAbsent bool
	}{
		{
			name:       "stated account-wide",
			scope:      func(f *inventoryFixture) { f.provider.setAccountScopeAccountWide() },
			wantAbsent: true,
		},
		{
			name:       "stated restriction with ids",
			scope:      func(f *inventoryFixture) { f.provider.setAccountScopeRestricted(501) },
			wantAbsent: false,
		},
		{
			name:       "no permissions object at all",
			scope:      func(f *inventoryFixture) { f.provider.setAccountScopeUnstated() },
			wantAbsent: false,
		},
		{
			name: "servers permission without an all flag states nothing",
			scope: func(f *inventoryFixture) {
				f.provider.permissions = `{"servers":{"mode":"r"}}`
			},
			wantAbsent: false,
		},
		{
			name: "a contradiction (all:true beside ids) is read as restricted",
			scope: func(f *inventoryFixture) {
				f.provider.permissions = `{"servers":{"mode":"r","all":true,"ids":[501]}}`
			},
			wantAbsent: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newInventoryFixture(t)
			gone := f.seedServer("Gone", providerProtocols(502))
			tc.scope(f)
			// The listing and the account agree on one server, so the count comparison
			// corroborates; only the credential's scope differs between the cases.
			f.provider.set(inventoryJSON(501))
			f.provider.setAccountServers(1)
			if err := f.reconcile(context.Background()); err != nil {
				t.Fatalf("reconciliation pass failed: %v", err)
			}
			if got := f.row(gone).ProviderAbsent(); got != tc.wantAbsent {
				t.Fatalf("absence = %v, want %v", got, tc.wantAbsent)
			}
		})
	}
}

// Corroboration is still required: account-wide scope with a disagreement between the
// listing and the account summary certifies nothing.
func TestReconcileGigahostInventory_ScopeAloneDoesNotCertify(t *testing.T) {
	cases := []struct {
		name        string
		listed      string
		accountSize int
	}{
		{name: "listing smaller than the account", listed: inventoryJSON(501), accountSize: 2},
		{name: "listing larger than the account", listed: inventoryJSON(501, 502), accountSize: 1},
		{name: "summary unavailable", listed: inventoryJSON(501), accountSize: -1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newInventoryFixture(t)
			gone := f.seedServer("Gone", providerProtocols(502))
			f.provider.setAccountScopeAccountWide()
			f.provider.set(tc.listed)
			f.provider.setAccountServers(tc.accountSize)
			if err := f.reconcile(context.Background()); err != nil {
				t.Fatalf("reconciliation pass failed: %v", err)
			}
			if f.row(gone).ProviderAbsent() {
				t.Fatal("the credential's scope alone certified an uncorroborated listing")
			}
		})
	}
}
