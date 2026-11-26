package handlers

// Identity crossed with durable effect.
//
// The reconciliation pass compares a stored row against the ids a listing names, so an id
// the decoder coerces into a neighbouring value does not merely mislabel a response: the
// pass then CLEARS a real server's mark and RECORDS absence on another row from the same
// unusable listing. This file crosses every reachable wire shape for a server id with the
// two durable outcomes and states the required outcome per cell.
//
// | wire shape for the entry id      | required outcome                                  |
// |----------------------------------|---------------------------------------------------|
// | integer, in range                | usable: listed row is cleared / omitted row marked |
// | numeric string                   | usable: same as an integer (documented shape)      |
// | whole number with a decimal point| usable: same identity, nothing else changes        |
// | fractional (501.5)               | unusable: pass fails, no mark set, no mark cleared |
// | outside int64                    | unusable: pass fails, no mark set, no mark cleared |
// | non-numeric string               | unusable: pass fails, no mark set, no mark cleared |
// | null                             | unusable (names no server): pass fails, nothing    |
// | absent                           | unusable (names no server): pass fails, nothing    |
// | boolean / object / array         | unusable: pass fails, no mark set, no mark cleared |
// | duplicate of a listed id         | unusable (ambiguous): pass fails, nothing          |
// | a different server's id          | usable, but it names that server: this row stays   |
// |                                  | unlisted, so the omission rule applies to it       |
//
// Every case runs the real client against the fixture over HTTP and reads the outcomes back
// from SQLite, so a decode shortcut cannot hide behind a stubbed client.

import (
	"context"
	"testing"
	"time"
)

// listingWithRawID builds a one-page listing whose single entry uses the given raw JSON
// token as its server id. An empty literal omits the id field entirely.
func listingWithRawID(idLiteral string) string {
	if idLiteral == "" {
		return `{"meta":{"page":1,"total_pages":1,"total":1},"data":[{"status":"active"}]}`
	}
	return `{"meta":{"page":1,"total_pages":1,"total":1},"data":[{"srv_id":` + idLiteral + `,"status":"active"}]}`
}

func TestReconcileGigahostInventory_IdentityStateSpace(t *testing.T) {
	type outcome struct {
		// wantListedMarkKept: the listed row starts WITH a mark, so "kept" means a
		// durable clear was reached and "cleared" means the usable listing named it.
		wantListedMarkKept bool
		// wantOmittedMarked: the omitted row starts WITHOUT a mark, so a true value
		// can only mean this pass set one.
		wantOmittedMarked bool
		wantErr           bool
	}

	cases := []struct {
		name      string
		idLiteral string
		want      outcome
		wantNote  string
	}{
		{
			name:      "integer in range",
			idLiteral: `501`,
			want:      outcome{wantListedMarkKept: false, wantOmittedMarked: true},
		},
		{
			name:      "numeric string",
			idLiteral: `"501"`,
			want:      outcome{wantListedMarkKept: false, wantOmittedMarked: true},
		},
		{
			name:      "whole number with a decimal point",
			idLiteral: `501.0`,
			want:      outcome{wantListedMarkKept: false, wantOmittedMarked: true},
		},
		{
			name:      "fractional id",
			idLiteral: `501.5`,
			want:      outcome{wantListedMarkKept: true, wantErr: true},
			wantNote:  "a fractional id must not be truncated into 501",
		},
		{
			name:      "id outside int64",
			idLiteral: `92233720368547758080`,
			want:      outcome{wantListedMarkKept: true, wantErr: true},
		},
		{
			name:      "non-numeric string id",
			idLiteral: `"not-a-server"`,
			want:      outcome{wantListedMarkKept: true, wantErr: true},
		},
		{
			name:      "null id",
			idLiteral: `null`,
			want:      outcome{wantListedMarkKept: true, wantErr: true},
		},
		{
			name:      "absent id",
			idLiteral: ``,
			want:      outcome{wantListedMarkKept: true, wantErr: true},
		},
		{
			name:      "boolean id",
			idLiteral: `true`,
			want:      outcome{wantListedMarkKept: true, wantErr: true},
		},
		{
			name:      "object id",
			idLiteral: `{"value":501}`,
			want:      outcome{wantListedMarkKept: true, wantErr: true},
		},
		{
			name:      "array id",
			idLiteral: `[501]`,
			want:      outcome{wantListedMarkKept: true, wantErr: true},
		},
		{
			name:      "a different server's id",
			idLiteral: `503`,
			want:      outcome{wantListedMarkKept: true, wantOmittedMarked: true},
			wantNote:  "503 is a usable identity that names another server, so 501 is simply omitted",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newInventoryFixture(t)
			listed := f.seedServer("Listed", providerProtocols(501))
			omitted := f.seedServer("Omitted", providerProtocols(502))

			// Only the listed row carries a mark; the omitted one does not, so a mark
			// appearing there is this pass's own doing.
			recorded := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
			if err := f.db.SetServerProviderAbsence(context.Background(), listed, recorded, fixtureAccount); err != nil {
				t.Fatalf("failed to seed the mark: %v", err)
			}

			f.provider.set(listingWithRawID(tc.idLiteral))
			err := f.reconcile(context.Background())
			if tc.want.wantErr && err == nil {
				t.Fatalf("an unusable identity was accepted as an answer (%s)", tc.wantNote)
			}
			if !tc.want.wantErr && err != nil {
				t.Fatalf("a usable identity was refused: %v", err)
			}

			// No mark may be SET on the omitted row, and the listed row's mark may only be
			// cleared when the entry actually named it.
			if got := f.row(listed).ProviderAbsent(); got != tc.want.wantListedMarkKept {
				t.Fatalf("listed row still marked = %v, want %v", got, tc.want.wantListedMarkKept)
			}
			if got := f.row(omitted).ProviderAbsent(); got != tc.want.wantOmittedMarked {
				t.Fatalf("omitted row marked = %v, want %v (a mark was set from this listing)", got, tc.want.wantOmittedMarked)
			}
			if kept := f.row(listed).ProviderAbsentAccountID; tc.want.wantListedMarkKept && kept != fixtureAccount {
				t.Fatalf("a kept mark lost its observing account: %q", kept)
			}

			// The recorded observing account moves only with the mark, so a false clear is
			// visible even when the timestamp is later rewritten.
			if !tc.want.wantListedMarkKept && f.row(listed).ProviderAbsentAccountID != "" {
				t.Fatalf("a cleared mark kept its observing account: %q", f.row(listed).ProviderAbsentAccountID)
			}

			// Control in the same run: the same two rows, the same pass, a usable listing.
			f.provider.set(inventoryJSON(501))
			if err := f.reconcile(context.Background()); err != nil {
				t.Fatalf("control pass failed: %v", err)
			}
			if f.row(listed).ProviderAbsent() {
				t.Fatal("the control pass did not clear the listed row")
			}
			if !f.row(omitted).ProviderAbsent() {
				t.Fatal("the control pass did not mark the omitted row")
			}
		})
	}
}

// A duplicate id is ambiguous rather than merely unusual: the pass must not pick one of the
// two entries and act on it.
func TestReconcileGigahostInventory_DuplicateIdentityChangesNothing(t *testing.T) {
	f := newInventoryFixture(t)
	listed := f.seedServer("Listed", providerProtocols(501))
	omitted := f.seedServer("Omitted", providerProtocols(502))

	recorded := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	for _, id := range []int64{listed, omitted} {
		if err := f.db.SetServerProviderAbsence(context.Background(), id, recorded, fixtureAccount); err != nil {
			t.Fatalf("failed to seed the mark: %v", err)
		}
	}

	f.provider.set(`{"meta":{"page":1,"total_pages":1,"total":2},"data":[{"srv_id":501,"status":"active"},{"srv_id":501,"status":"active"}]}`)
	if err := f.reconcile(context.Background()); err == nil {
		t.Fatal("a listing naming the same server twice was accepted")
	}
	if !f.row(listed).ProviderAbsent() {
		t.Fatal("an ambiguous listing cleared a mark")
	}
	if !f.row(omitted).ProviderAbsent() {
		t.Fatal("an ambiguous listing changed the other row")
	}
}
