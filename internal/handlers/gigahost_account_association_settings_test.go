package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Keep the account unchanged so only the credential configuration is superseded.
// Exercise both the SQL epoch fence with a stable client and normal key resolution.
func TestAssociationSettingsSaveInvalidatesOldPreview(t *testing.T) {
	t.Run("StableClient", func(t *testing.T) { testAssociationSettingsSave(t, false) })
	t.Run("StoredCredential", func(t *testing.T) { testAssociationSettingsSave(t, true) })
}

func testAssociationSettingsSave(t *testing.T, resolveStored bool) {
	t.Helper()
	f := newInventoryFixture(t)
	if resolveStored {
		useStoredAssociationCredential(t, f)
	}
	row := f.seedLegacyServer("Legacy-deleted", 811)
	f.provider.set(inventoryJSON())
	f.provider.answerPerServer(811, http.StatusNotFound)

	saveAssociationKey(t, f, "flux_live_"+strings.Repeat("a", 64))
	preview := f.associationPreviewCall()
	if preview.Unlisted != 1 || preview.PreviewID == "" {
		t.Fatalf("preview = %+v, want one missing row and an authority", preview)
	}
	before := associationSettingsEpoch(t, f)
	saveAssociationKey(t, f, "flux_live_"+strings.Repeat("b", 64))
	after := associationSettingsEpoch(t, f)
	if after != before+1 {
		t.Errorf("settings save epoch = %d -> %d, want one increment", before, after)
	}
	t.Logf("Settings handler epoch: %d -> %d", before, after)

	rec := f.associationActionRaw(fmt.Sprintf(`{"preview_id":%q,"include_unlisted":true}`, preview.PreviewID))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "gigahost_association_configuration_changed") {
		t.Errorf("old confirmation = %d %s, want configuration-changed conflict", rec.Code, rec.Body.String())
	}
	if got := f.row(row); got.ProviderAccountKnown() || got.ProviderAbsent() {
		t.Fatalf("old confirmation changed durable state: account=%q absent=%t", got.ProviderAccountID, got.ProviderAbsent())
	}

	fresh := f.associationPreviewCall()
	if fresh.Unlisted != 1 || fresh.PreviewID == "" || fresh.PreviewID == preview.PreviewID {
		t.Fatalf("fresh preview = %+v, want a new authority for the missing row", fresh)
	}
	result := f.associationActionCallWithPreview(fresh.PreviewID, true)
	if result.Associated != 1 || result.Unlisted != 1 || result.Unattributed != 0 {
		t.Fatalf("fresh explicit confirmation = %+v", result)
	}
	if got := f.row(row); got.ProviderAccountID != fixtureAccount || got.ProviderAbsent() {
		t.Fatalf("fresh confirmation: account=%q absent=%t", got.ProviderAccountID, got.ProviderAbsent())
	}
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !f.row(row).ProviderAbsent() {
		t.Fatal("ordinary inventory did not mark the associated missing row absent")
	}
}

func useStoredAssociationCredential(t *testing.T, f *inventoryFixture) {
	t.Helper()
	t.Setenv("GIGAHOST_API_KEY", "")
	f.h.SetGigahostClient(nil)
	original := http.DefaultTransport
	http.DefaultTransport = durableRoundTripper(func(req *http.Request) (*http.Response, error) {
		// No request may leave the process; inspect the actual bearer key built
		// from the current SQLite setting before serving the provider fixture.
		if req.Method != http.MethodGet {
			return nil, fmt.Errorf("unexpected provider write")
		}
		if req.Header.Get("Authorization") != "Bearer "+f.h.gigahostCredential(req.Context(), nil) {
			return nil, fmt.Errorf("provider request used a stale credential")
		}
		local := req.Clone(req.Context())
		local.URL.Path = strings.TrimPrefix(req.URL.Path, "/api/v0")
		rec := httptest.NewRecorder()
		f.provider.handle(rec, local)
		return rec.Result(), nil
	})
	t.Cleanup(func() { http.DefaultTransport = original })
}

func saveAssociationKey(t *testing.T, f *inventoryFixture, key string) {
	t.Helper()
	rec := postSettingsSave(t, f.h, fmt.Sprintf(`{"gigahost":{"api_key":%q}}`, key))
	if rec.Code != http.StatusOK {
		t.Fatalf("Settings save = %d %s", rec.Code, rec.Body.String())
	}
	var stored struct {
		APIKey string `json:"api_key"`
	}
	if err := f.db.GetSetting(context.Background(), "gigahost", &stored); err != nil {
		t.Fatal(err)
	}
	if stored.APIKey != key {
		t.Fatal("Settings save did not persist the replacement credential")
	}
}

func associationSettingsEpoch(t *testing.T, f *inventoryFixture) int64 {
	t.Helper()
	epoch, err := f.db.GigahostConfigEpoch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return epoch
}
