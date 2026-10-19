package handlers

import (
	"context"
	"net/http"
	"testing"
)

func TestVPNUpdateConfigHandlerI1Protocol(t *testing.T) {
	for _, withService := range []bool{true, false} {
		name := "database"
		if withService {
			name = "service"
		}
		t.Run(name, func(t *testing.T) {
			f := newFlagFixture(t, withService)
			get := func() string {
				t.Helper()
				cfg, err := f.db.GetVPNConfig(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				return cfg.DataPlaneI1Protocol()
			}
			if got := get(); got != "sip" {
				t.Fatalf("default = %q", got)
			}
			f.putOK(t, `{"vpn_data_plane_i1_protocol":"dns"}`)
			if got := get(); got != "dns" {
				t.Fatalf("switched = %q", got)
			}
			f.putOK(t, `{"health_threshold_ms":750}`)
			if got := get(); got != "dns" {
				t.Fatalf("unrelated update changed protocol to %q", got)
			}
			if w := f.put(t, `{"vpn_data_plane_i1_protocol":"quic"}`); w.Code != http.StatusBadRequest {
				t.Fatalf("invalid protocol returned %d, want 400", w.Code)
			}
			if got := get(); got != "dns" {
				t.Fatalf("invalid update changed protocol to %q", got)
			}
		})
	}
}
