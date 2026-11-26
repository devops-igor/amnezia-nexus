package handlers

// Fixtures for the one-time account association tests: seeding a legacy row, driving
// the two endpoints as a given role, and decoding the answers. They live in their own
// file so the behavioural cases stay focused and each file stays within the size rule.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// associationReasonCount mirrors one entry of a response's reasons list.
type associationReasonCount struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// associationPreview mirrors the preview response.
type associationPreview struct {
	Candidates   int                      `json:"candidates"`
	AlreadyBound int                      `json:"already_bound"`
	Attributable int                      `json:"attributable"`
	Unlisted     int                      `json:"unlisted"`
	Unattributed int                      `json:"unattributed"`
	Reasons      []associationReasonCount `json:"reasons"`
}

// associationResult mirrors the action response.
type associationResult struct {
	Associated   int                      `json:"associated"`
	Unlisted     int                      `json:"unlisted"`
	AlreadyBound int                      `json:"already_bound"`
	Unattributed int                      `json:"unattributed"`
	Reasons      []associationReasonCount `json:"reasons"`
}

// seedLegacyServer registers a provider-provisioned row the way a deployment that
// predates the account column did: the provider server id is recorded, the account
// is not.
func (f *inventoryFixture) seedLegacyServer(name string, providerServerID int64) int64 {
	id, err := f.db.CreateServer(context.Background(), &models.Server{
		Name:      name,
		Host:      "198.51.100.11",
		SSHUser:   "root",
		SSHPort:   22,
		Protocols: providerProtocols(providerServerID),
	})
	if err != nil {
		f.t.Fatalf("failed to seed a legacy server %q: %v", name, err)
	}
	return id
}

// seedServerUnderAccount registers a provider-provisioned row that already records
// the account it belongs to, which is what a deployment on this build does.
func (f *inventoryFixture) seedServerUnderAccount(name string, providerServerID int64, account string) int64 {
	id, err := f.db.CreateServer(context.Background(), &models.Server{
		Name:              name,
		Host:              "198.51.100.12",
		SSHUser:           "root",
		SSHPort:           22,
		Protocols:         providerProtocols(providerServerID),
		ProviderAccountID: account,
	})
	if err != nil {
		f.t.Fatalf("failed to seed server %q under %q: %v", name, account, err)
	}
	return id
}

// associationRequest builds one request to an association endpoint as the given
// role, with the session the handlers' own role check reads.
func (f *inventoryFixture) associationRequest(method, body string, role models.UserRole) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/admin/hosting/gigahost/account-association", strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "admin-1",
		Role:   role,
	}))
	rec := httptest.NewRecorder()
	if method == http.MethodGet {
		f.h.GigahostAccountAssociationPreviewHandler(rec, req)
	} else {
		f.h.GigahostAccountAssociationHandler(rec, req)
	}
	return rec
}

// associationPreviewCall runs the preview and decodes it.
func (f *inventoryFixture) associationPreviewCall() associationPreview {
	rec := f.associationRequest(http.MethodGet, "", models.RoleAdmin)
	if rec.Code != http.StatusOK {
		f.t.Fatalf("association preview returned %d: %s", rec.Code, rec.Body.String())
	}
	var preview associationPreview
	if err := json.Unmarshal(rec.Body.Bytes(), &preview); err != nil {
		f.t.Fatalf("failed to decode the association preview: %v (%s)", err, rec.Body.String())
	}
	return preview
}

// associationActionCall runs the action and decodes its outcome.
func (f *inventoryFixture) associationActionCall(includeUnlisted bool) associationResult {
	body := fmt.Sprintf(`{"include_unlisted":%t}`, includeUnlisted)
	rec := f.associationRequest(http.MethodPost, body, models.RoleAdmin)
	if rec.Code != http.StatusOK {
		f.t.Fatalf("association action returned %d: %s", rec.Code, rec.Body.String())
	}
	var result associationResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		f.t.Fatalf("failed to decode the association outcome: %v (%s)", err, rec.Body.String())
	}
	return result
}
