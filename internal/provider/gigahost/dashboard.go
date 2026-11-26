package gigahost

// The account summary (GET /dashboard).
//
// It exists here for one fact: the account-wide server count. The endpoint is
// documented as available "to every valid token and API key, regardless of its
// permissions", and `services` counts the account's own servers - unlike the server
// list, which a permission-limited key has filtered. That makes the summary the only
// documented, key-reachable statement about how many servers the account actually
// has, and therefore the only way the panel can tell a complete listing from a
// filtered one.
//
// Only the counts are decoded; nothing else from this endpoint is used, logged or
// stored.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// DashboardServices is the account summary's service counts.
type DashboardServices struct {
	Virtual   int
	Dedicated int
}

// ServerCount is the number of servers the account holds, whatever the request's
// key may be allowed to see.
func (s DashboardServices) ServerCount() int { return s.Virtual + s.Dedicated }

// Dashboard is the part of the account summary this panel uses.
type Dashboard struct {
	// ServicesPresent reports whether the response carried service counts at all.
	// A summary without them attests nothing.
	ServicesPresent bool
	Services        DashboardServices
}

// GetDashboard reads the account summary's service counts.
func (c *client) GetDashboard(ctx context.Context) (*Dashboard, error) {
	var rawData []byte
	if err := c.doRequest(ctx, http.MethodGet, "/dashboard", nil, &rawData); err != nil {
		return nil, fmt.Errorf("failed to read the account summary: %w", err)
	}
	dashboard, err := decodeDashboard(rawData)
	if err != nil {
		return nil, err
	}
	return dashboard, nil
}

// decodeDashboard reads the service counts out of an account summary.
//
// The documented shape is {"data":{"services":{"virtual":3,"dedicated":1,…}}}. The
// counts are accepted as JSON numbers or as numeric text, because this API mixes the
// two shapes elsewhere. A response without a services object is reported as absent
// rather than as zero: "the provider did not say" must never read as "the account has
// no servers".
func decodeDashboard(rawData []byte) (*Dashboard, error) {
	var envelope struct {
		Data struct {
			Services *struct {
				Virtual   json.RawMessage `json:"virtual"`
				Dedicated json.RawMessage `json:"dedicated"`
			} `json:"services"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rawData, &envelope); err != nil {
		return nil, fmt.Errorf("account summary is not a JSON object: %w", err)
	}
	if envelope.Data.Services == nil {
		return &Dashboard{ServicesPresent: false}, nil
	}
	dashboard := &Dashboard{ServicesPresent: true}
	var err error
	if dashboard.Services.Virtual, err = serviceCount(envelope.Data.Services.Virtual); err != nil {
		return nil, fmt.Errorf("account summary virtual server count: %w", err)
	}
	if dashboard.Services.Dedicated, err = serviceCount(envelope.Data.Services.Dedicated); err != nil {
		return nil, fmt.Errorf("account summary dedicated server count: %w", err)
	}
	return dashboard, nil
}

// serviceCount decodes one service count: a JSON number, numeric text, or absent
// (which counts as zero, since the other count still bounds the account).
func serviceCount(raw json.RawMessage) (int, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return 0, nil
	}
	if trimmed[0] == '"' {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return 0, err
		}
		trimmed = strings.TrimSpace(text)
		if trimmed == "" {
			return 0, nil
		}
	}
	count, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, fmt.Errorf("not a count: %s", trimmed)
	}
	if count < 0 {
		return 0, fmt.Errorf("negative count: %d", count)
	}
	return count, nil
}
