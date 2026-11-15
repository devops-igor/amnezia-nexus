package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

// This file implements the read-only policy dry run of issue #825:
// POST /api/vpn/policy/explain.
//
// Authorization and CSRF are deliberately not re-implemented here. The route is
// mounted inside the same /api/vpn/policy group as GET/PUT/sync/stats, so it
// inherits middleware.RequireAdmin and the router-wide CSRF middleware exactly
// as they are: a non-admin gets the same 403 the neighboring endpoints return,
// and an unauthenticated caller the same 401.
//
// Read-only is structural, not a promise: this handler only reads a request body
// and calls Service.ExplainPolicy, which itself only reads the published
// snapshot, load-free session evidence through SessionCache.Inspect, and the
// configured resolver. Nothing here writes; see vpn_pbr_policy_explain.go for
// the per-subsystem argument (no route-cache insertion, no evidence, no DNS
// interception, no flow, no counter movement).

const (
	// policyExplainMaxBodyBytes bounds the request body. The contract has one
	// name, one address or a short list, and an optional session id.
	policyExplainMaxBodyBytes = 8 << 10
	// policyExplainMaxAddresses bounds how many addresses one answer evaluates,
	// so a single request cannot drive an unbounded per-address scan.
	policyExplainMaxAddresses = 8
	// policyExplainMaxSessionID bounds the session selector.
	policyExplainMaxSessionID = 128
	// policyExplainTimeout bounds the whole request including the ad-hoc lookup,
	// and stays above the lookup's own default budget.
	policyExplainTimeout = 5 * time.Second
)

// policyExplainRequest is the accepted request body. A name, an address or a
// list of addresses is required; session_id only selects whose evidence is read.
type policyExplainRequest struct {
	Domain    string   `json:"domain"`
	IP        string   `json:"ip"`
	IPs       []string `json:"ips"`
	SessionID string   `json:"session_id"`
}

// ExplainPolicyHandler serves POST /api/vpn/policy/explain.
func (h *Handlers) ExplainPolicyHandler(w http.ResponseWriter, r *http.Request) {
	if h.vpnSvc == nil {
		h.JSONError(w, http.StatusServiceUnavailable, "unavailable", "VPN data plane is not available")
		return
	}

	req, ok := h.decodePolicyExplain(w, r)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), policyExplainTimeout)
	defer cancel()

	explanation, err := h.vpnSvc.ExplainPolicy(ctx, req)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to explain the routing decision: "+err.Error())
		return
	}
	h.JSON(w, http.StatusOK, explanation)
}

// decodePolicyExplain reads and validates the body. It writes the error
// response itself and reports whether the caller may proceed.
//
// Every rejection is specific, because the operator is debugging a policy and a
// generic "invalid input" would hide which field was wrong. The body-limit rules
// and the semantic validation are separate steps so each one stays readable.
func (h *Handlers) decodePolicyExplain(w http.ResponseWriter, r *http.Request) (vpn.PolicyExplainRequest, bool) {
	raw, ok := h.readPolicyExplainBody(w, r)
	if !ok {
		return vpn.PolicyExplainRequest{}, false
	}
	var body policyExplainRequest
	if err := json.Unmarshal(raw, &body); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return vpn.PolicyExplainRequest{}, false
	}

	out, rejection := buildPolicyExplainRequest(body)
	if rejection != "" {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", rejection)
		return vpn.PolicyExplainRequest{}, false
	}
	return out, true
}

// readPolicyExplainBody applies the body limits and reports a specific reason.
func (h *Handlers) readPolicyExplainBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r == nil || r.Body == nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Request body is empty")
		return nil, false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, policyExplainMaxBodyBytes+1))
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return nil, false
	}
	defer func() { _ = r.Body.Close() }()
	switch {
	case len(raw) == 0:
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Request body is empty")
		return nil, false
	case len(raw) > policyExplainMaxBodyBytes:
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Request body is too large")
		return nil, false
	}
	return raw, true
}

// buildPolicyExplainRequest turns a decoded body into a validated request, or
// returns the operator-facing rejection. It is pure so each rule can be read
// and tested on its own.
func buildPolicyExplainRequest(body policyExplainRequest) (vpn.PolicyExplainRequest, string) {
	out := vpn.PolicyExplainRequest{SessionID: strings.TrimSpace(body.SessionID)}
	if len(out.SessionID) > policyExplainMaxSessionID {
		return vpn.PolicyExplainRequest{}, "session_id is longer than 128 characters"
	}

	rawName := strings.TrimSpace(body.Domain)
	if rawName != "" {
		normalized, normErr := policy.NormalizeDomain(rawName)
		if normErr != nil {
			return vpn.PolicyExplainRequest{}, "domain: " + normErr.Error()
		}
		out.Name = normalized
	}

	addresses, addrErr := parsePolicyExplainAddresses(body.IP, body.IPs)
	if addrErr != "" {
		return vpn.PolicyExplainRequest{}, addrErr
	}
	if out.Name == "" && len(addresses) == 0 {
		return vpn.PolicyExplainRequest{}, "a domain name or at least one address is required"
	}

	out.Addresses = addresses
	out.Value = policyExplainInputValue(rawName, body.IP, body.IPs)
	return out, ""
}

// policyExplainInputValue echoes what the operator typed, preferring the name
// they entered and falling back to their address input.
func policyExplainInputValue(rawName, single string, list []string) string {
	if rawName != "" {
		return rawName
	}
	if joined := strings.Join(list, ", "); joined != "" {
		return joined
	}
	return strings.TrimSpace(single)
}

// parsePolicyExplainAddresses parses ip and ips into distinct IPv4 addresses.
// It returns a specific message on rejection.
func parsePolicyExplainAddresses(single string, list []string) ([]netip.Addr, string) {
	candidates := make([]string, 0, len(list)+1)
	if trimmed := strings.TrimSpace(single); trimmed != "" {
		candidates = append(candidates, trimmed)
	}
	for _, raw := range list {
		if trimmed := strings.TrimSpace(raw); trimmed != "" {
			candidates = append(candidates, trimmed)
		}
	}
	if len(candidates) > policyExplainMaxAddresses {
		return nil, "at most 8 addresses may be evaluated per request"
	}

	out := make([]netip.Addr, 0, len(candidates))
	seen := make(map[netip.Addr]struct{}, len(candidates))
	for _, raw := range candidates {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, "ip: " + raw + " is not a valid address"
		}
		addr = addr.Unmap()
		if !addr.Is4() {
			// IPv6 evaluation is out of scope for policy routing and is stated in
			// the answer's limitations; accepting it would imply a verdict the
			// data path cannot produce.
			return nil, "ip: " + raw + " is not IPv4; policy routing evaluates IPv4 only"
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out, ""
}
