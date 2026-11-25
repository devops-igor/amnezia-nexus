package handlers

// The provider account a client acts for, and how it is recorded.
//
// A successful inventory read enumerates one account, so absence may only be
// recorded for rows provisioned under that account. These helpers produce the
// account identity and never touch the credential: the API key, any secret and
// every request header stay out of the stored value.

import (
	"context"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// gigahostAccountIdentity returns the account identifier of a provider account
// read.
//
// The customer id is preferred because it is the identifier the provider also
// reports per server, so an inventory answer and a row association are comparable.
// The account id is the fallback for responses that carry only that. An empty
// result means the provider did not name the account: every caller must treat
// that as unknown rather than as a match, because an unknown association may never
// justify a durable absence.
func gigahostAccountIdentity(account *gigahost.AccountInfo) string {
	if account == nil {
		return ""
	}
	if custID := strings.TrimSpace(account.CustID); custID != "" {
		return custID
	}
	return strings.TrimSpace(account.ID)
}

// gigahostServerAccount returns the account the provider says owns one of its
// servers, or "" when the provider does not say.
//
// This is the association a registration records, and it is deliberately a read of
// the provisioning's own server rather than of the configured account: the answer
// belongs to that server. A key whose visibility does not cover the server is
// refused, so the association stays unknown instead of borrowing whichever account
// happens to be configured at registration time.
func (h *Handlers) gigahostServerAccount(ctx context.Context, client gigahost.Client, providerServerID int64) string {
	if client == nil || providerServerID <= 0 {
		return ""
	}
	server, err := client.GetServer(ctx, providerServerID)
	if err != nil || server == nil {
		return ""
	}
	return strings.TrimSpace(server.CustID.String())
}
