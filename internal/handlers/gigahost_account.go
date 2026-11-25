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

// gigahostAccountIdentity returns the provider-issued identifier of the account a
// client acts for: the account id the API reports, falling back to the customer id
// it reports beside it.
//
// It is an opaque account identifier, never the API key, a secret or a request
// header, so recording it cannot replay a credential. An empty result means the
// provider did not name the account: every caller must treat that as unknown
// rather than as a match, because an unknown association may never justify a
// durable absence.
func gigahostAccountIdentity(account *gigahost.AccountInfo) string {
	if account == nil {
		return ""
	}
	if id := strings.TrimSpace(account.ID); id != "" {
		return id
	}
	return strings.TrimSpace(account.CustID)
}

// gigahostAccountFor resolves the account identity of a provider client, or ""
// when the provider cannot name it. A failed account read is not fatal: the caller
// records the association as unknown, which keeps that row out of every absence
// decision while leaving the deployment itself intact.
func (h *Handlers) gigahostAccountFor(ctx context.Context, client gigahost.Client) string {
	if client == nil {
		return ""
	}
	account, err := client.GetAccount(ctx)
	if err != nil {
		return ""
	}
	return gigahostAccountIdentity(account)
}
