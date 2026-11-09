package gigahost

// SSH public keys on the account, per the documented provider contract
// (GET /account -> data.sshkeys[], POST /account/sshkey).
//
// The documented behavior that shapes this file:
//
//   - Registration returns no identifier: "Returns 200 on success; the new key
//     and its key_id are listed in GET /account". So a caller can only learn the
//     id it must pass to an order by reading the account back.
//   - Order and reinstall accept ssh_keys as *numeric* ids and silently ignore
//     "keys that are not yours". An unverified id therefore does not fail the
//     order; it buys a server nobody can log into. That is why the association
//     must be proven against a listing before the order is dispatched.
//   - key_id and key_added are returned as strings ("Numbers read from the
//     account are mostly returned as strings"), while ssh_keys in an order body
//     is numeric.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// ErrSSHKeyUnverified reports that a registration request had an ambiguous
// outcome (timeout, 5xx, undecodable reply) and the key could not be found in
// the account listing afterwards. It is explicitly NOT evidence that the key is
// missing: the provider may have registered it. Callers must not blindly retry.
var ErrSSHKeyUnverified = errors.New("ssh key registration outcome unverified")

// SSHKeyInfo is one entry of the documented GET /account data.sshkeys list.
//
// KeyData is the full OpenSSH public key line as the account stores it
// (type, base64 blob and usually a trailing comment). Only type and blob are
// compared, because the documentation does not promise that the comment round
// trips unchanged.
type SSHKeyInfo struct {
	KeyID    string `json:"key_id"`
	CustID   string `json:"cust_id"`
	KeyName  string `json:"key_name"`
	KeyAdded string `json:"key_added"`
	KeyData  string `json:"key_data"`
}

// ID parses the documented string key_id into the numeric id an order needs.
func (k SSHKeyInfo) ID() (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(k.KeyID), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("account returned a non-numeric ssh key id %q", k.KeyID)
	}
	return id, nil
}

// ListSSHKeys returns the keys registered on the authenticated account by
// reading GET /account.
//
// This deliberately does not reuse GetAccount: that decode exists for the
// credit/eligibility contract and has several fallback shapes for it. Mixing
// key-material decoding into it would let a key-shape change break credit reads
// (and the reverse). Same documented endpoint, separate concern.
func (c *client) ListSSHKeys(ctx context.Context) ([]SSHKeyInfo, error) {
	var raw []byte
	if err := c.doRequest(ctx, http.MethodGet, "/account", nil, &raw); err != nil {
		return nil, fmt.Errorf("failed to read account ssh keys: %w", err)
	}
	keys, err := parseAccountSSHKeys(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to decode account ssh keys: %w", err)
	}
	return keys, nil
}

// parseAccountSSHKeys extracts data.sshkeys, also tolerating a top-level
// sshkeys object for a payload that omits the data envelope.
func parseAccountSSHKeys(raw []byte) ([]SSHKeyInfo, error) {
	var envelope struct {
		Data struct {
			SSHKeys []SSHKeyInfo `json:"sshkeys"`
		} `json:"data"`
		SSHKeys []SSHKeyInfo `json:"sshkeys"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if envelope.Data.SSHKeys != nil {
		return envelope.Data.SSHKeys, nil
	}
	return envelope.SSHKeys, nil
}

// RegisterSSHKey adds a public key to the account via POST /account/sshkey.
//
// The reply carries no id, so success here only means "the provider accepted the
// request". The caller must confirm the key is listed before using it.
func (c *client) RegisterSSHKey(ctx context.Context, name, publicKey string) error {
	body := map[string]string{
		"name": strings.TrimSpace(name),
		"data": strings.TrimSpace(publicKey),
	}
	if body["name"] == "" {
		return errors.New("ssh key name is required")
	}
	if body["data"] == "" {
		return errors.New("ssh public key is required")
	}
	var raw []byte
	if err := c.doRequest(ctx, http.MethodPost, "/account/sshkey", body, &raw); err != nil {
		return err
	}
	return nil
}

// ManagedKeyName is the account label for managed key material.
//
// Derived from the key itself, so the same material always produces the same
// label, and restricted to the documented label alphabet (letters, digits,
// space and - _ . @) so the provider cannot reject it as an invalid name.
func ManagedKeyName(publicKey string) (string, error) {
	normalized, err := NormalizeAuthorizedKey(publicKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(normalized))
	return "nexus-" + hex.EncodeToString(sum[:8]), nil
}

// NormalizeAuthorizedKey reduces an OpenSSH public key line to "type base64blob".
//
// Deliberately implemented without an SSH library: the documented provider key
// types include algorithms a Go SSH parser may refuse (ssh-dss among them), and
// nothing here verifies a signature. It only has to compare key material we
// generated ourselves and to reject a line that is not a public key at all, which
// the base64 round trip establishes.
func NormalizeAuthorizedKey(line string) (string, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return "", errors.New("not an OpenSSH public key line")
	}
	keyType, blob := fields[0], fields[1]
	if !strings.HasPrefix(keyType, "ssh-") && !strings.HasPrefix(keyType, "ecdsa-") && !strings.HasPrefix(keyType, "sk-") {
		return "", fmt.Errorf("unsupported public key type %q", keyType)
	}
	decoded, err := base64.StdEncoding.DecodeString(blob)
	if err != nil || len(decoded) == 0 {
		return "", errors.New("public key blob is not valid base64")
	}
	canonical := base64.StdEncoding.EncodeToString(decoded)
	return keyType + " " + canonical, nil
}

// AuthorizedKeyMatches reports whether two key lines carry the same type and
// blob. The comment is ignored: the documentation does not state that it is
// preserved on registration.
func AuthorizedKeyMatches(a, b string) bool {
	na, errA := NormalizeAuthorizedKey(a)
	nb, errB := NormalizeAuthorizedKey(b)
	if errA != nil || errB != nil {
		return false
	}
	return na == nb
}

// FindSSHKeyByMaterial returns the account entry whose key material matches the
// given public key line.
func FindSSHKeyByMaterial(keys []SSHKeyInfo, publicKey string) (SSHKeyInfo, bool) {
	for _, key := range keys {
		if AuthorizedKeyMatches(key.KeyData, publicKey) {
			return key, true
		}
	}
	return SSHKeyInfo{}, false
}

// IsRegistrationAmbiguous reports whether a registration error leaves the
// outcome unknown: the provider may or may not have stored the key.
//
// A 4xx answer is a decision ("invalid name", "SSH-key invalid") and is not
// ambiguous. A timeout, transport failure, 5xx or an undecodable reply is.
func IsRegistrationAmbiguous(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 {
			return false
		}
		return true
	}
	if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrRateLimited) {
		return false
	}
	return true
}
