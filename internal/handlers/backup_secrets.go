package handlers

import "strings"

// BackupFormatVersion identifies the JSON backup payload contract.
//
//	0/absent — legacy export written before issue #343. It could carry
//	           decrypted panel secrets and must be handled as sensitive.
//	2        — credential-free export: panel credentials are omitted, so a
//	           restored panel keeps its live secrets and the operator re-enters
//	           anything that only existed in the file.
//
// Restore accepts 0..BackupFormatVersion and rejects anything newer, so an
// older panel cannot silently misread a payload written by a newer one.
const BackupFormatVersion = 2

// backupSecretFieldNames are the settings field names that can carry a
// credential. Matching is by exact leaf name — dotted legacy keys such as
// "gigahost.api_key" are reduced to their last segment.
var backupSecretFieldNames = map[string]bool{
	"key_text":              true, // ssl.key_text: TLS private key
	"private_key":           true, // generic request/legacy shape
	"server_private_key":    true, // vpn_config: portal Curve25519 private key
	"header_protection_key": true, // vpn_config + AWG backend metadata
	"headerprotectionkey":   true, // AWG metadata alias (HeaderProtectionKey)
	"hpkey":                 true, // AWG metadata alias
	"api_key":               true, // gigahost.api_key
	"bot_token":             true, // telegram.bot_token
	"token":                 true, // telegram.token and other bearer tokens
	"share_token":           true,
	"password":              true,
	"password_hash":         true,
	"secret":                true,
}

// backupSecretSuffixes catch future field names built from the same vocabulary
// (for example server_private_key). Exact names alone drifted from production
// once already: the scrub knew "private_key" while the persisted portal field is
// "server_private_key". A suffix keeps a new *_private_key or *_api_key secret
// from leaking by being added after this list was written.
var backupSecretSuffixes = []string{
	"_private_key",
	"_api_key",
	"_secret",
	"_token",
	"_password",
	"_password_hash",
}

// isBackupSecretField reports whether a settings field name carries a credential.
func isBackupSecretField(key string) bool {
	leaf := strings.ToLower(key)
	if i := strings.LastIndex(leaf, "."); i >= 0 {
		leaf = leaf[i+1:]
	}
	if backupSecretFieldNames[leaf] {
		return true
	}
	for _, suffix := range backupSecretSuffixes {
		if strings.HasSuffix(leaf, suffix) {
			return true
		}
	}
	return false
}

// redactBackupSettings returns a deep copy of a settings value with every
// credential-bearing field removed.
//
// The export is a metadata artifact: a removed field is unambiguous, and restore
// keeps the live value (see mergePreservingSecrets) instead of blanking it.
// Over-redaction is safe here; under-redaction is the defect.
func redactBackupSettings(value any) any {
	switch node := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(node))
		for key, child := range node {
			if isBackupSecretField(key) {
				continue
			}
			out[key] = redactBackupSettings(child)
		}
		return out
	case []any:
		out := make([]any, len(node))
		for i, child := range node {
			out[i] = redactBackupSettings(child)
		}
		return out
	default:
		return value
	}
}

// mergePreservingSecrets overlays an incoming settings value on the live value,
// keeping the live credential whenever the incoming one is absent or blank.
//
// A credential-free export therefore cannot blank a working TLS key or bot
// token, and a legacy export that still carries the plaintext value keeps it.
func mergePreservingSecrets(incoming, existing any) any {
	inMap, ok := incoming.(map[string]any)
	if !ok {
		return incoming
	}
	exMap, _ := existing.(map[string]any)

	merged := make(map[string]any, len(inMap))
	for key, value := range inMap {
		merged[key] = mergeSettingField(key, value, exMap[key])
	}
	// A redacted export omits the field entirely; keep the live one.
	for key, value := range exMap {
		if _, present := inMap[key]; present {
			continue
		}
		if isBackupSecretField(key) {
			merged[key] = value
		}
	}
	return merged
}

// mergeSettingField decides one settings field: keep the live credential when
// the backup omitted or blanked it, otherwise take the backup's value (a legacy
// export that still carries a plaintext secret keeps it).
func mergeSettingField(key string, incoming, existing any) any {
	if isBackupSecretField(key) && isBlankBackupValue(incoming) && !isBlankBackupValue(existing) {
		return existing
	}
	return mergePreservingSecrets(incoming, existing)
}

// isBlankBackupValue reports whether a decoded JSON value carries no value.
// Only absent/nil/empty-string count: false and 0 are real values.
func isBlankBackupValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return typed == ""
	}
	return false
}
