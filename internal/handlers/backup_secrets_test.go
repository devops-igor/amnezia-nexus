package handlers

import (
	"reflect"
	"testing"
)

// TestRedactBackupSettings proves the export scrub is complete and does not
// mutate the map it was handed. Issue #343: the "credential-free" export carried
// a decrypted TLS private key.
func TestRedactBackupSettings(t *testing.T) {
	tests := []struct {
		name     string
		in       any
		expected any
	}{
		{
			name:     "ssl private key removed, public certificate kept",
			in:       map[string]any{"key_text": "canary-key", "cert_text": "canary-cert"},
			expected: map[string]any{"cert_text": "canary-cert"},
		},
		{
			name:     "telegram tokens removed, chat id kept",
			in:       map[string]any{"bot_token": "bot", "token": "tok", "chat_id": "42"},
			expected: map[string]any{"chat_id": "42"},
		},
		{
			name:     "provider api key removed",
			in:       map[string]any{"api_key": "key", "plan": "basic"},
			expected: map[string]any{"plan": "basic"},
		},
		{
			name:     "dotted legacy key is matched by its leaf name",
			in:       map[string]any{"gigahost.api_key": "key", "gigahost.plan": "basic"},
			expected: map[string]any{"gigahost.plan": "basic"},
		},
		{
			name: "nested maps and lists are scrubbed",
			in: map[string]any{
				"vpn_config": map[string]any{
					"private_key": "key",
					"peers":       []any{map[string]any{"secret": "s", "name": "peer-1"}},
				},
				"limits": map[string]any{"max_connections_per_user": 10},
			},
			expected: map[string]any{
				"vpn_config": map[string]any{
					"peers": []any{map[string]any{"name": "peer-1"}},
				},
				"limits": map[string]any{"max_connections_per_user": 10},
			},
		},
		{
			name:     "non-map value passes through",
			in:       "plain-setting",
			expected: "plain-setting",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redactBackupSettings(tt.in); !reflect.DeepEqual(got, tt.expected) {
				t.Fatalf("redactBackupSettings() = %#v, want %#v", got, tt.expected)
			}
		})
	}
}

func TestRedactBackupSettingsDoesNotMutateInput(t *testing.T) {
	input := map[string]any{
		"ssl": map[string]any{"key_text": "canary-key", "cert_text": "canary-cert"},
	}
	_ = redactBackupSettings(input)

	ssl, ok := input["ssl"].(map[string]any)
	if !ok {
		t.Fatalf("input ssl is not a map: %#v", input["ssl"])
	}
	if ssl["key_text"] != "canary-key" {
		t.Errorf("redaction mutated the caller's map: key_text = %#v", ssl["key_text"])
	}
}

// TestMergePreservingSecrets proves a credential-free backup cannot blank a
// live secret on restore, while a legacy backup that carries one still applies.
func TestMergePreservingSecrets(t *testing.T) {
	tests := []struct {
		name     string
		incoming any
		existing any
		expected any
	}{
		{
			name:     "omitted secret keeps the live value",
			incoming: map[string]any{"cert_text": "new-cert"},
			existing: map[string]any{"key_text": "live-key", "cert_text": "old-cert"},
			expected: map[string]any{"cert_text": "new-cert", "key_text": "live-key"},
		},
		{
			name:     "blank secret keeps the live value",
			incoming: map[string]any{"key_text": "", "cert_text": "new-cert"},
			existing: map[string]any{"key_text": "live-key", "cert_text": "old-cert"},
			expected: map[string]any{"key_text": "live-key", "cert_text": "new-cert"},
		},
		{
			name:     "incoming secret wins when present (legacy backup)",
			incoming: map[string]any{"key_text": "backup-key"},
			existing: map[string]any{"key_text": "live-key"},
			expected: map[string]any{"key_text": "backup-key"},
		},
		{
			name:     "blank secret with no live value stays absent",
			incoming: map[string]any{"key_text": ""},
			existing: nil,
			expected: map[string]any{"key_text": ""},
		},
		{
			name: "nested maps merge recursively",
			incoming: map[string]any{
				"vpn_config": map[string]any{"port": 51820, "private_key": ""},
			},
			existing: map[string]any{
				"vpn_config": map[string]any{"port": 443, "private_key": "live-key"},
			},
			expected: map[string]any{
				"vpn_config": map[string]any{"port": 51820, "private_key": "live-key"},
			},
		},
		{
			name:     "non-map incoming is returned unchanged",
			incoming: 42,
			existing: map[string]any{"key_text": "live-key"},
			expected: 42,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mergePreservingSecrets(tt.incoming, tt.existing); !reflect.DeepEqual(got, tt.expected) {
				t.Fatalf("mergePreservingSecrets() = %#v, want %#v", got, tt.expected)
			}
		})
	}
}

func TestIsBlankBackupValue(t *testing.T) {
	tests := []struct {
		value any
		blank bool
	}{
		{nil, true},
		{"", true},
		{"value", false},
		{false, false},
		{0, false},
		{[]any{}, false},
	}
	for _, tt := range tests {
		if got := isBlankBackupValue(tt.value); got != tt.blank {
			t.Errorf("isBlankBackupValue(%#v) = %v, want %v", tt.value, got, tt.blank)
		}
	}
}
