package config

import (
	"os"
	"testing"
)

// TestCookieInsecureEnvOverride covers COOKIE_INSECURE parsing: only explicit
// truthy values ("1", "true", ...) enable the dev override; unset or invalid
// values keep it off.
func TestCookieInsecureEnvOverride(t *testing.T) {
	tmpDir := t.TempDir()

	cases := []struct {
		raw  string
		want bool
	}{
		{"", false},
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"0", false},
		{"false", false},
		{"no", false},
		{"garbage", false},
		{" 1 ", true},
	}

	for _, tc := range cases {
		t.Run("value="+tc.raw, func(t *testing.T) {
			os.Unsetenv("SECRET_KEY")
			os.Unsetenv("COOKIE_INSECURE")
			os.Setenv("DATA_DIR", tmpDir)
			defer os.Unsetenv("DATA_DIR")

			if tc.raw != "" {
				os.Setenv("COOKIE_INSECURE", tc.raw)
				defer os.Unsetenv("COOKIE_INSECURE")
			}

			cfg, err := LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig failed: %v", err)
			}
			if cfg.CookieInsecure != tc.want {
				t.Errorf("COOKIE_INSECURE=%q: got CookieInsecure=%v, want %v", tc.raw, cfg.CookieInsecure, tc.want)
			}
		})
	}

	os.Unsetenv("COOKIE_INSECURE")
}
