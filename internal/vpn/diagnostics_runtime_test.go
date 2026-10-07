package vpn

import (
	"os"
	"testing"
)

func TestMemoryLimitUsesOnlyDiscoveredFiniteCapacity(t *testing.T) {
	for _, tc := range []struct {
		name, v2, v1 string
		want         uint64
	}{
		{"v2 finite", "67108864\n", "134217728", 67108864},
		{"v1 fallback", "max", "134217728\n", 134217728},
		{"missing", "", "", 0},
		{"unlimited", "max", "9223372036854771712", 0},
		{"malformed", "bad", "-1", 0},
		{"zero", "0", "0", 0},
		{"invalid v2 finite v1", "bad", "64", 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limit := readMemoryLimit(func(path string) ([]byte, error) {
				value := tc.v1
				if path == "/sys/fs/cgroup/memory.max" {
					value = tc.v2
				}
				if value == "" {
					return nil, os.ErrNotExist
				}
				return []byte(value), nil
			})
			if limit != tc.want {
				t.Fatalf("capacity=%d, want %d", limit, tc.want)
			}
		})
	}
}
