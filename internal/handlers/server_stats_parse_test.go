package handlers

import (
	"testing"
)

func TestParseCombinedStats(t *testing.T) {
	t.Run("ValidLinuxStats", func(t *testing.T) {
		raw := "===CPU===\n15.5\n" +
			"===RAM===\n2097152 8388608\n" +
			"===DISK===\n10485760 52428800\n" +
			"===NET===\n102400 204800\n" +
			"===UPTIME===\nup 3 days, 4 hours\n"

		stats, err := parseCombinedStats(raw)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if stats.CPU != 15.5 {
			t.Errorf("expected CPU 15.5, got %v", stats.CPU)
		}
		if stats.RAMUsed != 2097152 || stats.RAMTotal != 8388608 {
			t.Errorf("expected RAM 2097152/8388608, got used=%d total=%d", stats.RAMUsed, stats.RAMTotal)
		}
		if stats.RAMPercent != 25.0 {
			t.Errorf("expected RAMPercent 25.0, got %v", stats.RAMPercent)
		}
		if stats.DiskUsed != 10485760 || stats.DiskTotal != 52428800 {
			t.Errorf("expected Disk 10485760/52428800, got used=%d total=%d", stats.DiskUsed, stats.DiskTotal)
		}
		if stats.DiskPercent != 20.0 {
			t.Errorf("expected DiskPercent 20.0, got %v", stats.DiskPercent)
		}
		if stats.NetRx != 102400 || stats.NetTx != 204800 {
			t.Errorf("expected Net 102400/204800, got rx=%d tx=%d", stats.NetRx, stats.NetTx)
		}
		if stats.Uptime != "up 3 days, 4 hours" {
			t.Errorf("expected Uptime 'up 3 days, 4 hours', got %q", stats.Uptime)
		}
	})

	t.Run("EmptyStringReturnsError", func(t *testing.T) {
		for _, empty := range []string{"", "   \n\t  \n"} {
			_, err := parseCombinedStats(empty)
			if err == nil {
				t.Errorf("expected error for empty raw stats %q, got nil", empty)
			}
		}
	})

	t.Run("MissingCPUSectionReturnsError", func(t *testing.T) {
		raw := "===RAM===\n2097152 8388608\n" +
			"===DISK===\n10485760 52428800\n" +
			"===NET===\n102400 204800\n"

		_, err := parseCombinedStats(raw)
		if err == nil {
			t.Errorf("expected error for missing CPU stats, got nil")
		}
	})

	t.Run("EmptyCPUSectionReturnsError", func(t *testing.T) {
		for _, emptyCPU := range []string{
			"===CPU===\n\n===RAM===\n2097152 8388608\n===DISK===\n10485760 52428800\n===NET===\n102400 204800\n",
			"===CPU===\n   \t  \n===RAM===\n2097152 8388608\n===DISK===\n10485760 52428800\n===NET===\n102400 204800\n",
		} {
			_, err := parseCombinedStats(emptyCPU)
			if err == nil {
				t.Errorf("expected error for empty CPU stats, got nil")
			}
		}
	})

	t.Run("MalformedCPUReturnsError", func(t *testing.T) {
		for _, badCPU := range []string{
			"===CPU===\nnot-a-number\n===RAM===\n2097152 8388608\n===DISK===\n10485760 52428800\n===NET===\n102400 204800\n",
			"===CPU===\n-5.0\n===RAM===\n2097152 8388608\n===DISK===\n10485760 52428800\n===NET===\n102400 204800\n",
		} {
			_, err := parseCombinedStats(badCPU)
			if err == nil {
				t.Errorf("expected error for malformed CPU stats, got nil")
			}
		}
	})

	t.Run("MissingRAMSectionReturnsError", func(t *testing.T) {
		raw := "===CPU===\n10.0\n" +
			"===DISK===\n10485760 52428800\n" +
			"===NET===\n102400 204800\n" +
			"===UPTIME===\nup 1 day\n"

		_, err := parseCombinedStats(raw)
		if err == nil {
			t.Errorf("expected error for missing RAM stats, got nil")
		}
	})

	t.Run("MalformedRAMUsedReturnsError", func(t *testing.T) {
		for _, badRAM := range []string{
			"===CPU===\n10.0\n===RAM===\nabc 8388608\n===DISK===\n10485760 52428800\n===NET===\n102400 204800\n",
			"===CPU===\n10.0\n===RAM===\n-10 8388608\n===DISK===\n10485760 52428800\n===NET===\n102400 204800\n",
			"===CPU===\n10.0\n===RAM===\n2097152\n===DISK===\n10485760 52428800\n===NET===\n102400 204800\n",
		} {
			_, err := parseCombinedStats(badRAM)
			if err == nil {
				t.Errorf("expected error for malformed RAM stats, got nil")
			}
		}
	})

	t.Run("MissingDISKSectionReturnsError", func(t *testing.T) {
		raw := "===CPU===\n10.0\n" +
			"===RAM===\n2097152 8388608\n" +
			"===NET===\n102400 204800\n" +
			"===UPTIME===\nup 1 day\n"

		_, err := parseCombinedStats(raw)
		if err == nil {
			t.Errorf("expected error for missing DISK stats, got nil")
		}
	})

	t.Run("MalformedDISKUsedReturnsError", func(t *testing.T) {
		for _, badDisk := range []string{
			"===CPU===\n10.0\n===RAM===\n2097152 8388608\n===DISK===\nabc 52428800\n===NET===\n102400 204800\n",
			"===CPU===\n10.0\n===RAM===\n2097152 8388608\n===DISK===\n-1 52428800\n===NET===\n102400 204800\n",
			"===CPU===\n10.0\n===RAM===\n2097152 8388608\n===DISK===\n10485760\n===NET===\n102400 204800\n",
		} {
			_, err := parseCombinedStats(badDisk)
			if err == nil {
				t.Errorf("expected error for malformed DISK stats, got nil")
			}
		}
	})

	t.Run("MissingNETSectionReturnsError", func(t *testing.T) {
		raw := "===CPU===\n10.0\n" +
			"===RAM===\n2097152 8388608\n" +
			"===DISK===\n10485760 52428800\n" +
			"===UPTIME===\nup 1 day\n"

		_, err := parseCombinedStats(raw)
		if err == nil {
			t.Errorf("expected error for missing NET stats, got nil")
		}
	})

	t.Run("MalformedNETReturnsError", func(t *testing.T) {
		for _, badNet := range []string{
			"===CPU===\n10.0\n===RAM===\n2097152 8388608\n===DISK===\n10485760 52428800\n===NET===\ninvalid net\n",
			"===CPU===\n10.0\n===RAM===\n2097152 8388608\n===DISK===\n10485760 52428800\n===NET===\n100\n",
			"===CPU===\n10.0\n===RAM===\n2097152 8388608\n===DISK===\n10485760 52428800\n===NET===\n-1 50\n",
			"===CPU===\n10.0\n===RAM===\n2097152 8388608\n===DISK===\n10485760 52428800\n===NET===\n50 -1\n",
		} {
			_, err := parseCombinedStats(badNet)
			if err == nil {
				t.Errorf("expected error for malformed NET stats, got nil")
			}
		}
	})

	t.Run("IncompleteOutputZeroTotalsReturnsError", func(t *testing.T) {
		for _, zeroTotals := range []string{
			"===CPU===\n10.0\n===RAM===\n0 0\n===DISK===\n0 5000000\n===NET===\n0 0\n",
			"===CPU===\n10.0\n===RAM===\n0 1000000\n===DISK===\n0 0\n===NET===\n0 0\n",
			"===CPU===\n10.0\n===RAM===\n0 0\n===DISK===\n0 0\n===NET===\n0 0\n",
		} {
			_, err := parseCombinedStats(zeroTotals)
			if err == nil {
				t.Errorf("expected error for zero totals, got nil")
			}
		}
	})

	t.Run("LegitimateZerosAccepted", func(t *testing.T) {
		raw := "===CPU===\n0.0\n" +
			"===RAM===\n0 1000000\n" +
			"===DISK===\n0 5000000\n" +
			"===NET===\n0 0\n" +
			"===UPTIME===\nup 10 minutes\n"

		stats, err := parseCombinedStats(raw)
		if err != nil {
			t.Fatalf("expected no error for legitimate zeros, got: %v", err)
		}
		if stats.CPU != 0.0 {
			t.Errorf("expected CPU 0.0, got %v", stats.CPU)
		}
		if stats.RAMUsed != 0 || stats.RAMTotal != 1000000 {
			t.Errorf("expected RAM 0/1000000, got used=%d total=%d", stats.RAMUsed, stats.RAMTotal)
		}
		if stats.RAMPercent != 0.0 {
			t.Errorf("expected RAMPercent 0.0, got %v", stats.RAMPercent)
		}
		if stats.DiskUsed != 0 || stats.DiskTotal != 5000000 {
			t.Errorf("expected Disk 0/5000000, got used=%d total=%d", stats.DiskUsed, stats.DiskTotal)
		}
		if stats.DiskPercent != 0.0 {
			t.Errorf("expected DiskPercent 0.0, got %v", stats.DiskPercent)
		}
		if stats.NetRx != 0 || stats.NetTx != 0 {
			t.Errorf("expected Net 0/0, got rx=%d tx=%d", stats.NetRx, stats.NetTx)
		}
		if stats.Uptime != "up 10 minutes" {
			t.Errorf("expected Uptime 'up 10 minutes', got %q", stats.Uptime)
		}
	})
}
