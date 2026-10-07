package vpn

import (
	"testing"
	"time"
)

func BenchmarkRollingHistory_Snapshot(b *testing.B) {
	rh := NewRollingHistory()
	baseTime := time.Unix(1700000000, 0)

	rates := make(map[string]float64, len(knownDropReasonKeys))
	for _, k := range knownDropReasonKeys {
		rates[k] = 1.5
	}
	backends := []BackendHistoryPoint{
		{ID: 1, RxBps: 1000, TxBps: 2000, RxPps: 10, TxPps: 20, TrafficAvailable: true, Routable: true},
	}

	for i := 0; i < 96*4; i++ {
		pt := HistoryPoint{
			Timestamp:       baseTime.Add(time.Duration(i*10) * time.Second).Unix(),
			DropReasonRates: rates,
			Backends:        backends,
		}
		rh.Add(pt)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		series := rh.Snapshot()
		_ = series
	}
}
