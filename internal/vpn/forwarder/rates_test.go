package forwarder

import (
	"testing"
	"time"
)

func TestRateTracker_RatesAndEWMA(t *testing.T) {
	rt := NewRateTracker()
	t0 := time.Now()

	// Initial sample at t0
	rt.Sample(t0, 0, 0, 0, 0, 0, 0)

	// Sample after 1 second: 1000 bytes RX, 2000 bytes TX, 10 pkts RX, 20 pkts TX, 1 drop
	t1 := t0.Add(1 * time.Second)
	rt.Sample(t1, 1000, 2000, 10, 20, 1, 1)

	rates := rt.Snapshot(10, 20)
	if rates.RxBps != 8000.0 { // 1000 * 8 / 1s
		t.Errorf("expected RxBps=8000, got %f", rates.RxBps)
	}
	if rates.TxBps != 16000.0 { // 2000 * 8 / 1s
		t.Errorf("expected TxBps=16000, got %f", rates.TxBps)
	}
	if rates.RxPps != 10.0 {
		t.Errorf("expected RxPps=10, got %f", rates.RxPps)
	}
	if rates.TxPps != 20.0 {
		t.Errorf("expected TxPps=20, got %f", rates.TxPps)
	}
	if rates.DropRatePps != 1.0 {
		t.Errorf("expected DropRatePps=1, got %f", rates.DropRatePps)
	}
	if rates.RxBpsAvg5m <= 0 || rates.TxBpsAvg5m <= 0 {
		t.Errorf("expected non-zero EWMA: 5m_rx=%f, 5m_tx=%f", rates.RxBpsAvg5m, rates.TxBpsAvg5m)
	}

	// Check pressure snapshot
	pressure := rt.PressureSnapshot(600, 1000, 700, 1)
	if pressure.UtilizationPct != 60.0 {
		t.Errorf("expected UtilizationPct=60%%, got %f", pressure.UtilizationPct)
	}
	if pressure.HighWaterPct != 70.0 {
		t.Errorf("expected HighWaterPct=70%%, got %f", pressure.HighWaterPct)
	}
	if pressure.QueueFullDropRate != 1 {
		t.Errorf("queue refusal rate=%v, want 1", pressure.QueueFullDropRate)
	}

}

func TestForwarder_RatesAndPressureAPI(t *testing.T) {
	f, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 2048, 100)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits failed: %v", err)
	}

	rxPackets, txPackets := f.PacketStats()
	if rxPackets != 0 || txPackets != 0 {
		t.Errorf("expected zero packet stats initially, got rx=%d tx=%d", rxPackets, txPackets)
	}

	rates := f.Rates()
	if rates.TotalRxPackets != 0 || rates.TotalTxPackets != 0 {
		t.Errorf("expected zero totals in rates snapshot, got rx=%d tx=%d", rates.TotalRxPackets, rates.TotalTxPackets)
	}

	pressure := f.QueuePressure()
	if pressure.Capacity != 0 || pressure.Occupancy != 0 {
		t.Errorf("expected zero queue pressure with no routes, got occ=%d cap=%d", pressure.Occupancy, pressure.Capacity)
	}
}
