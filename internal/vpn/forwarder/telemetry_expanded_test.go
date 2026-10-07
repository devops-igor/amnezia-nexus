package forwarder

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

type expandedTimedWriter struct {
	delay  time.Duration
	failed bool
}

func (w expandedTimedWriter) Write(p []byte) (int, error) {
	time.Sleep(w.delay)
	if w.failed {
		return 0, errors.New("test write failure")
	}
	return len(p), nil
}

func TestWriteDurationPrometheusHistogramRealCompletions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := NewForwarder(nil, "")
		f.RegisterSession("s", "c", "peer", "192.0.2.1", 1)
		route := f.routesByPeer["peer"]
		f.writeClientPacket(route, expandedTimedWriter{delay: 110 * time.Microsecond}, []byte{1})
		f.writeClientPacket(route, expandedTimedWriter{delay: 2 * time.Millisecond, failed: true}, []byte{1})
		exporter, ok := any(f).(interface{ WriteDurationMetrics(io.Writer) error })
		if !ok {
			t.Fatal("forwarder has no Prometheus write-duration exporter")
		}
		var buf bytes.Buffer
		if err := exporter.WriteDurationMetrics(&buf); err != nil {
			t.Fatal(err)
		}
		text := buf.String()
		for _, want := range []string{
			"# TYPE nexus_forwarder_write_duration_seconds histogram",
			"nexus_forwarder_write_duration_seconds_bucket{le=\"0.00025\"} 1",
			"nexus_forwarder_write_duration_seconds_bucket{le=\"0.0025\"} 2",
			"nexus_forwarder_write_duration_seconds_bucket{le=\"+Inf\"} 2",
			"nexus_forwarder_write_duration_seconds_count 2",
			"nexus_forwarder_write_duration_seconds_sum 0.00211",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("missing %q in %s", want, text)
			}
		}
		if strings.Contains(text, "peer") || strings.Contains(text, "192.") {
			t.Fatal("histogram exposed identities")
		}
		if got := f.DeviceWriteSnapshot(); got.Count != 2 || got.Errors != 1 {
			t.Fatalf("histogram changed legacy counters: %+v", got)
		}
	})
}

// Reflection keeps this regression runnable against the pre-feature overlay:
// missing telemetry is an assertion failure, rather than a build failure.
func expandedBackendTraffic(t *testing.T, f *Forwarder) map[string]map[string]any {
	t.Helper()
	method := reflect.ValueOf(f).MethodByName("BackendTrafficSnapshot")
	if !method.IsValid() {
		t.Fatal("backend traffic has no production sampling surface")
	}
	out := method.Call(nil)
	encoded, err := json.Marshal(out[0].Interface())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func TestBackendAndRouteTrafficRealPacketsAndLifecycle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := NewForwarder(nil, "")
		f.RegisterSession("s", "c", "peer", "192.0.2.1", 1)
		f.RegisterSession("s2", "c2", "peer2", "192.0.2.2", 2)
		dev := newMockPacketDev()
		f.AttachBackendDevice(1, dev)
		first := expandedBackendTraffic(t, f)
		if first["1"]["available"] != false || first["2"]["available"] != false {
			t.Fatal("unsampled rates presented as measured zero")
		}
		packet := make([]byte, 28)
		packet[0], packet[3] = 0x45, 28
		packet[12], packet[14], packet[15] = 192, 2, 1
		packet[16], packet[18], packet[19] = 192, 2, 1
		if err := f.RouteClientToBackend("peer", packet); err != nil {
			t.Fatal(err)
		}
		if err := f.RouteBackendToClient(1, packet, "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		next := expandedBackendTraffic(t, f)["1"]
		for key, want := range map[string]any{"available": true, "rx_bytes": float64(28), "tx_bytes": float64(28), "rx_bytes_per_sec": float64(28), "tx_bytes_per_sec": float64(28), "rx_pps": float64(1), "tx_pps": float64(1)} {
			if next[key] != want {
				t.Errorf("%s=%v; want %v", key, next[key], want)
			}
		}
		raw, _ := json.Marshal(f.InspectRoutes())
		var routes []map[string]any
		_ = json.Unmarshal(raw, &routes)
		var found map[string]any
		for _, r := range routes {
			if r["peer_key"] == "peer" {
				found = r
			}
		}
		if found["session_age_sec"] != float64(1) || found["last_traffic_age_sec"] != float64(1) {
			t.Errorf("route ages absent or wrong: %s", raw)
		}
		traffic, ok := found["traffic"].(map[string]any)
		if !ok || traffic["rx_bytes"] != float64(28) || traffic["tx_bytes"] != float64(28) {
			t.Errorf("route directional traffic missing: %s", raw)
		}
		f.DetachBackendDevice(1)
		if _, exists := expandedBackendTraffic(t, f)["1"]; exists {
			t.Fatal("removed device retained stale traffic generation")
		}
		f.AttachBackendDevice(1, dev)
		fresh := expandedBackendTraffic(t, f)["1"]
		if fresh["available"] != false || fresh["rx_bytes"] != float64(0) {
			t.Errorf("re-registration carried prior counters/rates: %v", fresh)
		}
		time.Sleep(time.Second)
		idle := expandedBackendTraffic(t, f)["1"]
		if idle["available"] != true || idle["rx_bytes_per_sec"] != float64(0) {
			t.Errorf("measured idle state unavailable: %v", idle)
		}
	})
}
