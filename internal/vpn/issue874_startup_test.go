package vpn

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// constructorFailureTimeout bounds a fixture constructor failure path. Device
// shutdown joins the TUN reader and the echo goroutines, so a cleanup path that
// strands one of them shows up as a constructor that never returns.
const constructorFailureTimeout = 10 * time.Second

// exchangeOnce runs one client payload exchange against the reference server and
// asserts the echoed payload identity.
func exchangeOnce(t *testing.T, client *HarnessClient, payload []byte) {
	t.Helper()
	udpConn, err := client.DialUDP()
	if err != nil {
		t.Fatalf("dial udp through tunnel: %v", err)
	}
	defer func() {
		if err := udpConn.Close(); err != nil {
			t.Errorf("close udp conn: %v", err)
		}
	}()

	echo, err := client.ExchangeUDP(udpConn, payload)
	if err != nil {
		t.Fatalf("udp exchange: %v", err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("udp echo mismatch: got %q, want %q", echo, payload)
	}
}

// requireBoundedConstructorError runs a fixture constructor and requires it to
// return a classified error, without panicking, within the shutdown bound. A
// constructor that panics or never returns fails the test: the second is what a
// cleanup path that left a device or goroutine behind looks like.
func requireBoundedConstructorError(t *testing.T, name, wantSubstring string, fn func() (any, error)) error {
	t.Helper()

	type result struct {
		value  any
		err    error
		panics any
	}
	done := make(chan result, 1)
	go func() {
		var out result
		defer func() {
			out.panics = recover()
			done <- out
		}()
		out.value, out.err = fn()
	}()

	select {
	case out := <-done:
		if out.panics != nil {
			t.Fatalf("%s: constructor panicked instead of returning an error: %v", name, out.panics)
		}
		if out.value != nil {
			t.Fatalf("%s: constructor returned a live value alongside its failure: %T (err=%v)", name, out.value, out.err)
		}
		if out.err == nil {
			t.Fatalf("%s: constructor reported no error", name)
		}
		if !strings.Contains(out.err.Error(), wantSubstring) {
			t.Fatalf("%s: constructor error = %q, want it to contain %q", name, out.err, wantSubstring)
		}
		return out.err
	case <-time.After(constructorFailureTimeout):
		t.Fatalf("%s: constructor did not return within %s; its cleanup left a device or goroutine behind", name, constructorFailureTimeout)
		return nil
	}
}

// newClientAsValue adapts NewClient to the constructor-failure helper.
func newClientAsValue(h *DifferentialHarness) (any, error) {
	client, err := h.NewClient()
	if client == nil {
		return nil, err
	}
	return client, err
}

// newClientWithStartup adapts a client construction with an injected startup step
// to the constructor-failure helper.
func newClientWithStartup(h *DifferentialHarness, start func(*device.Device) error) (any, error) {
	client, err := h.newClient(start)
	if client == nil {
		return nil, err
	}
	return client, err
}

// newReferenceServerAsValue adapts a reference constructor call to the
// constructor-failure helper.
func newReferenceServerAsValue(start func() (*ReferenceServer, error)) (any, error) {
	server, err := start()
	if server == nil {
		return nil, err
	}
	return server, err
}

// TestIssue874_ReferenceExchange is the ordinary current-pin payload control: the
// constructors must still build a working reference/client pair whose payload
// survives the tunnel unchanged.
func TestIssue874_ReferenceExchange(t *testing.T) {
	harness := NewDifferentialHarness(t)

	refServer, err := harness.StartReferenceServer()
	if err != nil {
		t.Fatalf("start reference server: %v", err)
	}
	defer func() {
		if err := harness.StopReferenceServer(refServer); err != nil {
			t.Errorf("stop reference server: %v", err)
		}
	}()

	client, err := harness.NewClient()
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Errorf("close client: %v", err)
		}
	}()

	exchangeOnce(t, client, []byte("issue874-reference-exchange"))
}

// TestIssue874_ClientConstructorFailurePaths exercises the client constructor's
// configuration and listener-startup failure seams. Both must return their
// classified error without panicking, and the device shutdown they perform must
// close the device once instead of closing the device and its TUN separately.
func TestIssue874_ClientConstructorFailurePaths(t *testing.T) {
	t.Run("Configuration", func(t *testing.T) {
		harness := NewDifferentialHarness(t)
		// Leading device-level key, before any peer key: an out-of-range listen
		// port is rejected after the device exists.
		harness.rawClientConfig = "ListenPort = 999999\n" + harness.rawClientConfig

		requireBoundedConstructorError(t, "client configuration failure", "client uapi:",
			func() (any, error) { return newClientAsValue(harness) })
	})

	t.Run("Startup", func(t *testing.T) {
		harness := NewDifferentialHarness(t)
		injected := errors.New("injected client startup failure")

		// The device and its TUN exist and the configuration was accepted: only
		// the startup operation itself fails.
		err := requireBoundedConstructorError(t, "client startup failure", "client up:",
			func() (any, error) {
				return newClientWithStartup(harness, func(*device.Device) error {
					return injected
				})
			})
		if !errors.Is(err, injected) {
			t.Fatalf("client startup failure returned %v, want the injected error %v", err, injected)
		}
	})
}

// TestIssue874_ReferenceConstructorFailurePaths exercises the reference
// constructor's listener and configuration failure seams. The listener seam
// injects a bounded error at the exact boundary where the constructor used to
// close the device and the tun separately.
func TestIssue874_ReferenceConstructorFailurePaths(t *testing.T) {
	t.Run("Listener", func(t *testing.T) {
		harness := NewDifferentialHarness(t)
		injected := errors.New("injected reference listener failure")

		err := requireBoundedConstructorError(t, "reference listener failure", injected.Error(),
			func() (any, error) {
				return newReferenceServerAsValue(func() (*ReferenceServer, error) {
					return harness.startReferenceServer(func(*netstack.Net, netip.AddrPort) (referenceListeners, error) {
						return referenceListeners{}, injected
					})
				})
			})
		if !errors.Is(err, injected) {
			t.Fatalf("reference listener failure returned %v, want the opener error %v", err, injected)
		}
	})

	t.Run("Configuration", func(t *testing.T) {
		harness := NewDifferentialHarness(t)
		// A server private key that decodes to the wrong length is rejected by
		// IpcSet on the reference device.
		shortKey := base64.StdEncoding.EncodeToString([]byte("abcd"))
		harness.svc.mu.Lock()
		harness.svc.cfg.ServerPrivateKey = shortKey
		harness.svc.mu.Unlock()

		requireBoundedConstructorError(t, "reference configuration failure", "reference ipc set:",
			func() (any, error) {
				return newReferenceServerAsValue(harness.StartReferenceServer)
			})
	})
}
