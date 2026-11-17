package vpn

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

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

// holdUDPPort binds a wildcard UDP port without socket-reuse options and keeps it
// until the test ends. A later bind of that port fails whatever options the
// binding side sets, which makes the fixture's bind failure deterministic. A port
// of 0 picks a free port, which is returned.
func holdUDPPort(t *testing.T, port int) uint16 {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socket for held port: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: port}); err != nil {
		t.Fatalf("bind held udp port %d: %v", port, err)
	}
	bound, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatalf("read held udp port: %v", err)
	}
	v4, ok := bound.(*syscall.SockaddrInet4)
	if !ok {
		t.Fatalf("held udp port has address type %T, want IPv4", bound)
	}
	return uint16(v4.Port)
}

// assertConstructorStage requires err to come from one of the documented
// constructor failure stages. Which stage reports an upstream bind failure depends
// on whether the device is already up, so the test pins that the error came from
// the constructor and not from somewhere else.
func assertConstructorStage(t *testing.T, name string, err error, stages ...string) {
	t.Helper()
	for _, stage := range stages {
		if strings.HasPrefix(err.Error(), stage) {
			return
		}
	}
	t.Fatalf("%s: constructor error = %q, want one of %q", name, err, stages)
}

// newClientAsValue adapts NewClient to the constructor-failure helper.
func newClientAsValue(h *DifferentialHarness) (any, error) {
	client, err := h.NewClient()
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

	t.Run("ListenerBind", func(t *testing.T) {
		harness := NewDifferentialHarness(t)
		// A port this test holds without reuse options cannot be bound, so the
		// device's listener step fails.
		port := holdUDPPort(t, 0)
		harness.rawClientConfig = fmt.Sprintf("ListenPort = %d\n%s", port, harness.rawClientConfig)

		err := requireBoundedConstructorError(t, "client listener failure", "address already in use",
			func() (any, error) { return newClientAsValue(harness) })
		assertConstructorStage(t, "client listener failure", err, "client uapi:", "client up:")
	})
}

// TestIssue874_ReferenceConstructorFailurePaths exercises the reference
// constructor's listener, configuration and listener-startup failure seams. The
// listener seam injects a bounded error at the exact boundary where the
// constructor used to close the device and the tun separately.
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

	t.Run("ListenerBind", func(t *testing.T) {
		harness := NewDifferentialHarness(t)
		// Point the constructor at a port this test holds without reuse options,
		// so the device's listener step cannot bind it.
		harness.listenPort = int(holdUDPPort(t, 0))

		err := requireBoundedConstructorError(t, "reference listener bind failure", "address already in use",
			func() (any, error) {
				return newReferenceServerAsValue(harness.StartReferenceServer)
			})
		assertConstructorStage(t, "reference listener bind failure", err, "reference ipc set:", "reference up:")
	})
}
