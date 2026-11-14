package gigahost

import "net/http"

// newOwnedTransport returns the transport a default-constructed client uses.
//
// The panel's catalog load was observed to stall on a request issued over a
// connection the client had already reused, while the same request answered in
// about 90 ms on a fresh connection. This transport therefore stops reusing
// provider connections: every call dials its own, which is the condition under
// which the catalog completed.
//
// The policy is applied to a clone, so it never reaches http.DefaultTransport
// (another caller's transport) or a transport injected through Config. Clone
// also keeps the standard transport settings in one place instead of restating
// them here: proxy resolution, the dialer, HTTP/2 negotiation and TLS
// verification all stay exactly as the standard library defines them.
//
// DisableKeepAlives does not retry a request; a non-idempotent order POST is
// still transmitted at most once per call.
func newOwnedTransport() http.RoundTripper {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// Nothing to clone: a replaced global default is not ours to change, so
		// keep it rather than substituting a different transport.
		return http.DefaultTransport
	}
	owned := base.Clone()
	owned.DisableKeepAlives = true
	return owned
}
