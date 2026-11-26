package ssh

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ProviderPresenceStore supplies the current durable observation, not the
// snapshot that originally created a cached connection. Production pools use
// the database; transports without a stored row retain the config observation.
type ProviderPresenceStore interface {
	IsServerProviderAbsent(context.Context, int64) (bool, error)
}

// errPresenceUnavailable marks a failed read of the durable observation. It is
// not a transport failure: nothing is known about the connection, so a
// validation that meets it must decline to measure without reporting the
// connection as dead or unhealthy.
var errPresenceUnavailable = errors.New("provider presence could not be read")

// errLivenessUnknown marks a validation that ran out of budget before the
// exchange was admitted. The presence gate and the peer's reply share that
// budget, so an expired budget on its own proves nothing about the connection:
// the observation read may still be pending. Unknown leaves the entry alone and
// decides later.
var errLivenessUnknown = errors.New("SSH liveness not measured")

// errLivenessUnresponsive marks a validation whose presence gate admitted the
// exchange and wrote the request, but whose peer did not complete it within the
// budget. That is the socket's own failure: it is retired from the pool and
// replaced on the next acquisition, not parked like an unanswered lookup. Keeping
// the two apart is the point — a pending database read must never retire a
// healthy socket, and a hung socket must never be kept as if it were unmeasured.
var errLivenessUnresponsive = errors.New("SSH connection unresponsive")

// isPresenceBlocked reports whether err came from the presence gate rather than
// from the transport. Every layer that inspects the outcome of an exchange must
// use it before concluding that a connection is dead.
func isPresenceBlocked(err error) bool {
	return errors.Is(err, ErrProviderAbsent) || errors.Is(err, errPresenceUnavailable)
}

func checkProviderPresence(ctx context.Context, cfg Config) error {
	if cfg.ProviderAbsent {
		return ErrProviderAbsent
	}
	store := cfg.presenceStore
	if store == nil {
		store, _ = cfg.Store.(ProviderPresenceStore)
	}
	if store == nil || cfg.ServerID == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	absent, err := store.IsServerProviderAbsent(ctx, *cfg.ServerID)
	if err != nil {
		return fmt.Errorf("%w: %w", errPresenceUnavailable, err)
	}
	if absent {
		return ErrProviderAbsent
	}
	return nil
}

// dialClient is private to pool checkout. Public constructors cannot establish
// a transport without the pool's admission, including one-shot Dial callers.
func dialClient(ctx context.Context, cfg Config) (*Client, error) {
	client := NewClient(cfg)
	if err := client.connect(ctx); err != nil {
		return nil, err
	}
	return client, nil
}
