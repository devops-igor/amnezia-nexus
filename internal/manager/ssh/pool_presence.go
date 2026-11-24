package ssh

import (
	"context"
	"fmt"
	"time"
)

// ProviderPresenceStore supplies the current durable observation, not the
// snapshot that originally created a cached connection. Production pools use
// the database; transports without a stored row retain the config observation.
type ProviderPresenceStore interface {
	IsServerProviderAbsent(context.Context, int64) (bool, error)
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
		return fmt.Errorf("check SSH provider presence: %w", err)
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
