package ssh

import "context"

type operationOwnerKey struct{}

// operationContext admits one public operation. Nested steps on this same
// client belong to that operation, including its cleanup; absence blocks the
// next operation without interrupting work that has already begun.
func (c *Client) operationContext(ctx context.Context) (context.Context, error) {
	if ctx.Value(operationOwnerKey{}) == c {
		return ctx, nil
	}
	if err := checkProviderPresence(ctx, c.cfg); err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, operationOwnerKey{}, c), nil
}
