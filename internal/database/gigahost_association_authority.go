package database

// The durable provider account association authority.
//
// A preview states which account answered, which provider configuration it was
// produced under, and which rows the account no longer lists. That statement is
// stored here rather than in the panel's memory, and every binding write carries it
// in its own statement: the row is written only if this table still holds that exact
// authority, at that exact version, under the configuration epoch in force.
//
// The point of putting it in the database is atomicity: a newer preview, or a save of
// a different provider key, is itself a write to this database, so it cannot land
// between a binding's revalidation and the binding's own commit. Either it committed
// first - and then the binding's condition is false - or the binding committed first,
// under an authority that was still current when it did.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// GigahostAssociationAuthority is one administrator's live authorization to write
// provider account associations.
type GigahostAssociationAuthority struct {
	Admin            string
	Token            string
	Version          int64
	Account          string
	ConfigEpoch      int64
	ConfigGeneration uint64
	ConfigScope      string
	Unlisted         []int64
	ExpiresAt        time.Time
}

// GigahostConfigEpoch reports the durable version of the effective provider
// configuration. A save of the gigahost settings bumps it in the same transaction as
// the setting.
func (d *DB) GigahostConfigEpoch(ctx context.Context) (int64, error) {
	var epoch int64
	err := d.sqlDB.QueryRowContext(ctx, "SELECT epoch FROM gigahost_config_epoch WHERE id = 1").Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("failed to read the provider configuration epoch: %w", err)
	}
	return epoch, nil
}

// generationToStored converts the provider client generation to the signed value the
// authority row stores. A generation that cannot round-trip is refused rather than
// silently wrapped.
func generationToStored(generation uint64) (int64, error) {
	if generation > math.MaxInt64 {
		return 0, errors.New("provider client generation is out of range for the association authority")
	}
	return int64(generation), nil
}

// generationFromStored converts a stored generation back to the client's value.
func generationFromStored(generation int64) (uint64, error) {
	if generation < 0 {
		return 0, errors.New("stored provider client generation is negative")
	}
	return uint64(generation), nil
}

// StoreGigahostAssociationAuthority makes one preview the administrator's authority,
// replacing whatever they held before in the same statement.
//
// The version advances on every store, so a confirmation that names an earlier
// version can never be mistaken for the current one even if its token were reused.
func (d *DB) StoreGigahostAssociationAuthority(ctx context.Context, authority GigahostAssociationAuthority) error {
	if strings.TrimSpace(authority.Admin) == "" || strings.TrimSpace(authority.Token) == "" {
		return errors.New("refusing to store an association authority without an administrator or a token")
	}
	unlisted, err := json.Marshal(authority.Unlisted)
	if err != nil {
		return fmt.Errorf("failed to encode the previewed unlisted rows: %w", err)
	}
	generation, err := generationToStored(authority.ConfigGeneration)
	if err != nil {
		return err
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err = d.sqlDB.ExecContext(ctx, `
		INSERT INTO gigahost_association_authority
			(admin, token, version, account, config_epoch, config_generation, config_scope, unlisted, expires_at)
		VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(admin) DO UPDATE SET
			token = excluded.token,
			version = gigahost_association_authority.version + 1,
			account = excluded.account,
			config_epoch = excluded.config_epoch,
			config_generation = excluded.config_generation,
			config_scope = excluded.config_scope,
			unlisted = excluded.unlisted,
			expires_at = excluded.expires_at`,
		authority.Admin, authority.Token, authority.Account, authority.ConfigEpoch,
		generation, authority.ConfigScope, string(unlisted), authority.ExpiresAt.Unix())
	if err != nil {
		return fmt.Errorf("failed to store the association authority: %w", err)
	}
	return nil
}

// GigahostAssociationAuthorityToken reports the token the administrator currently
// holds, so a presented token can be refused as superseded rather than unknown.
func (d *DB) GigahostAssociationAuthorityToken(ctx context.Context, admin string) (string, bool, error) {
	var token string
	err := d.sqlDB.QueryRowContext(ctx,
		"SELECT token FROM gigahost_association_authority WHERE admin = ?", strings.TrimSpace(admin)).Scan(&token)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("failed to read the association authority token: %w", err)
	}
	return token, true, nil
}

// ClearGigahostAssociationAuthority withdraws the administrator's authority as its
// own write. It reports whether a row was removed.
func (d *DB) ClearGigahostAssociationAuthority(ctx context.Context, admin string) (bool, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	res, err := d.sqlDB.ExecContext(ctx, "DELETE FROM gigahost_association_authority WHERE admin = ?", strings.TrimSpace(admin))
	if err != nil {
		return false, fmt.Errorf("failed to clear the association authority: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to read the association authority result: %w", err)
	}
	return affected > 0, nil
}

// LoadGigahostAssociationAuthority returns the authority a token names, when it is
// still the administrator's current one and has not expired.
//
// An expired row is removed as part of the read's own write, and reported as absent.
func (d *DB) LoadGigahostAssociationAuthority(ctx context.Context, admin, token string, now time.Time) (GigahostAssociationAuthority, bool, error) {
	admin = strings.TrimSpace(admin)
	token = strings.TrimSpace(token)
	if admin == "" || token == "" {
		return GigahostAssociationAuthority{}, false, nil
	}
	var (
		authority  GigahostAssociationAuthority
		unlisted   string
		generation int64
		expires    int64
	)
	err := d.sqlDB.QueryRowContext(ctx, `
		SELECT admin, token, version, account, config_epoch, config_generation, config_scope, unlisted, expires_at
		FROM gigahost_association_authority WHERE admin = ? AND token = ?`,
		admin, token).Scan(&authority.Admin, &authority.Token, &authority.Version, &authority.Account,
		&authority.ConfigEpoch, &generation, &authority.ConfigScope, &unlisted, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return GigahostAssociationAuthority{}, false, nil
	}
	if err != nil {
		return GigahostAssociationAuthority{}, false, fmt.Errorf("failed to read the association authority: %w", err)
	}
	if authority.ConfigGeneration, err = generationFromStored(generation); err != nil {
		return GigahostAssociationAuthority{}, false, err
	}
	authority.ExpiresAt = time.Unix(expires, 0)
	if err := json.Unmarshal([]byte(unlisted), &authority.Unlisted); err != nil {
		return GigahostAssociationAuthority{}, false, fmt.Errorf("failed to decode the previewed unlisted rows: %w", err)
	}
	if !now.Before(authority.ExpiresAt) {
		_, _ = d.ClearGigahostAssociationAuthority(ctx, admin)
		return GigahostAssociationAuthority{}, false, nil
	}
	return authority, true, nil
}

// CurrentGigahostAssociationAuthority reports whether this token is still the
// administrator's live authority under the configuration in force. It is used to
// explain a refused binding, never to authorize one.
func (d *DB) CurrentGigahostAssociationAuthority(
	ctx context.Context, authority GigahostAssociationAuthority, liveGeneration uint64, now time.Time,
) (bool, error) {
	live, err := generationToStored(liveGeneration)
	if err != nil {
		return false, err
	}
	var count int
	err = d.sqlDB.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM gigahost_association_authority a
		JOIN gigahost_config_epoch e ON e.id = 1
		WHERE a.admin = ? AND a.token = ? AND a.version = ?
		  AND a.config_epoch = e.epoch
		  AND a.config_generation = ? AND a.config_scope = ?
		  AND a.expires_at > ?`,
		authority.Admin, authority.Token, authority.Version,
		live, authority.ConfigScope, now.Unix()).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to revalidate the association authority: %w", err)
	}
	return count > 0, nil
}

// BindServerProviderAccountUnderAuthority records which provider account a server row
// belongs to, and only while the authority it was previewed under is still current.
//
// The emptiness predicate that makes the association write-once and the authority
// predicate are one statement, so a newer preview or a provider-key save that commits
// after this call has begun cannot leave a stale authority authorizing a later row:
// the row's write and the authority's currency are decided together.
//
// liveGeneration is the provider client generation in force at this call, read from
// the process that owns the client. Comparing it to the generation the preview recorded
// is what turns "the client was replaced" into a refused write.
func (d *DB) BindServerProviderAccountUnderAuthority(
	ctx context.Context, id int64, accountID string, authority GigahostAssociationAuthority,
	liveGeneration uint64, now time.Time,
) (bool, error) {
	account := strings.TrimSpace(accountID)
	if account == "" {
		return false, errors.New("refusing to associate a server with an empty provider account")
	}
	live, err := generationToStored(liveGeneration)
	if err != nil {
		return false, err
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	res, err := d.sqlDB.ExecContext(ctx, `
		UPDATE servers SET provider_account_id = ?
		WHERE id = ?
		  AND (provider_account_id IS NULL OR TRIM(provider_account_id) = '')
		  AND EXISTS (
			SELECT 1 FROM gigahost_association_authority a
			JOIN gigahost_config_epoch e ON e.id = 1
			WHERE a.admin = ? AND a.token = ? AND a.version = ?
			  AND a.config_epoch = e.epoch
			  AND a.config_generation = ?
			  AND a.expires_at > ?
		  )`,
		account, id,
		authority.Admin, authority.Token, authority.Version,
		live, now.Unix())
	if err != nil {
		return false, fmt.Errorf("failed to associate server %d with a provider account: %w", id, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to read the association result for server %d: %w", id, err)
	}
	return affected > 0, nil
}

// BumpGigahostConfigEpoch advances the durable provider-configuration version. The
// caller is responsible for running it inside the same transaction as the settings
// write it accompanies; SetSetting and SetSettingsBulk do this for the gigahost key.
func bumpGigahostConfigEpochTx(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, "UPDATE gigahost_config_epoch SET epoch = epoch + 1 WHERE id = 1"); err != nil {
		return fmt.Errorf("failed to advance the provider configuration epoch: %w", err)
	}
	return nil
}
