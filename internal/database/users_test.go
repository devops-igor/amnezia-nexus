package database

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestUsersEmptyAndNotFound(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	allUsers, err := db.GetAllUsers(ctx)
	if err != nil || len(allUsers) != 0 {
		t.Fatalf("GetAllUsers empty DB = (%v, %v), want ([], nil)", allUsers, err)
	}

	c, err := db.CountUsers(ctx)
	if err != nil || c != 0 {
		t.Errorf("CountUsers empty DB = %d, err = %v, want 0, nil", c, err)
	}

	uNonExistent, err := db.GetUser(ctx, "non-existent-uuid")
	if err != nil || uNonExistent != nil {
		t.Errorf("GetUser(non-existent) = (%v, %v), want (nil, nil)", uNonExistent, err)
	}

	uByIDAlias, err := db.GetUserByID(ctx, "non-existent-uuid")
	if err != nil || uByIDAlias != nil {
		t.Errorf("GetUserByID(non-existent) = (%v, %v), want (nil, nil)", uByIDAlias, err)
	}

	uByUsername, err := db.GetUserByUsername(ctx, "ghost")
	if err != nil || uByUsername != nil {
		t.Errorf("GetUserByUsername(ghost) = (%v, %v), want (nil, nil)", uByUsername, err)
	}

	uByShareToken, err := db.GetUserByShareToken(ctx, "invalid-token")
	if err != nil || uByShareToken != nil {
		t.Errorf("GetUserByShareToken(invalid) = (%v, %v), want (nil, nil)", uByShareToken, err)
	}
}

func TestUsersCreateAndRetrieve(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	emailStr := "alice@example.com"
	telStr := "123456789"
	descStr := "Main administrator account"
	tokenStr := "share-token-alice-12345"
	passHashStr := "$2b$12$sharepasswordhash"
	monthResetStr := "2026-08-01T00:00:00Z"
	lastResetStr := "2026-08-01T00:00:00Z"
	expDate := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	u1 := &models.User{
		ID:                     "custom-alice-id",
		Username:               " Alice ",
		Email:                  &emailStr,
		TelegramID:             &telStr,
		Description:            &descStr,
		PasswordHash:           "$2b$12$hashAlice",
		Role:                   models.RoleAdmin,
		Enabled:                true,
		TrafficLimit:           10000000,
		TrafficUsed:            2000000,
		TrafficTotal:           5000000,
		TrafficTotalRx:         2000000,
		TrafficTotalTx:         3000000,
		MonthlyRx:              1000000,
		MonthlyTx:              1000000,
		MonthlyResetAt:         &monthResetStr,
		TrafficResetStrategy:   models.ResetStrategyMonthly,
		ShareEnabled:           true,
		ShareToken:             &tokenStr,
		SharePasswordHash:      &passHashStr,
		CreatedAt:              time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		LastResetAt:            &lastResetStr,
		ExpirationDate:         &expDate,
		ExpiresAt:              &expiresAt,
		AWGMimicry:             models.AWGMimicryTLS,
		PasswordChangeRequired: true,
		Limits:                 map[string]any{"max_ips": 3},
	}

	id1, err := db.CreateUser(ctx, u1)
	if err != nil || id1 != "custom-alice-id" {
		t.Fatalf("CreateUser u1 failed: id=%s, err=%v", id1, err)
	}

	retrievedAlice, err := db.GetUser(ctx, id1)
	if err != nil || retrievedAlice == nil {
		t.Fatalf("GetUser(alice) failed: %v", err)
	}
	if retrievedAlice.Username != "alice" || retrievedAlice.Role != models.RoleAdmin {
		t.Errorf("Alice data mismatch: %+v", retrievedAlice)
	}

	byShare, err := db.GetUserByShareToken(ctx, tokenStr)
	if err != nil || byShare == nil || byShare.ID != id1 {
		t.Errorf("GetUserByShareToken failed: %+v, err=%v", byShare, err)
	}

	u2 := &models.User{Username: "bob_default"}
	id2, _ := db.CreateUser(ctx, u2)
	retrievedBob, _ := db.GetUser(ctx, id2)
	if retrievedBob.Role != models.RoleUser || retrievedBob.TrafficResetStrategy != models.ResetStrategyNever || retrievedBob.AWGMimicry != models.AWGMimicryAuto {
		t.Errorf("Bob default fields mismatch: %+v", retrievedBob)
	}
}

func TestUsersUpdateAndLimits(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	uID, _ := db.CreateUser(ctx, &models.User{Username: "update_user"})

	upGhost, err := db.UpdateUser(ctx, "ghost-id", map[string]any{"username": "ghost"})
	if err != nil || upGhost {
		t.Errorf("UpdateUser(ghost) = (%v, %v), want (false, nil)", upGhost, err)
	}

	if _, err := db.UpdateUser(ctx, uID, map[string]any{"invalid_col": "bad"}); err == nil {
		t.Errorf("expected error updating invalid column")
	}

	if ok, err := db.UpdateUser(ctx, uID, map[string]any{}); err != nil || !ok {
		t.Errorf("UpdateUser empty map failed: (%v, %v)", ok, err)
	}

	newExp := time.Date(2028, 6, 1, 0, 0, 0, 0, time.UTC)
	ok, err := db.UpdateUser(ctx, uID, map[string]any{
		"username":                 " Updated_User ",
		"email":                    "updated@example.com",
		"enabled":                  true,
		"share_enabled":            true,
		"password_change_required": false,
		"limits":                   map[string]any{"quota_mb": 5000},
		"expiration_date":          &newExp,
		"expires_at":               newExp,
	})
	if err != nil || !ok {
		t.Fatalf("UpdateUser failed: %v", err)
	}

	updated, _ := db.GetUser(ctx, uID)
	if updated.Username != "updated_user" || *updated.Email != "updated@example.com" {
		t.Errorf("Updated fields mismatch: %+v", updated)
	}

	if err := db.UpdateUserLimits(ctx, uID, map[string]any{"custom_limit": 100}); err != nil {
		t.Fatalf("UpdateUserLimits failed: %v", err)
	}

	futureExpiry := time.Now().Add(48 * time.Hour)
	if err := db.UpdateUserExpiry(ctx, uID, &futureExpiry); err != nil {
		t.Fatalf("UpdateUserExpiry failed: %v", err)
	}
	if err := db.UpdateUserExpiry(ctx, uID, nil); err != nil {
		t.Fatalf("UpdateUserExpiry(nil) failed: %v", err)
	}

	_, _ = db.ToggleUser(ctx, uID, false)
	toggledOff, _ := db.GetUser(ctx, uID)
	if toggledOff.Enabled {
		t.Errorf("expected disabled user")
	}
}

func TestUsersTrafficLeaderboardAndReset(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	u1ID, _ := db.CreateUser(ctx, &models.User{Username: "alice_traffic", Enabled: true, TrafficResetStrategy: models.ResetStrategyMonthly})
	u2ID, _ := db.CreateUser(ctx, &models.User{Username: "bob_traffic", Enabled: true, TrafficResetStrategy: models.ResetStrategyNever})

	if err := db.UpdateUserTraffic(ctx, u1ID, 500, 1500); err != nil {
		t.Fatalf("UpdateUserTraffic alice failed: %v", err)
	}
	if err := db.UpdateUserTraffic(ctx, u2ID, 1000, 3000); err != nil {
		t.Fatalf("UpdateUserTraffic bob failed: %v", err)
	}

	lbMonthly, err := db.GetLeaderboard(ctx, "monthly")
	if err != nil || len(lbMonthly) != 2 {
		t.Fatalf("GetLeaderboard(monthly) failed: len=%d, err=%v", len(lbMonthly), err)
	}

	lbTotal, err := db.GetLeaderboard(ctx, "total")
	if err != nil || len(lbTotal) != 2 {
		t.Fatalf("GetLeaderboard(total) failed: len=%d, err=%v", len(lbTotal), err)
	}

	resetRows, err := db.ResetMonthlyTraffic(ctx)
	if err != nil || resetRows != 1 {
		t.Fatalf("ResetMonthlyTraffic affected %d rows, want 1, err=%v", resetRows, err)
	}
}

func TestUsersQuotaAndExpiration(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	_, _ = db.CreateUser(ctx, &models.User{
		Username:     "quota_user",
		TrafficLimit: 1000,
		TrafficUsed:  2000,
		Enabled:      true,
	})
	overQuota, err := db.GetUsersOverQuota(ctx)
	if err != nil || len(overQuota) != 1 || overQuota[0].Username != "quota_user" {
		t.Errorf("GetUsersOverQuota failed: %+v, err=%v", overQuota, err)
	}

	pastTime := time.Now().Add(-10 * time.Hour)
	_, _ = db.CreateUser(ctx, &models.User{
		Username:  "expired_user",
		ExpiresAt: &pastTime,
		Enabled:   true,
	})
	expired, err := db.GetExpiredUsers(ctx)
	if err != nil || len(expired) != 1 || expired[0].Username != "expired_user" {
		t.Errorf("GetExpiredUsers failed: %+v, err=%v", expired, err)
	}
}

func TestUsersDeleteAndCascade(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	delUID, _ := db.CreateUser(ctx, &models.User{Username: "delete_cascade_user"})
	sID, _ := db.CreateServer(ctx, &models.Server{Name: "Cascade Server", Host: "1.2.3.4"})
	_, _ = db.CreateConnection(ctx, &models.UserConnection{UserID: delUID, ServerID: sID, Protocol: "awg"})
	_ = db.LogConnectionCreation(ctx, delUID)
	_ = db.CreateVPNSession(ctx, &models.VPNSession{UserID: delUID, PeerPublicKey: "peer-del-key"})

	delRes, err := db.DeleteUser(ctx, delUID)
	if err != nil || !delRes {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	delCheck, _ := db.GetUser(ctx, delUID)
	if delCheck != nil {
		t.Errorf("deleted user still exists")
	}

	delGhost, err := db.DeleteUser(ctx, "ghost-id")
	if err != nil || delGhost {
		t.Errorf("DeleteUser(ghost) = (%v, %v), want (false, nil)", delGhost, err)
	}
}

func TestUsersDateAndNullScanningEdgeCases(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	_, _ = db.sqlDB.ExecContext(ctx, `INSERT INTO users (id, username, password_hash, expiration_date) VALUES ('u-expdate-only', 'expdate_only', 'h', '2027-01-01T00:00:00Z')`)
	uExpDateOnly, err := db.GetUser(ctx, "u-expdate-only")
	if err != nil || uExpDateOnly == nil || uExpDateOnly.ExpirationDate == nil || uExpDateOnly.ExpiresAt == nil {
		t.Errorf("uExpDateOnly reciprocal population failed: %+v", uExpDateOnly)
	}

	_, _ = db.sqlDB.ExecContext(ctx, `INSERT INTO users (id, username, password_hash, expires_at) VALUES ('u-expiresat-only', 'expiresat_only', 'h', '2027-01-01T00:00:00Z')`)
	uExpiresAtOnly, err := db.GetUser(ctx, "u-expiresat-only")
	if err != nil || uExpiresAtOnly == nil || uExpiresAtOnly.ExpirationDate == nil || uExpiresAtOnly.ExpiresAt == nil {
		t.Errorf("uExpiresAtOnly reciprocal population failed: %+v", uExpiresAtOnly)
	}

	_, _ = db.sqlDB.ExecContext(ctx, `INSERT INTO users (id, username, password_hash, role, traffic_reset_strategy, awg_mimicry, limits) VALUES ('u-empty-enums', 'empty_enums', 'h', '', '', '', 'invalid-json{')`)
	uEmptyEnums, err := db.GetUser(ctx, "u-empty-enums")
	if err != nil || uEmptyEnums == nil || uEmptyEnums.Role != models.RoleUser || uEmptyEnums.TrafficResetStrategy != models.ResetStrategyNever || uEmptyEnums.AWGMimicry != models.AWGMimicryAuto {
		t.Errorf("default fallback for empty enum strings failed: %+v", uEmptyEnums)
	}

	badLimits := map[string]any{"bad": make(chan int)}
	if _, err := db.UpdateUser(ctx, "u-empty-enums", map[string]any{"limits": badLimits}); err == nil {
		t.Errorf("expected error updating user with unmarshalable limits")
	}
}

func TestUserSessionVersion(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	// 1. Newly created user should default to SessionVersion = 1
	user := &models.User{
		Username: "version_test_user",
		Role:     models.RoleUser,
		Enabled:  true,
	}
	userID, err := db.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	fetched, err := db.GetUser(ctx, userID)
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	if fetched.SessionVersion != 1 {
		t.Errorf("expected new user SessionVersion=1, got %d", fetched.SessionVersion)
	}

	// 2. Bump session version
	v2, err := db.BumpUserSessionVersion(ctx, userID)
	if err != nil {
		t.Fatalf("BumpUserSessionVersion failed: %v", err)
	}
	if v2 != 2 {
		t.Errorf("expected bumped version=2, got %d", v2)
	}

	fetchedAfterBump, err := db.GetUser(ctx, userID)
	if err != nil {
		t.Fatalf("GetUser after bump failed: %v", err)
	}
	if fetchedAfterBump.SessionVersion != 2 {
		t.Errorf("expected fetched SessionVersion=2, got %d", fetchedAfterBump.SessionVersion)
	}

	// 3. Bump again
	v3, err := db.BumpUserSessionVersion(ctx, userID)
	if err != nil {
		t.Fatalf("BumpUserSessionVersion 2nd failed: %v", err)
	}
	if v3 != 3 {
		t.Errorf("expected bumped version=3, got %d", v3)
	}

	// 4. Non-existent user returns error
	if _, err := db.BumpUserSessionVersion(ctx, "non-existent-user-id"); err == nil {
		t.Errorf("expected error bumping session version for non-existent user")
	}
}

func TestMigrateUserSessionVersion(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	// Verify migrateUserSessionVersion is idempotent on an already migrated table
	if err := db.migrateUserSessionVersion(ctx); err != nil {
		t.Fatalf("expected idempotent migrateUserSessionVersion to succeed: %v", err)
	}

	// Create a user and verify session_version is scanned correctly
	u := &models.User{
		Username: "mig_user",
		Role:     models.RoleUser,
		Enabled:  true,
	}
	uid, err := db.CreateUser(ctx, u)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	got, err := db.GetUser(ctx, uid)
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	if got.SessionVersion != 1 {
		t.Errorf("expected SessionVersion 1, got %d", got.SessionVersion)
	}
}

func TestUpdateUserAndBumpSession_Atomicity(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	// 1. Create a user with SessionVersion=1
	u := &models.User{
		ID:             "atomic-test-user",
		Username:       "atomic_user",
		PasswordHash:   "initial-hash",
		SessionVersion: 1,
	}
	userID, err := db.CreateUser(ctx, u)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// 2. Successful atomic update: update password_hash and telegramId while bumping session_version
	updates := map[string]any{
		"password_hash": "new-secret-hash",
		"telegramId":    "@atomic_tele",
	}
	ok, newVer, err := db.UpdateUserAndBumpSession(ctx, userID, updates)
	if err != nil {
		t.Fatalf("UpdateUserAndBumpSession failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected ok=true for existing user")
	}
	if newVer != 2 {
		t.Fatalf("expected new session_version=2, got %d", newVer)
	}

	// Verify both fields and session_version are updated in DB
	fetched, err := db.GetUser(ctx, userID)
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	if fetched.PasswordHash != "new-secret-hash" {
		t.Errorf("expected PasswordHash='new-secret-hash', got %q", fetched.PasswordHash)
	}
	if fetched.TelegramID == nil || *fetched.TelegramID != "@atomic_tele" {
		t.Errorf("expected TelegramID='@atomic_tele', got %v", fetched.TelegramID)
	}
	if fetched.SessionVersion != 2 {
		t.Errorf("expected SessionVersion=2, got %d", fetched.SessionVersion)
	}

	// 3. Rollback on cancelled context: neither password nor session_version should change
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	failUpdates := map[string]any{
		"password_hash": "rolled-back-hash",
		"telegramId":    "@never_tele",
	}
	_, _, err = db.UpdateUserAndBumpSession(canceledCtx, userID, failUpdates)
	if err == nil {
		t.Fatalf("expected error with canceled context, got nil")
	}

	// Verify no changes were committed to the user
	fetchedAfterCancel, err := db.GetUser(ctx, userID)
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	if fetchedAfterCancel.PasswordHash != "new-secret-hash" {
		t.Errorf("expected PasswordHash to remain 'new-secret-hash', got %q", fetchedAfterCancel.PasswordHash)
	}
	if fetchedAfterCancel.TelegramID == nil || *fetchedAfterCancel.TelegramID != "@atomic_tele" {
		t.Errorf("expected TelegramID to remain '@atomic_tele', got %v", fetchedAfterCancel.TelegramID)
	}
	if fetchedAfterCancel.SessionVersion != 2 {
		t.Errorf("expected SessionVersion to remain 2, got %d", fetchedAfterCancel.SessionVersion)
	}

	// 4. Rollback on invalid column: verify transaction fails and rolls back
	invalidUpdates := map[string]any{
		"password_hash":  "invalid-col-hash",
		"unknown_column": "invalid_val",
	}
	_, _, err = db.UpdateUserAndBumpSession(ctx, userID, invalidUpdates)
	if err == nil {
		t.Fatalf("expected error with invalid column, got nil")
	}

	fetchedAfterInvalid, err := db.GetUser(ctx, userID)
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	if fetchedAfterInvalid.PasswordHash != "new-secret-hash" {
		t.Errorf("expected PasswordHash to remain 'new-secret-hash', got %q", fetchedAfterInvalid.PasswordHash)
	}
	if fetchedAfterInvalid.SessionVersion != 2 {
		t.Errorf("expected SessionVersion to remain 2, got %d", fetchedAfterInvalid.SessionVersion)
	}

	// 5. Non-existent user returns ok=false, newVer=0, err=nil
	okGhost, verGhost, err := db.UpdateUserAndBumpSession(ctx, "non-existent-user", updates)
	if err != nil {
		t.Fatalf("UpdateUserAndBumpSession for ghost returned error: %v", err)
	}
	if okGhost {
		t.Errorf("expected ok=false for non-existent user, got true")
	}
	if verGhost != 0 {
		t.Errorf("expected ver=0 for non-existent user, got %d", verGhost)
	}
}
