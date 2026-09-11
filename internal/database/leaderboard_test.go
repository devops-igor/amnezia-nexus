package database

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

func TestLeaderboardEmpty(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	entriesEmpty, err := db.GetLeaderboardSnapshot(ctx, 2026, 8)
	if err != nil || len(entriesEmpty) != 0 {
		t.Fatalf("GetLeaderboardSnapshot empty DB = (%v, %v), want ([], nil)", entriesEmpty, err)
	}

	historyEmpty, err := db.GetLeaderboardHistory(ctx, 0)
	if err != nil || len(historyEmpty) != 0 {
		t.Fatalf("GetLeaderboardHistory empty DB = (%v, %v), want ([], nil)", historyEmpty, err)
	}

	savedZero, err := db.SaveLeaderboardSnapshot(ctx, 2026, 8)
	if err != nil || savedZero != 0 {
		t.Errorf("SaveLeaderboardSnapshot empty = (%d, %v), want (0, nil)", savedZero, err)
	}
}

func TestLeaderboardSnapshotsAndHistory(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	u1ID, _ := db.CreateUser(ctx, &models.User{Username: "top_user_1", Enabled: true, TrafficResetStrategy: models.ResetStrategyMonthly})
	u2ID, _ := db.CreateUser(ctx, &models.User{Username: "top_user_2", Enabled: true, TrafficResetStrategy: models.ResetStrategyMonthly})
	u3ID, _ := db.CreateUser(ctx, &models.User{Username: "disabled_user", Enabled: false, TrafficResetStrategy: models.ResetStrategyMonthly})

	_ = db.UpdateUserTraffic(ctx, u1ID, 10000, 20000)
	_ = db.UpdateUserTraffic(ctx, u2ID, 5000, 10000)
	_ = db.UpdateUserTraffic(ctx, u3ID, 50000, 50000)

	savedCount, err := db.SaveLeaderboardSnapshot(ctx, 2026, 8)
	if err != nil || savedCount != 2 {
		t.Fatalf("SaveLeaderboardSnapshot expected 2, got %d, err=%v", savedCount, err)
	}

	snapEntries, err := db.GetLeaderboardSnapshot(ctx, 2026, 8)
	if err != nil || len(snapEntries) != 2 {
		t.Fatalf("GetLeaderboardSnapshot expected 2, got %d, err=%v", len(snapEntries), err)
	}
	if snapEntries[0].Username != "top_user_1" || snapEntries[0].Rank != 1 || snapEntries[0].Total != 30000 {
		t.Errorf("Snapshot rank 1 mismatch: %+v", snapEntries[0])
	}
	if snapEntries[1].Username != "top_user_2" || snapEntries[1].Rank != 2 || snapEntries[1].Total != 15000 {
		t.Errorf("Snapshot rank 2 mismatch: %+v", snapEntries[1])
	}

	_, _ = db.SaveLeaderboardSnapshot(ctx, 2026, 7)

	historyDefaultLimit, err := db.GetLeaderboardHistory(ctx, -1)
	if err != nil || len(historyDefaultLimit) != 4 {
		t.Fatalf("GetLeaderboardHistory(-1) expected 4, got %d, err=%v", len(historyDefaultLimit), err)
	}

	historyLimited, err := db.GetLeaderboardHistory(ctx, 2)
	if err != nil || len(historyLimited) != 2 {
		t.Fatalf("GetLeaderboardHistory(2) expected 2, got %d, err=%v", len(historyLimited), err)
	}
}

func TestLeaderboardSnapshotPruning(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	uID, _ := db.CreateUser(ctx, &models.User{Username: "prune_user", Enabled: true, TrafficResetStrategy: models.ResetStrategyMonthly})
	_ = db.UpdateUserTraffic(ctx, uID, 1000, 2000)

	now := time.Now()
	currYear, currMonth := now.Year(), int(now.Month())
	oldDate := now.AddDate(0, -2, 0)
	oldYear, oldMonth := oldDate.Year(), int(oldDate.Month())

	_, _ = db.SaveLeaderboardSnapshot(ctx, currYear, currMonth)
	_, _ = db.SaveLeaderboardSnapshot(ctx, oldYear, oldMonth)

	deletedOld, err := db.DeleteOldSnapshots(ctx, 1)
	if err != nil || deletedOld != 1 {
		t.Errorf("DeleteOldSnapshots(1) = (%d, %v), want (1, nil)", deletedOld, err)
	}

	historyAfterDelete, _ := db.GetLeaderboardHistory(ctx, 100)
	if len(historyAfterDelete) != 1 {
		t.Errorf("expected 1 snapshot remaining after pruning, got %d", len(historyAfterDelete))
	}
}

func TestGetLeaderboard_LastMonth(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	// 1. When DB is empty, GetLeaderboard("last-month") must return non-nil empty slice
	entriesEmpty, err := db.GetLeaderboard(ctx, "last-month")
	if err != nil {
		t.Fatalf("GetLeaderboard(last-month) on empty DB failed: %v", err)
	}
	if entriesEmpty == nil {
		t.Fatalf("GetLeaderboard(last-month) returned nil slice, want non-nil empty slice")
	}
	if len(entriesEmpty) != 0 {
		t.Fatalf("GetLeaderboard(last-month) returned %d entries, want 0", len(entriesEmpty))
	}

	// 2. Create users with traffic in users table (all-time & monthly)
	u1ID, _ := db.CreateUser(ctx, &models.User{Username: "alice", Enabled: true, TrafficResetStrategy: models.ResetStrategyMonthly})
	u2ID, _ := db.CreateUser(ctx, &models.User{Username: "bob", Enabled: true, TrafficResetStrategy: models.ResetStrategyMonthly})
	_ = db.UpdateUserTraffic(ctx, u1ID, 100000, 200000) // total = 300,000
	_ = db.UpdateUserTraffic(ctx, u2ID, 50000, 50000)   // total = 100,000

	// Verify all-time returns both users
	allTime, err := db.GetLeaderboard(ctx, "all-time")
	if err != nil || len(allTime) != 2 {
		t.Fatalf("GetLeaderboard(all-time) failed: len=%d, err=%v", len(allTime), err)
	}

	// Verify monthly returns both users
	monthly, err := db.GetLeaderboard(ctx, "monthly")
	if err != nil || len(monthly) != 2 {
		t.Fatalf("GetLeaderboard(monthly) failed: len=%d, err=%v", len(monthly), err)
	}

	// But without a snapshot for last month, "last-month" MUST return empty slice (not all-time traffic!)
	lastMonthNoSnap, err := db.GetLeaderboard(ctx, "last-month")
	if err != nil {
		t.Fatalf("GetLeaderboard(last-month) with users but no snapshot failed: %v", err)
	}
	if lastMonthNoSnap == nil {
		t.Fatalf("GetLeaderboard(last-month) returned nil slice, want non-nil empty slice")
	}
	if len(lastMonthNoSnap) != 0 {
		t.Fatalf("GetLeaderboard(last-month) returned %d entries from all-time traffic, want 0 (no snapshot)", len(lastMonthNoSnap))
	}

	// 3. Now insert a snapshot for the prior calendar month directly into leaderboard_snapshots
	now := time.Now()
	prev := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).AddDate(0, -1, 0)
	prevYear, prevMonth := prev.Year(), int(prev.Month())

	query := `INSERT INTO leaderboard_snapshots (year, month, username, rank, download, upload, total, snapshot_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	// Bob was rank 1 last month with 45000, Alice was rank 2 with 25000
	_, err = db.ExecContext(ctx, query, prevYear, prevMonth, "bob", 1, 20000, 25000, 45000, now.Format(time.RFC3339))
	if err != nil {
		t.Fatalf("failed to insert snapshot entry: %v", err)
	}
	_, err = db.ExecContext(ctx, query, prevYear, prevMonth, "alice", 2, 10000, 15000, 25000, now.Format(time.RFC3339))
	if err != nil {
		t.Fatalf("failed to insert snapshot entry: %v", err)
	}

	// 4. Query GetLeaderboard("last-month") - must return the snapshot data
	lastMonthWithSnap, err := db.GetLeaderboard(ctx, "last-month")
	if err != nil {
		t.Fatalf("GetLeaderboard(last-month) failed: %v", err)
	}
	if len(lastMonthWithSnap) != 2 {
		t.Fatalf("GetLeaderboard(last-month) expected 2 entries from snapshot, got %d", len(lastMonthWithSnap))
	}

	if lastMonthWithSnap[0].Username != "bob" || lastMonthWithSnap[0].Rank != 1 || lastMonthWithSnap[0].Total != 45000 {
		t.Errorf("expected bob rank 1 total 45000, got: %+v", lastMonthWithSnap[0])
	}
	if lastMonthWithSnap[1].Username != "alice" || lastMonthWithSnap[1].Rank != 2 || lastMonthWithSnap[1].Total != 25000 {
		t.Errorf("expected alice rank 2 total 25000, got: %+v", lastMonthWithSnap[1])
	}
}
