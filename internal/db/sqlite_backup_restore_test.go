package db

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-web/internal/models"
)

// TestSQLiteBackupRestorePreservesHealthData proves that the standard self-host
// backup procedure — close the app, copy the SQLite file, reopen it elsewhere —
// preserves all logged health data, including the JSON-serialized symptom and
// cycle-factor fields. For a tracker that owns the user's records, silent data
// loss or corruption on restore would be the worst-case failure, so it is worth
// an explicit regression.
func TestSQLiteBackupRestorePreservesHealthData(t *testing.T) {
	dir := t.TempDir()
	originalPath := filepath.Join(dir, "ovumcy.db")

	originalDB, err := OpenDatabase(Config{Driver: DriverSQLite, SQLitePath: originalPath})
	if err != nil {
		t.Fatalf("open original database: %v", err)
	}
	originalRepos := NewRepositories(originalDB)

	user := &models.User{
		Email:            "owner@example.com",
		PasswordHash:     "hash",
		RecoveryCodeHash: "recovery",
		Role:             models.RoleOwner,
		CycleLength:      models.DefaultCycleLength,
		PeriodLength:     models.DefaultPeriodLength,
		AutoPeriodFill:   true,
		CreatedAt:        time.Now().UTC(),
	}
	if err := originalRepos.Users.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	seedLogs := []models.DailyLog{
		{
			UserID: user.ID, Date: backupRestoreDay(t, "2026-02-01"),
			IsPeriod: true, CycleStart: true, Flow: "heavy", Mood: 3,
			Notes:           "first day, cramps",
			SymptomIDs:      []uint{1, 4, 7},
			CycleFactorKeys: []string{"stress", "travel"},
		},
		{
			UserID: user.ID, Date: backupRestoreDay(t, "2026-02-02"),
			IsPeriod: true, Flow: "light", BBT: 36.5,
		},
		{
			UserID: user.ID, Date: backupRestoreDay(t, "2026-02-15"),
			SexActivity: "protected", CervicalMucus: "eggwhite",
		},
	}
	for i := range seedLogs {
		if err := originalRepos.DailyLogs.Create(&seedLogs[i]); err != nil {
			t.Fatalf("create day log %d: %v", i, err)
		}
	}

	// Close the original connection so SQLite flushes (and checkpoints any WAL)
	// into the main file before it is copied.
	if sqlDB, err := originalDB.DB(); err == nil {
		if err := sqlDB.Close(); err != nil {
			t.Fatalf("close original database: %v", err)
		}
	}

	backupPath := filepath.Join(dir, "ovumcy-backup.db")
	copyFileForBackupTest(t, originalPath, backupPath)

	restoredDB, err := OpenDatabase(Config{Driver: DriverSQLite, SQLitePath: backupPath})
	if err != nil {
		t.Fatalf("open restored database: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := restoredDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	restoredRepos := NewRepositories(restoredDB)

	restoredUser, err := restoredRepos.Users.FindByID(user.ID)
	if err != nil {
		t.Fatalf("find restored user: %v", err)
	}
	if restoredUser.Email != user.Email || restoredUser.Role != user.Role {
		t.Fatalf("restored user mismatch: email=%q role=%q", restoredUser.Email, restoredUser.Role)
	}

	restoredLogs, err := restoredRepos.DailyLogs.ListByUser(user.ID)
	if err != nil {
		t.Fatalf("list restored logs: %v", err)
	}
	if len(restoredLogs) != len(seedLogs) {
		t.Fatalf("expected %d restored logs, got %d", len(seedLogs), len(restoredLogs))
	}

	restoredByDate := make(map[string]models.DailyLog, len(restoredLogs))
	for _, log := range restoredLogs {
		restoredByDate[log.Date.Format("2006-01-02")] = log
	}

	for _, want := range seedLogs {
		key := want.Date.Format("2006-01-02")
		got, ok := restoredByDate[key]
		if !ok {
			t.Fatalf("missing restored log for %s", key)
		}
		if got.IsPeriod != want.IsPeriod || got.CycleStart != want.CycleStart ||
			got.Flow != want.Flow || got.Mood != want.Mood || got.Notes != want.Notes ||
			got.BBT != want.BBT || got.SexActivity != want.SexActivity ||
			got.CervicalMucus != want.CervicalMucus {
			t.Fatalf("scalar field mismatch for %s:\n got %+v\nwant %+v", key, got, want)
		}
		if !slices.Equal(got.SymptomIDs, want.SymptomIDs) {
			t.Fatalf("SymptomIDs mismatch for %s: got %v want %v", key, got.SymptomIDs, want.SymptomIDs)
		}
		if !slices.Equal(got.CycleFactorKeys, want.CycleFactorKeys) {
			t.Fatalf("CycleFactorKeys mismatch for %s: got %v want %v", key, got.CycleFactorKeys, want.CycleFactorKeys)
		}
	}
}

func backupRestoreDay(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.ParseInLocation("2006-01-02", value, time.UTC)
	if err != nil {
		t.Fatalf("parse day %q: %v", value, err)
	}
	return parsed
}

func copyFileForBackupTest(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("open source for backup: %v", err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.Create(dst)
	if err != nil {
		t.Fatalf("create backup file: %v", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatalf("copy backup bytes: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close backup file: %v", err)
	}
}
