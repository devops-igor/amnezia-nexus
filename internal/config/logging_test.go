package config

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
)

// TestNewLogHandlerKeepsDocumentedLevels pins the LOG_LEVEL mapping the panel and
// the server install: each documented name accepts its own records and rejects
// lower ones, and an unrecognised value falls back to the documented INFO default.
func TestNewLogHandlerKeepsDocumentedLevels(t *testing.T) {
	cases := []struct {
		level    string
		emit     slog.Level
		wantEmit bool
	}{
		{"DEBUG", slog.LevelDebug, true},
		{"DEBUG", slog.LevelInfo, true},
		{"INFO", slog.LevelInfo, true},
		{"INFO", slog.LevelWarn, true},
		{"INFO", slog.LevelDebug, false},
		{"WARN", slog.LevelWarn, true},
		{"WARN", slog.LevelInfo, false},
		{"ERROR", slog.LevelError, true},
		{"ERROR", slog.LevelWarn, false},
		{"unknown-level", slog.LevelInfo, true},
		{"unknown-level", slog.LevelDebug, false},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		slog.New(NewLogHandler(&buf, tc.level)).Log(context.Background(), tc.emit, "probe")
		if got := buf.Len() > 0; got != tc.wantEmit {
			t.Errorf("LOG_LEVEL=%s record at %s emitted=%v, want %v", tc.level, tc.emit, got, tc.wantEmit)
		}
	}
}
