package config

import (
	"io"
	"log/slog"
)

// parseLogLevel maps a documented LOG_LEVEL value (README: DEBUG, INFO, WARN,
// ERROR) to a slog.Level. Any other value falls back to INFO, the documented
// default, so an unrecognised setting cannot silently hide more than the default.
func parseLogLevel(name string) slog.Level {
	switch name {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// NewLogHandler returns the text handler the panel and the server install, at
// the level named by the documented LOG_LEVEL value. It is the single definition
// those binaries and the regressions that assert operator-visible logging all
// derive from, so a test never observes a threshold the deployed handler lacks.
func NewLogHandler(w io.Writer, logLevel string) slog.Handler {
	return slog.NewTextHandler(w, &slog.HandlerOptions{Level: parseLogLevel(logLevel)})
}
