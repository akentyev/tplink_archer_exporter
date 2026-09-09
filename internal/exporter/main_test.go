package exporter

import (
	"io"
	"log"
	"log/slog"
	"os"
	"testing"
)

// A poller held back from logging in says so every cycle; the tests that read
// those records install captureLog. slog.SetDefault redirects the log package
// too and clears its flags; both are put back, so what goes through log still
// reports.
func TestMain(m *testing.M) {
	out, flags := log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	log.SetOutput(out)
	log.SetFlags(flags)
	os.Exit(m.Run())
}
