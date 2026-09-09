package push

import (
	"io"
	"log"
	"log/slog"
	"os"
	"testing"
)

// The sender warns on every refused or failed push; the tests that read those
// records install captureLog. slog.SetDefault redirects the log package too
// and clears its flags; both are put back because httptest leaves
// Server.ErrorLog nil and a handler panic goes through log.
func TestMain(m *testing.M) {
	out, flags := log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	log.SetOutput(out)
	log.SetFlags(flags)
	os.Exit(m.Run())
}
