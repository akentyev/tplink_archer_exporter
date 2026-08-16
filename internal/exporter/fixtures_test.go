package exporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// One copy of the fixtures serves both packages, so tpapi's anonymisation
// guards cover every reply in the repo.
const fixtureDir = "../tpapi/testdata"

// fixture reads one reply as Call hands it to a parser: decrypted, redacted,
// unwrapped from the envelope.
func fixture(t *testing.T, name string) json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return json.RawMessage(raw)
}
