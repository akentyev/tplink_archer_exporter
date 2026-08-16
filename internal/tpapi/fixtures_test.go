package tpapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Run over testdata/: real firmware replies with identifiers swapped out.
// See testdata/README.md.

func fixtures(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no fixtures found")
	}
	out := make(map[string]json.RawMessage, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(p)] = raw
	}
	return out
}

func walkJSON(t *testing.T, raw json.RawMessage, fn func(key string, val any)) {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var walk func(any)
	walk = func(n any) {
		switch x := n.(type) {
		case map[string]any:
			for k, val := range x {
				fn(k, val)
				walk(val)
			}
		case []any:
			for _, val := range x {
				walk(val)
			}
		}
	}
	walk(v)
}

// Guards the directory, not a behaviour: a fixture with a live credential in it
// would be committed and published.
func TestFixturesCarryNoSecrets(t *testing.T) {
	for name, raw := range fixtures(t) {
		walkJSON(t, raw, func(k string, v any) {
			s, ok := v.(string)
			if !ok || !IsSecretField(k) || strings.TrimSpace(s) == "" {
				return
			}
			if s != Mask {
				t.Errorf("%s: field %q holds %q, want %q — re-anonymise before committing",
					name, k, s, Mask)
			}
		})
	}
}

var (
	docMAC  = regexp.MustCompile(`^00[:-]00[:-]5[Ee][:-]`)
	anyIPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	testNet = regexp.MustCompile(`^(192\.0\.2\.|0\.0\.0\.0|255\.)`)
)

// Anonymisation must hold for addresses too, not just credentials.
func TestFixturesUseDocumentationAddresses(t *testing.T) {
	macish := regexp.MustCompile(`^[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}$`)
	for name, raw := range fixtures(t) {
		walkJSON(t, raw, func(k string, v any) {
			s, ok := v.(string)
			if !ok {
				return
			}
			if macish.MatchString(s) && !docMAC.MatchString(s) {
				t.Errorf("%s: %q = %q is outside the documentation OUI", name, k, s)
			}
			for _, ip := range anyIPv4.FindAllString(s, -1) {
				if !testNet.MatchString(ip) {
					t.Errorf("%s: %q contains %q, outside TEST-NET-1", name, k, ip)
				}
			}
		})
	}
}

// Every MAC must collapse to one canonical spelling whatever endpoint it came
// from; the joins downstream depend on it.
func TestNormalizeMACOverFixtures(t *testing.T) {
	macKeys := map[string]bool{"mac": true, "macaddr": true, "connect_device_mac": true, "host_mac": true}
	canonical := regexp.MustCompile(`^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$`)

	seen := 0
	for name, raw := range fixtures(t) {
		walkJSON(t, raw, func(k string, v any) {
			s, ok := v.(string)
			if !ok || !macKeys[k] || s == "" {
				return
			}
			got := NormalizeMAC(s)
			if !canonical.MatchString(got) {
				t.Errorf("%s: NormalizeMAC(%q) = %q, not canonical", name, s, got)
			}
			seen++
		})
	}
	if seen == 0 {
		t.Fatal("no MAC fields found in fixtures; the test is not covering anything")
	}
}

// leasetime is either a literal or a duration whose hours are unpadded and may
// exceed a day, which is why parsing it cannot be naive.
func TestFixturesPinLeaseTimeShapes(t *testing.T) {
	var clients []struct {
		LeaseTime string `json:"leasetime"`
	}
	if err := json.Unmarshal(fixtures(t)["dhcp_clients.json"], &clients); err != nil {
		t.Fatal(err)
	}
	var permanent, countdown, overADay int
	for _, c := range clients {
		switch {
		case c.LeaseTime == "Permanent":
			permanent++
		case strings.Count(c.LeaseTime, ":") == 2:
			countdown++
			if h, _, _ := strings.Cut(c.LeaseTime, ":"); len(h) > 2 {
				overADay++
			}
		default:
			t.Errorf("unexpected leasetime %q", c.LeaseTime)
		}
	}
	if permanent == 0 || countdown == 0 {
		t.Fatalf("fixture should keep both forms, got %d permanent / %d counting down",
			permanent, countdown)
	}
	if overADay == 0 {
		t.Error("fixture no longer covers hours beyond 24; that case broke naive parsers")
	}
}
