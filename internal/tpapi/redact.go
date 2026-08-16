package tpapi

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Secrets are masked here, in the client, the moment a reply is decrypted —
// not at the point where something gets written to disk. The router hands out
// live Wi-Fi PSKs, VPN private keys and account passwords in ordinary read
// responses, and a recon tool exists to learn field *names*, never their
// credential values. Masking at the source means no caller can leak one by
// accident, however it later decides to print or store what Call returned.

// Mask replaces a redacted value. It is deliberately a string for every field,
// so a dump still shows that the field was there.
const Mask = "<redacted>"

// Matching is default-deny: any field whose name hints at a credential is
// masked unless it looks like it *describes* one rather than *being* one.
var (
	secretHint = []string{
		"pass", "pwd", "psk", "key", "secret", "token", "credential", "cert", "private",
	}
	// A name ending like this is a cipher name, a version, a size or a flag —
	// e.g. psk_version "wpa2", psk_cipher "aes", wpa_group_rekey 3600.
	describesSecret = []string{
		"_version", "_cipher", "_format", "_type", "_mode", "_select", "_cycle",
		"_exist", "_support", "_rekey", "_status", "_enable", "_len", "_length",
		"_max", "_min", "_num", "_count", "_time", "_id", "_state", "_list",
	}
	// A name starting like this is a capability or UI flag —
	// e.g. support_guest_dynpasswd, hide_password_recovery.
	flagPrefix = []string{"support_", "hide_", "enable_", "is_", "has_", "show_", "need_"}
)

// IsSecretField reports whether a field of this name should have its value
// masked. Over-matching is the intended failure mode: masking a MAC that the
// firmware happens to call "key" costs nothing, since the same object carries
// it as "mac" too.
func IsSecretField(name string) bool {
	n := strings.ToLower(name)
	hinted := false
	for _, h := range secretHint {
		if strings.Contains(n, h) {
			hinted = true
			break
		}
	}
	if !hinted {
		return false
	}
	for _, p := range flagPrefix {
		if strings.HasPrefix(n, p) {
			return false
		}
	}
	for _, s := range describesSecret {
		if strings.HasSuffix(n, s) {
			return false
		}
	}
	return true
}

// Redact masks every credential-shaped field in a decoded payload. The input is
// returned untouched when nothing matched, so payloads that hold no secrets
// keep the router's own key order in the dumps.
func Redact(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep counters like trafficUsage exact, not float64
	var v any
	if err := dec.Decode(&v); err != nil {
		return raw // not JSON; nothing to walk
	}
	var hit bool
	v = redactValue(v, &hit)
	if !hit {
		return raw
	}
	// json.Marshal escapes <, > and & as \uXXXX, mangling both the mask and
	// fields carrying markup (wireless?form=portal_content).
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return raw
	}
	return bytes.TrimRight(buf.Bytes(), "\n") // Encode appends one
}

func redactValue(v any, hit *bool) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if IsSecretField(k) && maskable(val) {
				t[k] = Mask
				*hit = true
				continue
			}
			t[k] = redactValue(val, hit)
		}
	case []any:
		for i, val := range t {
			t[i] = redactValue(val, hit)
		}
	}
	return v
}

// maskable keeps numbers and booleans alone — a numeric "key" is an index, and
// no flag is a credential — and leaves empty strings visible, because "this
// field exists and is unset" is exactly what a recon dump is for.
func maskable(v any) bool {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t) != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	return false
}
