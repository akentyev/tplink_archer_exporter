package tpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// Every name below came from a real AX80 dump.
func TestIsSecretField(t *testing.T) {
	secret := []string{
		"password", "psk_key", "wpa_key", "wep_key1", "wep_key4",
		"wireless_2g_psk_key", "wireless_5g_psk_key", "guest_2g_psk_key",
		"guest_2g5g_psk_key", "iot_5g_psk_key", "mlo_host_2g_psk_key",
		"guest_5g_portal_password", "netbios_pass", "preshared_key",
		"private_key", "public_key", "key", "old_pwd", "new_pwd", "cfm_pwd",
	}
	for _, n := range secret {
		if !IsSecretField(n) {
			t.Errorf("%q should be treated as a secret", n)
		}
	}

	// Describe a credential, or are capability flags.
	keep := []string{
		"psk_version", "psk_cipher", "wireless_2g_psk_version",
		"wireless_5g_psk_cipher", "guest_2g5g_passwd_cycle",
		"support_guest_dynpasswd", "hide_password_recovery",
		"wpa_group_rekey", "cert_exist", "enable_auth",
		// no credential hint at all
		"macaddr", "ipaddr", "hostname", "leasetime", "trafficUsage",
		"deviceTag", "wire_type", "access_uptime", "connect_device_id",
	}
	for _, n := range keep {
		if IsSecretField(n) {
			t.Errorf("%q should not be masked", n)
		}
	}
}

func TestRedactMasksNestedSecrets(t *testing.T) {
	in := json.RawMessage(`{
		"ssid": "home",
		"psk_key": "hunter2hunter2",
		"psk_version": "wpa2",
		"clients": [{"mac": "AA-BB", "password": "s3cr3t"}],
		"vpn": {"private_key": "abcdef", "listen_port": 51820}
	}`)
	out := Redact(in)
	s := string(out)

	for _, leak := range []string{"hunter2hunter2", "s3cr3t", "abcdef"} {
		if strings.Contains(s, leak) {
			t.Fatalf("secret %q survived redaction: %s", leak, s)
		}
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["ssid"] != "home" || got["psk_version"] != "wpa2" {
		t.Fatalf("non-secret fields were altered: %v", got)
	}
	if got["psk_key"] != Mask {
		t.Fatalf("psk_key = %v, want %q", got["psk_key"], Mask)
	}
	// The field must survive so the dump still shows the shape.
	if _, ok := got["psk_key"]; !ok {
		t.Fatal("psk_key should be present but masked, not dropped")
	}
	vpn := got["vpn"].(map[string]any)
	if vpn["private_key"] != Mask {
		t.Fatalf("nested private_key not masked: %v", vpn)
	}
	if vpn["listen_port"].(float64) != 51820 {
		t.Fatalf("neighbouring field altered: %v", vpn)
	}
	client := got["clients"].([]any)[0].(map[string]any)
	if client["password"] != Mask || client["mac"] != "AA-BB" {
		t.Fatalf("array element handled wrong: %v", client)
	}
}

// Numbers and booleans are never credentials; an empty string is signal.
func TestRedactLeavesNonStringsAndBlanks(t *testing.T) {
	in := json.RawMessage(`{"key": 3, "password": "", "wep_key1": "", "private": true}`)
	out := Redact(in)
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if n, ok := got["key"].(json.Number); ok && n.String() != "3" {
		t.Fatalf("numeric key altered: %v", got["key"])
	}
	if got["password"] != "" || got["wep_key1"] != "" {
		t.Fatalf("empty strings should stay visible: %v", got)
	}
	if got["private"] != true {
		t.Fatalf("bool altered: %v", got)
	}
}

// Go's default encoder escapes <, > and &, which would mangle both the mask and
// any field carrying markup (the portal content form returns HTML).
func TestRedactDoesNotEscapeHTML(t *testing.T) {
	in := json.RawMessage(`{"psk_key":"x","content":"<b>hi</b> you & me"}`)
	out := string(Redact(in))
	if !strings.Contains(out, `"`+Mask+`"`) {
		t.Fatalf("mask was escaped: %s", out)
	}
	// "u003c" and friends can only appear as part of a \uXXXX escape.
	for _, esc := range []string{"u003c", "u003e", "u0026"} {
		if strings.Contains(out, esc) {
			t.Fatalf("payload contains a unicode escape (%s): %s", esc, out)
		}
	}
	if !strings.Contains(out, "<b>hi</b> you & me") {
		t.Fatalf("markup field was altered: %s", out)
	}
}

// Counters must not round-trip through float64 as 5.21486e+09.
func TestRedactKeepsBigIntegersExact(t *testing.T) {
	in := json.RawMessage(`{"trafficUsage": 5214864152, "psk_key": "x"}`)
	out := Redact(in)
	if !strings.Contains(string(out), "5214864152") {
		t.Fatalf("counter lost precision: %s", out)
	}
}

// Untouched payloads keep the router's byte order.
func TestRedactReturnsInputWhenNothingMatched(t *testing.T) {
	in := json.RawMessage(`{"zebra":1,"alpha":2}`)
	if got := Redact(in); string(got) != string(in) {
		t.Fatalf("payload was rewritten for no reason: %s", got)
	}
	if got := Redact(nil); got != nil {
		t.Fatalf("nil payload became %q", got)
	}
	if got := Redact(json.RawMessage(`not json`)); string(got) != "not json" {
		t.Fatalf("non-JSON payload was altered: %s", got)
	}
}
