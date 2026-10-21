package tpapi

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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

// walkValue calls fn for every value below v with the key it sits under. Array
// elements take the nearest enclosing key, "" when there is none.
func walkValue(key string, v any, fn func(key string, val any)) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			fn(k, val)
			walkValue(k, val, fn)
		}
	case []any:
		for _, val := range x {
			fn(key, val)
			walkValue(key, val, fn)
		}
	}
}

// A guard lists what one fixture leaks, one message per violation, each naming
// the fixture, the key and the value.
type guard func(name string, raw json.RawMessage) []string

func guardFixtures(t *testing.T, g guard) {
	t.Helper()
	for name, raw := range fixtures(t) {
		for _, p := range g(name, raw) {
			t.Errorf("%s — re-anonymise before committing", p)
		}
	}
}

// A leakRow is an inline fixture holding one leak the guard must report exactly
// once or, with no value, only stand-ins it must pass.
type leakRow struct {
	name, raw  string
	key, value string // the leak
	also       string // more the problem must name, such as the MAC behind an EUI-64
}

func checkLeakRows(t *testing.T, g guard, rows []leakRow) {
	t.Helper()
	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			got := g("leak.json", json.RawMessage(tt.raw))
			if tt.value == "" {
				if len(got) != 0 {
					t.Fatalf("want no problems, got %q", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("want exactly one problem, got %d: %q", len(got), got)
			}
			// Messages quote the key and the value with %q.
			for _, want := range []string{"leak.json", strconv.Quote(tt.key), strconv.Quote(tt.value), tt.also} {
				if !strings.Contains(got[0], want) {
					t.Errorf("problem %q does not name %q", got[0], want)
				}
			}
		})
	}
}

// Guards the directory, not a behaviour: a fixture with a live credential in it
// would be committed and published.
func TestFixturesCarryNoSecrets(t *testing.T) { guardFixtures(t, secretProblems) }

func TestSecretGuardCatchesLeaks(t *testing.T) {
	checkLeakRows(t, secretProblems, []leakRow{
		{
			name:  "flat",
			raw:   `[{"private_key": "wg-private-key", "public_key": "<redacted>"}]`,
			key:   "private_key",
			value: "wg-private-key",
		},
		{
			name:  "array element",
			raw:   `{"key": ["<redacted>", "wg-preshared-key"]}`,
			key:   "key",
			value: "wg-preshared-key",
		},
		{
			name:  "nested in an object under a secret key",
			raw:   `{"private_key": {"value": "wg-private-key"}}`,
			key:   "private_key",
			value: "wg-private-key",
		},
		{
			name:  "inside an object nested in an object",
			raw:   `{"wireless_2g_extinfo": {"wireless_2g_psk_key": "wifi-psk"}}`,
			key:   "wireless_2g_psk_key",
			value: "wifi-psk",
		},
		{
			name: "masked, blank or describing a secret",
			raw: `[
				{"wireless_2g_psk_key": "<redacted>", "wireless_2g_wep_key1": "",
				 "wireless_2g_psk_cipher": "aes", "guest_2g_extinfo": {"support_guest_dynpasswd": "on"}},
				{"key": "<redacted>", "name": "bulb-a"}
			]`,
		},
	})
}

// secretProblems lists unmasked credentials. Redact replaces a secret field's
// whole value, so any non-blank string anywhere inside one is a leak.
func secretProblems(name string, raw json.RawMessage) []string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return []string{fmt.Sprintf("%s: %v", name, err)}
	}
	var out []string
	var walk func(secret string, v any)
	walk = func(secret string, v any) {
		switch x := v.(type) {
		case string:
			if secret != "" && strings.TrimSpace(x) != "" && x != Mask {
				out = append(out, fmt.Sprintf("%s: field %q holds %q, want %q", name, secret, x, Mask))
			}
		case map[string]any:
			for k, val := range x {
				inner := secret
				if IsSecretField(k) {
					inner = k
				}
				walk(inner, val)
			}
		case []any:
			for _, elem := range x {
				walk(secret, elem)
			}
		}
	}
	walk("", v)
	slices.Sort(out)
	return out
}

var (
	// IANA's OUI 00-00-5E also holds live protocol MACs, such as VRRP's
	// 00-00-5E-00-01-xx; only 00-00-5E-00-53-xx is for documentation (RFC 7042).
	docMAC      = regexp.MustCompile(`^00[:-]00[:-]5[Ee][:-]00[:-]53[:-]`)
	macish      = regexp.MustCompile(`^[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}$`)
	bareMAC     = regexp.MustCompile(`^[0-9A-Fa-f]{12}$`)
	dottedRun   = regexp.MustCompile(`[0-9.]+`)
	ipv4Shape   = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)
	standInIPv4 = regexp.MustCompile(`^(192\.0\.2\.|0\.0\.0\.0|255\.)`)
	linkLocal   = netip.MustParsePrefix("fe80::/10")
	docIPv6     = netip.MustParsePrefix("2001:db8::/32")
)

// Anonymisation must hold for addresses too, not just credentials.
func TestFixturesUseDocumentationAddresses(t *testing.T) { guardFixtures(t, addressProblems) }

func TestAddressGuardCatchesLeaks(t *testing.T) {
	checkLeakRows(t, addressProblems, []leakRow{
		{
			name:  "IPv4 outside TEST-NET-1 as an array element",
			raw:   `{"dns_servers": ["192.0.2.26", "198.51.100.7"]}`,
			key:   "dns_servers",
			value: "198.51.100.7",
		},
		{
			name:  "IPv4 outside TEST-NET-1 inside a CIDR",
			raw:   `{"address": "198.51.100.7/24"}`,
			key:   "address",
			value: "198.51.100.7/24",
		},
		{
			name:  "IPv4 outside TEST-NET-1 glued to a word",
			raw:   `{"note": "ip198.51.100.7"}`,
			key:   "note",
			value: "ip198.51.100.7",
		},
		{
			name:  "IPv4 outside TEST-NET-1 after a word and a dot",
			raw:   `{"note": "host.198.51.100.7"}`,
			key:   "note",
			value: "host.198.51.100.7",
		},
		{
			name:  "IPv4 outside TEST-NET-1 after a stand-in and a comma",
			raw:   `{"dns": "192.0.2.26,198.51.100.7"}`,
			key:   "dns",
			value: "192.0.2.26,198.51.100.7",
		},
		{
			name:  "IPv4 outside TEST-NET-1 ending a sentence",
			raw:   `{"note": "upstream 198.51.100.7."}`,
			key:   "note",
			value: "upstream 198.51.100.7.",
		},
		{
			name:  "MAC in IANA's OUI outside the documentation range",
			raw:   `{"mac": "00-00-5E-00-01-07"}`,
			key:   "mac",
			value: "00-00-5E-00-01-07",
		},
		{
			name:  "MAC outside the documentation range with a trailing newline",
			raw:   `{"mac": "00-00-5E-00-01-07\n"}`,
			key:   "mac",
			value: "00-00-5E-00-01-07\n",
		},
		{
			name:  "bare twelve-hex MAC under device_id",
			raw:   `[{"device_id": "AABBCCDDEEFF"}]`,
			key:   "device_id",
			value: "AABBCCDDEEFF",
		},
		{
			name:  "bare twelve-hex MAC under device_id with a leading space",
			raw:   `{"device_id": " AABBCCDDEEFF"}`,
			key:   "device_id",
			value: " AABBCCDDEEFF",
		},
		{
			name:  "bare twelve-hex MAC under a key containing mac",
			raw:   `{"connect_device_mac": "AABBCCDDEEFF"}`,
			key:   "connect_device_mac",
			value: "AABBCCDDEEFF",
		},
		{
			name:  "IPv6 just outside the documentation prefix",
			raw:   `{"wan_ipv6_ip6addr": "2001:db9::1/64"}`,
			key:   "wan_ipv6_ip6addr",
			value: "2001:db9::1/64",
		},
		{
			name:  "IPv6 just outside link-local",
			raw:   `{"lan_ipv6_ipaddr": "FEC0::1/64"}`,
			key:   "lan_ipv6_ipaddr",
			value: "FEC0::1/64",
		},
		{
			name: "documentation addresses only",
			raw: `[
				{"mac": "00-00-5E-00-53-0A", "macaddr": "00-00-5e-00-53-01", "host_mac": "00:00:5E:00:53:0B",
				 "device_id": "00005E005301", "session_id": "0123456789ab"},
				{"ipaddr": "192.0.2.25", "allowed_ips": "0.0.0.0/0", "netmask": "255.255.255.0",
				 "version": "1.2.3.4.5"},
				{"lan_ipv6_ipaddr": "FE80::200:5EFF:FE00:5315/64", "lan_ipv6_link_local_addr": "FEBF::1",
				 "wan_ipv6_gateway": "::", "dns6": "2001:db8::1"}
			]`,
		},
	})
}

// addressProblems lists the MACs and IP addresses in one fixture outside the
// documentation ranges; IPv4 may also be 0.0.0.0 or 255.*, IPv6 link-local
// or ::.
func addressProblems(name string, raw json.RawMessage) []string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return []string{fmt.Sprintf("%s: %v", name, err)}
	}
	var out []string
	walkValue("", v, func(k string, val any) {
		s, ok := val.(string)
		if !ok {
			return
		}
		bad := func(why string) {
			out = append(out, fmt.Sprintf("%s: %q = %q %s", name, k, s, why))
		}
		// RE2's $ is end of text, so "00-00-5E-00-01-07\n" would pass untrimmed.
		m := strings.TrimSpace(s)
		// The firmware writes bare twelve-hex MACs in device_id
		// (vpn?form=vpn_user_devices); under other keys it is any hex.
		bare := (strings.Contains(k, "mac") || k == "device_id") && bareMAC.MatchString(m)
		if macish.MatchString(m) || bare {
			if hw, err := net.ParseMAC(m); err != nil || !docMAC.MatchString(hw.String()) {
				bad("is outside 00-00-5E-00-53-xx")
			}
		}
		for _, ip := range ipv4s(s) {
			if !standInIPv4.MatchString(ip) {
				bad("contains " + ip + ", outside TEST-NET-1")
			}
		}
		for _, a := range ipv6Addrs(s) {
			if a != netip.IPv6Unspecified() && !linkLocal.Contains(a) && !docIPv6.Contains(a) {
				bad("contains " + a.String() + ", outside fe80::/10, 2001:db8::/32 and ::")
			}
		}
	})
	slices.Sort(out)
	return out
}

// ipv4s returns the dotted quads in s that make up a whole run of digits and
// dots, edge dots aside. "ip198.51.100.7" and "… 198.51.100.7." count, the
// version "1.2.3.4.5" does not, and "192.0.2.26,198.51.100.7" yields both:
// runs never share the separator between them.
func ipv4s(s string) []string {
	var out []string
	for _, run := range dottedRun.FindAllString(s, -1) {
		if run = strings.Trim(run, "."); ipv4Shape.MatchString(run) {
			out = append(out, run)
		}
	}
	return out
}

// ipv6Addrs returns the IPv6 addresses written in s, including one glued to a
// label or a full stop: "ip:fe80::1", "… fe80::1.".
func ipv6Addrs(s string) []netip.Addr {
	notIPv6 := func(r rune) bool { return !strings.ContainsRune("0123456789ABCDEFabcdef:.", r) }
	var addrs []netip.Addr
	for _, tok := range strings.FieldsFunc(s, notIPv6) {
		tok = strings.TrimRight(tok, ".")
		if strings.HasPrefix(tok, ":") && !strings.HasPrefix(tok, "::") {
			tok = tok[1:]
		}
		if a, err := netip.ParseAddr(tok); err == nil && a.Is6() {
			addrs = append(addrs, a)
		}
	}
	return addrs
}

var (
	testNet1       = netip.MustParsePrefix("192.0.2.0/24")
	standInNTP     = map[string]bool{"europe.pool.ntp.org": true, "nl.pool.ntp.org": true}
	exampleDomains = []string{"example.net", "example.com", "example.org"} // RFC 2606
	// Stands in for the router's own id, which traffic?form=dev_name carries on
	// every row.
	standInDeviceID = "467345895992F440CC845294D32EC4E4FDFD9795"
	hexRun          = regexp.MustCompile(`[0-9A-Fa-f]+`)
)

// Identity the address and secret guards miss: EUI-64 addresses, SSIDs, NTP
// servers, the router's device id, the VPN endpoint and the remote-management
// host.
func TestFixturesCarryOnlyStandInIdentities(t *testing.T) { guardFixtures(t, standInProblems) }

// The clean row carries the stand-ins the committed fixtures use, so it also
// pins the multissid exception and the universal/local flip.
func TestStandInGuardCatchesLeaks(t *testing.T) {
	checkLeakRows(t, standInProblems, []leakRow{
		{
			name:  "SSID",
			raw:   `{"wireless_2g_ssid": "HomeNet", "wireless_2g_enable_portal_multissid": "off"}`,
			key:   "wireless_2g_ssid",
			value: "HomeNet",
		},
		{
			name:  "SSID under an upper-case key",
			raw:   `{"SSID": "HomeNet"}`,
			key:   "SSID",
			value: "HomeNet",
		},
		{
			name:  "SSID under a key that does not end in ssid",
			raw:   `{"ssid_5g": "HomeNet"}`,
			key:   "ssid_5g",
			value: "HomeNet",
		},
		{
			name:  "SSID with testnet after its start",
			raw:   `{"wireless_5g_ssid": "home-testnet"}`,
			key:   "wireless_5g_ssid",
			value: "home-testnet",
		},
		{
			name:  "SSID inside an object nested in an object",
			raw:   `{"guest_2g_extinfo": {"ssid": "HomeNet"}}`,
			key:   "ssid",
			value: "HomeNet",
		},
		{
			name:  "EUI-64 address of a MAC outside the documentation range",
			raw:   `{"lan_ipv6_assign_type": "slaac", "lan_ipv6_ipaddr": "FE80::A8BB:CCFF:FEDD:EEFF/64"}`,
			key:   "lan_ipv6_ipaddr",
			value: "FE80::A8BB:CCFF:FEDD:EEFF/64",
			also:  "aa:bb:cc:dd:ee:ff",
		},
		{
			name:  "EUI-64 address of a MAC elsewhere in IANA's OUI",
			raw:   `{"lan_ipv6_ipaddr": "FE80::200:5EFF:FE12:3456/64"}`,
			key:   "lan_ipv6_ipaddr",
			value: "FE80::200:5EFF:FE12:3456/64",
			also:  "00:00:5e:12:34:56",
		},
		{
			name:  "EUI-64 address outside link-local",
			raw:   `{"lan_ipv6_ipaddr": "2001:DB8::A8BB:CCFF:FEDD:EEFF/64"}`,
			key:   "lan_ipv6_ipaddr",
			value: "2001:DB8::A8BB:CCFF:FEDD:EEFF/64",
			also:  "aa:bb:cc:dd:ee:ff",
		},
		{
			name:  "EUI-64 address as an array element",
			raw:   `{"addresses": ["::", "FE80::A8BB:CCFF:FEDD:EEFF/64"]}`,
			key:   "addresses",
			value: "FE80::A8BB:CCFF:FEDD:EEFF/64",
			also:  "aa:bb:cc:dd:ee:ff",
		},
		{
			name:  "EUI-64 address glued to a label",
			raw:   `{"description": "ip:FE80::A8BB:CCFF:FEDD:EEFF"}`,
			key:   "description",
			value: "ip:FE80::A8BB:CCFF:FEDD:EEFF",
			also:  "aa:bb:cc:dd:ee:ff",
		},
		{
			name:  "EUI-64 address ending a sentence",
			raw:   `{"description": "neighbour FE80::A8BB:CCFF:FEDD:EEFF."}`,
			key:   "description",
			value: "neighbour FE80::A8BB:CCFF:FEDD:EEFF.",
			also:  "aa:bb:cc:dd:ee:ff",
		},
		{
			name:  "first NTP server",
			raw:   `{"ntp_svr1": "0.pool.ntp.org", "ntp_svr2": "europe.pool.ntp.org"}`,
			key:   "ntp_svr1",
			value: "0.pool.ntp.org",
		},
		{
			name:  "second NTP server",
			raw:   `{"ntp_svr1": "nl.pool.ntp.org", "ntp_svr2": "0.pool.ntp.org"}`,
			key:   "ntp_svr2",
			value: "0.pool.ntp.org",
		},
		{
			name:  "VPN endpoint",
			raw:   `[{"endpoint_address": "vpn.realcorp.invalid", "endpoint_port": "51820"}]`,
			key:   "endpoint_address",
			value: "vpn.realcorp.invalid",
		},
		{
			name:  "VPN endpoint under a lookalike of an example domain",
			raw:   `[{"endpoint_address": "vpn.notexample.net", "endpoint_port": "51820"}]`,
			key:   "endpoint_address",
			value: "vpn.notexample.net",
		},
		{
			name:  "VPN endpoint with an example domain inside its name",
			raw:   `[{"endpoint_address": "vpn.example.net.evil.invalid", "endpoint_port": "51820"}]`,
			key:   "endpoint_address",
			value: "vpn.example.net.evil.invalid",
		},
		{
			name:  "remote management address",
			raw:   `{"enable": "off", "web_address": "https://203.0.113.5:443"}`,
			key:   "web_address",
			value: "https://203.0.113.5:443",
		},
		{
			name:  "remote management address without a scheme",
			raw:   `{"enable": "off", "web_address": "203.0.113.5:443"}`,
			key:   "web_address",
			value: "203.0.113.5:443",
		},
		{
			name:  "router's device id",
			raw:   `[{"connect_device_id": "1111111111111111111111111111111111111111", "connect_device_mac": "00-00-5E-00-53-0A"}]`,
			key:   "connect_device_id",
			value: "1111111111111111111111111111111111111111",
		},
		{
			name:  "router's device id under another key",
			raw:   `[{"connect_device_id": "467345895992F440CC845294D32EC4E4FDFD9795", "router_id": "1111111111111111111111111111111111111111"}]`,
			key:   "router_id",
			value: "1111111111111111111111111111111111111111",
		},
		{
			name:  "router's device id inside text",
			raw:   `{"note": "id=1111111111111111111111111111111111111111;"}`,
			key:   "note",
			value: "id=1111111111111111111111111111111111111111;",
		},
		{
			name: "stand-ins only",
			raw: `[
				{"wireless_2g_ssid": "testnet-2g", "mlo_host_2g_ssid": "",
				 "wireless_2g_enable_portal_multissid": "off",
				 "lan_ipv6_ipaddr": "FE80::200:5EFF:FE00:5315/64", "wan_ipv6_gateway": "::"},
				{"ntp_svr1": "nl.pool.ntp.org", "ntp_svr2": "europe.pool.ntp.org"},
				{"endpoint_address": "vpn.example.net", "endpoint_port": "51820"},
				{"web_address": "https://192.0.2.29:443"},
				{"connect_device_id": "467345895992F440CC845294D32EC4E4FDFD9795", "connect_device_mac": "00-00-5E-00-53-0A"},
				{"router_id": "467345895992F440CC845294D32EC4E4FDFD9795", "note": "id=467345895992F440CC845294D32EC4E4FDFD9795;",
				 "hex39": "111111111111111111111111111111111111111", "hex41": "11111111111111111111111111111111111111111",
				 "sha256": "1111111111111111111111111111111111111111111111111111111111111111"}
			]`,
		},
	})
}

// standInProblems lists the identities in one fixture that are not stand-ins.
func standInProblems(name string, raw json.RawMessage) []string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return []string{fmt.Sprintf("%s: %v", name, err)}
	}
	var out []string
	walkValue("", v, func(k string, val any) {
		s, ok := val.(string)
		if !ok {
			return
		}
		bad := func(why string) {
			out = append(out, fmt.Sprintf("%s: %q = %q %s", name, k, s, why))
		}
		for _, a := range ipv6Addrs(s) {
			if mac, ok := eui64MAC(a); ok && !docMAC.MatchString(mac.String()) {
				bad("embeds MAC " + mac.String() + ", outside 00-00-5E-00-53-xx")
			}
		}
		// *_multissid keys hold an on/off switch, not a network name.
		ssidKey := strings.Contains(strings.ReplaceAll(strings.ToLower(k), "multissid", ""), "ssid")
		if ssidKey && s != "" && !strings.HasPrefix(s, "testnet") {
			bad("is neither empty nor a testnet* SSID")
		}
		if strings.HasPrefix(k, "ntp_svr") && !standInNTP[s] {
			bad("is not a stand-in NTP server")
		}
		if k != "connect_device_id" {
			for _, run := range hexRun.FindAllString(s, -1) {
				if len(run) == 40 && run != standInDeviceID {
					bad("contains " + run + ", a 40-hex id other than the stand-in")
				}
			}
		}
		switch k {
		case "connect_device_id":
			if s != standInDeviceID {
				bad("is not the stand-in device id")
			}
		case "endpoint_address":
			if !standInHost(s) {
				bad("is outside TEST-NET-1 and the example domains")
			}
		case "web_address":
			var host string // stays "" without a scheme, as in "192.0.2.29:443"
			if u, err := url.Parse(s); err == nil {
				host = u.Hostname()
			}
			if !standInHost(host) {
				bad("has no host in TEST-NET-1 or the example domains")
			}
		}
	})
	slices.Sort(out)
	return out
}

// eui64MAC returns the MAC an EUI-64 interface identifier was built from: the
// MAC's first three bytes with the universal/local bit 0x02 flipped, then ff:fe,
// then its last three bytes.
func eui64MAC(a netip.Addr) (net.HardwareAddr, bool) {
	b := a.As16()
	if b[11] != 0xff || b[12] != 0xfe {
		return nil, false
	}
	return net.HardwareAddr{b[8] ^ 0x02, b[9], b[10], b[13], b[14], b[15]}, true
}

func standInHost(host string) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		return testNet1.Contains(a)
	}
	host = strings.ToLower(host)
	for _, d := range exampleDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// Every MAC must collapse to one canonical spelling whatever endpoint it came
// from; the joins downstream depend on it.
func TestNormalizeMACOverFixtures(t *testing.T) {
	macKeys := map[string]bool{"mac": true, "macaddr": true, "connect_device_mac": true, "host_mac": true}
	canonical := regexp.MustCompile(`^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$`)

	seen := 0
	for name, raw := range fixtures(t) {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		walkValue("", v, func(k string, val any) {
			s, ok := val.(string)
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
