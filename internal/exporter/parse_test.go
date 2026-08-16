package exporter

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/akentyev/tplink_archer_exporter/internal/tpapi"
)

// Written against the contract in parse.go and snapshot.go plus the fixtures in
// ../tpapi/testdata, with no implementation in sight. Every expectation is a
// value the firmware actually sent; a synthetic case says so and names the fact
// it rests on.

// One device in the three spellings the firmware uses for it.
const (
	macDashUpper = "00-00-5E-00-53-0A" // clients.json, dhcp_clients.json, arp_list.json
	macDashLower = "00-00-5e-00-53-0a" // client_times.json
	macColons    = "00:00:5E:00:53:0A" // vpn_users.json
	macCanonical = "00:00:5e:00:53:0a"
)

var canonicalMAC = regexp.MustCompile(`^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$`)

// secs turns the fractional seconds the firmware sends into a Duration.
func secs(f float64) time.Duration {
	return time.Duration(f * float64(time.Second))
}

// durClose compares durations built from float64 seconds. onlineTime arrives as
// 1931.6000000001, so the last nanoseconds are noise, not signal.
func durClose(got, want time.Duration) bool {
	d := got - want
	if d < 0 {
		d = -d
	}
	return d <= time.Millisecond
}

// namesMAC reports whether an error names a device, in the spelling its own
// endpoint uses or in the normalised one.
func namesMAC(err error, mac string) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, strings.ToLower(mac)) ||
		strings.Contains(msg, tpapi.NormalizeMAC(mac))
}

func loadClients(t *testing.T) []Client {
	t.Helper()
	got, err := parseClients(fixture(t, "clients.json"))
	if err != nil {
		t.Fatalf("parseClients(clients.json): %v", err)
	}
	return got
}

func loadClientTimes(t *testing.T) map[string]ClientTimes {
	t.Helper()
	got, err := parseClientTimes(fixture(t, "client_times.json"))
	if err != nil {
		t.Fatalf("parseClientTimes(client_times.json): %v", err)
	}
	return got
}

func clientByMAC(t *testing.T, clients []Client, mac string) Client {
	t.Helper()
	for _, c := range clients {
		if c.MAC == mac {
			return c
		}
	}
	t.Fatalf("no client with MAC %s among the %d parsed", mac, len(clients))
	return Client{}
}

func TestParseClients(t *testing.T) {
	clients := loadClients(t)
	if len(clients) != 18 {
		t.Fatalf("got %d clients, want the 18 game_accelerator returned", len(clients))
	}
	for _, c := range clients {
		if !canonicalMAC.MatchString(c.MAC) {
			t.Errorf("MAC %q left unnormalised; game_accelerator spells them %s", c.MAC, macDashUpper)
		}
	}

	// Wired, wireless, and the one whose onlineTime carries a float tail.
	for _, want := range []Client{
		{
			MAC: macCanonical, IP: "192.0.2.11", Hostname: "thermostat",
			Iface: "wired", Type: "Computer",
			TrafficBytes: 5278837500, DownBytesPerS: 1293, UpBytesPerS: 1391,
			Session: secs(512845.6),
		},
		{
			MAC: "00:00:5e:00:53:0f", IP: "192.0.2.16", Hostname: "speaker",
			Iface: "2.4G", Type: "IoT Devices",
			TrafficBytes: 96789900, DownBytesPerS: 678, UpBytesPerS: 1692,
			Session: secs(20012.6),
		},
		{
			MAC: "00:00:5e:00:53:10", IP: "192.0.2.17", Hostname: "hub",
			Iface: "wired", Type: "Computer",
			TrafficBytes: 2426153919, DownBytesPerS: 0, UpBytesPerS: 0,
			Session: secs(1931.6000000001),
		},
	} {
		got := clientByMAC(t, clients, want.MAC)
		if !durClose(got.Session, want.Session) {
			t.Errorf("%s: session %v, want %v — onlineTime is seconds of the current session",
				want.MAC, got.Session, want.Session)
		}
		got.Session, want.Session = 0, 0
		if got != want {
			t.Errorf("%s: parsed %+v, want %+v — deviceName/deviceTag/deviceType map to "+
				"Hostname/Iface/Type, trafficUsage is cumulative bytes and the speeds are bytes per second",
				want.MAC, got, want)
		}
	}
}

// isGuest is false for all 18 devices in the fixture, so the true side is
// synthetic; field names and spellings are lifted from clients.json.
func TestParseClientsGuestFlag(t *testing.T) {
	raw := json.RawMessage(`[{"deviceName":"guest-phone","deviceTag":"2.4G","deviceType":"Mobile",
	 "ip":"192.0.2.40","mac":"00-00-5E-00-53-40","isGuest":true,"trafficUsage":1024,
	 "downloadSpeed":0,"uploadSpeed":0,"onlineTime":5}]`)
	got, err := parseClients(raw)
	if err != nil {
		t.Fatalf("parseClients: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d clients, want 1", len(got))
	}
	if !got[0].Guest {
		t.Errorf("isGuest:true parsed as Guest=false; the guest SSID would disappear from the metrics")
	}
}

// The MAC is the join key and the only label on the numeric client metrics, so a
// second row carrying one collides instead of adding. Synthetic: the fixture has
// eighteen distinct MACs.
func TestParseClientsDropsARepeatedMAC(t *testing.T) {
	raw := json.RawMessage(`[
	 {"deviceName":"thermostat","deviceTag":"wired","deviceType":"Computer","ip":"192.0.2.11",
	  "mac":"00-00-5E-00-53-0A","isGuest":false,"trafficUsage":5278837500,"downloadSpeed":1293,
	  "uploadSpeed":1391,"onlineTime":512845.6},
	 {"deviceName":"speaker","deviceTag":"2.4G","deviceType":"IoT Devices","ip":"192.0.2.16",
	  "mac":"00:00:5e:00:53:0a","isGuest":false,"trafficUsage":96789900,"downloadSpeed":678,
	  "uploadSpeed":1692,"onlineTime":20012.6}]`)
	got, err := parseClients(raw)
	if len(got) != 1 {
		t.Fatalf("got %d clients from two rows spelling one MAC, want 1", len(got))
	}
	if got[0].Hostname != "thermostat" || got[0].TrafficBytes != 5278837500 {
		t.Errorf("kept %+v; of a repeated MAC the first row stays", got[0])
	}
	if err == nil {
		t.Fatal("a dropped duplicate went unreported; nothing else shows that a client is missing")
	}
	if !namesMAC(err, macDashUpper) {
		t.Errorf("error %q does not name the repeated MAC %s", err, macCanonical)
	}
}

func TestParseClientTimes(t *testing.T) {
	times := loadClientTimes(t)
	if len(times) != 18 {
		t.Fatalf("got %d entries, want the 18 traffic?form=dev_name returned", len(times))
	}
	for mac := range times {
		if !canonicalMAC.MatchString(mac) {
			t.Errorf("key %q is not a normalised MAC; dev_name spells them %s", mac, macDashLower)
		}
	}

	for _, tc := range []struct {
		mac  string
		want ClientTimes
	}{
		{
			// Lower-dashed in the reply, unlike every other endpoint.
			mac: macCanonical,
			want: ClientTimes{
				ConnectedAt: time.Unix(1786281883, 0),
				Via:         "00:00:5e:00:53:15",
			},
		},
		{
			// The one row in this reply spelled upper-dashed where the rest are
			// lower-dashed.
			mac: "00:00:5e:00:53:07",
			want: ClientTimes{
				ConnectedAt: time.Unix(1786673666, 0),
				Via:         "00:00:5e:00:53:15",
			},
		},
	} {
		got, ok := times[tc.mac]
		if !ok {
			t.Errorf("no entry for %s; the reply carries it as %s", tc.mac, macDashLower)
			continue
		}
		if !got.ConnectedAt.Equal(tc.want.ConnectedAt) {
			t.Errorf("%s: ConnectedAt %v, want %v — access_time is an absolute unix stamp",
				tc.mac, got.ConnectedAt, tc.want.ConnectedAt)
		}
		if got.Via != tc.want.Via {
			t.Errorf("%s: Via %q, want %q — connect_device_mac arrives upper-dashed and must be normalised",
				tc.mac, got.Via, tc.want.Via)
		}
	}
}

func TestMergeClientTimesJoinsAcrossMACSpellings(t *testing.T) {
	clients := loadClients(t)
	times := loadClientTimes(t)
	if len(clients) != 18 || len(times) != 18 {
		t.Fatalf("join would prove nothing: %d clients, %d time entries", len(clients), len(times))
	}

	merged := mergeClientTimes(clients, times)
	if len(merged) != len(clients) {
		t.Fatalf("merge returned %d clients out of %d", len(merged), len(clients))
	}
	matched := 0
	for _, c := range merged {
		if !c.ConnectedAt.IsZero() && c.Via != "" {
			matched++
		}
	}
	if matched != 18 {
		t.Errorf("%d of 18 clients got their times; clients.json spells MACs %s and client_times.json %s, "+
			"so an unnormalised join half-matches and the gap reads as missing devices",
			matched, macDashUpper, macDashLower)
	}

	got := clientByMAC(t, merged, macCanonical)
	if !got.ConnectedAt.Equal(time.Unix(1786281883, 0)) || got.Via != "00:00:5e:00:53:15" {
		t.Errorf("%s (thermostat): ConnectedAt %v, Via %q; want %v and %q",
			macCanonical, got.ConnectedAt, got.Via, time.Unix(1786281883, 0), "00:00:5e:00:53:15")
	}
	if got.Hostname != "thermostat" || got.TrafficBytes != 5278837500 {
		t.Errorf("%s: merge lost the game_accelerator half: %+v", macCanonical, got)
	}
}

// The two endpoints are polled separately and can disagree for one cycle.
func TestMergeClientTimesKeepsClientsWithoutTimes(t *testing.T) {
	clients := []Client{
		{MAC: macCanonical, Hostname: "thermostat"},
		{MAC: "00:00:5e:00:53:99", Hostname: "arrived-between-polls"},
	}
	times := map[string]ClientTimes{
		macCanonical: {ConnectedAt: time.Unix(1786281883, 0), Via: "00:00:5e:00:53:15"},
	}

	merged := mergeClientTimes(clients, times)
	if len(merged) != 2 {
		t.Fatalf("got %d clients, want 2: a client without a times entry is dropped", len(merged))
	}
	matched := clientByMAC(t, merged, macCanonical)
	if !matched.ConnectedAt.Equal(time.Unix(1786281883, 0)) || matched.Via != "00:00:5e:00:53:15" {
		t.Errorf("%s: times not merged in: %+v", macCanonical, matched)
	}
	late := clientByMAC(t, merged, "00:00:5e:00:53:99")
	if !late.ConnectedAt.IsZero() || late.Via != "" {
		t.Errorf("unmatched client picked up times from somewhere: %+v", late)
	}
	if late.Hostname != "arrived-between-polls" {
		t.Errorf("unmatched client lost its own fields: %+v", late)
	}
}

func TestMergeClientTimesEmpty(t *testing.T) {
	if got := mergeClientTimes(nil, nil); len(got) != 0 {
		t.Errorf("mergeClientTimes(nil, nil) = %v, want empty", got)
	}
	if got := mergeClientTimes(nil, map[string]ClientTimes{macCanonical: {}}); len(got) != 0 {
		t.Errorf("times without clients invented %d clients", len(got))
	}
	if got := mergeClientTimes([]Client{{MAC: macCanonical}}, nil); len(got) != 1 {
		t.Errorf("clients without times returned %d clients, want 1", len(got))
	}
}

// access_uptime is the router's uptime when a client connected, not seconds
// online: access_time - access_uptime is the boot instant, which status?form=all
// and status?form=wan_speed reach without reading dev_name at all.
func TestAccessUptimeIsTheRouterUptimeAtConnect(t *testing.T) {
	type row struct {
		AccessTime int64 `json:"access_time"`
		Uptime     int64 `json:"access_uptime"`
	}
	var rows []row
	if err := json.Unmarshal(fixture(t, "client_times.json"), &rows); err != nil {
		t.Fatalf("client_times.json: %v", err)
	}
	if len(rows) != 18 {
		t.Fatalf("got %d rows, want the 18 traffic?form=dev_name returned", len(rows))
	}

	epochs := make([]int64, 0, len(rows))
	connected := make([]int64, 0, len(rows))
	for _, r := range rows {
		epochs = append(epochs, r.AccessTime-r.Uptime)
		connected = append(connected, r.AccessTime)
	}
	span := slices.Max(connected) - slices.Min(connected)
	if span < 500_000 {
		t.Fatalf("access_time spans %ds over the fixture; the 511474s of the capture is what makes a "+
			"constant difference mean anything", span)
	}
	if spread := slices.Max(epochs) - slices.Min(epochs); spread > 600 {
		t.Errorf("access_time - access_uptime spreads over %ds while access_time spans %ds; the "+
			"difference is the router's boot instant, 560s wide in this capture, so access_uptime is "+
			"uptime at connect and not time online", spread, span)
	}

	uptime, err := parseWANUptime(fixture(t, "status_all.json"))
	if err != nil {
		t.Fatalf("parseWANUptime(status_all.json): %v", err)
	}
	_, _, sampledAt, err := parseWANSpeed(fixture(t, "status_wan_speed.json"))
	if err != nil {
		t.Fatalf("parseWANSpeed(status_wan_speed.json): %v", err)
	}
	// wan_ipv4_uptime restarts when the WAN reconnects, so it lands at or after
	// boot: 64s past the latest client epoch on this capture, 624s past the
	// earliest.
	boot := sampledAt.Add(-uptime).Unix()
	for _, e := range epochs {
		if d := boot - e; d < -15*60 || d > 15*60 {
			t.Errorf("a client's access_time - access_uptime is %d, %ds from the %d that "+
				"test_time - wan_ipv4_uptime puts the boot instant at; the two are the same quantity",
				e, d, boot)
		}
	}
}

// onlineTime counts the current session; cumulative seconds would scatter
// access_time + onlineTime over days.
func TestOnlineTimeIsTheCurrentSession(t *testing.T) {
	merged := mergeClientTimes(loadClients(t), loadClientTimes(t))
	if len(merged) != 18 {
		t.Fatalf("got %d merged clients, want 18", len(merged))
	}

	var earliest, latest time.Time
	for _, c := range merged {
		at := c.ConnectedAt.Add(c.Session)
		if earliest.IsZero() || at.Before(earliest) {
			earliest = at
		}
		if at.After(latest) {
			latest = at
		}
	}
	if spread := latest.Sub(earliest); spread > 15*time.Minute {
		t.Errorf("ConnectedAt+Session scatters over %v across the 18 clients; it lands on the capture "+
			"instant, 560s wide in this fixture, because onlineTime counts the current session only",
			spread)
	}
}

func TestParseLeases(t *testing.T) {
	leases, err := parseLeases(fixture(t, "dhcp_clients.json"))
	if err != nil {
		t.Fatalf("parseLeases(dhcp_clients.json): %v", err)
	}
	if len(leases) != 19 {
		t.Fatalf("got %d leases, want the 19 dhcps?form=client returned", len(leases))
	}

	byMAC := make(map[string]Lease, len(leases))
	for _, l := range leases {
		if !canonicalMAC.MatchString(l.MAC) {
			t.Errorf("macaddr %q left unnormalised", l.MAC)
		}
		byMAC[l.MAC] = l
	}

	for _, want := range []Lease{
		{MAC: macCanonical, IP: "192.0.2.11", Hostname: "thermostat", Remaining: time.Hour + 32*time.Minute + 14*time.Second},
		{MAC: "00:00:5e:00:53:00", IP: "192.0.2.1", Hostname: "laptop", Permanent: true},
		{MAC: "00:00:5e:00:53:10", IP: "192.0.2.17", Hostname: "hub", Remaining: 2159*time.Hour + 58*time.Minute + 5*time.Second},
	} {
		got, ok := byMAC[want.MAC]
		if !ok {
			t.Errorf("no lease for %s", want.MAC)
			continue
		}
		if got != want {
			t.Errorf("%s: parsed %+v, want %+v — fields are macaddr/ipaddr/name and leasetime is what is left",
				want.MAC, got, want)
		}
	}

	var permanent int
	for _, l := range leases {
		if l.Permanent {
			permanent++
			if l.Remaining != 0 {
				t.Errorf("%s: Permanent lease carries Remaining %v; there is no expiry to report",
					l.MAC, l.Remaining)
			}
		}
	}
	if permanent != 13 {
		t.Errorf("got %d permanent leases, want 13", permanent)
	}
}

func TestParseLeaseRemaining(t *testing.T) {
	for _, tc := range []struct {
		in        string
		want      time.Duration
		permanent bool
	}{
		{in: "Permanent", permanent: true},
		// Hours run past a day and carry no leading zero, minutes and seconds
		// come unpadded: time.Parse("15:04:05") rejects every one of these.
		{in: "2144:2:32", want: 2144*time.Hour + 2*time.Minute + 32*time.Second},
		{in: "2159:58:5", want: 2159*time.Hour + 58*time.Minute + 5*time.Second},
		{in: "1:27:2", want: time.Hour + 27*time.Minute + 2*time.Second},
		{in: "1:9:10", want: time.Hour + 9*time.Minute + 10*time.Second},
		{in: "1:26:49", want: time.Hour + 26*time.Minute + 49*time.Second},
		{in: "0:0:0", want: 0}, // synthetic: a lease at the moment it expires
	} {
		got, permanent, err := parseLeaseRemaining(tc.in)
		if err != nil {
			t.Errorf("parseLeaseRemaining(%q): %v", tc.in, err)
			continue
		}
		if permanent != tc.permanent {
			t.Errorf("parseLeaseRemaining(%q): permanent = %v, want %v", tc.in, permanent, tc.permanent)
		}
		if got != tc.want {
			t.Errorf("parseLeaseRemaining(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseLeaseRemainingRejectsMalformed(t *testing.T) {
	for _, in := range []string{
		"",
		"1:27",
		"1:27:2:9",
		"abc",
		"1:2b:3",
		"::",
	} {
		got, permanent, err := parseLeaseRemaining(in)
		if err == nil {
			t.Errorf("parseLeaseRemaining(%q) = %v, permanent=%v, nil error; malformed input must not "+
				"produce a plausible duration", in, got, permanent)
		}
	}
}

// A leasetime that will not parse costs its own lease. Dropping the reply would
// take the other eighteen devices out of the metrics with it.
func TestParseLeasesSkipsTheRowItCannotRead(t *testing.T) {
	raw := json.RawMessage(`[
	 {"macaddr":"00-00-5E-00-53-0A","ipaddr":"192.0.2.11","name":"thermostat","leasetime":"1:52:14"},
	 {"macaddr":"00-00-5E-00-53-0B","ipaddr":"192.0.2.12","name":"bulb-a","leasetime":"soon"},
	 {"macaddr":"00-00-5E-00-53-00","ipaddr":"192.0.2.1","name":"laptop","leasetime":"Permanent"}]`)
	got, err := parseLeases(raw)
	if len(got) != 2 {
		t.Fatalf("got %d leases from three rows, one of them unreadable, want 2: %+v", len(got), got)
	}
	want := []Lease{
		{MAC: macCanonical, IP: "192.0.2.11", Hostname: "thermostat", Remaining: time.Hour + 52*time.Minute + 14*time.Second},
		{MAC: "00:00:5e:00:53:00", IP: "192.0.2.1", Hostname: "laptop", Permanent: true},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("lease %d: parsed %+v, want %+v", i, got[i], want[i])
		}
	}
	if err == nil {
		t.Fatal("the skipped lease went unreported")
	}
	if !namesMAC(err, "00-00-5E-00-53-0B") {
		t.Errorf("error %q does not name the lease it dropped", err)
	}
}

func TestParseReservations(t *testing.T) {
	res, err := parseReservations(fixture(t, "dhcp_reservations.json"))
	if err != nil {
		t.Fatalf("parseReservations(dhcp_reservations.json): %v", err)
	}
	if len(res) != 17 {
		t.Fatalf("got %d reservations, want the 17 dhcps?form=reservation returned", len(res))
	}

	byMAC := make(map[string]Reservation, len(res))
	for _, r := range res {
		if !canonicalMAC.MatchString(r.MAC) {
			t.Errorf("mac %q left unnormalised", r.MAC)
		}
		if !r.Enabled {
			t.Errorf("%s: enable:\"on\" parsed as disabled", r.MAC)
		}
		byMAC[r.MAC] = r
	}

	// Field names differ from the lease reply: mac/ip/hostname, not
	// macaddr/ipaddr/name.
	want := Reservation{MAC: "00:00:5e:00:53:01", IP: "192.0.2.2", Hostname: "laptop", Enabled: true}
	if got := byMAC[want.MAC]; got != want {
		t.Errorf("%s: parsed %+v, want %+v", want.MAC, got, want)
	}
	// thermostat is leased and not reserved.
	if _, ok := byMAC[macCanonical]; ok {
		t.Errorf("%s is in the reservations; the fixture has it leased only", macCanonical)
	}
}

// Membership in the reservation reply is the only reliable source of "is
// reserved"; "Permanent" is not a reservation flag.
func TestReservationIsNotTheSameAsPermanentLease(t *testing.T) {
	leases, err := parseLeases(fixture(t, "dhcp_clients.json"))
	if err != nil {
		t.Fatalf("parseLeases: %v", err)
	}
	res, err := parseReservations(fixture(t, "dhcp_reservations.json"))
	if err != nil {
		t.Fatalf("parseReservations: %v", err)
	}
	if len(leases) == 0 || len(res) == 0 {
		t.Fatalf("nothing to cross-check: %d leases, %d reservations", len(leases), len(res))
	}

	reserved := make(map[string]bool, len(res))
	for _, r := range res {
		reserved[r.MAC] = true
	}

	var countingDown []string
	for _, l := range leases {
		if reserved[l.MAC] && !l.Permanent {
			countingDown = append(countingDown, l.MAC)
		}
	}
	if len(countingDown) != 2 {
		t.Errorf("got %d reserved MACs with a counting-down lease (%v), want 2 — "+
			"taking Permanent as the reservation flag misses them", len(countingDown), countingDown)
	}

	leased := make(map[string]bool, len(leases))
	for _, l := range leases {
		leased[l.MAC] = true
	}
	var unleased int
	for mac := range reserved {
		if !leased[mac] {
			unleased++
		}
	}
	if unleased != 2 {
		t.Errorf("got %d reservations without a lease, want 2 — a reservation exists whether or not "+
			"the device is on the network", unleased)
	}
}

func TestParseDHCPSetting(t *testing.T) {
	got, err := parseDHCPSetting(fixture(t, "dhcp_setting.json"))
	if err != nil {
		t.Fatalf("parseDHCPSetting(dhcp_setting.json): %v", err)
	}
	want := &DHCPSetting{
		Enabled:    true,
		LeaseTime:  120 * time.Minute,
		RangeStart: "192.0.2.23",
		RangeEnd:   "192.0.2.24",
		Gateway:    "192.0.2.22",
	}
	if *got != *want {
		t.Errorf("parsed %+v, want %+v — leasetime is the string \"120\" counted in minutes, "+
			"and it describes the pool, not any individual lease", *got, *want)
	}
}

func TestParsePorts(t *testing.T) {
	got, err := parsePorts(fixture(t, "ports.json"))
	if err != nil {
		t.Fatalf("parsePorts(ports.json): %v", err)
	}
	want := []Port{
		{Name: "wanlan1g", Up: true, SpeedMbits: 1000, Duplex: "FULL", IsWAN: true},
		{Name: "lan1"},
		{Name: "lan2"},
		{Name: "lan3"},
		// Connected at 2.5G and still not the WAN port: is_wan is absent here.
		{Name: "wanlan2g5", Up: true, SpeedMbits: 2500, Duplex: "FULL"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d ports, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("port %d: parsed %+v, want %+v — a dark port sends speed:\"\" and duplex:\"\", "+
				"so speed cannot be unmarshalled into an int", i, got[i], want[i])
		}
	}
}

func TestParsePortsHandlesEmptySpeed(t *testing.T) {
	got, err := parsePorts(fixture(t, "ports.json"))
	if err != nil {
		t.Fatalf("parsePorts(ports.json): %v", err)
	}
	dark := 0
	for _, p := range got {
		if p.Name == "lan1" || p.Name == "lan2" || p.Name == "lan3" {
			dark++
			if p.Up {
				t.Errorf("%s: status \"unconnected\" parsed as up", p.Name)
			}
			if p.SpeedMbits != 0 {
				t.Errorf("%s: SpeedMbits %d, want 0 for speed:\"\"", p.Name, p.SpeedMbits)
			}
		}
	}
	if dark != 3 {
		t.Errorf("found %d unconnected lan ports, want 3", dark)
	}
}

// A speed that is neither a number nor "" costs its own port; the switch keeps
// the rest. Synthetic: every port in the fixture reads.
func TestParsePortsSkipsTheRowItCannotRead(t *testing.T) {
	raw := json.RawMessage(`[
	 {"name":"wanlan1g","status":"connected","duplex":"FULL","speed":1000,"is_wan":true},
	 {"name":"lan3","status":"unconnected","duplex":"","speed":"fast"},
	 {"name":"wanlan2g5","status":"connected","duplex":"FULL","speed":2500}]`)
	got, err := parsePorts(raw)
	if len(got) != 2 {
		t.Fatalf("got %d ports from three rows, one of them unreadable, want 2: %+v", len(got), got)
	}
	want := []Port{
		{Name: "wanlan1g", Up: true, SpeedMbits: 1000, Duplex: "FULL", IsWAN: true},
		{Name: "wanlan2g5", Up: true, SpeedMbits: 2500, Duplex: "FULL"},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("port %d: parsed %+v, want %+v", i, got[i], want[i])
		}
	}
	if err == nil {
		t.Fatal("the skipped port went unreported")
	}
	if !strings.Contains(err.Error(), "lan3") {
		t.Errorf("error %q does not name the port it dropped", err)
	}
}

func TestParsePerf(t *testing.T) {
	got, err := parsePerf(fixture(t, "status_all.json"))
	if err != nil {
		t.Fatalf("parsePerf(status_all.json): %v", err)
	}
	if got.CPU != 0.02 {
		t.Errorf("CPU = %v, want 0.02 — cpu_usage is a ratio, the UI multiplies by 100 to display it",
			got.CPU)
	}
	if got.Memory != 0.4 {
		t.Errorf("Memory = %v, want 0.4 — mem_usage is a ratio, 40%%", got.Memory)
	}
	wantCores := []float64{0.02, 0.03, 0.02, 0.03}
	if len(got.Cores) != len(wantCores) {
		t.Fatalf("found %d cores, want %d: cpu1_usage..cpu4_usage", len(got.Cores), len(wantCores))
	}
	for i, want := range wantCores {
		if got.Cores[i] != want {
			t.Errorf("core %d = %v, want %v", i+1, got.Cores[i], want)
		}
	}
}

// The UI finds the core count by probing cpuN_usage until a key is missing:
// for (t=1; e['cpu'+t+'_usage'] !== undefined; t++). A parser that instead
// collects every cpu*_usage key would report five cores here.
func TestParsePerfCoreProbeStopsAtGap(t *testing.T) {
	raw := json.RawMessage(`{"cpu_usage":0.11,"cpu1_usage":0.02,"cpu2_usage":0.03,
	 "cpu5_usage":0.99,"mem_usage":0.5}`)
	got, err := parsePerf(raw)
	if err != nil {
		t.Fatalf("parsePerf: %v", err)
	}
	if len(got.Cores) != 2 {
		t.Fatalf("found %d cores, want 2: the sequence stops at the missing cpu3_usage", len(got.Cores))
	}
	for i, v := range got.Cores {
		if v == 0.99 {
			t.Errorf("core %d picked up cpu5_usage from beyond the gap", i+1)
		}
	}
}

func TestParseWANUptime(t *testing.T) {
	got, err := parseWANUptime(fixture(t, "status_all.json"))
	if err != nil {
		t.Fatalf("parseWANUptime(status_all.json): %v", err)
	}
	want := 1117521 * time.Second
	if got != want {
		t.Errorf("wan_ipv4_uptime = %v, want %v (%.1f days) — the value is seconds",
			got, want, want.Hours()/24)
	}
}

func TestParseInternetStatus(t *testing.T) {
	internet, link, _, err := parseInternet(fixture(t, "status_internet.json"))
	if err != nil {
		t.Fatalf("parseInternet(status_internet.json): %v", err)
	}
	if !internet {
		t.Error("internet_status \"connected\" parsed as down")
	}
	if !link {
		t.Error("wan_internet_status \"connected\" parsed as down")
	}

	// Synthetic: the capture has only the connected state.
	down := json.RawMessage(`{"internet_status":"disconnected","modem_internet_status":"unplugged",
	 "wan_internet_status":"unplugged","wanlan_internet_status":"unplugged"}`)
	internet, link, _, err = parseInternet(down)
	if err != nil {
		t.Fatalf("parseInternet: %v", err)
	}
	if internet {
		t.Error("internet_status \"disconnected\" parsed as up")
	}
	if link {
		t.Error("wan_internet_status \"unplugged\" parsed as up")
	}
}

// internetStatusReply is status?form=internet with one state in both fields.
func internetStatusReply(state string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(
		`{"internet_status":%q,"modem_internet_status":"unplugged",
		  "wan_internet_status":%q,"wanlan_internet_status":"unplugged"}`, state, state))
}

// Only the connected state is in the capture; the rest are synthetic, from the
// firmware's five-state enum, which the UI matches after toUpperCase.
func TestParseInternetStatusCollapsesTheFiveStates(t *testing.T) {
	for _, tc := range []struct {
		state string
		up    bool
	}{
		{"connected", true},
		{"poor_connected", true},
		{"connecting", false},
		{"disconnected", false},
		{"unplugged", false},
		{"CONNECTED", true},
		{"POOR_CONNECTED", true},
		{"Disconnected", false},
	} {
		internet, link, _, err := parseInternet(internetStatusReply(tc.state))
		if err != nil {
			t.Errorf("parseInternet(%q): %v", tc.state, err)
			continue
		}
		if internet != tc.up {
			t.Errorf("internet_status %q read as up=%v, want %v — connected and poor_connected are the "+
				"two up states and the comparison is not case-sensitive", tc.state, internet, tc.up)
		}
		if link != tc.up {
			t.Errorf("wan_internet_status %q read as up=%v, want %v", tc.state, link, tc.up)
		}
	}
}

func TestParseInternetState(t *testing.T) {
	_, _, got, err := parseInternet(fixture(t, "status_internet.json"))
	if err != nil {
		t.Fatalf("parseInternet(status_internet.json): %v", err)
	}
	if got != "connected" {
		t.Errorf("state = %q, want \"connected\" — it is internet_status as it arrived", got)
	}

	for _, tc := range []struct{ in, want string }{
		{"CONNECTED", "connected"},
		{"POOR_CONNECTED", "poor_connected"},
		{"Unplugged", "unplugged"},
	} {
		_, _, got, err := parseInternet(internetStatusReply(tc.in))
		if err != nil {
			t.Errorf("parseInternet(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("internet_status %q became state %q, want %q — the state is lowercased so a change "+
				"of spelling does not split the series in two", tc.in, got, tc.want)
		}
	}
}

func TestParseWireless(t *testing.T) {
	got, err := parseWireless(fixture(t, "status_all.json"))
	if err != nil {
		t.Fatalf("parseWireless(status_all.json): %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d bands %v, want 2 — wireless_wps_active shares the prefix and is not a band",
			len(got), got)
	}

	// The fixture carries 2.4G enabled and 5G disabled, so the pair also shows
	// that a band's channel is read whether or not its radio is on.
	for _, tc := range []struct {
		band    string
		enabled bool
		channel int
		txPower string
	}{
		{"2g", true, 6, "high"},
		{"5g", false, 36, "high"},
	} {
		g, ok := got[tc.band]
		if !ok {
			t.Errorf("no key for band %q; the reply carries wireless_%s_enable", tc.band, tc.band)
			continue
		}
		switch {
		case g.Enabled == nil:
			t.Errorf("band %q: Enabled is nil although wireless_%s_enable is in the reply", tc.band, tc.band)
		case *g.Enabled != tc.enabled:
			t.Errorf("band %q: Enabled = %v, want %v — the field is on/off", tc.band, *g.Enabled, tc.enabled)
		}
		switch {
		case g.Channel == nil:
			t.Errorf("band %q: Channel is nil although wireless_%s_current_channel is in the reply",
				tc.band, tc.band)
		case *g.Channel != tc.channel:
			t.Errorf("band %q: Channel = %d, want %d — current_channel is a number in a string",
				tc.band, *g.Channel, tc.channel)
		}
		if g.TxPower != tc.txPower {
			t.Errorf("band %q: TxPower = %q, want %q", tc.band, g.TxPower, tc.txPower)
		}
	}
}

// wireless_5g_channel is the setting, wireless_5g_current_channel the channel
// the radio landed on.
func TestParseWirelessTakesTheCurrentChannel(t *testing.T) {
	raw := json.RawMessage(`{"wireless_5g_enable":"on","wireless_5g_channel":"auto",
	 "wireless_5g_current_channel":"36","wireless_5g_txpower":"high"}`)
	got, err := parseWireless(raw)
	if err != nil {
		t.Fatalf("parseWireless: %v", err)
	}
	if got["5g"].Channel == nil || *got["5g"].Channel != 36 {
		t.Errorf("5G channel = %v, want 36 — wireless_5g_channel says \"auto\", only current_channel "+
			"is a number", got["5g"].Channel)
	}
}

// A field the reply does not carry leaves nil. onOff("") is false, so a band
// whose enable is missing would otherwise publish a radio that is switched off.
// Synthetic: status?form=all carries all three fields for both bands.
func TestParseWirelessLeavesUnreadFieldsNil(t *testing.T) {
	got, err := parseWireless(json.RawMessage(`{"wireless_2g_current_channel":"6"}`))
	if err != nil {
		t.Fatalf("parseWireless: %v", err)
	}
	r, ok := got["2g"]
	if !ok {
		t.Fatalf("no key for band \"2g\" though the reply carries wireless_2g_current_channel: %v", got)
	}
	if r.Enabled != nil {
		t.Errorf("Enabled = %v for a band whose wireless_2g_enable never arrived; want nil", *r.Enabled)
	}
	if r.Channel == nil || *r.Channel != 6 {
		t.Errorf("Channel = %v, want 6 — the one field present is still read", r.Channel)
	}
	if r.TxPower != "" {
		t.Errorf("TxPower = %q for a band whose wireless_2g_txpower never arrived", r.TxPower)
	}

	// current_channel holds a number on every capture; anything else is unknown,
	// which is not channel 0.
	got, err = parseWireless(json.RawMessage(`{"wireless_5g_enable":"on","wireless_5g_current_channel":"auto"}`))
	if err != nil {
		t.Fatalf("parseWireless: %v", err)
	}
	r, ok = got["5g"]
	if !ok {
		t.Fatalf("no key for band \"5g\": %v", got)
	}
	if r.Channel != nil {
		t.Errorf("Channel = %d for current_channel \"auto\"; want nil", *r.Channel)
	}
	if r.Enabled == nil || !*r.Enabled {
		t.Errorf("Enabled = %v; an unreadable channel does not cost the band its enable flag", r.Enabled)
	}
}

func TestParseMeshNodes(t *testing.T) {
	got, err := parseMeshNodes(fixture(t, "mesh_nodes.json"))
	if err != nil {
		t.Fatalf("parseMeshNodes(mesh_nodes.json): %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d nodes, want the 1 easymesh_network returned", len(got))
	}
	want := MeshNode{
		MAC:     "00:00:5e:00:53:15",
		Name:    "Archer AX80",
		Model:   "Archer AX80",
		Role:    "main_router",
		Up:      true,
		Clients: 19,
	}
	if got[0] != want {
		t.Errorf("parsed %+v, want %+v — the only node is the router itself, status \"connected\" is up "+
			"and client_num is what it counts", got[0], want)
	}
}

// Every client reports the node it hangs off in connect_device_mac; on this
// network that is the one mesh node.
func TestMeshNodeMACJoinsClientVia(t *testing.T) {
	nodes, err := parseMeshNodes(fixture(t, "mesh_nodes.json"))
	if err != nil {
		t.Fatalf("parseMeshNodes: %v", err)
	}
	times := loadClientTimes(t)
	if len(nodes) == 0 || len(times) == 0 {
		t.Fatalf("join would prove nothing: %d nodes, %d time entries", len(nodes), len(times))
	}

	node := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		if !canonicalMAC.MatchString(n.MAC) {
			t.Errorf("mac %q left unnormalised; the reply spells it %s", n.MAC, macDashUpper)
		}
		node[n.MAC] = true
	}
	for mac, ct := range times {
		if !node[ct.Via] {
			t.Errorf("%s hangs off %q, which is not the mesh node %s", mac, ct.Via, nodes[0].MAC)
		}
	}
}

func TestParseWANSpeed(t *testing.T) {
	down, up, takenAt, err := parseWANSpeed(fixture(t, "status_wan_speed.json"))
	if err != nil {
		t.Fatalf("parseWANSpeed(status_wan_speed.json): %v", err)
	}
	if down != 1546905 || up != 23401 {
		t.Errorf("down/up = %v/%v, want 1546905/23401 — down_speed and up_speed are bytes per second",
			down, up)
	}
	want := time.Unix(1786802858, 0)
	if !takenAt.Equal(want) {
		t.Errorf("test_time = %v, want %v — it is the router's own unix stamp on the sample",
			takenAt, want)
	}
}

func TestParseFirmware(t *testing.T) {
	got, err := parseFirmware(fixture(t, "firmware.json"))
	if err != nil {
		t.Fatalf("parseFirmware(firmware.json): %v", err)
	}
	want := &Firmware{
		Version:  "1.4.1 Build 20251117 rel.76722(5255)",
		Hardware: "Archer AX80 v1.0",
		Model:    "Archer AX80",
	}
	if *got != *want {
		t.Errorf("parsed %+v, want %+v", *got, *want)
	}
}

func TestParseRouterClock(t *testing.T) {
	got, err := parseRouterClock(fixture(t, "time.json"))
	if err != nil {
		t.Fatalf("parseRouterClock(time.json): %v", err)
	}
	// date is MM/DD/YYYY: 08/15/2026 is 15 August, not 8 December.
	want := time.Date(2026, time.August, 15, 15, 1, 33, 0, time.Local)
	if !got.Wall.Equal(want) {
		t.Errorf("wall clock = %v, want %v — date is MM/DD/YYYY and the clock is built in the "+
			"exporter's own location so the skew is a like-for-like comparison", got.Wall, want)
	}
	if got.Timezone != "74" {
		t.Errorf("Timezone = %q, want %q — it is a TP-Link index, not a UTC offset", got.Timezone, "74")
	}
}

func TestParseTunnels(t *testing.T) {
	got, err := parseTunnels(fixture(t, "vpn_tunnels.json"))
	if err != nil {
		t.Fatalf("parseTunnels(vpn_tunnels.json): %v", err)
	}
	// One tunnel, still an array.
	if len(got) != 1 {
		t.Fatalf("got %d tunnels, want 1", len(got))
	}
	want := Tunnel{
		Name:          "NordVPN",
		Vendor:        "nordvpn",
		Type:          "wireguard",
		Endpoint:      "vpn.example.net:51820",
		Up:            true,
		DownBytesPerS: 1598,
		UpBytesPerS:   1147,
	}
	if got[0] != want {
		t.Errorf("parsed %+v, want %+v — des is the tunnel name and the speeds are instantaneous "+
			"bytes per second, there is no byte counter", got[0], want)
	}
}

func TestParseVPNServer(t *testing.T) {
	got, err := parseVPNServer(fixture(t, "vpn_enable.json"))
	if err != nil {
		t.Fatalf("parseVPNServer(vpn_enable.json): %v", err)
	}
	want := &VPNServer{Enabled: true, Type: "4"}
	if *got != *want {
		t.Errorf("parsed %+v, want %+v", *got, *want)
	}
}

func TestParseVPNUsers(t *testing.T) {
	got, err := parseVPNUsers(fixture(t, "vpn_users.json"))
	if err != nil {
		t.Fatalf("parseVPNUsers(vpn_users.json): %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d users, want 4", len(got))
	}

	byMAC := make(map[string]VPNUser, len(got))
	for _, u := range got {
		if !canonicalMAC.MatchString(u.MAC) {
			t.Errorf("mac %q left unnormalised; this endpoint alone uses colons (%s)", u.MAC, macColons)
		}
		byMAC[u.MAC] = u
	}

	for _, want := range []VPNUser{
		{MAC: macCanonical, Name: "thermostat", ClientType: "pc", Access: true},
		{MAC: "00:00:5e:00:53:0b", Name: "bulb-a", ClientType: "pc", Access: false},
		{MAC: "00:00:5e:00:53:16", Name: "camera25", ClientType: "Computer", Access: false},
	} {
		if got := byMAC[want.MAC]; got != want {
			t.Errorf("%s: parsed %+v, want %+v", want.MAC, got, want)
		}
	}

	granted := 0
	for _, u := range got {
		if u.Access {
			granted++
		}
	}
	if granted != 2 {
		t.Errorf("%d users with access, want 2", granted)
	}
}

// The third spelling; two of the four VPN users are also live clients.
func TestVPNUserMACsJoinClients(t *testing.T) {
	clients := loadClients(t)
	users, err := parseVPNUsers(fixture(t, "vpn_users.json"))
	if err != nil {
		t.Fatalf("parseVPNUsers: %v", err)
	}
	if len(clients) == 0 || len(users) == 0 {
		t.Fatalf("join would prove nothing: %d clients, %d users", len(clients), len(users))
	}

	online := make(map[string]bool, len(clients))
	for _, c := range clients {
		online[c.MAC] = true
	}
	matched := 0
	for _, u := range users {
		if online[u.MAC] {
			matched++
		}
	}
	if matched != 2 {
		t.Errorf("%d of 4 VPN users matched a client, want 2 — vpn_user_list sends %s where "+
			"game_accelerator sends %s", matched, macColons, macDashUpper)
	}

	if want := tpapi.NormalizeMAC(macDashUpper); want != macCanonical {
		t.Fatalf("NormalizeMAC(%q) = %q, want %q", macDashUpper, want, macCanonical)
	}
	for _, spelling := range []string{macDashUpper, macDashLower, macColons} {
		if got := tpapi.NormalizeMAC(spelling); got != macCanonical {
			t.Errorf("NormalizeMAC(%q) = %q; the three endpoints must land on one key", spelling, got)
		}
	}
	times := loadClientTimes(t)
	if _, ok := times[macCanonical]; !ok {
		t.Errorf("thermostat missing from client times under %s", macCanonical)
	}
	if !online[macCanonical] {
		t.Errorf("thermostat missing from clients under %s", macCanonical)
	}
}

func TestParseARP(t *testing.T) {
	got, err := parseARP(fixture(t, "arp_list.json"))
	if err != nil {
		t.Fatalf("parseARP(arp_list.json): %v", err)
	}
	if len(got) != 30 {
		t.Fatalf("got %d entries, want the 30 imb?form=arp_list returned", len(got))
	}

	unique := make(map[string]int, len(got))
	nameless := 0
	for _, e := range got {
		if !canonicalMAC.MatchString(e.MAC) {
			t.Errorf("mac %q left unnormalised", e.MAC)
		}
		unique[e.MAC]++
		if e.Name == "" {
			nameless++
		}
	}
	// Five MACs appear twice, on two addresses each.
	if len(unique) != 25 {
		t.Errorf("%d distinct MACs over %d rows, want 25 — duplicate MACs on different addresses "+
			"are separate rows", len(unique), len(got))
	}
	if nameless != 7 {
		t.Errorf("%d rows with an empty name, want 7 — a stale entry often has no name left",
			nameless)
	}

	online := make(map[string]bool)
	for _, c := range loadClients(t) {
		online[c.MAC] = true
	}
	stale := 0
	for mac := range unique {
		if !online[mac] {
			stale++
		}
	}
	if stale != 7 {
		t.Errorf("%d ARP MACs are not current clients, want 7", stale)
	}
	if _, ok := unique["00:00:5e:00:53:02"]; !ok {
		t.Errorf("desk-pc (00:00:5e:00:53:02) missing: it is in ARP and in the reservations, " +
			"but not among the online clients")
	}
}

func TestParseGuestNetworks(t *testing.T) {
	got, err := parseGuestNetworks(fixture(t, "status_all.json"))
	if err != nil {
		t.Fatalf("parseGuestNetworks(status_all.json): %v", err)
	}
	want := map[string]bool{"2g": false, "5g": false}
	if len(got) != len(want) {
		t.Fatalf("got %d bands %v, want %v", len(got), got, want)
	}
	for band, enabled := range want {
		v, ok := got[band]
		if !ok {
			t.Errorf("no key for band %q; the reply carries guest_%s_enable", band, band)
			continue
		}
		if v != enabled {
			t.Errorf("band %q = %v, want %v (guest_%s_enable is \"off\")", band, v, enabled, band)
		}
	}
}

// Only bands the reply mentions get a key: a missing band is not a disabled one.
func TestParseGuestNetworksOnlyMentionedBands(t *testing.T) {
	raw := json.RawMessage(`{"guest_2g_enable":"on","guest_2g_ssid":"testnet-guest"}`)
	got, err := parseGuestNetworks(raw)
	if err != nil {
		t.Fatalf("parseGuestNetworks: %v", err)
	}
	if len(got) != 1 || !got["2g"] {
		t.Errorf("parsed %v, want exactly {\"2g\": true}", got)
	}
}

// The IoT pair is the smart-home SSIDs, beside the guest ones and in the same
// shape.
func TestParseIoTNetworks(t *testing.T) {
	got, err := parseIoTNetworks(fixture(t, "status_all.json"))
	if err != nil {
		t.Fatalf("parseIoTNetworks(status_all.json): %v", err)
	}
	want := map[string]bool{"2g": false, "5g": false}
	if len(got) != len(want) {
		t.Fatalf("got %d bands %v, want %v", len(got), got, want)
	}
	for band, enabled := range want {
		v, ok := got[band]
		if !ok {
			t.Errorf("no key for band %q; the reply carries iot_%s_enable", band, band)
			continue
		}
		if v != enabled {
			t.Errorf("band %q = %v, want %v (iot_%s_enable is \"off\")", band, v, enabled, band)
		}
	}
}

// Only bands the reply mentions get a key, the same rule the guest pair follows.
func TestParseIoTNetworksOnlyMentionedBands(t *testing.T) {
	raw := json.RawMessage(`{"iot_5g_enable":"on","iot_5g_ssid":"testnet-iot-5g"}`)
	got, err := parseIoTNetworks(raw)
	if err != nil {
		t.Fatalf("parseIoTNetworks: %v", err)
	}
	if len(got) != 1 || !got["5g"] {
		t.Errorf("parsed %v, want exactly {\"5g\": true}", got)
	}
}

// bandFlagParser is one of the two parsers that read a pair of SSID flags out of
// status?form=all, beside the prefix it answers for.
type bandFlagParser struct {
	name   string
	prefix string
	call   func(json.RawMessage) (map[string]bool, error)
}

func bandFlagParsers() []bandFlagParser {
	return []bandFlagParser{
		{"parseGuestNetworks", "guest", parseGuestNetworks},
		{"parseIoTNetworks", "iot", parseIoTNetworks},
	}
}

// A reply that names no band of a parser's own prefix is an empty map, not an
// error. The other _2g_enable and _5g_enable fields below are real neighbours in
// status?form=all; the values are synthetic, so a parser matching on the suffix
// returns two enabled bands instead of none.
func TestBandFlagParsersReadTheirOwnPrefix(t *testing.T) {
	for _, p := range bandFlagParsers() {
		for _, raw := range []string{
			`{}`,
			`{"wireless_2g_enable":"on","wireless_5g_enable":"on"}`,
			`{"mlo_host_2g_enable":"on","mlo_host_5g_enable":"on"}`,
		} {
			got, err := p.call(json.RawMessage(raw))
			if err != nil {
				t.Errorf("%s(%s): %v — a reply carrying no %s_ band is not a failure",
					p.name, raw, err, p.prefix)
				continue
			}
			if len(got) != 0 {
				t.Errorf("%s(%s) = %v, want no keys: nothing in that reply names a %s_ band",
					p.name, raw, got, p.prefix)
			}
		}
	}
}

// Both parsers share an implementation, so a swapped prefix reports one pair
// under the other's name with neither metric going missing. On the reference
// device all four flags are "off", which is the one combination that cannot tell
// the two apart, so the values here are synthetic.
func TestGuestAndIoTBandsAreReadIndependently(t *testing.T) {
	raw := json.RawMessage(`{"guest_2g_enable":"on","guest_2g_ssid":"testnet-guest",
	 "guest_5g_enable":"on","guest_5g_ssid":"testnet-guest-5g",
	 "iot_2g_enable":"off","iot_2g_ssid":"testnet-iot",
	 "iot_5g_enable":"off","iot_5g_ssid":"testnet-iot-5g"}`)

	guest, err := parseGuestNetworks(raw)
	if err != nil {
		t.Fatalf("parseGuestNetworks: %v", err)
	}
	iot, err := parseIoTNetworks(raw)
	if err != nil {
		t.Fatalf("parseIoTNetworks: %v", err)
	}
	for _, tc := range []struct {
		prefix    string
		got, want map[string]bool
	}{
		{"guest", guest, map[string]bool{"2g": true, "5g": true}},
		{"iot", iot, map[string]bool{"2g": false, "5g": false}},
	} {
		if !maps.Equal(tc.got, tc.want) {
			t.Errorf("%s_* parsed as %v, want %v — the guest pair is up in this reply and the IoT pair "+
				"is not, and each parser reads its own four fields", tc.prefix, tc.got, tc.want)
		}
	}
}

func securityFixtures(t *testing.T) SecuritySources {
	t.Helper()
	return SecuritySources{
		srcRemote:      fixture(t, "security_remote.json"),
		srcUPnPEnable:  fixture(t, "security_upnp_enable.json"),
		srcUPnPService: fixture(t, "security_upnp_service.json"),
		srcNATvs:       fixture(t, "security_nat_vs.json"),
		srcNATpt:       fixture(t, "security_nat_pt.json"),
		srcDMZ:         fixture(t, "security_nat_dmz.json"),
		srcFirewall:    fixture(t, "security_firewall.json"),
	}
}

// securityFlags is every flag and the name to report it under.
func securityFlags(s *Security) map[string]*bool {
	return map[string]*bool{
		"RemoteManagement": s.RemoteManagement,
		"UPnPEnabled":      s.UPnPEnabled,
		"DMZ":              s.DMZ,
		"LANPing":          s.LANPing,
		"WANPing":          s.WANPing,
	}
}

func TestParseSecurity(t *testing.T) {
	got, errs := parseSecurity(securityFixtures(t))
	if len(errs) != 0 {
		t.Fatalf("parseSecurity over the fixtures: %v", errs)
	}

	for _, tc := range []struct {
		name string
		got  *bool
		want bool
		from string
	}{
		{"RemoteManagement", got.RemoteManagement, false, `administration?form=remote has enable:"off"`},
		{"UPnPEnabled", got.UPnPEnabled, true, `upnp?form=enable has enable:"on"`},
		{"DMZ", got.DMZ, false, `nat?form=dmz has enable:"off"`},
		{"LANPing", got.LANPing, true, `security_settings has lan_ping:"on"`},
		{"WANPing", got.WANPing, false, `security_settings has wan_ping:"off", and answering ping from the WAN is an alert`},
	} {
		if tc.got == nil {
			t.Errorf("%s is nil although its endpoint answered; nil is a reading nobody took", tc.name)
			continue
		}
		if *tc.got != tc.want {
			t.Errorf("%s = %v, want %v — %s", tc.name, *tc.got, tc.want, tc.from)
		}
	}

	// {} is what a load endpoint sends for an empty list, and it is the state
	// the "a forward appeared" alert fires out of.
	switch {
	case got.UPnPMappings == nil:
		t.Error("UPnPMappings is nil although upnp?form=service answered {}, which is no mappings")
	case *got.UPnPMappings != 0:
		t.Errorf("UPnPMappings = %d, want 0 for the empty reply {}", *got.UPnPMappings)
	}
	for _, kind := range []string{"vs", "pt"} {
		n, ok := got.PortForwards[kind]
		if !ok {
			t.Errorf("PortForwards has no %q key; the endpoint answered {}, which is no rules, "+
				"not no answer", kind)
			continue
		}
		if n != 0 {
			t.Errorf("PortForwards[%q] = %d, want 0", kind, n)
		}
	}

	// parseGuestNetworks fills this; the poller merges.
	if len(got.GuestNetworks) != 0 {
		t.Errorf("GuestNetworks = %v; it comes from status?form=all, not from the security endpoints",
			got.GuestNetworks)
	}
}

// A source that did not answer leaves nil: false would report "remote management
// is off" for a reading nobody took.
func TestParseSecurityLeavesUnreadFlagsNil(t *testing.T) {
	got, errs := parseSecurity(SecuritySources{srcUPnPEnable: fixture(t, "security_upnp_enable.json")})
	if len(errs) != 0 {
		t.Fatalf("a source that was never polled is not a parse failure, yet: %v", errs)
	}
	if got.UPnPEnabled == nil || !*got.UPnPEnabled {
		t.Errorf("UPnPEnabled = %v; the one source present was not read", got.UPnPEnabled)
	}
	for name, v := range securityFlags(got) {
		if name == "UPnPEnabled" || v == nil {
			continue
		}
		t.Errorf("%s = %v for an endpoint that never answered; want nil", name, *v)
	}
	if got.UPnPMappings != nil {
		t.Errorf("UPnPMappings = %d though upnp?form=service never answered; want nil", *got.UPnPMappings)
	}
	for _, kind := range []string{"vs", "pt"} {
		if _, ok := got.PortForwards[kind]; ok {
			t.Errorf("PortForwards has a %q key though nat?form=%s never answered", kind, kind)
		}
	}

	empty, errs := parseSecurity(nil)
	if len(errs) != 0 {
		t.Fatalf("parseSecurity(nil): %v", errs)
	}
	if empty == nil {
		t.Fatal("parseSecurity(nil) returned nil; want a value with every field unread")
	}
	for name, v := range securityFlags(empty) {
		if v != nil {
			t.Errorf("parseSecurity(nil) read %s as %v", name, *v)
		}
	}
}

// One unreadable reply costs the flags that reply carries and nothing else, and
// the error is keyed by the endpoint that sent it.
func TestParseSecurityChargesEachErrorToItsOwnEndpoint(t *testing.T) {
	for _, tc := range []struct {
		path string
		lost []string
	}{
		{srcRemote, []string{"RemoteManagement"}},
		{srcUPnPEnable, []string{"UPnPEnabled"}},
		{srcDMZ, []string{"DMZ"}},
		// One reply, two flags.
		{srcFirewall, []string{"LANPing", "WANPing"}},
	} {
		src := securityFixtures(t)
		src[tc.path] = json.RawMessage(`{"enable":`) // a reply torn in half
		got, errs := parseSecurity(src)

		if len(errs) != 1 || errs[tc.path] == nil {
			t.Errorf("%s answered rubbish and parseSecurity reported %v; want one error, keyed by that path",
				tc.path, errs)
		}
		lost := make(map[string]bool, len(tc.lost))
		for _, name := range tc.lost {
			lost[name] = true
		}
		for name, v := range securityFlags(got) {
			switch {
			case lost[name] && v != nil:
				t.Errorf("%s answered rubbish, yet %s = %v; an unreadable reply is not a reading",
					tc.path, name, *v)
			case !lost[name] && v == nil:
				t.Errorf("%s answered rubbish and took %s with it", tc.path, name)
			}
		}
		if got.UPnPMappings == nil || len(got.PortForwards) != 2 {
			t.Errorf("%s answered rubbish and the rule counts went with it: mappings %v, forwards %v",
				tc.path, got.UPnPMappings, got.PortForwards)
		}
	}
}

// The same for a count endpoint: its own key is left out, the other counts stand.
func TestParseSecurityBadCountCostsOnlyItsOwnKey(t *testing.T) {
	src := securityFixtures(t)
	src[srcNATvs] = json.RawMessage(`[{`)
	got, errs := parseSecurity(src)

	if len(errs) != 1 || errs[srcNATvs] == nil {
		t.Errorf("nat?form=vs answered rubbish and parseSecurity reported %v; want one error, keyed by "+
			"that path", errs)
	}
	if _, ok := got.PortForwards["vs"]; ok {
		t.Errorf("PortForwards has a \"vs\" key from an unreadable reply: %v", got.PortForwards)
	}
	if n, ok := got.PortForwards["pt"]; !ok || n != 0 {
		t.Errorf("PortForwards[\"pt\"] = %d, present %v; nat?form=pt answered {} and is unaffected", n, ok)
	}
	if got.UPnPMappings == nil || *got.UPnPMappings != 0 {
		t.Errorf("UPnPMappings = %v; upnp?form=service answered {} and is unaffected", got.UPnPMappings)
	}
	for name, v := range securityFlags(got) {
		if v == nil {
			t.Errorf("%s went nil because nat?form=vs answered rubbish", name)
		}
	}
}

// Rule counts, on the one fact the empty fixtures cannot show: a load endpoint
// with entries sends an array. No capture pins the rule shape, only the count.
func TestParseSecurityCountsRules(t *testing.T) {
	got, errs := parseSecurity(SecuritySources{
		srcUPnPService: json.RawMessage(`[{},{},{}]`),
		srcNATvs:       json.RawMessage(`[{}]`),
		srcNATpt:       json.RawMessage(`[{},{}]`),
	})
	if len(errs) != 0 {
		t.Fatalf("parseSecurity: %v", errs)
	}
	if got.UPnPMappings == nil || *got.UPnPMappings != 3 {
		t.Errorf("UPnPMappings = %v, want 3", got.UPnPMappings)
	}
	if n := got.PortForwards["vs"]; n != 1 {
		t.Errorf("PortForwards[\"vs\"] = %d, want 1", n)
	}
	if n := got.PortForwards["pt"]; n != 2 {
		t.Errorf("PortForwards[\"pt\"] = %d, want 2", n)
	}
}

// Every source parseSecurity folds together is polled and has a fixture; one
// added to neither would read nothing and say nothing.
func TestSecuritySourcesArePolledAndCovered(t *testing.T) {
	polled := make(map[string]bool, len(sources))
	for _, s := range sources {
		polled[s.Path] = true
	}
	covered := securityFixtures(t)
	for _, path := range securitySources {
		if !polled[path] {
			t.Errorf("%q is not in the poll set, so parseSecurity would never see it", path)
		}
		if _, ok := covered[path]; !ok {
			t.Errorf("%q has no reply in securityFixtures, so no test here reads it", path)
		}
	}
	if len(covered) != len(securitySources) {
		t.Errorf("securityFixtures holds %d replies for %d security sources", len(covered), len(securitySources))
	}
}

// The firmware writes switches as on/off strings and, in a few replies, as real
// JSON booleans. Numeric strings are enums or counts (vpn type:"4",
// ipsec:"1", conn_type:"0") and yes/no answers are capability flags, so neither
// is a switch.
func TestOnOff(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want bool
	}{
		{"on", true},
		{"off", false},
		{"On", true}, // status?form=all: lan_ipv4_dhcp_enable
		{"OFF", false},
		{true, true},   // ports.json: is_wan; vpn_tunnels.json: nat
		{false, false}, // security_remote.json: remote; firmware.json: upgraded
		{"", false},
		{nil, false},
		{"yes", false},
		{"1", false},
		{float64(1), false},
		{"enabled", false},
	} {
		if got := onOff(tc.in); got != tc.want {
			t.Errorf("onOff(%#v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// rawParsers is every parser that takes a reply, wrapped to one signature.
func rawParsers() []struct {
	name string
	call func(json.RawMessage) error
} {
	return []struct {
		name string
		call func(json.RawMessage) error
	}{
		{"parseClients", func(r json.RawMessage) error { _, err := parseClients(r); return err }},
		{"parseClientTimes", func(r json.RawMessage) error { _, err := parseClientTimes(r); return err }},
		{"parseLeases", func(r json.RawMessage) error { _, err := parseLeases(r); return err }},
		{"parseReservations", func(r json.RawMessage) error { _, err := parseReservations(r); return err }},
		{"parseDHCPSetting", func(r json.RawMessage) error { _, err := parseDHCPSetting(r); return err }},
		{"parsePorts", func(r json.RawMessage) error { _, err := parsePorts(r); return err }},
		{"parsePerf", func(r json.RawMessage) error { _, err := parsePerf(r); return err }},
		{"parseWANUptime", func(r json.RawMessage) error { _, err := parseWANUptime(r); return err }},
		{"parseInternet", func(r json.RawMessage) error { _, _, _, err := parseInternet(r); return err }},
		{"parseWireless", func(r json.RawMessage) error { _, err := parseWireless(r); return err }},
		{"parseMeshNodes", func(r json.RawMessage) error { _, err := parseMeshNodes(r); return err }},
		{"parseWANSpeed", func(r json.RawMessage) error { _, _, _, err := parseWANSpeed(r); return err }},
		{"parseFirmware", func(r json.RawMessage) error { _, err := parseFirmware(r); return err }},
		{"parseRouterClock", func(r json.RawMessage) error { _, err := parseRouterClock(r); return err }},
		{"parseTunnels", func(r json.RawMessage) error { _, err := parseTunnels(r); return err }},
		{"parseVPNServer", func(r json.RawMessage) error { _, err := parseVPNServer(r); return err }},
		{"parseVPNUsers", func(r json.RawMessage) error { _, err := parseVPNUsers(r); return err }},
		{"parseARP", func(r json.RawMessage) error { _, err := parseARP(r); return err }},
		{"parseGuestNetworks", func(r json.RawMessage) error { _, err := parseGuestNetworks(r); return err }},
		{"parseIoTNetworks", func(r json.RawMessage) error { _, err := parseIoTNetworks(r); return err }},
		{"parseSecurity", func(r json.RawMessage) error {
			_, errs := parseSecurity(SecuritySources{srcNATvs: r})
			return errs[srcNATvs]
		}},
	}
}

// A truncated reply must come back as an error, not a panic or a zero value.
func TestParsersRejectMalformedJSON(t *testing.T) {
	for _, p := range rawParsers() {
		for _, raw := range []string{`{`, `[{"mac":`, `[{"mac":"00-00-5E-00-53-00"},`} {
			if err := p.call(json.RawMessage(raw)); err == nil {
				t.Errorf("%s(%q) returned no error", p.name, raw)
			}
		}
	}
}

// listParser is a parser that reads an array reply, behind one signature, with a
// row from the capture that it decodes.
type listParser struct {
	name string
	row  string
	call func(json.RawMessage) (int, error)
}

// listParsers is the set both tests below drive: one gives each parser a torn
// row beside a good one, the other an empty reply. parseClientTimes is not here
// — it returns a map, and traffic?form=dev_name is a read rather than a load, so
// {} is not its empty spelling; both tests take it on separately.
func listParsers() []listParser {
	return []listParser{
		{"parseClients", `{"mac":"00-00-5E-00-53-0A","deviceName":"thermostat","onlineTime":512845.6}`,
			func(r json.RawMessage) (int, error) { v, err := parseClients(r); return len(v), err }},
		{"parseLeases", `{"macaddr":"00-00-5E-00-53-0A","ipaddr":"192.0.2.11","name":"thermostat","leasetime":"Permanent"}`,
			func(r json.RawMessage) (int, error) { v, err := parseLeases(r); return len(v), err }},
		{"parseReservations", `{"mac":"00-00-5E-00-53-01","ip":"192.0.2.2","hostname":"laptop","enable":"on"}`,
			func(r json.RawMessage) (int, error) { v, err := parseReservations(r); return len(v), err }},
		{"parsePorts", `{"name":"lan1","status":"unconnected","duplex":"","speed":""}`,
			func(r json.RawMessage) (int, error) { v, err := parsePorts(r); return len(v), err }},
		{"parseTunnels", `{"des":"NordVPN","vendor":"nordvpn","type":"wireguard","status":"connected"}`,
			func(r json.RawMessage) (int, error) { v, err := parseTunnels(r); return len(v), err }},
		{"parseVPNUsers", `{"mac":"00:00:5E:00:53:0A","name":"thermostat","client_type":"pc","access":"on"}`,
			func(r json.RawMessage) (int, error) { v, err := parseVPNUsers(r); return len(v), err }},
		{"parseARP", `{"mac":"00-00-5E-00-53-0A","ipaddr":"192.0.2.11","name":"thermostat"}`,
			func(r json.RawMessage) (int, error) { v, err := parseARP(r); return len(v), err }},
		{"parseMeshNodes", `{"mac":"00-00-5E-00-53-15","name":"Archer AX80","role":"main_router","status":"connected"}`,
			func(r json.RawMessage) (int, error) { v, err := parseMeshNodes(r); return len(v), err }},
	}
}

// Each row is decoded on its own: a row that is not an object costs that row,
// and the rest of the reply still arrives.
func TestListParsersKeepTheRowsTheyDecoded(t *testing.T) {
	parsers := append(listParsers(), listParser{
		"parseClientTimes",
		`{"mac":"00-00-5e-00-53-0a","access_time":1786281883,"connect_device_mac":"00-00-5E-00-53-15"}`,
		func(r json.RawMessage) (int, error) { v, err := parseClientTimes(r); return len(v), err },
	})
	for _, p := range parsers {
		n, err := p.call(json.RawMessage(`["torn",` + p.row + `]`))
		if n != 1 {
			t.Errorf("%s returned %d entries for a reply of one unreadable row and one good one, want 1",
				p.name, n)
		}
		if err == nil {
			t.Errorf("%s dropped a row and reported nothing; the endpoint would look healthy while a "+
				"device is missing", p.name)
		}
	}
}

// A load endpoint sends an array when it has entries and the literal {} when it
// has none — never []. Both spellings mean an empty list; [] is here because
// nothing guarantees the firmware keeps that habit.
func TestListParsersAcceptEmptyReplies(t *testing.T) {
	for _, p := range listParsers() {
		for _, raw := range []string{`{}`, `[]`} {
			n, err := p.call(json.RawMessage(raw))
			if err != nil {
				t.Errorf("%s(%s): %v — an empty list is not an error", p.name, raw, err)
				continue
			}
			if n != 0 {
				t.Errorf("%s(%s) returned %d entries, want 0", p.name, raw, n)
			}
		}
	}

	// The same for the map: no devices means no keys, not a panic.
	times, err := parseClientTimes(json.RawMessage(`[]`))
	if err != nil {
		t.Errorf("parseClientTimes([]): %v", err)
	}
	if len(times) != 0 {
		t.Errorf("parseClientTimes([]) returned %d entries, want 0", len(times))
	}
	if got := mergeClientTimes(nil, nil); len(got) != 0 {
		t.Errorf("mergeClientTimes(nil, nil) returned %d clients, want 0", len(got))
	}
}
