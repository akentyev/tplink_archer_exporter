package exporter

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// wantRouterSources is the router poll set in order, each path with the
// operation the firmware answers it to.
var wantRouterSources = []source{
	{Path: "admin/smart_network?form=game_accelerator", Operation: "loadDevice"},
	{Path: "admin/traffic?form=dev_name", Operation: "read"},
	{Path: "admin/dhcps?form=client", Operation: "load"},
	{Path: "admin/dhcps?form=reservation", Operation: "load"},
	{Path: "admin/dhcps?form=setting", Operation: "read"},
	{Path: "admin/status?form=all", Operation: "read"},
	{Path: "admin/status?form=router", Operation: "read"},
	{Path: "admin/status?form=internet", Operation: "read"},
	{Path: "admin/status?form=wan_speed", Operation: "read"},
	{Path: "admin/vpn?form=server", Operation: "load"},
	{Path: "admin/vpn?form=vpn_user_list", Operation: "load"},
	{Path: "admin/vpn?form=enable", Operation: "read"},
	{Path: "admin/firmware?form=upgrade", Operation: "read"},
	{Path: "admin/time?form=settings", Operation: "read"},
	{Path: "admin/administration?form=remote", Operation: "read"},
	{Path: "admin/upnp?form=enable", Operation: "read"},
	{Path: "admin/upnp?form=service", Operation: "load"},
	{Path: "admin/nat?form=vs", Operation: "load"},
	{Path: "admin/nat?form=pt", Operation: "load"},
	{Path: "admin/nat?form=dmz", Operation: "read"},
	{Path: "admin/security_settings?form=new_enable", Operation: "read"},
	{Path: "admin/imb?form=arp_list", Operation: "load"},
	{Path: "admin/easymesh_network?form=get_mesh_device_list_all", Operation: "read"},
}

var wantAPSources = []source{
	{Path: "admin/smart_network?form=game_accelerator", Operation: "loadDevice"},
	{Path: "admin/traffic?form=dev_name", Operation: "read"},
	{Path: "admin/dhcps?form=client", Operation: "load"},
	{Path: "admin/dhcps?form=reservation", Operation: "load"},
	{Path: "admin/dhcps?form=setting", Operation: "read"},
	{Path: "admin/status?form=all", Operation: "read"},
	{Path: "admin/status?form=router", Operation: "read"},
	{Path: "admin/status?form=internet", Operation: "read"},
	{Path: "admin/firmware?form=upgrade", Operation: "read"},
	{Path: "admin/time?form=settings", Operation: "read"},
	{Path: "admin/easymesh_network?form=get_mesh_device_list_all", Operation: "read"},
}

func pollSet(set []source) []string {
	out := make([]string, 0, len(set))
	for _, s := range set {
		out = append(out, s.Path+" "+s.Operation)
	}
	return out
}

// tpapi.Client.Mode lowercases what the device sends, so only "ap" picks the
// access point set.
func TestSourcesForMode(t *testing.T) {
	if n := len(sources); n != 23 {
		t.Errorf("sources holds %d endpoints, want 23: the router poll set does not change with modes", n)
	}
	if got, want := pollSet(sources), pollSet(wantRouterSources); !slices.Equal(got, want) {
		t.Errorf("sources is\n\t%s\nwant the router poll set, in its order:\n\t%s",
			strings.Join(got, "\n\t"), strings.Join(want, "\n\t"))
	}
	if n := len(apSources); n != 11 {
		t.Errorf("apSources holds %d endpoints, want 11: status?form=internet is polled on an access point too", n)
	}
	if modeAP != "ap" {
		t.Errorf("modeAP = %q, want %q, the spelling tpapi.Client.Mode reports an access point in", modeAP, "ap")
	}

	for _, tc := range []struct {
		name, mode string
		want       []source
		why        string
	}{
		{"no mode named", "", wantRouterSources, "a keys reply that names no mode is polled as a router"},
		{"router", "router", wantRouterSources, "a router is polled with its twenty-three sources"},
		{"repeater", "repeater", wantRouterSources, "every mode but ap keeps the router poll set"},
		{"client", "client", wantRouterSources, "every mode but ap keeps the router poll set"},
		{"multissid", "multissid", wantRouterSources, "every mode but ap keeps the router poll set"},
		{"ap in upper case", "AP", wantRouterSources, "the match is exact; tpapi.Client.Mode already lowercases"},
		{"ap", "ap", wantAPSources, "an access point is polled with its eleven sources"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, want := pollSet(sourcesFor(tc.mode)), pollSet(tc.want)
			if !slices.Equal(got, want) {
				t.Errorf("sourcesFor(%q) is\n\t%s\nwant\n\t%s\n%s", tc.mode,
					strings.Join(got, "\n\t"), strings.Join(want, "\n\t"), tc.why)
			}
		})
	}

	prev := -1
	for _, ap := range apSources {
		i := slices.IndexFunc(sources, func(s source) bool { return s.Path == ap.Path })
		if i < 0 {
			t.Errorf("apSources polls %s, which sources does not", ap.Path)
			continue
		}
		if op := sources[i].Operation; op != ap.Operation {
			t.Errorf("apSources polls %s with %q, sources with %q", ap.Path, ap.Operation, op)
		}
		switch {
		case i == prev:
			t.Errorf("apSources names %s twice in a row", ap.Path)
		case i < prev:
			t.Errorf("apSources polls %s after %s; sources polls it before", ap.Path, sources[prev].Path)
		default:
			prev = i
		}
	}
}

func apAssembleReplies(t *testing.T, status string) map[string]json.RawMessage {
	t.Helper()
	return map[string]json.RawMessage{
		srcStatusAll: fixture(t, status),
		srcClients:   fixture(t, "ap_clients.json"),
	}
}

// An access point's status?form=all carries no WAN uptime.
func TestAssembleAccessPointReadsNoWANUptime(t *testing.T) {
	for _, tc := range []struct {
		name, status string
	}{
		{"the access point's reply", "ap_status_all.json"},
		{"a reply that carries wan_ipv4_uptime", "status_all.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := &Snapshot{Mode: "ap", Errors: map[string]error{}}
			assemble(snap, apAssembleReplies(t, tc.status))

			if len(snap.Errors) != 0 {
				t.Errorf("assemble on an access point, status?form=all from %s, reports errors: %v",
					tc.status, snap.Errors)
			}
			if snap.WAN != nil {
				t.Errorf("WAN = %+v on an access point, status?form=all from %s; the uptime is not read there, "+
					"and nothing else of the WAN was handed to assemble", *snap.WAN, tc.status)
			}
			if snap.Perf == nil {
				t.Errorf("no Perf, though status?form=all from %s carries cpu_usage and mem_usage", tc.status)
			}
			for _, band := range []string{"2g", "5g"} {
				if _, ok := snap.Wireless[band]; !ok {
					t.Errorf("Wireless has no %q, though status?form=all from %s carries wireless_%s_*: %v",
						band, tc.status, band, snap.Wireless)
				}
			}
			if n := len(snap.Clients); n != 5 {
				t.Errorf("%d clients, want the 5 in ap_clients.json", n)
			}
		})
	}
}

// The same replies under no mode are a router's, which reports its WAN uptime
// in status?form=all.
func TestAssembleRouterStillRequiresWANUptime(t *testing.T) {
	snap := &Snapshot{Mode: "", Errors: map[string]error{}}
	assemble(snap, apAssembleReplies(t, "ap_status_all.json"))

	err := snap.Errors[srcStatusAll]
	if err == nil {
		t.Fatalf("no error for %s under no mode, whose reply carries no wan_ipv4_uptime; Errors = %v",
			srcStatusAll, snap.Errors)
	}
	if !strings.Contains(err.Error(), "wan_ipv4_uptime") {
		t.Errorf("Errors[%s] = %v; it should name wan_ipv4_uptime, the key a router's reply is missing",
			srcStatusAll, err)
	}
	if snap.Perf == nil {
		t.Error("no Perf; the missing uptime costs the uptime, and cpu_usage in the same reply is still read")
	}
}

// The access point's own Network Map shows internet_status as its connection.
func TestAssembleAccessPointReadsInternetStatus(t *testing.T) {
	connected := fixture(t, "ap_status_internet.json")
	// Synthetic: the capture has only the connected state.
	down := json.RawMessage(`{"wan_internet_status":"unplugged","wanlan_internet_status":"unplugged",
	 "internet_status":"disconnected","modem_internet_status":"unplugged"}`)

	for _, tc := range []struct {
		name, status string // status is the status?form=all fixture
		internet     json.RawMessage
		wantUp       bool
		wantState    string
	}{
		{"the access point's replies", "ap_status_all.json", connected, true, "connected"},
		{"a status?form=all that carries wan_ipv4_uptime", "status_all.json", connected, true, "connected"},
		{"the internet down", "ap_status_all.json", down, false, "disconnected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			replies := apAssembleReplies(t, tc.status)
			replies[srcInternet] = tc.internet
			snap := &Snapshot{Mode: "ap", Errors: map[string]error{}}
			assemble(snap, replies)

			if len(snap.Errors) != 0 {
				t.Errorf("assemble on an access point, status?form=all from %s, reports errors: %v",
					tc.status, snap.Errors)
			}
			wan := snap.WAN
			if wan == nil {
				t.Fatal("no WAN on an access point, though status?form=internet was handed to assemble")
			}
			if !wan.HaveStatus || wan.InternetUp != tc.wantUp || wan.State != tc.wantState {
				t.Errorf("HaveStatus %v, InternetUp %v, State %q; want true, %v, %q — internet_status is read "+
					"on an access point as on a router", wan.HaveStatus, wan.InternetUp, wan.State,
					tc.wantUp, tc.wantState)
			}
			if wan.HaveUptime || wan.Uptime != 0 {
				t.Errorf("HaveUptime %v, Uptime %v on an access point, status?form=all from %s; the uptime is "+
					"not read there, whether the reply carries it or not", wan.HaveUptime, wan.Uptime, tc.status)
			}
			if wan.HaveSpeed || wan.DownBytesPerS != 0 || wan.UpBytesPerS != 0 || !wan.SpeedTakenAt.IsZero() {
				t.Errorf("WAN = %+v carries a speed sample, though status?form=wan_speed was not handed to "+
					"assemble", *wan)
			}
		})
	}
}

// The access point's client list carries the signal and the rates as the
// router's does.
func TestAssembleFillsClientRadio(t *testing.T) {
	for _, tc := range []struct {
		name, mode, clients string // clients is the fixture; "" is no reply at all
		want                map[string]ClientRadio
	}{
		{"an access point", "ap", "ap_clients.json", wantAPRadio()},
		{"a router", "router", "clients.json", wantRouterRadio()},
		{"no mode named", "", "clients.json", wantRouterRadio()},
		{"the client list did not answer", "ap", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			replies := map[string]json.RawMessage{}
			if tc.clients != "" {
				replies[srcClients] = fixture(t, tc.clients)
			}
			snap := &Snapshot{Mode: tc.mode, Errors: map[string]error{}}
			assemble(snap, replies)

			if err := snap.Errors[srcClients]; err != nil {
				t.Errorf("assemble reports %v for %s, whose reply is %q", err, srcClients, tc.clients)
			}
			radioMapHolds(t, snap.ClientRadio, tc.want)
		})
	}
}
