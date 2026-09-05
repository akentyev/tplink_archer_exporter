package exporter

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Written against the descriptors in collector.go, with no collector in sight.
// Those descriptors are the contract: dashboards and alerts outlive this code.
//
// Expectations are written in the text exposition format and compared with
// testutil, which pins name, help, type, labels and value together. Labels go in
// alphabetical order because that is the order a registry emits them in;
// the order of the series themselves does not matter, both sides are sorted.
//
// The State and Snapshot values are literals, so nothing here depends on the
// parsers. The values in them are the anonymised ones from ../tpapi/testdata:
// MACs in 00:00:5e:00:53:xx, addresses in 192.0.2.0/24.

// takenAt is the instant the snapshot was taken, and the router's own stamp on
// the throughput sample. Lease expiry and the router clock below are arithmetic
// on it.
var takenAt = time.Unix(1786802858, 0)

// stubSource stands in for the poller: one State per scrape, no router.
type stubSource struct {
	st    State
	reads atomic.Int64
}

func (s *stubSource) State() State {
	s.reads.Add(1)
	return s.st
}

// fullState is what a scrape sees after a cycle in which everything answered.
// Two endpoints have failed at some point since start, which is why they carry
// a count without being missing from the snapshot. The session was taken once
// and four cycles stayed away over the cooldown that followed.
func fullState() State {
	return State{
		Snapshot:         fullSnapshot(),
		Up:               true,
		LastAttempt:      takenAt,
		Logins:           1,
		LoginFailures:    2,
		EndpointErrors:   map[string]uint64{srcLeases: 3, srcTunnels: 1},
		SessionsLost:     1,
		LoginsSuppressed: 4,
		PollDuration:     1500 * time.Millisecond,
	}
}

func fullSnapshot() *Snapshot {
	on, off := true, false
	channel2g, channel5g := 6, 36
	noMappings := 0
	return &Snapshot{
		TakenAt: takenAt,

		Firmware: &Firmware{
			Version:  "1.4.1 Build 20251117 rel.76722(5255)",
			Hardware: "Archer AX80 v1.0",
			Model:    "Archer AX80",
		},
		WAN: &WAN{
			HaveUptime:    true,
			Uptime:        1117521 * time.Second,
			HaveStatus:    true,
			InternetUp:    true,
			LinkUp:        true,
			State:         "connected",
			HaveSpeed:     true,
			DownBytesPerS: 1546905,
			UpBytesPerS:   23401,
			SpeedTakenAt:  takenAt,
		},
		Perf: &Perf{
			CPU:    0.02,
			Cores:  []float64{0.02, 0.03, 0.02, 0.03},
			Memory: 0.4,
		},
		// A linked WAN port, a dark one, and a 2.5G port that is not the WAN.
		Ports: []Port{
			{Name: "wanlan1g", Up: true, SpeedMbits: 1000, Duplex: "FULL", IsWAN: true},
			{Name: "lan1"},
			{Name: "wanlan2g5", Up: true, SpeedMbits: 2500, Duplex: "FULL"},
		},
		Router: &RouterClock{Wall: takenAt.Add(12 * time.Second), Timezone: "74"},
		Wireless: map[string]Radio{
			"2g": {Enabled: &on, Channel: &channel2g, TxPower: "high"},
			"5g": {Enabled: &off, Channel: &channel5g, TxPower: "low"},
		},
		Mesh: []MeshNode{{
			MAC: "00:00:5e:00:53:15", Name: "Archer AX80", Model: "Archer AX80",
			Role: "main_router", Up: true, Clients: 19,
		}},

		Clients: []Client{
			{
				MAC: "00:00:5e:00:53:0a", IP: "192.0.2.11", Hostname: "thermostat",
				Iface: "wired", Type: "Computer",
				TrafficBytes: 5278837500, DownBytesPerS: 1293, UpBytesPerS: 1391,
				Session:     time.Hour,
				ConnectedAt: time.Unix(1786799258, 0),
				Via:         "00:00:5e:00:53:15",
			},
			{
				MAC: "00:00:5e:00:53:0f", IP: "192.0.2.16", Hostname: "speaker",
				Iface: "2.4G", Type: "IoT Devices", Guest: true,
				TrafficBytes: 96789900, DownBytesPerS: 678, UpBytesPerS: 1692,
				Session:     20012 * time.Second,
				ConnectedAt: time.Unix(1786782846, 0),
				Via:         "00:00:5e:00:53:15",
			},
		},

		// One lease counting down and one permanent; the reserved addresses are
		// a third set again, and one of them is switched off.
		Leases: []Lease{
			{
				MAC: "00:00:5e:00:53:0a", IP: "192.0.2.11", Hostname: "thermostat",
				Remaining: time.Hour + 32*time.Minute + 14*time.Second,
			},
			{MAC: "00:00:5e:00:53:00", IP: "192.0.2.1", Hostname: "laptop", Permanent: true},
		},
		Reservations: []Reservation{
			{MAC: "00:00:5e:00:53:01", IP: "192.0.2.2", Hostname: "laptop", Enabled: true},
			{MAC: "00:00:5e:00:53:02", IP: "192.0.2.3", Hostname: "desk-pc"},
		},
		DHCP: &DHCPSetting{
			Enabled:    true,
			LeaseTime:  120 * time.Minute,
			RangeStart: "192.0.2.23",
			RangeEnd:   "192.0.2.24",
			Gateway:    "192.0.2.22",
		},

		Tunnels: []Tunnel{{
			Name: "NordVPN", Vendor: "nordvpn", Type: "wireguard",
			Endpoint: "vpn.example.net:51820", Up: true,
			DownBytesPerS: 1598, UpBytesPerS: 1147,
		}},
		VPNServer: &VPNServer{Enabled: true, Type: "4"},
		VPNUsers: []VPNUser{
			{MAC: "00:00:5e:00:53:0a", Name: "thermostat", ClientType: "pc", Access: true},
			{MAC: "00:00:5e:00:53:0b", Name: "bulb-a", ClientType: "pc"},
		},

		// Every security endpoint answered, so every flag holds a reading rather
		// than a nil.
		Security: &Security{
			RemoteManagement: &off,
			UPnPEnabled:      &on,
			UPnPMappings:     &noMappings,
			DMZ:              &off,
			LANPing:          &on,
			WANPing:          &off,
			PortForwards:     map[string]int{"vs": 0, "pt": 0},
			GuestNetworks:    map[string]bool{"2g": false, "5g": false},
			IoTNetworks:      map[string]bool{"2g": false, "5g": false},
		},
		// Two rows for one MAC on two addresses.
		ARP: []ARPEntry{
			{MAC: "00:00:5e:00:53:0a", IP: "192.0.2.11", Name: "thermostat"},
			{MAC: "00:00:5e:00:53:02", IP: "192.0.2.3", Name: "desk-pc"},
			{MAC: "00:00:5e:00:53:02", IP: "192.0.2.30"},
		},

		Errors: map[string]error{},
	}
}

const healthGolden = `
# HELP tplink_endpoints_failed Endpoints that did not answer in the cycle behind the snapshot being served.
# TYPE tplink_endpoints_failed gauge
tplink_endpoints_failed 0
# HELP tplink_login_failed_total Failed logins since start, session conflicts included.
# TYPE tplink_login_failed_total counter
tplink_login_failed_total 2
# HELP tplink_login_suppressed_total Logins not attempted since start: during the cooldown after losing the session, against the hourly cap, or inside the backoff after a failed cycle.
# TYPE tplink_login_suppressed_total counter
tplink_login_suppressed_total 4
# HELP tplink_login_total Successful logins since start.
# TYPE tplink_login_total counter
tplink_login_total 1
# HELP tplink_scrape_duration_seconds Duration of the last poll cycle.
# TYPE tplink_scrape_duration_seconds gauge
tplink_scrape_duration_seconds 1.5
# HELP tplink_scrape_errors_total Endpoint failures since start, by endpoint.
# TYPE tplink_scrape_errors_total counter
tplink_scrape_errors_total{endpoint="admin/dhcps?form=client"} 3
tplink_scrape_errors_total{endpoint="admin/vpn?form=server"} 1
# HELP tplink_session_blocked 1 when the router's single web session is held by someone else.
# TYPE tplink_session_blocked gauge
tplink_session_blocked 0
# HELP tplink_session_lost_total Sessions the exporter concluded it had lost, since start. Someone opening the web UI is the usual cause; a reboot or an upgrade reads the same.
# TYPE tplink_session_lost_total counter
tplink_session_lost_total 1
# HELP tplink_snapshot_timestamp_seconds Unix time of the snapshot being served; its age is time() minus this.
# TYPE tplink_snapshot_timestamp_seconds gauge
tplink_snapshot_timestamp_seconds 1786802858
# HELP tplink_up 1 when the last poll reached the router.
# TYPE tplink_up gauge
tplink_up 1
`

// healthMetrics is the exporter's own state as healthGolden spells it, never a
// reading off the router. tplink_exporter_build_info belongs beside these and is
// missing on purpose: its go_version comes from the toolchain, so buildInfoGolden
// renders it instead of a const holding it.
var healthMetrics = []string{
	"tplink_up", "tplink_session_blocked", "tplink_scrape_duration_seconds",
	"tplink_scrape_errors_total", "tplink_login_total", "tplink_login_failed_total",
	"tplink_session_lost_total", "tplink_login_suppressed_total",
}

const routerGolden = `
# HELP tplink_firmware_info Firmware the router reports about itself.
# TYPE tplink_firmware_info gauge
tplink_firmware_info{hardware="Archer AX80 v1.0",model="Archer AX80",version="1.4.1 Build 20251117 rel.76722(5255)"} 1
# HELP tplink_wan_speed_bytes Current WAN throughput in bytes per second.
# TYPE tplink_wan_speed_bytes gauge
tplink_wan_speed_bytes{dir="rx"} 1546905
tplink_wan_speed_bytes{dir="tx"} 23401
# HELP tplink_wan_speed_timestamp_seconds Unix time the router stamped on its throughput sample.
# TYPE tplink_wan_speed_timestamp_seconds gauge
tplink_wan_speed_timestamp_seconds 1786802858
# HELP tplink_wan_status 1 when connected. iface="internet" is reachability, iface="link" the physical WAN port.
# TYPE tplink_wan_status gauge
tplink_wan_status{iface="internet"} 1
tplink_wan_status{iface="link"} 1
# HELP tplink_wan_status_info The raw internet_status, which tplink_wan_status collapses to 0/1.
# TYPE tplink_wan_status_info gauge
tplink_wan_status_info{state="connected"} 1
# HELP tplink_wan_uptime_seconds Seconds the WAN link has been up; resets on reconnect.
# TYPE tplink_wan_uptime_seconds gauge
tplink_wan_uptime_seconds 1117521
`

// wanMetrics is every family a WAN can produce; what a case leaves out of its
// samples must be absent from the scrape.
var wanMetrics = []string{
	"tplink_wan_uptime_seconds", "tplink_wan_status", "tplink_wan_status_info",
	"tplink_wan_speed_bytes", "tplink_wan_speed_timestamp_seconds",
}

// The router clock is a stamp rather than a difference; a difference would
// measure the container's timezone along with the drift.
const performanceGolden = `
# HELP tplink_cpu_core_usage_ratio Per-core CPU load as a ratio in 0..1.
# TYPE tplink_cpu_core_usage_ratio gauge
tplink_cpu_core_usage_ratio{core="1"} 0.02
tplink_cpu_core_usage_ratio{core="2"} 0.03
tplink_cpu_core_usage_ratio{core="3"} 0.02
tplink_cpu_core_usage_ratio{core="4"} 0.03
# HELP tplink_cpu_cores Cores found by probing cpuN_usage; varies by model.
# TYPE tplink_cpu_cores gauge
tplink_cpu_cores 4
# HELP tplink_cpu_usage_ratio CPU load as a ratio in 0..1; the UI shows it multiplied by 100.
# TYPE tplink_cpu_usage_ratio gauge
tplink_cpu_usage_ratio 0.02
# HELP tplink_memory_usage_ratio Memory in use as a ratio in 0..1.
# TYPE tplink_memory_usage_ratio gauge
tplink_memory_usage_ratio 0.4
# HELP tplink_router_clock_info The router's timezone as a TP-Link index, which is not an offset and cannot be resolved to a location.
# TYPE tplink_router_clock_info gauge
tplink_router_clock_info{timezone="74"} 1
# HELP tplink_router_clock_timestamp_seconds Unix time from the router's own clock, read in the exporter's location. The firmware reports a TP-Link timezone index rather than an offset, so both must run the same zone for time() minus this to mean drift.
# TYPE tplink_router_clock_timestamp_seconds gauge
tplink_router_clock_timestamp_seconds 1786802870
`

const portsGolden = `
# HELP tplink_port_info One series per port, carrying the duplex mode.
# TYPE tplink_port_info gauge
tplink_port_info{duplex="",is_wan="false",port="lan1"} 1
tplink_port_info{duplex="FULL",is_wan="false",port="wanlan2g5"} 1
tplink_port_info{duplex="FULL",is_wan="true",port="wanlan1g"} 1
# HELP tplink_port_link 1 when the port has a link.
# TYPE tplink_port_link gauge
tplink_port_link{is_wan="false",port="lan1"} 0
tplink_port_link{is_wan="false",port="wanlan2g5"} 1
tplink_port_link{is_wan="true",port="wanlan1g"} 1
# HELP tplink_port_speed_mbits Negotiated port speed in Mbit/s; 0 on a dark port. Duplex is not a label here: it empties when the link drops, and the series has to fall to zero rather than be replaced.
# TYPE tplink_port_speed_mbits gauge
tplink_port_speed_mbits{is_wan="false",port="lan1"} 0
tplink_port_speed_mbits{is_wan="false",port="wanlan2g5"} 2500
tplink_port_speed_mbits{is_wan="true",port="wanlan1g"} 1000
`

const wifiGolden = `
# HELP tplink_wifi_channel Channel the band is actually using, resolved even when the setting is auto.
# TYPE tplink_wifi_channel gauge
tplink_wifi_channel{band="2g"} 6
tplink_wifi_channel{band="5g"} 36
# HELP tplink_wifi_radio_enabled 1 when the radio on that band is on.
# TYPE tplink_wifi_radio_enabled gauge
tplink_wifi_radio_enabled{band="2g"} 1
tplink_wifi_radio_enabled{band="5g"} 0
# HELP tplink_wifi_txpower_info Transmit power level of the band: high, middle or low.
# TYPE tplink_wifi_txpower_info gauge
tplink_wifi_txpower_info{band="2g",level="high"} 1
tplink_wifi_txpower_info{band="5g",level="low"} 1
`

const meshGolden = `
# HELP tplink_mesh_node_clients Clients attached to that node.
# TYPE tplink_mesh_node_clients gauge
tplink_mesh_node_clients{mac="00:00:5e:00:53:15"} 19
# HELP tplink_mesh_node_info One series per EasyMesh node.
# TYPE tplink_mesh_node_info gauge
tplink_mesh_node_info{mac="00:00:5e:00:53:15",model="Archer AX80",name="Archer AX80",role="main_router"} 1
# HELP tplink_mesh_node_up 1 when the node is connected.
# TYPE tplink_mesh_node_up gauge
tplink_mesh_node_up{mac="00:00:5e:00:53:15"} 1
`

const clientsGolden = `
# HELP tplink_client_connected_since_seconds Unix time the current session began.
# TYPE tplink_client_connected_since_seconds gauge
tplink_client_connected_since_seconds{mac="00:00:5e:00:53:0a"} 1786799258
tplink_client_connected_since_seconds{mac="00:00:5e:00:53:0f"} 1786782846
# HELP tplink_client_info One series per client. Everything that churns lives here, so numeric metrics keep a single mac label.
# TYPE tplink_client_info gauge
tplink_client_info{guest="false",hostname="thermostat",iface="wired",ip="192.0.2.11",mac="00:00:5e:00:53:0a",type="Computer",via="00:00:5e:00:53:15"} 1
tplink_client_info{guest="true",hostname="speaker",iface="2.4G",ip="192.0.2.16",mac="00:00:5e:00:53:0f",type="IoT Devices",via="00:00:5e:00:53:15"} 1
# HELP tplink_client_session_seconds Length of the current session; restarts on reconnect.
# TYPE tplink_client_session_seconds gauge
tplink_client_session_seconds{mac="00:00:5e:00:53:0a"} 3600
tplink_client_session_seconds{mac="00:00:5e:00:53:0f"} 20012
# HELP tplink_client_speed_bytes Current client throughput in bytes per second.
# TYPE tplink_client_speed_bytes gauge
tplink_client_speed_bytes{dir="rx",mac="00:00:5e:00:53:0a"} 1293
tplink_client_speed_bytes{dir="rx",mac="00:00:5e:00:53:0f"} 678
tplink_client_speed_bytes{dir="tx",mac="00:00:5e:00:53:0a"} 1391
tplink_client_speed_bytes{dir="tx",mac="00:00:5e:00:53:0f"} 1692
# HELP tplink_client_traffic_bytes_total Bytes the client has moved; resets when the router reboots.
# TYPE tplink_client_traffic_bytes_total counter
tplink_client_traffic_bytes_total{mac="00:00:5e:00:53:0a"} 5278837500
tplink_client_traffic_bytes_total{mac="00:00:5e:00:53:0f"} 96789900
# HELP tplink_clients Clients currently online, by connection type.
# TYPE tplink_clients gauge
tplink_clients{iface="2.4G"} 1
tplink_clients{iface="wired"} 1
`

// Expiry is TakenAt plus what is left: 1786802858 + 5534.
const dhcpGolden = `
# HELP tplink_dhcp_lease_expiry_seconds Unix time the lease runs out. Absent for a permanent lease: a far-future stand-in would break sorting by soonest.
# TYPE tplink_dhcp_lease_expiry_seconds gauge
tplink_dhcp_lease_expiry_seconds{hostname="thermostat",ip="192.0.2.11",mac="00:00:5e:00:53:0a"} 1786808392
# HELP tplink_dhcp_lease_permanent 1 when the lease never expires. Not the same as being reserved.
# TYPE tplink_dhcp_lease_permanent gauge
tplink_dhcp_lease_permanent{hostname="laptop",ip="192.0.2.1",mac="00:00:5e:00:53:00"} 1
tplink_dhcp_lease_permanent{hostname="thermostat",ip="192.0.2.11",mac="00:00:5e:00:53:0a"} 0
# HELP tplink_dhcp_pool_lease_seconds Lease length configured for the pool; individual leases can differ.
# TYPE tplink_dhcp_pool_lease_seconds gauge
tplink_dhcp_pool_lease_seconds 7200
# HELP tplink_dhcp_reservation 1 when the address is reserved for this MAC.
# TYPE tplink_dhcp_reservation gauge
tplink_dhcp_reservation{hostname="desk-pc",ip="192.0.2.3",mac="00:00:5e:00:53:02"} 0
tplink_dhcp_reservation{hostname="laptop",ip="192.0.2.2",mac="00:00:5e:00:53:01"} 1
`

const vpnGolden = `
# HELP tplink_vpn_server_enabled 1 when the router's own VPN server is on.
# TYPE tplink_vpn_server_enabled gauge
tplink_vpn_server_enabled 1
# HELP tplink_vpn_tunnel_info One series per outbound VPN tunnel of the router.
# TYPE tplink_vpn_tunnel_info gauge
tplink_vpn_tunnel_info{endpoint="vpn.example.net:51820",name="NordVPN",type="wireguard",vendor="nordvpn"} 1
# HELP tplink_vpn_tunnel_speed_bytes Current tunnel throughput in bytes per second; the firmware keeps no byte counter.
# TYPE tplink_vpn_tunnel_speed_bytes gauge
tplink_vpn_tunnel_speed_bytes{dir="rx",name="NordVPN"} 1598
tplink_vpn_tunnel_speed_bytes{dir="tx",name="NordVPN"} 1147
# HELP tplink_vpn_tunnel_up 1 when the tunnel is connected.
# TYPE tplink_vpn_tunnel_up gauge
tplink_vpn_tunnel_up{name="NordVPN"} 1
# HELP tplink_vpn_user_access 1 when the user may use the VPN server. Permission, not an active session — the firmware does not report who is connected.
# TYPE tplink_vpn_user_access gauge
tplink_vpn_user_access{client_type="pc",mac="00:00:5e:00:53:0a",name="thermostat"} 1
tplink_vpn_user_access{client_type="pc",mac="00:00:5e:00:53:0b",name="bulb-a"} 0
`

// Nothing is forwarded and nothing is mapped on the reference device, so these
// are the zeros an "it stopped being empty" alert fires out of.
const securityGolden = `
# HELP tplink_dmz_enabled 1 when a host is exposed to the WAN through the DMZ.
# TYPE tplink_dmz_enabled gauge
tplink_dmz_enabled 0
# HELP tplink_firewall_ping_allowed 1 when the router answers ICMP echo from that side.
# TYPE tplink_firewall_ping_allowed gauge
tplink_firewall_ping_allowed{source="lan"} 1
tplink_firewall_ping_allowed{source="wan"} 0
# HELP tplink_guest_network_enabled 1 when the guest SSID on that band is up.
# TYPE tplink_guest_network_enabled gauge
tplink_guest_network_enabled{band="2g"} 0
tplink_guest_network_enabled{band="5g"} 0
# HELP tplink_iot_network_enabled 1 when the IoT SSID on that band is up. A separate pair the router keeps for smart-home devices.
# TYPE tplink_iot_network_enabled gauge
tplink_iot_network_enabled{band="2g"} 0
tplink_iot_network_enabled{band="5g"} 0
# HELP tplink_port_forward_rules Forwarding rules configured, by kind: vs is virtual servers, pt is port triggering.
# TYPE tplink_port_forward_rules gauge
tplink_port_forward_rules{kind="pt"} 0
tplink_port_forward_rules{kind="vs"} 0
# HELP tplink_remote_management_enabled 1 when the router accepts management from the WAN side.
# TYPE tplink_remote_management_enabled gauge
tplink_remote_management_enabled 0
# HELP tplink_upnp_enabled 1 when UPnP is on.
# TYPE tplink_upnp_enabled gauge
tplink_upnp_enabled 1
# HELP tplink_upnp_mappings Port mappings devices have opened through UPnP.
# TYPE tplink_upnp_mappings gauge
tplink_upnp_mappings 0
`

// securityFlagMetrics is every family the pointer fields of Security can
// produce; PortForwards, GuestNetworks and IoTNetworks come from other replies.
var securityFlagMetrics = []string{
	"tplink_remote_management_enabled", "tplink_upnp_enabled", "tplink_upnp_mappings",
	"tplink_dmz_enabled", "tplink_firewall_ping_allowed",
}

// bandNetworkMetrics is the two SSID pairs status?form=all carries beside the
// host radios.
var bandNetworkMetrics = []string{"tplink_guest_network_enabled", "tplink_iot_network_enabled"}

const arpGolden = `
# HELP tplink_arp_entry_info One series per ARP entry. Wider than the client list — stale addresses stay, which is what makes it the source for an unknown MAC.
# TYPE tplink_arp_entry_info gauge
tplink_arp_entry_info{ip="192.0.2.11",mac="00:00:5e:00:53:0a",name="thermostat"} 1
tplink_arp_entry_info{ip="192.0.2.3",mac="00:00:5e:00:53:02",name="desk-pc"} 1
tplink_arp_entry_info{ip="192.0.2.30",mac="00:00:5e:00:53:02",name=""} 1
`

// metricGroup is one part of the exposition and the text it must equal.
type metricGroup struct{ name, want string }

// metricGroups is the whole exposition of fullState, split up so a failure names
// the part of the router it came from. Every descriptor in collector.go appears
// in exactly one group; TestGoldensCoverEveryDescriptor holds that true.
func metricGroups() []metricGroup {
	return []metricGroup{
		{"build", buildInfoGolden(testBuild.Version, testBuild.Revision)},
		{"health", healthGolden},
		{"router", routerGolden},
		{"performance", performanceGolden},
		{"ports", portsGolden},
		{"wifi", wifiGolden},
		{"mesh", meshGolden},
		{"clients", clientsGolden},
		{"dhcp", dhcpGolden},
		{"vpn", vpnGolden},
		{"security", securityGolden},
		{"arp", arpGolden},
	}
}

// gathererFor registers a collector over st with no age limit, so a golden is
// about content alone.
func gathererFor(t *testing.T, st State) prometheus.Gatherer {
	t.Helper()
	return gathererWithMaxAge(t, st, 0)
}

// gathererWithMaxAge registers a collector over st reporting testBuild.
func gathererWithMaxAge(t *testing.T, st State, maxAge time.Duration) prometheus.Gatherer {
	t.Helper()
	return gathererWithBuild(t, st, maxAge, testBuild)
}

// goldenNames lists the metrics a golden covers, read from its TYPE lines, so
// the filter passed to GatherAndCompare cannot drift from the text it filters.
func goldenNames(t *testing.T, golden string) []string {
	t.Helper()
	var names []string
	for name := range goldenTypes(t, golden) {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// goldenTypes reads the declared type of every metric in a golden.
func goldenTypes(t *testing.T, golden string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, line := range strings.Split(golden, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 4 || fields[0] != "#" || fields[1] != "TYPE" {
			continue
		}
		if _, dup := out[fields[2]]; dup {
			t.Fatalf("%s is declared twice in one golden", fields[2])
		}
		out[fields[2]] = fields[3]
	}
	if len(out) == 0 {
		t.Fatalf("no TYPE line in golden:\n%s", golden)
	}
	return out
}

// goldenFamily cuts the HELP, TYPE and sample lines of one metric out of a
// golden, so a test about part of the exposition restates none of its values.
func goldenFamily(t *testing.T, golden, name string) string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(golden, "\n") {
		switch {
		case strings.HasPrefix(line, "# HELP "+name+" "),
			strings.HasPrefix(line, "# TYPE "+name+" "),
			strings.HasPrefix(line, name+" "),
			strings.HasPrefix(line, name+"{"):
			out = append(out, line)
		}
	}
	if len(out) < 3 {
		t.Fatalf("golden holds no HELP, TYPE and sample lines for %s", name)
	}
	return strings.Join(out, "\n") + "\n"
}

// goldenHeader is the HELP and TYPE lines of one metric, without its samples, so
// a test can state values of its own against the documented shape.
func goldenHeader(t *testing.T, golden, name string) string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(goldenFamily(t, golden, name), "\n") {
		if strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n") + "\n"
}

// expositionFor turns sample lines into an exposition, taking each family's HELP
// and TYPE from golden. Samples of one metric are grouped, which is what the text
// parser requires.
func expositionFor(t *testing.T, golden string, samples ...string) string {
	t.Helper()
	var order []string
	byName := map[string][]string{}
	for _, s := range samples {
		name := s
		if i := strings.IndexAny(name, "{ "); i >= 0 {
			name = name[:i]
		}
		if _, seen := byName[name]; !seen {
			order = append(order, name)
		}
		byName[name] = append(byName[name], s)
	}

	var out strings.Builder
	for _, name := range order {
		out.WriteString(goldenHeader(t, golden, name))
		for _, s := range byName[name] {
			out.WriteString(s + "\n")
		}
	}
	return out.String()
}

// goldenSeries counts the series a golden expects: every line that is not a
// comment.
func goldenSeries(golden string) int {
	n := 0
	for _, line := range strings.Split(golden, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			n++
		}
	}
	return n
}

// goldensSeries is the size of a whole scrape of fullState.
func goldensSeries() int {
	n := 0
	for _, grp := range metricGroups() {
		n += goldenSeries(grp.want)
	}
	return n
}

// Desc keeps its fields unexported and prints them in this shape:
// Desc{fqName: "x", help: "y", unit: "", constLabels: {}, variableLabels: {a,b}}.
var descShape = regexp.MustCompile(`^Desc\{fqName: "([^"]+)", help: "(.*?)", unit: ".*?", constLabels: \{.*?\}, variableLabels: \{(.*)\}\}$`)

type metricDesc struct {
	help   string
	labels []string // sorted, as a registry emits them
}

// describedMetrics is what Describe announces, keyed by metric name.
func describedMetrics(t *testing.T) map[string]metricDesc {
	t.Helper()
	ch := make(chan *prometheus.Desc, 64)
	go func() {
		NewCollector(&stubSource{}, 0, testBuild).Describe(ch)
		close(ch)
	}()

	out := map[string]metricDesc{}
	for d := range ch {
		m := descShape.FindStringSubmatch(d.String())
		if m == nil {
			t.Fatalf("cannot read a name and labels out of %s", d)
		}
		help, err := strconv.Unquote(`"` + m[2] + `"`)
		if err != nil {
			t.Fatalf("cannot read the help of %s: %v", m[1], err)
		}
		var labels []string
		if m[3] != "" {
			labels = strings.Split(m[3], ",")
			slices.Sort(labels)
		}
		if _, dup := out[m[1]]; dup {
			t.Errorf("%s was announced twice by Describe", m[1])
		}
		out[m[1]] = metricDesc{help: help, labels: labels}
	}
	return out
}

// The metric surface: name, help, type, labels and value for every descriptor,
// over a cycle in which everything answered.
func TestSnapshotExposition(t *testing.T) {
	g := gathererFor(t, fullState())

	for _, grp := range metricGroups() {
		t.Run(grp.name, func(t *testing.T) {
			names := goldenNames(t, grp.want)
			if err := testutil.GatherAndCompare(g, strings.NewReader(grp.want), names...); err != nil {
				t.Errorf("the %s metrics are not what the descriptors promise:\n%v", grp.name, err)
			}
		})
	}
}

// The goldens above are the whole scrape.
func TestNothingIsExposedBeyondTheGoldens(t *testing.T) {
	g := gathererFor(t, fullState())

	want := goldensSeries()
	got, err := testutil.GatherAndCount(g)
	if err != nil {
		t.Fatalf("gathering a full snapshot failed: %v", err)
	}
	if got != want {
		t.Errorf("a scrape carried %d series, the goldens account for %d; a family that no golden "+
			"covers is one no test holds to a name, a label set or a type", got, want)
	}

	// Scrapes are independent reads of the same State.
	again, err := testutil.GatherAndCount(g)
	if err != nil {
		t.Fatalf("gathering a second time failed: %v", err)
	}
	if again != got {
		t.Errorf("the second scrape carried %d series against the first one's %d; the collector serves "+
			"the same snapshot until the poller replaces it", again, got)
	}
}

// Describe is what a registry registers and what a dashboard's metric list comes
// from.
func TestGoldensCoverEveryDescriptor(t *testing.T) {
	described := describedMetrics(t)

	covered := map[string]string{}
	for _, grp := range metricGroups() {
		for name := range goldenTypes(t, grp.want) {
			if other, dup := covered[name]; dup {
				t.Errorf("%s is expected by both the %s and the %s golden", name, other, grp.name)
			}
			covered[name] = grp.name
			if _, ok := described[name]; !ok {
				t.Errorf("%s is expected by the %s golden but Describe never announces it", name, grp.name)
			}
		}
	}
	for name := range described {
		if _, ok := covered[name]; !ok {
			t.Errorf("Describe announces %s and no golden covers it; add it to a group so its labels "+
				"and its type are pinned somewhere", name)
		}
	}
}

// trafficUsage resets when the router reboots and the five exporter counters
// when the process restarts. Everything else is a reading of now, and a gauge.
func TestResettingValuesAreCounters(t *testing.T) {
	counters := map[string]bool{
		"tplink_client_traffic_bytes_total": true,
		"tplink_scrape_errors_total":        true,
		"tplink_login_total":                true,
		"tplink_login_failed_total":         true,
		"tplink_session_lost_total":         true,
		"tplink_login_suppressed_total":     true,
	}

	var want strings.Builder
	seen := map[string]bool{}
	for _, grp := range metricGroups() {
		for name, typ := range goldenTypes(t, grp.want) {
			seen[name] = true
			if !counters[name] {
				if typ != "gauge" {
					t.Errorf("%s is expected as a %s; only a value that resets is a counter", name, typ)
				}
				continue
			}
			if typ != "counter" {
				t.Errorf("%s is expected as a %s, want counter: it resets, and rate() over a gauge "+
					"reads the reset as a fall to zero", name, typ)
			}
			want.WriteString(goldenFamily(t, grp.want, name))
		}
	}
	for name := range counters {
		if !seen[name] {
			t.Errorf("%s is a counter that no golden expects", name)
		}
	}

	names := make([]string, 0, len(counters))
	for name := range counters {
		names = append(names, name)
	}
	err := testutil.GatherAndCompare(gathererFor(t, fullState()), strings.NewReader(want.String()), names...)
	if err != nil {
		t.Errorf("the values that reset are not published as counters:\n%v", err)
	}
}

// Before the first cycle there is nothing to serve: the scrape answers with the
// health metrics alone, and no snapshot timestamp, since zero would read as 1970.
func TestNoSnapshotServesHealthOnly(t *testing.T) {
	st := State{
		Up:               false,
		SessionBlocked:   true,
		LastAttempt:      takenAt,
		LoginFailures:    3,
		EndpointErrors:   map[string]uint64{},
		SessionsLost:     1,
		LoginsSuppressed: 2,
		PollDuration:     900 * time.Millisecond,
	}
	const want = `
# HELP tplink_login_failed_total Failed logins since start, session conflicts included.
# TYPE tplink_login_failed_total counter
tplink_login_failed_total 3
# HELP tplink_login_suppressed_total Logins not attempted since start: during the cooldown after losing the session, against the hourly cap, or inside the backoff after a failed cycle.
# TYPE tplink_login_suppressed_total counter
tplink_login_suppressed_total 2
# HELP tplink_login_total Successful logins since start.
# TYPE tplink_login_total counter
tplink_login_total 0
# HELP tplink_scrape_duration_seconds Duration of the last poll cycle.
# TYPE tplink_scrape_duration_seconds gauge
tplink_scrape_duration_seconds 0.9
# HELP tplink_session_blocked 1 when the router's single web session is held by someone else.
# TYPE tplink_session_blocked gauge
tplink_session_blocked 1
# HELP tplink_session_lost_total Sessions the exporter concluded it had lost, since start. Someone opening the web UI is the usual cause; a reboot or an upgrade reads the same.
# TYPE tplink_session_lost_total counter
tplink_session_lost_total 1
# HELP tplink_up 1 when the last poll reached the router.
# TYPE tplink_up gauge
tplink_up 0
`

	// No filter: this is the whole scrape, so anything else is a failure. The
	// build is in it because it is served whatever the poller found.
	whole := want + buildInfoGolden(testBuild.Version, testBuild.Revision)
	if err := testutil.GatherAndCompare(gathererFor(t, st), strings.NewReader(whole)); err != nil {
		t.Errorf("a scrape before the first successful cycle is not health and the build alone:\n%v", err)
	}
}

// Past maxAge the readings leave a hole rather than a flat line; health and the
// snapshot timestamp are served at any age.
func TestSnapshotPastMaxAgeIsNotServed(t *testing.T) {
	const maxAge = 5 * time.Minute
	for _, tc := range []struct {
		name   string
		age    time.Duration
		maxAge time.Duration
		served bool
	}{
		{"inside maxAge", time.Minute, maxAge, true},
		{"an hour old against a five-minute maxAge", time.Hour, maxAge, false},
		{"maxAge zero is no limit", time.Hour, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := fullState()
			st.Snapshot.TakenAt = time.Now().Add(-tc.age).Truncate(time.Second)
			g := gathererWithMaxAge(t, st, tc.maxAge)

			stamp := goldenHeader(t, healthGolden, "tplink_snapshot_timestamp_seconds") +
				fmt.Sprintf("tplink_snapshot_timestamp_seconds %d\n", st.Snapshot.TakenAt.Unix())
			err := testutil.GatherAndCompare(g, strings.NewReader(stamp), "tplink_snapshot_timestamp_seconds")
			if err != nil {
				t.Errorf("%s: the snapshot timestamp is what makes the age visible and is served at any age:\n%v",
					tc.name, err)
			}

			if !tc.served {
				var want strings.Builder
				for _, name := range healthMetrics {
					want.WriteString(goldenFamily(t, healthGolden, name))
				}
				want.WriteString(stamp)
				want.WriteString(buildInfoGolden(testBuild.Version, testBuild.Revision))
				if err := testutil.GatherAndCompare(g, strings.NewReader(want.String())); err != nil {
					t.Errorf("%s: a snapshot past maxAge leaves health, its timestamp and the build, "+
						"nothing else:\n%v", tc.name, err)
				}
				return
			}

			got, err := testutil.GatherAndCount(g)
			if err != nil {
				t.Fatalf("gathering failed: %v", err)
			}
			if want := goldensSeries(); got != want {
				t.Errorf("%s: a scrape carried %d series against the %d a full snapshot has; this snapshot "+
					"is inside the limit and is served whole", tc.name, got, want)
			}
			err = testutil.GatherAndCompare(g, strings.NewReader(goldenFamily(t, clientsGolden, "tplink_client_info")),
				"tplink_client_info")
			if err != nil {
				t.Errorf("%s: the readings themselves are not served:\n%v", tc.name, err)
			}
		})
	}
}

// Failures inside a cycle do not lower tplink_up: the router answered.
// tplink_endpoints_failed is what says how much of the snapshot is missing.
func TestEndpointsFailedCountsTheCycle(t *testing.T) {
	down := errors.New("endpoint did not answer")
	for _, tc := range []struct {
		name string
		errs map[string]error
		want int
	}{
		{"a clean cycle", map[string]error{}, 0},
		{"three sources of the poll set failed", map[string]error{
			srcLeases: down, srcTunnels: down, srcMesh: down,
		}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := fullState()
			st.Snapshot.Errors = tc.errs

			want := goldenHeader(t, healthGolden, "tplink_endpoints_failed") +
				fmt.Sprintf("tplink_endpoints_failed %d\n", tc.want) +
				goldenFamily(t, healthGolden, "tplink_up")
			err := testutil.GatherAndCompare(gathererFor(t, st), strings.NewReader(want),
				"tplink_endpoints_failed", "tplink_up")
			if err != nil {
				t.Errorf("%s: tplink_endpoints_failed counts the failures of the cycle behind the "+
					"snapshot, beside a tplink_up that says the router answered:\n%v", tc.name, err)
			}
		})
	}
}

// WAN is three replies folded into one struct, and any of them can be missing.
// A zero InternetUp from an endpoint that never answered would raise the alert
// this exporter exists for.
func TestWANPublishesOnlyTheRepliesThatAnswered(t *testing.T) {
	for _, tc := range []struct {
		name string
		wan  *WAN
		want []string
	}{
		{
			name: "only status?form=wan_speed answered",
			wan: &WAN{
				HaveSpeed: true, DownBytesPerS: 1546905, UpBytesPerS: 23401, SpeedTakenAt: takenAt,
			},
			want: []string{
				`tplink_wan_speed_bytes{dir="rx"} 1546905`,
				`tplink_wan_speed_bytes{dir="tx"} 23401`,
				`tplink_wan_speed_timestamp_seconds 1786802858`,
			},
		},
		{
			name: "only status?form=internet answered, and the line is down",
			wan:  &WAN{HaveStatus: true, State: "disconnected"},
			want: []string{
				`tplink_wan_status{iface="internet"} 0`,
				`tplink_wan_status{iface="link"} 0`,
				`tplink_wan_status_info{state="disconnected"} 1`,
			},
		},
		{
			name: "only status?form=all answered",
			wan:  &WAN{HaveUptime: true, Uptime: 1117521 * time.Second},
			want: []string{`tplink_wan_uptime_seconds 1117521`},
		},
		{
			name: "none of the three answered",
			wan:  &WAN{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := fullState()
			st.Snapshot.WAN = tc.wan

			want := expositionFor(t, routerGolden, tc.want...)
			err := testutil.GatherAndCompare(gathererFor(t, st), strings.NewReader(want), wanMetrics...)
			if err != nil {
				t.Errorf("%s: a WAN field no reply filled has no series, and a zero one reads as "+
					"\"the internet is down\":\n%v", tc.name, err)
			}
		})
	}
}

// A nil flag is an endpoint that did not answer, a false one is the router
// saying off.
func TestSecurityFlagsPublishOnlyWhatWasRead(t *testing.T) {
	on, off := true, false
	none := 0
	for _, tc := range []struct {
		name string
		sec  *Security
		want []string
	}{
		{
			name: "no security endpoint answered",
			sec:  &Security{},
		},
		{
			name: "administration?form=remote did not answer",
			sec:  &Security{UPnPEnabled: &on},
			want: []string{`tplink_upnp_enabled 1`},
		},
		{
			name: "administration?form=remote said off",
			sec:  &Security{RemoteManagement: &off},
			want: []string{`tplink_remote_management_enabled 0`},
		},
		{
			name: "administration?form=remote said on",
			sec:  &Security{RemoteManagement: &on},
			want: []string{`tplink_remote_management_enabled 1`},
		},
		{
			name: "upnp?form=enable answered and ?form=service did not",
			sec:  &Security{UPnPEnabled: &on},
			want: []string{`tplink_upnp_enabled 1`},
		},
		{
			name: "both upnp endpoints answered with nothing mapped",
			sec:  &Security{UPnPEnabled: &on, UPnPMappings: &none},
			want: []string{`tplink_upnp_enabled 1`, `tplink_upnp_mappings 0`},
		},
		{
			name: "the firewall reply carried lan_ping and not wan_ping",
			sec:  &Security{LANPing: &on},
			want: []string{`tplink_firewall_ping_allowed{source="lan"} 1`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := fullState()
			st.Snapshot.Security = tc.sec

			want := expositionFor(t, securityGolden, tc.want...)
			err := testutil.GatherAndCompare(gathererFor(t, st), strings.NewReader(want), securityFlagMetrics...)
			if err != nil {
				t.Errorf("%s: a nil flag has no series and a false one is published as 0:\n%v", tc.name, err)
			}
		})
	}
}

// The guest and the IoT pair are two maps behind two metrics. A nil map is
// status?form=all not having answered, and publishing it as zeros would read as
// "both SSIDs are down".
func TestBandNetworksPublishOnlyWhatWasRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		sec  *Security
		want []string
	}{
		{
			name: "status?form=all did not answer",
			sec:  &Security{},
		},
		{
			name: "the guest pair is up and the IoT pair is not",
			sec: &Security{
				GuestNetworks: map[string]bool{"2g": true, "5g": true},
				IoTNetworks:   map[string]bool{"2g": false, "5g": false},
			},
			want: []string{
				`tplink_guest_network_enabled{band="2g"} 1`,
				`tplink_guest_network_enabled{band="5g"} 1`,
				`tplink_iot_network_enabled{band="2g"} 0`,
				`tplink_iot_network_enabled{band="5g"} 0`,
			},
		},
		{
			name: "the IoT pair is up and the guest pair is not",
			sec: &Security{
				GuestNetworks: map[string]bool{"2g": false, "5g": false},
				IoTNetworks:   map[string]bool{"2g": true, "5g": true},
			},
			want: []string{
				`tplink_guest_network_enabled{band="2g"} 0`,
				`tplink_guest_network_enabled{band="5g"} 0`,
				`tplink_iot_network_enabled{band="2g"} 1`,
				`tplink_iot_network_enabled{band="5g"} 1`,
			},
		},
		{
			name: "the reply named one IoT band and no guest one",
			sec:  &Security{IoTNetworks: map[string]bool{"5g": true}},
			want: []string{`tplink_iot_network_enabled{band="5g"} 1`},
		},
		{
			name: "the reply named one guest band and no IoT one",
			sec:  &Security{GuestNetworks: map[string]bool{"2g": true}},
			want: []string{`tplink_guest_network_enabled{band="2g"} 1`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := fullState()
			st.Snapshot.Security = tc.sec

			want := expositionFor(t, securityGolden, tc.want...)
			err := testutil.GatherAndCompare(gathererFor(t, st), strings.NewReader(want), bandNetworkMetrics...)
			if err != nil {
				t.Errorf("%s: each pair is published under its own name, and a band nothing was read for "+
					"has no series:\n%v", tc.name, err)
			}
		})
	}
}

// The three Wi-Fi fields of a band arrive independently: a nil Enabled published
// as 0 reads as "the radio is off", a nil Channel as "channel 0".
func TestWiFiPublishesOnlyTheFieldsThatWereRead(t *testing.T) {
	on := true
	channel := 36
	for _, tc := range []struct {
		name     string
		wireless map[string]Radio
		want     []string
	}{
		{
			name:     "the band answered whole",
			wireless: map[string]Radio{"5g": {Enabled: &on, Channel: &channel, TxPower: "low"}},
			want: []string{
				`tplink_wifi_radio_enabled{band="5g"} 1`,
				`tplink_wifi_channel{band="5g"} 36`,
				`tplink_wifi_txpower_info{band="5g",level="low"} 1`,
			},
		},
		{
			name:     "wireless_5g_enable is missing",
			wireless: map[string]Radio{"5g": {Channel: &channel, TxPower: "low"}},
			want: []string{
				`tplink_wifi_channel{band="5g"} 36`,
				`tplink_wifi_txpower_info{band="5g",level="low"} 1`,
			},
		},
		{
			name:     "wireless_5g_current_channel is missing",
			wireless: map[string]Radio{"5g": {Enabled: &on, TxPower: "low"}},
			want: []string{
				`tplink_wifi_radio_enabled{band="5g"} 1`,
				`tplink_wifi_txpower_info{band="5g",level="low"} 1`,
			},
		},
		{
			name:     "wireless_5g_txpower is missing",
			wireless: map[string]Radio{"5g": {Enabled: &on, Channel: &channel}},
			want: []string{
				`tplink_wifi_radio_enabled{band="5g"} 1`,
				`tplink_wifi_channel{band="5g"} 36`,
			},
		},
		{
			name:     "one band answered whole and the other carried txpower alone",
			wireless: map[string]Radio{"5g": {Enabled: &on, Channel: &channel, TxPower: "low"}, "2g": {TxPower: "high"}},
			want: []string{
				`tplink_wifi_radio_enabled{band="5g"} 1`,
				`tplink_wifi_channel{band="5g"} 36`,
				`tplink_wifi_txpower_info{band="2g",level="high"} 1`,
				`tplink_wifi_txpower_info{band="5g",level="low"} 1`,
			},
		},
		{
			name:     "a band with nothing in it",
			wireless: map[string]Radio{"5g": {}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := fullState()
			st.Snapshot.Wireless = tc.wireless

			want := expositionFor(t, wifiGolden, tc.want...)
			err := testutil.GatherAndCompare(gathererFor(t, st), strings.NewReader(want),
				"tplink_wifi_radio_enabled", "tplink_wifi_channel", "tplink_wifi_txpower_info")
			if err != nil {
				t.Errorf("%s: a Wi-Fi field the reply did not carry has no series:\n%v", tc.name, err)
			}
		})
	}
}

// A port going dark keeps one tplink_port_speed_mbits series and falls to zero,
// which is what delta(), changes() and a for: clause need.
func TestDarkPortKeepsOneSpeedSeries(t *testing.T) {
	if labels := describedMetrics(t)["tplink_port_speed_mbits"].labels; !slices.Equal(labels, []string{"is_wan", "port"}) {
		t.Fatalf("tplink_port_speed_mbits carries %v; a duplex label there replaces the series on a "+
			"link drop instead of letting it fall to zero", labels)
	}

	for _, tc := range []struct {
		name string
		port Port
		want []string
	}{
		{
			name: "linked",
			port: Port{Name: "wanlan1g", Up: true, SpeedMbits: 1000, Duplex: "FULL", IsWAN: true},
			want: []string{
				`tplink_port_speed_mbits{is_wan="true",port="wanlan1g"} 1000`,
				`tplink_port_info{duplex="FULL",is_wan="true",port="wanlan1g"} 1`,
			},
		},
		{
			name: "the cable came out",
			port: Port{Name: "wanlan1g", IsWAN: true},
			want: []string{
				`tplink_port_speed_mbits{is_wan="true",port="wanlan1g"} 0`,
				`tplink_port_info{duplex="",is_wan="true",port="wanlan1g"} 1`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := fullState()
			st.Snapshot.Ports = []Port{tc.port}

			want := expositionFor(t, portsGolden, tc.want...)
			err := testutil.GatherAndCompare(gathererFor(t, st), strings.NewReader(want),
				"tplink_port_speed_mbits", "tplink_port_info")
			if err != nil {
				t.Errorf("%s: the speed series keeps its labels across a link drop and the duplex change "+
					"lands on tplink_port_info:\n%v", tc.name, err)
			}
		})
	}
}

// A field the firmware left empty is an absence, not a value: a zero time.Time
// published as a stamp graphs as the year 1, and an empty label value mints a
// series that says nothing.
func TestEmptyValuesProduceNoSeries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Snapshot)
		absent string
		kept   string
		keptN  int
	}{
		{
			name:   "wan_speed answered without test_time",
			mutate: func(s *Snapshot) { s.WAN.SpeedTakenAt = time.Time{} },
			absent: "tplink_wan_speed_timestamp_seconds",
			kept:   "tplink_wan_speed_bytes",
			keptN:  2,
		},
		{
			name:   "internet_status arrived empty",
			mutate: func(s *Snapshot) { s.WAN.State = "" },
			absent: "tplink_wan_status_info",
			kept:   "tplink_wan_status",
			keptN:  2,
		},
		{
			name:   "time?form=settings carried no timezone",
			mutate: func(s *Snapshot) { s.Router.Timezone = "" },
			absent: "tplink_router_clock_info",
			kept:   "tplink_router_clock_timestamp_seconds",
			keptN:  1,
		},
		{
			name: "a client traffic?form=dev_name has not listed yet",
			mutate: func(s *Snapshot) {
				for i := range s.Clients {
					s.Clients[i].ConnectedAt = time.Time{}
				}
			},
			absent: "tplink_client_connected_since_seconds",
			kept:   "tplink_clients",
			keptN:  2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := fullState()
			tc.mutate(st.Snapshot)
			g := gathererFor(t, st)

			if err := testutil.GatherAndCompare(g, strings.NewReader(""), tc.absent); err != nil {
				t.Errorf("%s: %s has no value to carry:\n%v", tc.name, tc.absent, err)
			}
			n, err := testutil.GatherAndCount(g, tc.kept)
			if err != nil {
				t.Fatalf("gathering failed: %v", err)
			}
			if n != tc.keptN {
				t.Errorf("%s: %s carries %d series, want %d; only the empty field drops out",
					tc.name, tc.kept, n, tc.keptN)
			}
		})
	}
}

// A partial cycle is the ordinary case: the failed section is nil and the
// collector publishes the rest.
func TestPartialSnapshotEmitsWhatItHas(t *testing.T) {
	on := true
	st := State{
		Snapshot: &Snapshot{
			TakenAt:  takenAt,
			Firmware: fullSnapshot().Firmware,
			Clients:  fullSnapshot().Clients[:1],
			// nat?form=vs and ?form=pt did not answer, so PortForwards has no key;
			// status?form=all did not either, so there are no guest or IoT bands,
			// no Perf and no Wireless.
			Security: &Security{UPnPEnabled: &on, LANPing: &on},
			Errors:   map[string]error{srcStatusAll: errors.New("endpoint did not answer")},
		},
		Up:             true,
		LastAttempt:    takenAt,
		Logins:         1,
		EndpointErrors: map[string]uint64{srcStatusAll: 1},
		PollDuration:   1500 * time.Millisecond,
	}
	const want = `
# HELP tplink_client_connected_since_seconds Unix time the current session began.
# TYPE tplink_client_connected_since_seconds gauge
tplink_client_connected_since_seconds{mac="00:00:5e:00:53:0a"} 1786799258
# HELP tplink_client_info One series per client. Everything that churns lives here, so numeric metrics keep a single mac label.
# TYPE tplink_client_info gauge
tplink_client_info{guest="false",hostname="thermostat",iface="wired",ip="192.0.2.11",mac="00:00:5e:00:53:0a",type="Computer",via="00:00:5e:00:53:15"} 1
# HELP tplink_client_session_seconds Length of the current session; restarts on reconnect.
# TYPE tplink_client_session_seconds gauge
tplink_client_session_seconds{mac="00:00:5e:00:53:0a"} 3600
# HELP tplink_client_speed_bytes Current client throughput in bytes per second.
# TYPE tplink_client_speed_bytes gauge
tplink_client_speed_bytes{dir="rx",mac="00:00:5e:00:53:0a"} 1293
tplink_client_speed_bytes{dir="tx",mac="00:00:5e:00:53:0a"} 1391
# HELP tplink_client_traffic_bytes_total Bytes the client has moved; resets when the router reboots.
# TYPE tplink_client_traffic_bytes_total counter
tplink_client_traffic_bytes_total{mac="00:00:5e:00:53:0a"} 5278837500
# HELP tplink_clients Clients currently online, by connection type.
# TYPE tplink_clients gauge
tplink_clients{iface="wired"} 1
# HELP tplink_endpoints_failed Endpoints that did not answer in the cycle behind the snapshot being served.
# TYPE tplink_endpoints_failed gauge
tplink_endpoints_failed 1
# HELP tplink_firewall_ping_allowed 1 when the router answers ICMP echo from that side.
# TYPE tplink_firewall_ping_allowed gauge
tplink_firewall_ping_allowed{source="lan"} 1
# HELP tplink_firmware_info Firmware the router reports about itself.
# TYPE tplink_firmware_info gauge
tplink_firmware_info{hardware="Archer AX80 v1.0",model="Archer AX80",version="1.4.1 Build 20251117 rel.76722(5255)"} 1
# HELP tplink_login_failed_total Failed logins since start, session conflicts included.
# TYPE tplink_login_failed_total counter
tplink_login_failed_total 0
# HELP tplink_login_suppressed_total Logins not attempted since start: during the cooldown after losing the session, against the hourly cap, or inside the backoff after a failed cycle.
# TYPE tplink_login_suppressed_total counter
tplink_login_suppressed_total 0
# HELP tplink_login_total Successful logins since start.
# TYPE tplink_login_total counter
tplink_login_total 1
# HELP tplink_scrape_duration_seconds Duration of the last poll cycle.
# TYPE tplink_scrape_duration_seconds gauge
tplink_scrape_duration_seconds 1.5
# HELP tplink_scrape_errors_total Endpoint failures since start, by endpoint.
# TYPE tplink_scrape_errors_total counter
tplink_scrape_errors_total{endpoint="admin/status?form=all"} 1
# HELP tplink_session_blocked 1 when the router's single web session is held by someone else.
# TYPE tplink_session_blocked gauge
tplink_session_blocked 0
# HELP tplink_session_lost_total Sessions the exporter concluded it had lost, since start. Someone opening the web UI is the usual cause; a reboot or an upgrade reads the same.
# TYPE tplink_session_lost_total counter
tplink_session_lost_total 0
# HELP tplink_snapshot_timestamp_seconds Unix time of the snapshot being served; its age is time() minus this.
# TYPE tplink_snapshot_timestamp_seconds gauge
tplink_snapshot_timestamp_seconds 1786802858
# HELP tplink_up 1 when the last poll reached the router.
# TYPE tplink_up gauge
tplink_up 1
# HELP tplink_upnp_enabled 1 when UPnP is on.
# TYPE tplink_upnp_enabled gauge
tplink_upnp_enabled 1
`

	whole := want + buildInfoGolden(testBuild.Version, testBuild.Revision)
	if err := testutil.GatherAndCompare(gathererFor(t, st), strings.NewReader(whole)); err != nil {
		t.Errorf("a snapshot whose sections are partly nil is not exposed as what it holds:\n%v", err)
	}
}

// A dashboard reads "the web UI is busy" and "the router is unreachable" off
// these two.
func TestUpAndSessionBlockedAreIndependent(t *testing.T) {
	for _, tc := range []struct {
		name string
		st   State
		want string
	}{
		{
			name: "the router answered",
			st:   State{Up: true},
			want: "tplink_session_blocked 0\ntplink_up 1\n",
		},
		{
			name: "a login was refused because the single web session is held",
			st:   State{SessionBlocked: true},
			want: "tplink_session_blocked 1\ntplink_up 0\n",
		},
		{
			// The other half of what SessionBlocked means: the session was taken
			// and the poller is inside the cooldown, not asking for it back.
			name: "the session was taken and the poller is staying away",
			st:   State{SessionBlocked: true, SessionsLost: 1, LoginsSuppressed: 3},
			want: "tplink_session_blocked 1\ntplink_up 0\n",
		},
		{
			name: "the router did not answer at all",
			st:   State{},
			want: "tplink_session_blocked 0\ntplink_up 0\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := goldenHeader(t, healthGolden, "tplink_session_blocked") +
				goldenHeader(t, healthGolden, "tplink_up") + tc.want
			err := testutil.GatherAndCompare(gathererFor(t, tc.st), strings.NewReader(want),
				"tplink_up", "tplink_session_blocked")
			if err != nil {
				t.Errorf("%s: up and session_blocked are separate readings, not one:\n%v", tc.name, err)
			}
		})
	}
}

// A permanent lease gets no expiry series; tplink_dhcp_lease_permanent carries
// it instead.
func TestPermanentLeaseHasNoExpirySeries(t *testing.T) {
	g := gathererFor(t, fullState())
	const want = `
# HELP tplink_dhcp_lease_expiry_seconds Unix time the lease runs out. Absent for a permanent lease: a far-future stand-in would break sorting by soonest.
# TYPE tplink_dhcp_lease_expiry_seconds gauge
tplink_dhcp_lease_expiry_seconds{hostname="thermostat",ip="192.0.2.11",mac="00:00:5e:00:53:0a"} 1786808392
`
	err := testutil.GatherAndCompare(g, strings.NewReader(want), "tplink_dhcp_lease_expiry_seconds")
	if err != nil {
		t.Errorf("the permanent lease of 00:00:5e:00:53:00 must have no expiry at all, and the one "+
			"counting down expires at TakenAt plus what is left:\n%v", err)
	}
}

// ip and hostname churn: the first on a DHCP renewal, the second whenever a
// device decides to call itself something new. On a numeric metric each change
// starts a new series and ends the old one; on tplink_client_info that is the
// point of the metric.
func TestClientMetricsCarryMACAlone(t *testing.T) {
	described := describedMetrics(t)

	for _, tc := range []struct {
		metric string
		labels []string
	}{
		{"tplink_client_info", []string{"guest", "hostname", "iface", "ip", "mac", "type", "via"}},
		{"tplink_client_traffic_bytes_total", []string{"mac"}},
		{"tplink_client_speed_bytes", []string{"dir", "mac"}},
		{"tplink_client_session_seconds", []string{"mac"}},
		{"tplink_client_connected_since_seconds", []string{"mac"}},
		{"tplink_clients", []string{"iface"}},
	} {
		d, ok := described[tc.metric]
		if !ok {
			t.Errorf("%s is not among the descriptors Describe announces", tc.metric)
			continue
		}
		if !slices.Equal(d.labels, tc.labels) {
			t.Errorf("%s carries %v, want %v — ip and hostname belong to tplink_client_info alone, "+
				"or every DHCP renewal mints a series", tc.metric, d.labels, tc.labels)
		}
	}
}

// The firmware reports who may use the VPN server, never who is on it.
func TestVPNUserAccessIsPermissionNotASession(t *testing.T) {
	described := describedMetrics(t)

	if _, ok := described["tplink_vpn_user_access"]; !ok {
		t.Fatalf("no tplink_vpn_user_access descriptor; the metric is access, not connection, and %d "+
			"metrics were announced", len(described))
	}
	for name := range described {
		if strings.Contains(name, "vpn_user") && strings.HasSuffix(name, "_connected") {
			t.Errorf("%s reads as an active session; the firmware does not report who is connected", name)
		}
	}
	if help := described["tplink_vpn_user_access"].help; !strings.Contains(help, "Permission, not an active session") {
		t.Errorf("tplink_vpn_user_access is documented as %q; it has to say that it is permission and "+
			"not a session, or a dashboard will read it as one", help)
	}
}

// One scrape is one read of the poller's State. Reading it twice could serve two
// halves of two different cycles in one response.
func TestScrapeReadsStateOnce(t *testing.T) {
	src := &stubSource{st: fullState()}
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(NewCollector(src, 0, testBuild)); err != nil {
		t.Fatalf("a registry refused the collector: %v", err)
	}

	if _, err := reg.Gather(); err != nil {
		t.Fatalf("gathering failed: %v", err)
	}
	if n := src.reads.Load(); n != 1 {
		t.Errorf("one scrape read State %d times, want 1; a scrape serves one snapshot", n)
	}
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("gathering a second time failed: %v", err)
	}
	if n := src.reads.Load(); n != 2 {
		t.Errorf("two scrapes read State %d times, want 2; the next scrape must see the poller's "+
			"newer snapshot", n)
	}
}

// promlint keeps _total on counters, units in the names and help on everything.
func TestExpositionPassesTheLinter(t *testing.T) {
	g := gathererFor(t, fullState())

	n, err := testutil.GatherAndCount(g)
	if err != nil {
		t.Fatalf("gathering a full snapshot failed: %v", err)
	}
	if n == 0 {
		t.Fatal("nothing was exposed, so there is nothing to lint")
	}

	problems, err := testutil.GatherAndLint(g)
	if err != nil {
		t.Fatalf("linting the exposition failed: %v", err)
	}
	for _, p := range problems {
		t.Errorf("%s: %s", p.Metric, p.Text)
	}
}
