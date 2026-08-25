package exporter

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// The collector never talks to the router: a scrape reads the poller's last
// State out of memory.
//
// Descriptor names and labels are the contract: a rename breaks dashboards and
// alerts that outlive this code.

var (
	descBuildInfo        = prometheus.NewDesc("tplink_exporter_build_info", "The build this exporter is running; the value is always 1.", []string{"version", "revision", "go_version"}, nil)
	descUp               = prometheus.NewDesc("tplink_up", "1 when the last poll reached the router.", nil, nil)
	descSessionBlocked   = prometheus.NewDesc("tplink_session_blocked", "1 when the router's single web session is held by someone else.", nil, nil)
	descScrapeDuration   = prometheus.NewDesc("tplink_scrape_duration_seconds", "Duration of the last poll cycle.", nil, nil)
	descScrapeErrors     = prometheus.NewDesc("tplink_scrape_errors_total", "Endpoint failures since start, by endpoint.", []string{"endpoint"}, nil)
	descLogins           = prometheus.NewDesc("tplink_login_total", "Successful logins since start.", nil, nil)
	descLoginFailures    = prometheus.NewDesc("tplink_login_failed_total", "Failed logins since start, session conflicts included.", nil, nil)
	descSessionsLost     = prometheus.NewDesc("tplink_session_lost_total", "Sessions the exporter concluded it had lost, since start. Someone opening the web UI is the usual cause; a reboot or an upgrade reads the same.", nil, nil)
	descLoginsSuppressed = prometheus.NewDesc("tplink_login_suppressed_total", "Logins not attempted since start, either during the cooldown after losing the session or against the hourly cap.", nil, nil)
	descSnapshotTime     = prometheus.NewDesc("tplink_snapshot_timestamp_seconds", "Unix time of the snapshot being served; its age is time() minus this.", nil, nil)
	descFailedSources    = prometheus.NewDesc("tplink_endpoints_failed", "Endpoints that did not answer in the cycle behind the snapshot being served.", nil, nil)

	descFirmware      = prometheus.NewDesc("tplink_firmware_info", "Firmware the router reports about itself.", []string{"version", "hardware", "model"}, nil)
	descWANUptime     = prometheus.NewDesc("tplink_wan_uptime_seconds", "Seconds the WAN link has been up; resets on reconnect.", nil, nil)
	descWANStatus     = prometheus.NewDesc("tplink_wan_status", "1 when connected. iface=\"internet\" is reachability, iface=\"link\" the physical WAN port.", []string{"iface"}, nil)
	descWANStatusInfo = prometheus.NewDesc("tplink_wan_status_info", "The raw internet_status, which tplink_wan_status collapses to 0/1.", []string{"state"}, nil)
	descWANSpeed      = prometheus.NewDesc("tplink_wan_speed_bytes", "Current WAN throughput in bytes per second.", []string{"dir"}, nil)
	descWANSpeedAt    = prometheus.NewDesc("tplink_wan_speed_timestamp_seconds", "Unix time the router stamped on its throughput sample.", nil, nil)

	descCPU         = prometheus.NewDesc("tplink_cpu_usage_ratio", "CPU load as a ratio in 0..1; the UI shows it multiplied by 100.", nil, nil)
	descCPUCore     = prometheus.NewDesc("tplink_cpu_core_usage_ratio", "Per-core CPU load as a ratio in 0..1.", []string{"core"}, nil)
	descCPUCores    = prometheus.NewDesc("tplink_cpu_cores", "Cores found by probing cpuN_usage; varies by model.", nil, nil)
	descMemory      = prometheus.NewDesc("tplink_memory_usage_ratio", "Memory in use as a ratio in 0..1.", nil, nil)
	descRouterClock = prometheus.NewDesc("tplink_router_clock_timestamp_seconds", "Unix time from the router's own clock, read in the exporter's location. The firmware reports a TP-Link timezone index rather than an offset, so both must run the same zone for time() minus this to mean drift.", nil, nil)

	descRouterClockInfo = prometheus.NewDesc("tplink_router_clock_info", "The router's timezone as a TP-Link index, which is not an offset and cannot be resolved to a location.", []string{"timezone"}, nil)

	descPortLink  = prometheus.NewDesc("tplink_port_link", "1 when the port has a link.", []string{"port", "is_wan"}, nil)
	descPortSpeed = prometheus.NewDesc("tplink_port_speed_mbits", "Negotiated port speed in Mbit/s; 0 on a dark port. Duplex is not a label here: it empties when the link drops, and the series has to fall to zero rather than be replaced.", []string{"port", "is_wan"}, nil)
	descPortInfo  = prometheus.NewDesc("tplink_port_info", "One series per port, carrying the duplex mode.", []string{"port", "duplex", "is_wan"}, nil)

	descWiFiRadio   = prometheus.NewDesc("tplink_wifi_radio_enabled", "1 when the radio on that band is on.", []string{"band"}, nil)
	descWiFiChannel = prometheus.NewDesc("tplink_wifi_channel", "Channel the band is actually using, resolved even when the setting is auto.", []string{"band"}, nil)
	descWiFiTxPower = prometheus.NewDesc("tplink_wifi_txpower_info", "Transmit power level of the band: high, middle or low.", []string{"band", "level"}, nil)

	descClientInfo     = prometheus.NewDesc("tplink_client_info", "One series per client. Everything that churns lives here, so numeric metrics keep a single mac label.", []string{"mac", "ip", "hostname", "iface", "type", "guest", "via"}, nil)
	descClientTraffic  = prometheus.NewDesc("tplink_client_traffic_bytes_total", "Bytes the client has moved; resets when the router reboots.", []string{"mac"}, nil)
	descClientSpeed    = prometheus.NewDesc("tplink_client_speed_bytes", "Current client throughput in bytes per second.", []string{"mac", "dir"}, nil)
	descClientSession  = prometheus.NewDesc("tplink_client_session_seconds", "Length of the current session; restarts on reconnect.", []string{"mac"}, nil)
	descClientSince    = prometheus.NewDesc("tplink_client_connected_since_seconds", "Unix time the current session began.", []string{"mac"}, nil)
	descClientsByIface = prometheus.NewDesc("tplink_clients", "Clients currently online, by connection type.", []string{"iface"}, nil)

	descLeaseExpiry    = prometheus.NewDesc("tplink_dhcp_lease_expiry_seconds", "Unix time the lease runs out. Absent for a permanent lease: a far-future stand-in would break sorting by soonest.", []string{"mac", "ip", "hostname"}, nil)
	descLeasePermanent = prometheus.NewDesc("tplink_dhcp_lease_permanent", "1 when the lease never expires. Not the same as being reserved.", []string{"mac", "ip", "hostname"}, nil)
	descReservation    = prometheus.NewDesc("tplink_dhcp_reservation", "1 when the address is reserved for this MAC.", []string{"mac", "ip", "hostname"}, nil)
	descPoolLease      = prometheus.NewDesc("tplink_dhcp_pool_lease_seconds", "Lease length configured for the pool; individual leases can differ.", nil, nil)

	descTunnelInfo    = prometheus.NewDesc("tplink_vpn_tunnel_info", "One series per outbound VPN tunnel of the router.", []string{"name", "vendor", "type", "endpoint"}, nil)
	descTunnelUp      = prometheus.NewDesc("tplink_vpn_tunnel_up", "1 when the tunnel is connected.", []string{"name"}, nil)
	descTunnelSpeed   = prometheus.NewDesc("tplink_vpn_tunnel_speed_bytes", "Current tunnel throughput in bytes per second; the firmware keeps no byte counter.", []string{"name", "dir"}, nil)
	descVPNServer     = prometheus.NewDesc("tplink_vpn_server_enabled", "1 when the router's own VPN server is on.", nil, nil)
	descVPNUserAccess = prometheus.NewDesc("tplink_vpn_user_access", "1 when the user may use the VPN server. Permission, not an active session — the firmware does not report who is connected.", []string{"mac", "name", "client_type"}, nil)

	descRemoteMgmt   = prometheus.NewDesc("tplink_remote_management_enabled", "1 when the router accepts management from the WAN side.", nil, nil)
	descUPnPEnabled  = prometheus.NewDesc("tplink_upnp_enabled", "1 when UPnP is on.", nil, nil)
	descUPnPMappings = prometheus.NewDesc("tplink_upnp_mappings", "Port mappings devices have opened through UPnP.", nil, nil)
	descPortForwards = prometheus.NewDesc("tplink_port_forward_rules", "Forwarding rules configured, by kind: vs is virtual servers, pt is port triggering.", []string{"kind"}, nil)
	descDMZ          = prometheus.NewDesc("tplink_dmz_enabled", "1 when a host is exposed to the WAN through the DMZ.", nil, nil)
	descGuestNetwork = prometheus.NewDesc("tplink_guest_network_enabled", "1 when the guest SSID on that band is up.", []string{"band"}, nil)
	descIoTNetwork   = prometheus.NewDesc("tplink_iot_network_enabled", "1 when the IoT SSID on that band is up. A separate pair the router keeps for smart-home devices.", []string{"band"}, nil)
	descFirewallPing = prometheus.NewDesc("tplink_firewall_ping_allowed", "1 when the router answers ICMP echo from that side.", []string{"source"}, nil)

	descARPEntry = prometheus.NewDesc("tplink_arp_entry_info", "One series per ARP entry. Wider than the client list — stale addresses stay, which is what makes it the source for an unknown MAC.", []string{"mac", "ip", "name"}, nil)

	descMeshInfo    = prometheus.NewDesc("tplink_mesh_node_info", "One series per EasyMesh node.", []string{"mac", "name", "role", "model"}, nil)
	descMeshUp      = prometheus.NewDesc("tplink_mesh_node_up", "1 when the node is connected.", []string{"mac"}, nil)
	descMeshClients = prometheus.NewDesc("tplink_mesh_node_clients", "Clients attached to that node.", []string{"mac"}, nil)
)

// descriptors is every Desc Collect can emit; Describe announces exactly these.
var descriptors = []*prometheus.Desc{
	descBuildInfo, descUp, descSessionBlocked, descScrapeDuration, descScrapeErrors,
	descLogins, descLoginFailures, descSessionsLost, descLoginsSuppressed,
	descSnapshotTime, descFailedSources,
	descFirmware, descWANUptime, descWANStatus, descWANStatusInfo, descWANSpeed, descWANSpeedAt,
	descCPU, descCPUCore, descCPUCores, descMemory, descRouterClock, descRouterClockInfo,
	descPortLink, descPortSpeed, descPortInfo,
	descWiFiRadio, descWiFiChannel, descWiFiTxPower,
	descClientInfo, descClientTraffic, descClientSpeed, descClientSession,
	descClientSince, descClientsByIface,
	descLeaseExpiry, descLeasePermanent, descReservation, descPoolLease,
	descTunnelInfo, descTunnelUp, descTunnelSpeed, descVPNServer, descVPNUserAccess,
	descRemoteMgmt, descUPnPEnabled, descUPnPMappings, descPortForwards, descDMZ,
	descGuestNetwork, descIoTNetwork, descFirewallPing,
	descARPEntry,
	descMeshInfo, descMeshUp, descMeshClients,
}

// StateSource is what the collector needs; the poller satisfies it.
type StateSource interface {
	State() State
}

// Collector serves the poller's last snapshot as metrics.
type Collector struct {
	src    StateSource
	maxAge time.Duration
	build  BuildInfo
}

// NewCollector returns a Collector that reads src once per scrape. Past maxAge
// a snapshot stops being served and only the exporter's own health remains, so
// a frozen reading cannot be mistaken for a current one; zero means no limit.
// build is normalized here, so a zero BuildInfo still names a build rather than
// publishing empty labels.
func NewCollector(src StateSource, maxAge time.Duration, build BuildInfo) *Collector {
	return &Collector{src: src, maxAge: maxAge, build: build.normalized()}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range descriptors {
		ch <- d
	}
}

// Collect implements prometheus.Collector. One State per scrape, so a metric
// cannot disagree with the one beside it.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	st := c.src.State()
	collectHealth(ch, st, c.build)
	snap := st.Snapshot
	if snap == nil {
		return
	}
	gauge(ch, descSnapshotTime, float64(snap.TakenAt.Unix()))
	if c.maxAge > 0 && time.Since(snap.TakenAt) > c.maxAge {
		return
	}
	gauge(ch, descFailedSources, float64(len(snap.Errors)))

	collectRouter(ch, snap)
	collectClients(ch, snap)
	collectDHCP(ch, snap)
	collectVPN(ch, snap)
	collectSecurity(ch, snap)

	collectNeighbours(ch, snap)
}

func collectNeighbours(ch chan<- prometheus.Metric, snap *Snapshot) {
	for _, e := range snap.ARP {
		gauge(ch, descARPEntry, 1, e.MAC, e.IP, e.Name)
	}
	for _, n := range snap.Mesh {
		gauge(ch, descMeshInfo, 1, n.MAC, n.Name, n.Role, n.Model)
		gauge(ch, descMeshUp, b2f(n.Up), n.MAC)
		gauge(ch, descMeshClients, float64(n.Clients), n.MAC)
	}
}

func collectHealth(ch chan<- prometheus.Metric, st State, b BuildInfo) {
	// Collect returns early on a missing snapshot and on a stale one, both after
	// this call, so the build outlives the readings.
	gauge(ch, descBuildInfo, 1, b.Version, b.Revision, b.GoVersion)
	gauge(ch, descUp, b2f(st.Up))
	gauge(ch, descSessionBlocked, b2f(st.SessionBlocked))
	gauge(ch, descScrapeDuration, st.PollDuration.Seconds())
	counter(ch, descLogins, float64(st.Logins))
	counter(ch, descLoginFailures, float64(st.LoginFailures))
	counter(ch, descSessionsLost, float64(st.SessionsLost))
	counter(ch, descLoginsSuppressed, float64(st.LoginsSuppressed))
	for endpoint, n := range st.EndpointErrors {
		counter(ch, descScrapeErrors, float64(n), endpoint)
	}
}

func collectRouter(ch chan<- prometheus.Metric, snap *Snapshot) {
	if f := snap.Firmware; f != nil {
		gauge(ch, descFirmware, 1, f.Version, f.Hardware, f.Model)
	}
	if w := snap.WAN; w != nil {
		if w.HaveUptime {
			gauge(ch, descWANUptime, w.Uptime.Seconds())
		}
		if w.HaveStatus {
			gauge(ch, descWANStatus, b2f(w.InternetUp), "internet")
			gauge(ch, descWANStatus, b2f(w.LinkUp), "link")
			if w.State != "" {
				gauge(ch, descWANStatusInfo, 1, w.State)
			}
		}
		if w.HaveSpeed {
			gauge(ch, descWANSpeed, w.DownBytesPerS, "rx")
			gauge(ch, descWANSpeed, w.UpBytesPerS, "tx")
			if !w.SpeedTakenAt.IsZero() {
				gauge(ch, descWANSpeedAt, float64(w.SpeedTakenAt.Unix()))
			}
		}
	}
	if p := snap.Perf; p != nil {
		gauge(ch, descCPU, p.CPU)
		gauge(ch, descMemory, p.Memory)
		gauge(ch, descCPUCores, float64(len(p.Cores)))
		for i, v := range p.Cores {
			gauge(ch, descCPUCore, v, strconv.Itoa(i+1))
		}
	}
	if r := snap.Router; r != nil {
		gauge(ch, descRouterClock, float64(r.Wall.Unix()))
		if r.Timezone != "" {
			gauge(ch, descRouterClockInfo, 1, r.Timezone)
		}
	}
	for _, p := range snap.Ports {
		isWAN := strconv.FormatBool(p.IsWAN)
		gauge(ch, descPortLink, b2f(p.Up), p.Name, isWAN)
		gauge(ch, descPortSpeed, float64(p.SpeedMbits), p.Name, isWAN)
		gauge(ch, descPortInfo, 1, p.Name, p.Duplex, isWAN)
	}
	for band, radio := range snap.Wireless {
		flag(ch, descWiFiRadio, radio.Enabled, band)
		if radio.Channel != nil {
			gauge(ch, descWiFiChannel, float64(*radio.Channel), band)
		}
		if radio.TxPower != "" {
			gauge(ch, descWiFiTxPower, 1, band, radio.TxPower)
		}
	}
}

func collectClients(ch chan<- prometheus.Metric, snap *Snapshot) {
	byIface := map[string]int{}
	for _, c := range snap.Clients {
		byIface[c.Iface]++
		gauge(ch, descClientInfo, 1, c.MAC, c.IP, c.Hostname, c.Iface, c.Type,
			strconv.FormatBool(c.Guest), c.Via)
		counter(ch, descClientTraffic, float64(c.TrafficBytes), c.MAC)
		gauge(ch, descClientSpeed, c.DownBytesPerS, c.MAC, "rx")
		gauge(ch, descClientSpeed, c.UpBytesPerS, c.MAC, "tx")
		gauge(ch, descClientSession, c.Session.Seconds(), c.MAC)
		// A client the other endpoint has not reported yet keeps a zero time,
		// and zero is not a stamp.
		if !c.ConnectedAt.IsZero() {
			gauge(ch, descClientSince, float64(c.ConnectedAt.Unix()), c.MAC)
		}
	}
	for iface, n := range byIface {
		gauge(ch, descClientsByIface, float64(n), iface)
	}
}

func collectDHCP(ch chan<- prometheus.Metric, snap *Snapshot) {
	for _, l := range snap.Leases {
		gauge(ch, descLeasePermanent, b2f(l.Permanent), l.MAC, l.IP, l.Hostname)
		if !l.Permanent {
			gauge(ch, descLeaseExpiry, float64(snap.TakenAt.Add(l.Remaining).Unix()),
				l.MAC, l.IP, l.Hostname)
		}
	}
	for _, r := range snap.Reservations {
		gauge(ch, descReservation, b2f(r.Enabled), r.MAC, r.IP, r.Hostname)
	}
	if d := snap.DHCP; d != nil {
		gauge(ch, descPoolLease, d.LeaseTime.Seconds())
	}
}

func collectVPN(ch chan<- prometheus.Metric, snap *Snapshot) {
	for _, t := range snap.Tunnels {
		gauge(ch, descTunnelInfo, 1, t.Name, t.Vendor, t.Type, t.Endpoint)
		gauge(ch, descTunnelUp, b2f(t.Up), t.Name)
		gauge(ch, descTunnelSpeed, t.DownBytesPerS, t.Name, "rx")
		gauge(ch, descTunnelSpeed, t.UpBytesPerS, t.Name, "tx")
	}
	if s := snap.VPNServer; s != nil {
		gauge(ch, descVPNServer, b2f(s.Enabled))
	}
	for _, u := range snap.VPNUsers {
		gauge(ch, descVPNUserAccess, b2f(u.Access), u.MAC, u.Name, u.ClientType)
	}
}

func collectSecurity(ch chan<- prometheus.Metric, snap *Snapshot) {
	s := snap.Security
	if s == nil {
		return
	}
	// A nil flag is an endpoint that did not answer. Publishing 0 there would
	// report "remote management is off" for a reading nobody took.
	flag(ch, descRemoteMgmt, s.RemoteManagement)
	flag(ch, descUPnPEnabled, s.UPnPEnabled)
	flag(ch, descDMZ, s.DMZ)
	flag(ch, descFirewallPing, s.LANPing, "lan")
	flag(ch, descFirewallPing, s.WANPing, "wan")
	if s.UPnPMappings != nil {
		gauge(ch, descUPnPMappings, float64(*s.UPnPMappings))
	}
	for kind, n := range s.PortForwards {
		gauge(ch, descPortForwards, float64(n), kind)
	}
	for band, on := range s.GuestNetworks {
		gauge(ch, descGuestNetwork, b2f(on), band)
	}
	for band, on := range s.IoTNetworks {
		gauge(ch, descIoTNetwork, b2f(on), band)
	}
}

// flag publishes a reading the router gave, and nothing at all for one it did not.
func flag(ch chan<- prometheus.Metric, d *prometheus.Desc, v *bool, labels ...string) {
	if v != nil {
		gauge(ch, d, b2f(*v), labels...)
	}
}

func gauge(ch chan<- prometheus.Metric, d *prometheus.Desc, v float64, labels ...string) {
	ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...)
}

func counter(ch chan<- prometheus.Metric, d *prometheus.Desc, v float64, labels ...string) {
	ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, v, labels...)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
