// Package exporter turns router replies into Prometheus metrics.
//
// A Snapshot is one poll cycle's worth of data. Sections are pointers or nil
// slices because a cycle is expected to be partial: one endpoint failing must
// not discard the rest, so anything absent is nil and Errors says why.
package exporter

import "time"

type Snapshot struct {
	TakenAt time.Time

	Firmware *Firmware
	WAN      *WAN
	Perf     *Perf
	Ports    []Port
	Router   *RouterClock
	Wireless map[string]Radio
	Mesh     []MeshNode

	Clients []Client

	Leases       []Lease
	Reservations []Reservation
	DHCP         *DHCPSetting

	Tunnels   []Tunnel
	VPNServer *VPNServer
	VPNUsers  []VPNUser

	Security *Security
	ARP      []ARPEntry

	// Errors is keyed by "path?form=x" and records endpoints that did not
	// answer this cycle. The poller adds them to State.EndpointErrors, which is
	// what tplink_scrape_errors_total serves.
	Errors map[string]error
}

type Firmware struct {
	Version  string
	Hardware string
	Model    string
}

// WAN is built from three replies and any of them can be missing. The Have
// flags say which arrived: a zero InternetUp from an endpoint that never
// answered would read as "the internet is down", which is the alert this
// exporter exists to raise.
type WAN struct {
	HaveUptime bool
	Uptime     time.Duration // wan_ipv4_uptime, resets on reconnect

	HaveStatus bool
	InternetUp bool // status?form=internet, internet_status
	LinkUp     bool // wan_internet_status
	// State is internet_status lowercased: connected, poor_connected,
	// connecting, disconnected or unplugged. InternetUp collapses those five.
	State string

	HaveSpeed     bool
	DownBytesPerS float64 // status?form=wan_speed
	UpBytesPerS   float64
	SpeedTakenAt  time.Time // test_time, the router's own stamp on the sample
}

// Perf values are ratios in 0..1; the UI multiplies by 100 to display.
type Perf struct {
	CPU    float64
	Cores  []float64 // cpu1_usage..cpuN_usage; length is discovered, not fixed
	Memory float64
}

type Port struct {
	Name       string // "wanlan1g", "lan1"
	Up         bool   // status == "connected"
	SpeedMbits int    // 0 when down: the firmware sends "" there, not 0
	Duplex     string // "FULL", "" when down
	IsWAN      bool   // absent on LAN ports
}

// Radio is one Wi-Fi band, keyed "2g" or "5g" in Snapshot.Wireless. A nil field
// is one the reply did not carry: a zero Enabled would read as "radio off".
type Radio struct {
	Enabled *bool  // wireless_Xg_enable
	Channel *int   // wireless_Xg_current_channel, a number even where the setting says "auto"
	TxPower string // "high", "middle", "low"
}

// MeshNode is one EasyMesh device. The router counts as one, with Role
// "main_router", so a mesh with no satellites still lists it.
type MeshNode struct {
	MAC     string
	Name    string
	Model   string
	Role    string // "main_router"
	Up      bool   // status == "connected"
	Clients int    // client_num
}

// RouterClock is the router's own wall clock. Timezone is a TP-Link index
// ("74"), not a UTC offset, so it cannot be resolved to a location: the wall
// clock is read in the exporter's own location and published as it stands.
type RouterClock struct {
	Wall     time.Time // parsed from date + time, in the exporter's location
	Timezone string
}

// Client is assembled from two endpoints: parseClients fills everything from
// game_accelerator, mergeClientTimes adds the rest from traffic?form=dev_name.
type Client struct {
	MAC      string // normalised, lowercase colons
	IP       string
	Hostname string
	Iface    string // deviceTag: "wired", "2.4G", "5G"
	Type     string // deviceType: Computer, Mobile, Tablet, IoT Devices, Other
	Guest    bool

	TrafficBytes  uint64  // cumulative, resets on reboot -> counter
	DownBytesPerS float64 // instantaneous
	UpBytesPerS   float64
	Session       time.Duration // onlineTime, current session only

	// From traffic?form=dev_name. access_time is absolute; the access_uptime
	// beside it is the router's own uptime at that moment, not time online —
	// access_time minus access_uptime is the same boot instant for every
	// client, so it is not carried here.
	ConnectedAt time.Time
	Via         string // connect_device_mac, normalised: which mesh node
}

// Lease is a DHCP lease. Permanent means there is no expiry, which is not the
// same as being reserved — see Reservation.
type Lease struct {
	MAC       string
	IP        string
	Hostname  string
	Remaining time.Duration
	Permanent bool
}

type Reservation struct {
	MAC      string
	IP       string
	Hostname string
	Enabled  bool
}

type DHCPSetting struct {
	Enabled    bool
	LeaseTime  time.Duration // "120" in the reply, minutes
	RangeStart string
	RangeEnd   string
	Gateway    string
}

// Tunnel is an outbound VPN connection of the router itself.
type Tunnel struct {
	Name          string // des, e.g. "NordVPN"
	Vendor        string
	Type          string // "wireguard"
	Endpoint      string
	Up            bool // status == "connected"
	DownBytesPerS float64
	UpBytesPerS   float64
}

type VPNServer struct {
	Enabled bool
	Type    string
}

// VPNUser is an account on the router's VPN server. Access is permission, not
// an active session; the firmware does not report who is connected.
type VPNUser struct {
	MAC        string
	Name       string
	ClientType string
	Access     bool
}

// A nil field is an endpoint that did not answer. These are the flags an
// incident alert fires on, so "no reply" must not arrive as "off".
type Security struct {
	RemoteManagement *bool
	UPnPEnabled      *bool
	UPnPMappings     *int
	DMZ              *bool
	LANPing          *bool
	WANPing          *bool

	PortForwards map[string]int // "vs" and "pt" rule counts, keyed only when read

	// GuestNetworks and IoTNetworks are keyed by band ("2g", "5g") and come
	// from status?form=all, not from the security endpoints. Both are SSIDs
	// that let a stranger onto the network if they come up unasked.
	GuestNetworks map[string]bool
	IoTNetworks   map[string]bool
}

// ARPEntry comes from imb?form=arp_list, which is wider than the client list —
// it keeps stale addresses, so it is the source for "a MAC never seen before".
type ARPEntry struct {
	MAC  string
	IP   string
	Name string
}
