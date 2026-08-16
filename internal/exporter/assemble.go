package exporter

import "encoding/json"

// One cycle's replies turned into one Snapshot. A parser that fails is recorded
// against its endpoint like a failed request, and what it could still decode is
// kept: a partial snapshot beats none.

// source is one endpoint the poller reads each cycle.
type source struct {
	Path      string
	Operation string
}

// Named because some feed more than one parser and a typo would silently drop
// a section.
const (
	srcClients     = "admin/smart_network?form=game_accelerator"
	srcClientTimes = "admin/traffic?form=dev_name"
	srcLeases      = "admin/dhcps?form=client"
	srcReservation = "admin/dhcps?form=reservation"
	srcDHCP        = "admin/dhcps?form=setting"
	srcStatusAll   = "admin/status?form=all"
	srcPorts       = "admin/status?form=router"
	srcInternet    = "admin/status?form=internet"
	srcWANSpeed    = "admin/status?form=wan_speed"
	srcTunnels     = "admin/vpn?form=server"
	srcVPNUsers    = "admin/vpn?form=vpn_user_list"
	srcVPNServer   = "admin/vpn?form=enable"
	srcFirmware    = "admin/firmware?form=upgrade"
	srcClock       = "admin/time?form=settings"
	srcRemote      = "admin/administration?form=remote"
	srcUPnPEnable  = "admin/upnp?form=enable"
	srcUPnPService = "admin/upnp?form=service"
	srcNATvs       = "admin/nat?form=vs"
	srcNATpt       = "admin/nat?form=pt"
	srcDMZ         = "admin/nat?form=dmz"
	srcFirewall    = "admin/security_settings?form=new_enable"
	srcARP         = "admin/imb?form=arp_list"
	srcMesh        = "admin/easymesh_network?form=get_mesh_device_list_all"
)

// sources is the poll set: 23 requests per cycle, which must fit inside
// Interval with room to spare.
var sources = []source{
	{srcClients, "loadDevice"},
	{srcClientTimes, "read"},
	{srcLeases, "load"},
	{srcReservation, "load"},
	{srcDHCP, "read"},
	{srcStatusAll, "read"},
	{srcPorts, "read"},
	{srcInternet, "read"},
	{srcWANSpeed, "read"},
	{srcTunnels, "load"},
	{srcVPNUsers, "load"},
	{srcVPNServer, "read"},
	{srcFirmware, "read"},
	{srcClock, "read"},
	{srcRemote, "read"},
	{srcUPnPEnable, "read"},
	{srcUPnPService, "load"},
	{srcNATvs, "load"},
	{srcNATpt, "load"},
	{srcDMZ, "read"},
	{srcFirewall, "read"},
	{srcARP, "load"},
	{srcMesh, "read"},
}

// securitySources are the replies parseSecurity folds together.
var securitySources = []string{
	srcRemote, srcUPnPEnable, srcUPnPService, srcNATvs, srcNATpt, srcDMZ, srcFirewall,
}

// assemble turns the replies into one Snapshot. A parser that fails is recorded
// against its endpoint like a failed request; Errors has one slot per path and
// status?form=all feeds four parsers, so the first failure over a reply wins.
func assemble(snap *Snapshot, replies map[string]json.RawMessage) {
	fill(snap, replies, srcClients, parseClients, func(v []Client) { snap.Clients = v })
	fill(snap, replies, srcClientTimes, parseClientTimes, func(v map[string]ClientTimes) {
		snap.Clients = mergeClientTimes(snap.Clients, v)
	})
	fill(snap, replies, srcLeases, parseLeases, func(v []Lease) { snap.Leases = v })
	fill(snap, replies, srcReservation, parseReservations, func(v []Reservation) { snap.Reservations = v })
	fill(snap, replies, srcDHCP, parseDHCPSetting, func(v *DHCPSetting) { snap.DHCP = v })
	fill(snap, replies, srcPorts, parsePorts, func(v []Port) { snap.Ports = v })
	fill(snap, replies, srcStatusAll, parsePerf, func(v *Perf) { snap.Perf = v })
	fill(snap, replies, srcStatusAll, parseWireless, func(v map[string]Radio) { snap.Wireless = v })
	fill(snap, replies, srcFirmware, parseFirmware, func(v *Firmware) { snap.Firmware = v })
	fill(snap, replies, srcClock, parseRouterClock, func(v *RouterClock) { snap.Router = v })
	fill(snap, replies, srcTunnels, parseTunnels, func(v []Tunnel) { snap.Tunnels = v })
	fill(snap, replies, srcVPNServer, parseVPNServer, func(v *VPNServer) { snap.VPNServer = v })
	fill(snap, replies, srcVPNUsers, parseVPNUsers, func(v []VPNUser) { snap.VPNUsers = v })
	fill(snap, replies, srcARP, parseARP, func(v []ARPEntry) { snap.ARP = v })
	fill(snap, replies, srcMesh, parseMeshNodes, func(v []MeshNode) { snap.Mesh = v })

	assembleWAN(snap, replies)
	assembleSecurity(snap, replies)
}

// assembleWAN builds one WAN out of three replies; whichever answered fills its
// own fields.
func assembleWAN(snap *Snapshot, replies map[string]json.RawMessage) {
	wan := &WAN{}
	if raw, ok := replies[srcStatusAll]; ok {
		uptime, err := parseWANUptime(raw)
		if err != nil {
			snapError(snap, srcStatusAll, err)
		} else {
			wan.HaveUptime, wan.Uptime = true, uptime
		}
	}
	if raw, ok := replies[srcInternet]; ok {
		up, link, state, err := parseInternet(raw)
		if err != nil {
			snapError(snap, srcInternet, err)
		} else {
			wan.HaveStatus, wan.InternetUp, wan.LinkUp, wan.State = true, up, link, state
		}
	}
	if raw, ok := replies[srcWANSpeed]; ok {
		down, up, at, err := parseWANSpeed(raw)
		if err != nil {
			snapError(snap, srcWANSpeed, err)
		} else {
			wan.HaveSpeed = true
			wan.DownBytesPerS, wan.UpBytesPerS, wan.SpeedTakenAt = down, up, at
		}
	}
	if wan.HaveUptime || wan.HaveStatus || wan.HaveSpeed {
		snap.WAN = wan
	}
}

func assembleSecurity(snap *Snapshot, replies map[string]json.RawMessage) {
	src := SecuritySources{}
	for _, path := range securitySources {
		if raw, ok := replies[path]; ok {
			src[path] = raw
		}
	}
	guest, guestOK := replies[srcStatusAll]
	if len(src) == 0 && !guestOK {
		return
	}

	sec, errs := parseSecurity(src)
	for path, err := range errs {
		snapError(snap, path, err)
	}
	if guestOK {
		bands, err := parseGuestNetworks(guest)
		if err != nil {
			snapError(snap, srcStatusAll, err)
		} else {
			sec.GuestNetworks = bands
		}
		iot, err := parseIoTNetworks(guest)
		if err != nil {
			snapError(snap, srcStatusAll, err)
		} else {
			sec.IoTNetworks = iot
		}
	}
	snap.Security = sec
}

func fill[T any](snap *Snapshot, replies map[string]json.RawMessage, path string,
	parse func(json.RawMessage) (T, error), set func(T)) {
	raw, ok := replies[path]
	if !ok {
		return
	}
	v, err := parse(raw)
	if err != nil {
		snapError(snap, path, err)
	}
	// A parser that skipped a row still returns the rest.
	set(v)
}

func snapError(snap *Snapshot, path string, err error) {
	if _, exists := snap.Errors[path]; !exists {
		snap.Errors[path] = err
	}
}
