package exporter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/akentyev/tplink_archer_exporter/internal/tpapi"
)

// Parsers are pure: raw reply in, typed value out, no I/O. They take exactly
// what sits in internal/tpapi/testdata, so tests need no router.
//
// Every parser receives what tpapi.Call returned: decrypted, redacted and
// unwrapped from the envelope — the contents of "data".

// decodeList decodes each row on its own, so one malformed entry costs that
// entry and not the endpoint. Callers return what parsed along with the error.
func decodeList[T any](raw json.RawMessage) ([]T, error) {
	rows, err := listRows(raw)
	if err != nil {
		return nil, err
	}
	out := make([]T, 0, len(rows))
	var errs []error
	for i, row := range rows {
		var v T
		if err := json.Unmarshal(row, &v); err != nil {
			errs = append(errs, fmt.Errorf("row %d: %w", i, err))
			continue
		}
		out = append(out, v)
	}
	return out, errors.Join(errs...)
}

// A list endpoint answers with an array when it holds entries and with the
// object {} when it holds none, never with []. The router's own UI runs every
// list through assertArray for that reason.
func listRows(raw json.RawMessage) ([]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return nil, err
		}
		if len(obj) > 0 {
			return nil, fmt.Errorf("expected a list, got an object with %d keys", len(obj))
		}
		return nil, nil
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(trimmed, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// wrap names the endpoint an error came from, and keeps nil nil.
func wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", what, err)
}

// seconds keeps the fractions the firmware sends: onlineTime arrives as
// 512845.6, not as an integer.
func seconds(v float64) time.Duration {
	return time.Duration(v * float64(time.Second))
}

// parseClients reads smart_network?form=game_accelerator with loadDevice.
// MACs must go through tpapi.NormalizeMAC. Speeds and trafficUsage are bytes.
func parseClients(raw json.RawMessage) ([]Client, error) {
	type wire struct {
		DeviceName string  `json:"deviceName"`
		DeviceTag  string  `json:"deviceTag"`
		DeviceType string  `json:"deviceType"`
		IP         string  `json:"ip"`
		MAC        string  `json:"mac"`
		IsGuest    bool    `json:"isGuest"`
		Download   float64 `json:"downloadSpeed"`
		Upload     float64 `json:"uploadSpeed"`
		Traffic    float64 `json:"trafficUsage"`
		OnlineTime float64 `json:"onlineTime"`
	}
	in, err := decodeList[wire](raw)
	errs := []error{err}
	out := make([]Client, 0, len(in))
	// The MAC is the join key for every other endpoint and the only label on
	// the numeric metrics, so a repeat would collide rather than add.
	seen := make(map[string]bool, len(in))
	for _, w := range in {
		mac := tpapi.NormalizeMAC(w.MAC)
		if seen[mac] {
			errs = append(errs, fmt.Errorf("duplicate MAC %s, keeping the first", mac))
			continue
		}
		seen[mac] = true
		out = append(out, Client{
			MAC:           mac,
			IP:            w.IP,
			Hostname:      w.DeviceName,
			Iface:         w.DeviceTag,
			Type:          w.DeviceType,
			Guest:         w.IsGuest,
			TrafficBytes:  uint64(max(0, w.Traffic)),
			DownBytesPerS: w.Download,
			UpBytesPerS:   w.Upload,
			Session:       seconds(w.OnlineTime),
		})
	}
	return out, wrap("game_accelerator", errors.Join(errs...))
}

// parseClientTimes reads traffic?form=dev_name, keyed by normalised MAC.
// access_time is an absolute unix stamp.
//
// The access_uptime beside it is not time online: access_time minus
// access_uptime is the same instant for every client on the device — the
// router's boot epoch, which wan_ipv4_uptime confirms — so access_uptime is
// the router's uptime when that client connected, and it is not read here.
func parseClientTimes(raw json.RawMessage) (map[string]ClientTimes, error) {
	type wire struct {
		MAC        string `json:"mac"`
		AccessTime int64  `json:"access_time"`
		Via        string `json:"connect_device_mac"`
	}
	in, err := decodeList[wire](raw)
	out := make(map[string]ClientTimes, len(in))
	for _, w := range in {
		t := ClientTimes{Via: tpapi.NormalizeMAC(w.Via)}
		if w.AccessTime > 0 {
			t.ConnectedAt = time.Unix(w.AccessTime, 0)
		}
		out[tpapi.NormalizeMAC(w.MAC)] = t
	}
	return out, wrap("dev_name", err)
}

// ClientTimes is the half of Client that traffic?form=dev_name contributes.
type ClientTimes struct {
	ConnectedAt time.Time
	Via         string
}

// mergeClientTimes fills the time fields on clients. Clients with no matching
// entry keep zero times rather than being dropped; the two endpoints are polled
// separately and may disagree for a cycle.
func mergeClientTimes(clients []Client, times map[string]ClientTimes) []Client {
	for i := range clients {
		t, ok := times[clients[i].MAC]
		if !ok {
			continue
		}
		clients[i].ConnectedAt = t.ConnectedAt
		clients[i].Via = t.Via
	}
	return clients
}

// parseLeases reads dhcps?form=client. Fields are macaddr/ipaddr/name, not the
// mac/ip/hostname that dhcps?form=reservation uses.
func parseLeases(raw json.RawMessage) ([]Lease, error) {
	type wire struct {
		MAC       string `json:"macaddr"`
		IP        string `json:"ipaddr"`
		Name      string `json:"name"`
		LeaseTime string `json:"leasetime"`
	}
	in, err := decodeList[wire](raw)
	errs := []error{err}
	out := make([]Lease, 0, len(in))
	for _, w := range in {
		d, permanent, err := parseLeaseRemaining(w.LeaseTime)
		if err != nil {
			errs = append(errs, fmt.Errorf("lease for %s: %w", w.MAC, err))
			continue
		}
		out = append(out, Lease{
			MAC:       tpapi.NormalizeMAC(w.MAC),
			IP:        w.IP,
			Hostname:  w.Name,
			Remaining: d,
			Permanent: permanent,
		})
	}
	return out, wrap("dhcps client", errors.Join(errs...))
}

// parseLeaseRemaining reads the leasetime field: either the literal "Permanent"
// or H:MM:SS whose hours carry no leading zero and are not capped at 24
// ("1:52:14", but also "2146:15:35").
func parseLeaseRemaining(s string) (d time.Duration, permanent bool, err error) {
	s = strings.TrimSpace(s)
	if strings.EqualFold(s, "Permanent") {
		return 0, true, nil
	}
	fields := strings.Split(s, ":")
	if len(fields) != 3 {
		return 0, false, fmt.Errorf("leasetime %q is neither Permanent nor H:MM:SS", s)
	}
	// Minutes and seconds arrive unpadded too: "2144:2:32" is a real value.
	var n [3]int
	for i, f := range fields {
		v, convErr := strconv.Atoi(f)
		if convErr != nil || v < 0 {
			return 0, false, fmt.Errorf("leasetime %q: %q is not a count", s, f)
		}
		n[i] = v
	}
	if n[1] > 59 || n[2] > 59 {
		return 0, false, fmt.Errorf("leasetime %q: minutes and seconds must be below 60", s)
	}
	return time.Duration(n[0])*time.Hour + time.Duration(n[1])*time.Minute +
		time.Duration(n[2])*time.Second, false, nil
}

// parseReservations reads dhcps?form=reservation. Membership here is the only
// reliable source of "is reserved": some reserved MACs report a countdown
// rather than Permanent.
func parseReservations(raw json.RawMessage) ([]Reservation, error) {
	type wire struct {
		MAC      string `json:"mac"`
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
		Enable   any    `json:"enable"`
	}
	in, err := decodeList[wire](raw)
	out := make([]Reservation, 0, len(in))
	for _, w := range in {
		out = append(out, Reservation{
			MAC:      tpapi.NormalizeMAC(w.MAC),
			IP:       w.IP,
			Hostname: w.Hostname,
			Enabled:  onOff(w.Enable),
		})
	}
	return out, wrap("dhcps reservation", err)
}

// parseDHCPSetting reads dhcps?form=setting, whose leasetime is a count of
// minutes as a string and applies to the pool, not to every lease.
func parseDHCPSetting(raw json.RawMessage) (*DHCPSetting, error) {
	var w struct {
		Enable    any    `json:"enable"`
		LeaseTime string `json:"leasetime"`
		Start     string `json:"ipaddr_start"`
		End       string `json:"ipaddr_end"`
		Gateway   string `json:"gateway"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("dhcps setting: %w", err)
	}
	out := &DHCPSetting{
		Enabled:    onOff(w.Enable),
		RangeStart: w.Start,
		RangeEnd:   w.End,
		Gateway:    w.Gateway,
	}
	if w.LeaseTime != "" {
		n, err := strconv.Atoi(w.LeaseTime)
		if err != nil {
			return nil, fmt.Errorf("dhcps setting: leasetime %q is not a count of minutes", w.LeaseTime)
		}
		out.LeaseTime = time.Duration(n) * time.Minute
	}
	return out, nil
}

// parsePorts reads status?form=router. The speed field is an int on a linked
// port and an empty string on a dark one, so it cannot be unmarshalled into
// int directly. is_wan is absent except on the WAN port.
func parsePorts(raw json.RawMessage) ([]Port, error) {
	type wire struct {
		Name   string          `json:"name"`
		Status string          `json:"status"`
		Duplex string          `json:"duplex"`
		Speed  json.RawMessage `json:"speed"`
		IsWAN  bool            `json:"is_wan"`
	}
	in, err := decodeList[wire](raw)
	errs := []error{err}
	out := make([]Port, 0, len(in))
	for _, w := range in {
		speed, err := portSpeed(w.Speed)
		if err != nil {
			errs = append(errs, fmt.Errorf("port %s: %w", w.Name, err))
			continue
		}
		out = append(out, Port{
			Name:       w.Name,
			Up:         strings.EqualFold(w.Status, "connected"),
			SpeedMbits: speed,
			Duplex:     w.Duplex,
			IsWAN:      w.IsWAN,
		})
	}
	return out, wrap("status router", errors.Join(errs...))
}

func portSpeed(raw json.RawMessage) (int, error) {
	s := unquote(raw)
	if s == "" || s == "null" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("speed %q is neither a number nor empty", s)
	}
	return n, nil
}

// parsePerf reads cpu_usage, cpu1_usage..cpuN_usage and mem_usage out of
// status?form=all. Values are ratios. The core count is found by probing
// cpuN_usage until the key is missing, the way the UI does it.
func parsePerf(raw json.RawMessage) (*Perf, error) {
	fields, err := fieldMap(raw)
	if err != nil {
		return nil, fmt.Errorf("status all: %w", err)
	}
	cpu, ok := number(fields, "cpu_usage")
	if !ok {
		return nil, errors.New("status all: no cpu_usage")
	}
	mem, ok := number(fields, "mem_usage")
	if !ok {
		return nil, errors.New("status all: no mem_usage")
	}
	out := &Perf{CPU: cpu, Memory: mem}
	for i := 1; ; i++ {
		v, ok := number(fields, fmt.Sprintf("cpu%d_usage", i))
		if !ok {
			break
		}
		out.Cores = append(out.Cores, v)
	}
	return out, nil
}

// parseWANUptime reads wan_ipv4_uptime, in seconds, from status?form=all.
func parseWANUptime(raw json.RawMessage) (time.Duration, error) {
	fields, err := fieldMap(raw)
	if err != nil {
		return 0, fmt.Errorf("status all: %w", err)
	}
	v, ok := number(fields, "wan_ipv4_uptime")
	if !ok {
		return 0, errors.New("status all: no wan_ipv4_uptime")
	}
	return seconds(v), nil
}

// parseInternet reads status?form=internet. Of the five states — connected,
// poor_connected, connecting, disconnected, unplugged — the first two count as
// up. The UI compares after toUpperCase, so case is not guaranteed; state is
// the raw value lowercased, which keeps a change of spelling from splitting the
// series in two.
func parseInternet(raw json.RawMessage) (internetUp, linkUp bool, state string, err error) {
	var w struct {
		Internet string `json:"internet_status"`
		WAN      string `json:"wan_internet_status"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return false, false, "", fmt.Errorf("status internet: %w", err)
	}
	return connected(w.Internet), connected(w.WAN),
		strings.ToLower(strings.TrimSpace(w.Internet)), nil
}

func connected(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "connected", "poor_connected":
		return true
	}
	return false
}

// parseWireless reads wireless_2g_* and wireless_5g_* out of status?form=all,
// keyed by band.
func parseWireless(raw json.RawMessage) (map[string]Radio, error) {
	fields, err := fieldMap(raw)
	if err != nil {
		return nil, fmt.Errorf("status all: %w", err)
	}
	out := map[string]Radio{}
	for _, band := range []string{"2g", "5g"} {
		enable, hasEnable := text(fields, "wireless_"+band+"_enable")
		channel, hasChannel := text(fields, "wireless_"+band+"_current_channel")
		power, hasPower := text(fields, "wireless_"+band+"_txpower")
		if !hasEnable && !hasChannel && !hasPower {
			continue
		}
		r := Radio{TxPower: power}
		if hasEnable {
			on := onOff(enable)
			r.Enabled = &on
		}
		// current_channel holds a number even where the setting says "auto";
		// anything else leaves the channel unknown rather than failing the reply.
		if n, err := strconv.Atoi(channel); hasChannel && err == nil {
			r.Channel = &n
		}
		out[band] = r
	}
	return out, nil
}

// parseMeshNodes reads easymesh_network?form=get_mesh_device_list_all.
func parseMeshNodes(raw json.RawMessage) ([]MeshNode, error) {
	type wire struct {
		MAC       string `json:"mac"`
		Name      string `json:"name"`
		Model     string `json:"model"`
		Role      string `json:"role"`
		Status    string `json:"status"`
		ClientNum int    `json:"client_num"`
	}
	in, err := decodeList[wire](raw)
	out := make([]MeshNode, 0, len(in))
	for _, w := range in {
		out = append(out, MeshNode{
			MAC:     tpapi.NormalizeMAC(w.MAC),
			Name:    w.Name,
			Model:   w.Model,
			Role:    w.Role,
			Up:      strings.EqualFold(w.Status, "connected"),
			Clients: w.ClientNum,
		})
	}
	return out, wrap("mesh device list", err)
}

// parseWANSpeed reads status?form=wan_speed: {down_speed, up_speed, test_time}.
// Speeds are bytes per second; test_time is the router's stamp on the sample.
func parseWANSpeed(raw json.RawMessage) (down, up float64, takenAt time.Time, err error) {
	var w struct {
		Down     float64 `json:"down_speed"`
		Up       float64 `json:"up_speed"`
		TestTime int64   `json:"test_time"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return 0, 0, time.Time{}, fmt.Errorf("wan_speed: %w", err)
	}
	if w.TestTime > 0 {
		takenAt = time.Unix(w.TestTime, 0)
	}
	return w.Down, w.Up, takenAt, nil
}

// parseFirmware reads firmware?form=upgrade. Local information only; nothing
// here says whether an update exists.
func parseFirmware(raw json.RawMessage) (*Firmware, error) {
	var w struct {
		Version  string `json:"firmware_version"`
		Hardware string `json:"hardware_version"`
		Model    string `json:"model"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("firmware: %w", err)
	}
	return &Firmware{Version: w.Version, Hardware: w.Hardware, Model: w.Model}, nil
}

// parseRouterClock reads time?form=settings. date is MM/DD/YYYY, time is
// HH:MM:SS, timezone is a TP-Link index and not an offset — build the wall
// clock in the exporter's own location and compare like for like.
func parseRouterClock(raw json.RawMessage) (*RouterClock, error) {
	var w struct {
		Date     string `json:"date"`
		Time     string `json:"time"`
		Timezone string `json:"timezone"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("time settings: %w", err)
	}
	wall, err := time.ParseInLocation("01/02/2006 15:04:05", w.Date+" "+w.Time, time.Local)
	if err != nil {
		return nil, fmt.Errorf("time settings: %q %q: %w", w.Date, w.Time, err)
	}
	return &RouterClock{Wall: wall, Timezone: w.Timezone}, nil
}

// parseTunnels reads vpn?form=server, which returns an array even with one
// tunnel. Speeds are bytes per second and instantaneous; there is no byte
// counter. key, private_key and public_key arrive redacted. Endpoint is
// endpoint_address and endpoint_port joined by a colon.
func parseTunnels(raw json.RawMessage) ([]Tunnel, error) {
	type wire struct {
		Des      string  `json:"des"`
		Vendor   string  `json:"vendor"`
		Type     string  `json:"type"`
		Address  string  `json:"endpoint_address"`
		Port     string  `json:"endpoint_port"`
		Status   string  `json:"status"`
		Download float64 `json:"download_speed"`
		Upload   float64 `json:"upload_speed"`
	}
	in, err := decodeList[wire](raw)
	out := make([]Tunnel, 0, len(in))
	for _, w := range in {
		endpoint := w.Address
		if endpoint != "" && w.Port != "" {
			endpoint += ":" + w.Port
		}
		out = append(out, Tunnel{
			Name:          w.Des,
			Vendor:        w.Vendor,
			Type:          w.Type,
			Endpoint:      endpoint,
			Up:            strings.EqualFold(w.Status, "connected"),
			DownBytesPerS: w.Download,
			UpBytesPerS:   w.Upload,
		})
	}
	return out, wrap("vpn server", err)
}

// parseVPNServer reads vpn?form=enable.
func parseVPNServer(raw json.RawMessage) (*VPNServer, error) {
	var w struct {
		Enable any    `json:"enable"`
		Type   string `json:"type"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("vpn enable: %w", err)
	}
	return &VPNServer{Enabled: onOff(w.Enable), Type: w.Type}, nil
}

// parseVPNUsers reads vpn?form=vpn_user_list, where MACs come colon-separated
// while every other endpoint uses dashes.
func parseVPNUsers(raw json.RawMessage) ([]VPNUser, error) {
	type wire struct {
		MAC        string `json:"mac"`
		Name       string `json:"name"`
		ClientType string `json:"client_type"`
		Access     any    `json:"access"`
	}
	in, err := decodeList[wire](raw)
	out := make([]VPNUser, 0, len(in))
	for _, w := range in {
		out = append(out, VPNUser{
			MAC:        tpapi.NormalizeMAC(w.MAC),
			Name:       w.Name,
			ClientType: w.ClientType,
			Access:     onOff(w.Access),
		})
	}
	return out, wrap("vpn user list", err)
}

// parseARP reads imb?form=arp_list. Its enable field is IP-MAC binding, not
// whether the device is online.
func parseARP(raw json.RawMessage) ([]ARPEntry, error) {
	type wire struct {
		MAC  string `json:"mac"`
		IP   string `json:"ipaddr"`
		Name string `json:"name"`
	}
	in, err := decodeList[wire](raw)
	out := make([]ARPEntry, 0, len(in))
	for _, w := range in {
		out = append(out, ARPEntry{MAC: tpapi.NormalizeMAC(w.MAC), IP: w.IP, Name: w.Name})
	}
	return out, wrap("arp list", err)
}

// parseGuestNetworks reads guest_2g_enable and guest_5g_enable out of
// status?form=all, keyed by band. Only bands the reply mentions get a key.
func parseGuestNetworks(raw json.RawMessage) (map[string]bool, error) {
	return parseBandFlags(raw, "guest")
}

// parseIoTNetworks reads iot_2g_enable and iot_5g_enable out of the same reply.
// The router keeps a separate SSID pair for smart-home devices, off by default.
func parseIoTNetworks(raw json.RawMessage) (map[string]bool, error) {
	return parseBandFlags(raw, "iot")
}

func parseBandFlags(raw json.RawMessage, prefix string) (map[string]bool, error) {
	fields, err := fieldMap(raw)
	if err != nil {
		return nil, fmt.Errorf("status all: %w", err)
	}
	out := map[string]bool{}
	for _, band := range []string{"2g", "5g"} {
		v, ok := text(fields, prefix+"_"+band+"_enable")
		if !ok {
			continue
		}
		out[band] = onOff(v)
	}
	return out, nil
}

// SecuritySources are the several small replies that make up one Security
// value, keyed by "path?form=x" as polled.
type SecuritySources map[string]json.RawMessage

// parseSecurity folds administration?form=remote, upnp?form=enable and
// ?form=service, nat?form=vs, ?form=pt, ?form=dmz and
// security_settings?form=new_enable into one value. A source that did not
// answer leaves its field nil and its own entry in the returned map, so one
// failure costs one flag rather than the section, and the count is charged to
// the endpoint that actually failed.
func parseSecurity(src SecuritySources) (*Security, map[string]error) {
	out := &Security{}
	errs := map[string]error{}

	flag := func(path, field string) *bool {
		v, err := src.flag(path, field)
		if err != nil {
			errs[path] = err
		}
		return v
	}
	// Remote management is the enable field. The sibling remote boolean is read
	// by nothing in the router's own bundle.
	out.RemoteManagement = flag(srcRemote, "enable")
	out.UPnPEnabled = flag(srcUPnPEnable, "enable")
	out.DMZ = flag(srcDMZ, "enable")
	out.LANPing = flag(srcFirewall, "lan_ping")
	out.WANPing = flag(srcFirewall, "wan_ping")

	if n, err := src.count(srcUPnPService); err != nil {
		errs[srcUPnPService] = err
	} else {
		out.UPnPMappings = n
	}
	for _, r := range []struct{ kind, path string }{{"vs", srcNATvs}, {"pt", srcNATpt}} {
		n, err := src.count(r.path)
		switch {
		case err != nil:
			errs[r.path] = err
		case n != nil:
			if out.PortForwards == nil {
				out.PortForwards = map[string]int{}
			}
			out.PortForwards[r.kind] = *n
		}
	}
	if len(errs) == 0 {
		errs = nil
	}
	return out, errs
}

// flag returns nil when the source did not answer or does not carry the field.
func (src SecuritySources) flag(path, field string) (*bool, error) {
	raw, ok := src[path]
	if !ok {
		return nil, nil
	}
	fields, err := fieldMap(raw)
	if err != nil {
		return nil, err
	}
	v, ok := fields[field]
	if !ok {
		return nil, nil
	}
	var decoded any
	if err := json.Unmarshal(v, &decoded); err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	b := onOff(decoded)
	return &b, nil
}

func (src SecuritySources) count(path string) (*int, error) {
	raw, ok := src[path]
	if !ok {
		return nil, nil
	}
	entries, err := listRows(raw)
	if err != nil {
		return nil, err
	}
	n := len(entries)
	return &n, nil
}

// onOff reads the firmware's boolean spelling: "on"/"off" strings, and in a few
// replies real JSON booleans.
func onOff(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(strings.TrimSpace(x), "on")
	}
	return false
}

func fieldMap(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	return fields, nil
}

// number accepts both spellings the firmware uses: wan_ipv4_uptime is a JSON
// number, modem_ipv4_uptime the string "0", both in status?form=all.
func number(fields map[string]json.RawMessage, key string) (float64, bool) {
	raw, ok := fields[key]
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseFloat(unquote(raw), 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func text(fields map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := fields[key]
	if !ok {
		return "", false
	}
	return unquote(raw), true
}

func unquote(raw json.RawMessage) string {
	s := strings.TrimSpace(string(raw))
	var out string
	if err := json.Unmarshal([]byte(s), &out); err == nil {
		return out
	}
	return s
}
