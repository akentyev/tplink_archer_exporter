package tpapi

import (
	"net"
	"strings"
)

// One sweep of an AX80 returned the same devices in five places, spelled three
// ways:
//
//	smart_network?form=game_accelerator   00-00-5E-00-53-0A
//	traffic?form=dev_name                 00-00-5e-00-53-01
//	nat?form=client_list                  00-00-5E-00-53-01
//	dhcps?form=client                     00-00-5E-00-53-00
//	vpn?form=vpn_user_list                00:00:5E:00:53:0B
//
// Downstream joins by MAC, so these must collapse to one form or half-match.

// NormalizeMAC returns lowercase hex with colons (RFC 7042, and what Linux and
// node_exporter print). Anything net.ParseMAC does not read as a six-byte
// address comes back trimmed but unchanged, so junk stays visible instead of
// becoming a plausible wrong address.
//
// The parsing is net.ParseMAC's and not ours because the hand-written version
// stripped separators before counting hex digits, which turned 192.168.100.100
// into 19:21:68:10:01:00.
//
// Bare twelve-hex needs Go 1.26 or later, so the version in go.mod is
// load-bearing here and not only for the language. One sweep carried 66 of
// them, all in the device_id field of vpn?form=vpn_user_devices; every endpoint
// the exporter polls spells its MACs with hyphens or colons.
func NormalizeMAC(s string) string {
	s = strings.TrimSpace(s)
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return s
	}
	return hw.String()
}
