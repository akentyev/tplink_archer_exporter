package tpapi

import "testing"

func TestNormalizeMAC(t *testing.T) {
	// The five spellings one AX80 sweep produced, plus the usual variants.
	for _, tc := range []struct{ in, want string }{
		{"00-00-5E-00-53-0A", "00:00:5e:00:53:0a"}, // game_accelerator
		{"00-00-5e-00-53-01", "00:00:5e:00:53:01"}, // traffic?form=dev_name
		{"00-00-5E-00-53-01", "00:00:5e:00:53:01"}, // nat?form=client_list
		{"00-00-5E-00-53-00", "00:00:5e:00:53:00"}, // dhcps?form=client
		{"00:00:5E:00:53:0B", "00:00:5e:00:53:0b"}, // vpn?form=vpn_user_list
		{"00-00-5e-00-53-0b", "00:00:5e:00:53:0b"}, // the same device, as dhcps spells it
		{"00005E00530A", "00:00:5e:00:53:0a"},      // game_accelerator "key"
		{"0000.5e00.530a", "00:00:5e:00:53:0a"},    // cisco style
		{" 00:00:5E:00:53:0A ", "00:00:5e:00:53:0a"},
		{"00005e00530a", "00:00:5e:00:53:0a"},
		{"0000.5E00.530A", "00:00:5e:00:53:0a"},
		{"00-00-5e-00-53-0A", "00:00:5e:00:53:0a"}, // both cases inside one address
		{"\t00-00-5E-00-53-0A\n", "00:00:5e:00:53:0a"},
		{"00:00:5e:00:53:0a", "00:00:5e:00:53:0a"},
	} {
		got := NormalizeMAC(tc.in)
		if got != tc.want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", tc.in, got, tc.want)
			continue
		}
		if again := NormalizeMAC(got); again != got {
			t.Errorf("NormalizeMAC(%q) = %q on a second pass; an address normalised twice lands on a "+
				"second key", got, again)
		}
	}
}

// net.ParseMAC reads twelve hex digits with no separators only from Go 1.26 on.
// vpn?form=vpn_user_devices spells device_id that way, 66 rows in the sweep, and
// on an older toolchain each one stays unnormalised and splits its device in two.
func TestNormalizeMACBareTwelveHexNeedsGo126(t *testing.T) {
	for _, in := range []string{"00005E00530A", "00005e00530a"} {
		const want = "00:00:5e:00:53:0a"
		if got := NormalizeMAC(in); got != want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q — bare twelve hex parses only on Go 1.26 and "+
				"later, so go.mod must keep its floor there", in, got, want)
		}
	}
}

// Twelve hex digits left after the separators are stripped is not a MAC. Any
// dotted quad whose digits total twelve passes that test, and the hand-written
// parser read 192.168.100.100 as 19:21:68:10:01:00.
func TestNormalizeMACDoesNotTurnADottedAddressIntoAMAC(t *testing.T) {
	for _, in := range []string{
		"192.168.100.100",
		"255.255.255.000",
		"100.100.100.100",
	} {
		if got := NormalizeMAC(in); got != in {
			t.Errorf("NormalizeMAC(%q) = %q: an address became a plausible MAC, and it joins "+
				"tplink_client_info and the ARP metrics to a device that does not exist", in, got)
		}
	}
}

// Junk must stay recognisable, not become a plausible wrong address.
func TestNormalizeMACLeavesJunkAlone(t *testing.T) {
	for _, in := range []string{
		"", "---", "NON_HOST", // NON_HOST is what game_accelerator sends for "host"
		"192.0.2.1",      // nine digits; the twelve-digit trap has its own test above
		"00-00-5E-00-53", // too short
		"00-00-5E-00-53-0A-99",
		"zz-00-5E-00-53-0A",
		"00005E00530",             // eleven hex digits
		"00005E00530A0",           // thirteen
		"00:00:5e:00:53:0a:0b:0c", // net.ParseMAC reads eight-byte EUI-64 too, and it is not a MAC
		"00.00.5e.00.53.0a",       // dotted groups are fours, not pairs
		"000.05e.005.30a",
		"00 00 5e 00 53 0a", // space-separated, in no captured reply
	} {
		if got := NormalizeMAC(in); got != in {
			t.Errorf("NormalizeMAC(%q) = %q; junk stays visible instead of becoming an address "+
				"something downstream will join on", in, got)
		}
	}
}
