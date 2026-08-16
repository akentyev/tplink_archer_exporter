# Fixtures

Real replies from an Archer AX80 (firmware 1.4.1 Build 20251117), captured with
`cmd/recon`, then anonymised: MAC addresses were remapped into IANA's documentation OUI `00-00-5E-00-53-xx`, addresses
into TEST-NET-1 `192.0.2.0/24`, and host names, SSIDs and VPN endpoints replaced with stand-ins. The mapping is
one-to-one, so joins across files still work — the same device is the same MAC in every fixture.

Credentials are already `<redacted>`: `Client.Call` masks them before anything reaches disk.
`TestFixturesCarryNoSecrets` keeps it that way.

Shapes, field names, value formats and counts are untouched, which is the point:
these are what the firmware actually sends, including the awkward parts —
`leasetime` as `"Permanent"` or `"1:52:14"`, MACs in three different spellings, empty strings where a number is
expected.

Identity is what gets replaced, not hardware: port names (`wanlan1g`, `lan1`), vendor strings and protocol values stay
as the firmware sends them.

`internal/exporter` reads the same directory rather than keeping a second copy, so one anonymisation guard covers every
fixture in the repo.

One row per file, because the names do not always give the endpoint away:
`ports.json` comes from `form=router` and `vpn_tunnels.json` from `form=server`. The paths are the ones in
`internal/exporter/assemble.go`, minus the `admin/`
prefix every endpoint carries.

| file                         | endpoint                                                                          |
|------------------------------|-----------------------------------------------------------------------------------|
| `clients.json`               | `smart_network?form=game_accelerator` `loadDevice`                                |
| `client_times.json`          | `traffic?form=dev_name`                                                           |
| `dhcp_clients.json`          | `dhcps?form=client`                                                               |
| `dhcp_reservations.json`     | `dhcps?form=reservation`                                                          |
| `dhcp_setting.json`          | `dhcps?form=setting`                                                              |
| `status_all.json`            | `status?form=all` — CPU, memory, WAN uptime, Wi-Fi radios, guest and IoT networks |
| `ports.json`                 | `status?form=router`                                                              |
| `status_internet.json`       | `status?form=internet`                                                            |
| `status_wan_speed.json`      | `status?form=wan_speed`                                                           |
| `vpn_tunnels.json`           | `vpn?form=server`                                                                 |
| `vpn_users.json`             | `vpn?form=vpn_user_list`                                                          |
| `vpn_enable.json`            | `vpn?form=enable`                                                                 |
| `arp_list.json`              | `imb?form=arp_list` — wider than the client list, keeps stale entries             |
| `security_remote.json`       | `administration?form=remote`                                                      |
| `security_upnp_enable.json`  | `upnp?form=enable`                                                                |
| `security_upnp_service.json` | `upnp?form=service`                                                               |
| `security_nat_vs.json`       | `nat?form=vs`                                                                     |
| `security_nat_pt.json`       | `nat?form=pt`                                                                     |
| `security_nat_dmz.json`      | `nat?form=dmz`                                                                    |
| `security_firewall.json`     | `security_settings?form=new_enable`                                               |
| `mesh_nodes.json`            | `easymesh_network?form=get_mesh_device_list_all`                                  |
| `firmware.json`              | `firmware?form=upgrade`                                                           |
| `time.json`                  | `time?form=settings`                                                              |

`security_upnp_service.json`, `security_nat_vs.json` and `security_nat_pt.json`
are `{}`: the reference device has no UPnP mapping and no forwarding rule. That is the state the "a forward appeared"
alert fires out of, so it is worth a fixture, but it does not pin the shape of a non-empty reply.
