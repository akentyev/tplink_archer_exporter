// Command recon logs in to a TP-Link Archer router and dumps the decrypted JSON
// of every endpoint it can reach, so field names are known before any metric is
// defined. It only ever sends reporting operations.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/akentyev/tplink_archer_exporter/internal/tpapi"
)

type probe struct {
	Path string
	Ops  []string
	Note string
}

// focusProbes is a default run: what the exporter needs plus context. Paths come
// from the router's JS bundle, so "no such callback" means the endpoint is
// absent from this build. -all sweeps endpoints.go instead.
var focusProbes = []probe{
	// --- what the exporter needs --------------------------------------------
	{"admin/dhcps?form=client", []string{"load", "read", "list"}, "DHCP lease list"},
	{"admin/dhcps?form=reservation", []string{"load", "read", "list"}, "address reservations"},
	{"admin/dhcps?form=setting", []string{"read", "load"}, "DHCP pool + lease time"},
	{"admin/status?form=all", []string{"read"}, "connected clients live here: access_devices_wired + _wireless_host"},
	{"admin/easymesh_network?form=mesh_sclient_list_all", []string{"read"}, "clients across the mesh"},
	{"admin/smart_network?form=game_accelerator", []string{"loadDevice", "loadSpeed"}, "clients w/ throughput"},
	{"admin/smart_network?form=client_speed_limit", []string{"read_max"}, "per-client rate caps"},
	{"admin/smart_network?form=get_host_info", []string{"read"}, "how the router sees the machine running this"},
	{"admin/access_control?form=black_devices", []string{"load", "read"}, "blocked devices"},
	{"admin/access_control?form=white_devices", []string{"load", "read"}, "allowed devices"},

	// --- general status -----------------------------------------------------
	{"admin/status?form=internet", []string{"read"}, ""},
	{"admin/status?form=router", []string{"read"}, "per-port link speed/duplex"},
	{"admin/status?form=wan_speed", []string{"read"}, "current WAN throughput"},
	{"admin/vpn?form=server", []string{"load"}, "VPN tunnels + their throughput"},
	{"admin/vpn?form=vpn_user_list", []string{"load"}, "who may use the VPN"},
	{"admin/traffic?form=dev_name", []string{"read"}, "per-client connect time + cumulative uptime"},
	{"admin/network?form=wan_ipv4_status", []string{"read"}, "WAN connection type + autodetect state"},
	{"admin/network?form=wan_ipv6_status", []string{"read"}, ""},
	{"admin/network?form=lan_ipv4", []string{"read"}, ""},
	{"admin/network?form=status_ipv4", []string{"read"}, ""},
	{"admin/network?form=port_speed_current", []string{"read", "load"}, "link speed per port"},
	{"admin/wireless?form=wireless_2g", []string{"read"}, "?form=wireless alone is a prefix, not a form"},
	{"admin/wireless?form=wireless_5g", []string{"read"}, ""},
	{"admin/wireless?form=region", []string{"read"}, ""},
	{"admin/system?form=sysmode", []string{"read"}, ""},
	{"admin/firmware?form=upgrade", []string{"read"}, "firmware + hardware version (read only; write upgrades)"},
	{"admin/firmware?form=config", []string{"read"}, ""},
	{"admin/time?form=settings", []string{"read"}, "router clock — needed to age leases"},
	{"admin/time?form=dst", []string{"read"}, ""},
	{"admin/ledgeneral?form=setting", []string{"read"}, ""},
}

type result struct {
	Path      string          `json:"path"`
	Operation string          `json:"operation"`
	Note      string          `json:"note,omitempty"`
	OK        bool            `json:"ok"`
	Error     string          `json:"error,omitempty"`
	File      string          `json:"file,omitempty"`
	Data      json.RawMessage `json:"-"`
}

func main() {
	var (
		host    = flag.String("host", "", "router base URL, e.g. http://192.168.0.1 (or env TPLINK_HOST)")
		user    = flag.String("user", "admin", "web UI username")
		pass    = flag.String("password", "", "web UI password (or env TPLINK_PASSWORD)")
		outDir  = flag.String("out", "recon-out", "directory for the dumps")
		extra   = flag.String("extra", "", "comma-separated extra paths to probe, e.g. 'admin/foo?form=bar'")
		timeout = flag.Duration("timeout", 15*time.Second, "per-request timeout")
		all     = flag.Bool("all", false, "probe every endpoint the web UI knows, not just the focus list")
		force   = flag.Bool("force", true, "evict an existing web session instead of giving up")
		debug   = flag.Bool("debug", false, "log raw requests and responses")
	)
	flag.Parse()

	if *host == "" {
		*host = os.Getenv("TPLINK_HOST")
	}
	if *host == "" {
		fatal("host is required (-host or TPLINK_HOST), e.g. -host http://192.168.0.1")
	}
	if *pass == "" {
		*pass = os.Getenv("TPLINK_PASSWORD")
	}
	if *pass == "" {
		fatal("password is required (-password or TPLINK_PASSWORD)")
	}

	list := append([]probe(nil), focusProbes...)
	if *all {
		seen := map[string]bool{}
		for _, p := range list {
			seen[p.Path] = true
		}
		for _, p := range allEndpoints {
			if !seen[p.Path] {
				list = append(list, p)
			}
		}
	}
	for _, p := range strings.Split(*extra, ",") {
		if p = strings.TrimSpace(p); p != "" {
			list = append(list, probe{Path: p, Ops: []string{"read", "load", "list"}, Note: "user-supplied"})
		}
	}

	c, err := tpapi.New(*host, *user, *pass, *timeout)
	if err != nil {
		fatal("client: %v", err)
	}
	c.Debug = *debug
	c.Force = *force

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Before login, so a bad -out cannot strand the router's one session.
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal("mkdir: %v", err)
	}

	fmt.Printf("logging in to %s as %s\n", c.Host, *user)
	if err := c.Login(ctx); err != nil {
		fatal("login: %v\n\nHints: the AX80 allows one web session at a time — close the browser\ntab you have open on the router, wait for it to time out, and retry.", err)
	}
	defer func() {
		if err := c.Logout(context.WithoutCancel(ctx)); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "warning: logout failed: %v\n", err)
		}
	}()
	f := c.Features()
	fmt.Printf("login ok (certification %v: sha256=%t encrypt=%t replace-hash=%t oaep=%t)\n",
		f.Certifications, f.SHA256Hash, f.Encrypt, f.ReplaceHash, f.OAEP)

	var results []result
	answered, dumps := 0, 0
	for _, p := range list {
		rs := run(ctx, c, p)
		if rs[0].OK {
			answered++
		}
		for i := range rs {
			r := &rs[i]
			if !r.OK {
				fmt.Printf("  --   %-46s %s\n", p.Path, r.Error)
				continue
			}
			// Reported, not fatal: exiting here would skip the deferred logout.
			r.File = filepath.Join(*outDir, safeName(p.Path)+"."+r.Operation+".json")
			if err := os.WriteFile(r.File, indent(r.Data), 0o644); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "warning: write %s: %v\n", r.File, err)
				r.File = ""
			}
			dumps++
			fmt.Printf("  OK   %-46s op=%-10s %s\n", p.Path, r.Operation, summarize(r.Data))
		}
		results = append(results, rs...)
	}

	sort.SliceStable(results, func(i, j int) bool { return results[i].OK && !results[j].OK })
	idx, _ := json.MarshalIndent(results, "", "  ")
	_ = os.WriteFile(filepath.Join(*outDir, "index.json"), idx, 0o644)

	fmt.Printf("\n%d/%d endpoints answered, %d dumps in %s/\n", answered, len(list), dumps, *outDir)
}

// run tries every listed operation and keeps each that answers. They are not
// interchangeable: game_accelerator returns different objects for loadDevice and
// loadSpeed, so stopping at the first success would drop half the data.
func run(ctx context.Context, c *tpapi.Client, p probe) []result {
	var (
		out     []result
		lastErr string
	)
	for _, op := range p.Ops {
		data, err := c.Call(ctx, p.Path, op)
		if err != nil {
			lastErr = fmt.Sprintf("op=%s: %v", op, err)
			continue
		}
		out = append(out, result{Path: p.Path, Operation: op, Note: p.Note, OK: true, Data: data})
	}
	if len(out) > 0 {
		return out
	}
	return []result{{Path: p.Path, Note: p.Note, Error: lastErr}}
}

// summarize gives a one-line hint of the shape.
func summarize(d json.RawMessage) string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(d, &obj); err == nil {
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		s := strings.Join(keys, ",")
		if len(s) > 90 {
			s = s[:90] + "…"
		}
		return "{" + s + "}"
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(d, &arr); err == nil {
		return fmt.Sprintf("[%d items]", len(arr))
	}
	return strings.TrimSpace(string(d))
}

func indent(d json.RawMessage) []byte {
	var buf bytes.Buffer
	if err := json.Indent(&buf, d, "", "  "); err != nil {
		return d
	}
	buf.WriteByte('\n')
	return buf.Bytes()
}

func safeName(path string) string {
	r := strings.NewReplacer("/", "_", "?", "_", "=", "-", "&", "_")
	return r.Replace(path)
}

func fatal(format string, a ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
