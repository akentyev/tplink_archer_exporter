package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/akentyev/tplink_archer_exporter/internal/tpapi"
)

// Timing runs in a testing/synctest bubble, where tickers, timeouts and backoff
// are fake time: the suite covers minutes of polling in milliseconds.

// sourceFixture is the anonymised reply each source answers with and the
// operation it answers to. The replies are listed in ../tpapi/testdata/README.md;
// the operations are the ones the recon dumps are named after, as in
// admin_dhcps_form-client.load.json.
var sourceFixture = map[string]struct{ reply, operation string }{
	"admin/smart_network?form=game_accelerator": {"clients.json", "loadDevice"},
	"admin/traffic?form=dev_name":               {"client_times.json", "read"},
	"admin/dhcps?form=client":                   {"dhcp_clients.json", "load"},
	"admin/dhcps?form=reservation":              {"dhcp_reservations.json", "load"},
	"admin/dhcps?form=setting":                  {"dhcp_setting.json", "read"},
	"admin/status?form=all":                     {"status_all.json", "read"},
	"admin/status?form=router":                  {"ports.json", "read"},
	"admin/status?form=internet":                {"status_internet.json", "read"},
	"admin/status?form=wan_speed":               {"status_wan_speed.json", "read"},
	"admin/vpn?form=server":                     {"vpn_tunnels.json", "load"},
	"admin/vpn?form=vpn_user_list":              {"vpn_users.json", "load"},
	"admin/vpn?form=enable":                     {"vpn_enable.json", "read"},
	"admin/firmware?form=upgrade":               {"firmware.json", "read"},
	"admin/time?form=settings":                  {"time.json", "read"},
	"admin/administration?form=remote":          {"security_remote.json", "read"},
	"admin/upnp?form=enable":                    {"security_upnp_enable.json", "read"},
	"admin/upnp?form=service":                   {"security_upnp_service.json", "load"},
	"admin/nat?form=vs":                         {"security_nat_vs.json", "load"},
	"admin/nat?form=pt":                         {"security_nat_pt.json", "load"},
	"admin/nat?form=dmz":                        {"security_nat_dmz.json", "read"},
	"admin/security_settings?form=new_enable":   {"security_firewall.json", "read"},
	"admin/imb?form=arp_list":                   {"arp_list.json", "load"},

	"admin/easymesh_network?form=get_mesh_device_list_all": {"mesh_nodes.json", "read"},
}

// errNoSession is what tpapi.Client.Call returns before a login.
var errNoSession = errors.New("not logged in")

// replyLatency is what one request costs the fake router. Inside a synctest
// bubble the clock only moves when something waits, so without it a whole cycle
// would cost zero and PollDuration could not be observed.
const replyLatency = 20 * time.Millisecond

// fakeRouter is the device half: one session, the poll set answered from
// fixtures, and a call log. It can be told to fail an endpoint, block one, or
// hand the session to a browser.
type fakeRouter struct {
	replies map[string]json.RawMessage

	mu      sync.Mutex
	calls   []routerCall
	logins  []time.Time
	logouts []time.Time

	loginErr    error
	loginHang   bool
	callErr     map[string]error
	blocked     map[string]bool
	session     bool
	expired     bool
	expireOn    string
	expireAfter int    // hits on expireOn to let through before the session goes
	expireEvery string // re-armed on every login, for a tab that stays open
	expireDelay int    // what expireAfter is re-armed to
}

type routerCall struct {
	Path, Operation string
	At              time.Time
}

func newFakeRouter(t *testing.T) *fakeRouter {
	t.Helper()
	r := &fakeRouter{
		replies: make(map[string]json.RawMessage, len(sources)),
		callErr: map[string]error{},
		blocked: map[string]bool{},
	}
	if len(sourceFixture) != len(sources) {
		t.Fatalf("sourceFixture holds %d endpoints for a poll set of %d", len(sourceFixture), len(sources))
	}
	for _, s := range sources {
		src, ok := sourceFixture[s.Path]
		if !ok {
			t.Fatalf("source %q has no fixture; add the reply to ../tpapi/testdata and name it in sourceFixture", s.Path)
		}
		r.replies[s.Path] = fixture(t, src.reply)
	}
	return r
}

func (r *fakeRouter) Login(ctx context.Context) error {
	r.mu.Lock()
	r.logins = append(r.logins, time.Now())
	loginErr, hang := r.loginErr, r.loginHang
	r.mu.Unlock()

	// A real login is four round trips: config, two keys, the login itself.
	time.Sleep(4 * replyLatency)
	if hang {
		<-ctx.Done()
		return ctx.Err()
	}
	if loginErr != nil {
		return loginErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.session, r.expired = true, false
	r.expireOn, r.expireAfter = r.expireEvery, r.expireDelay
	return nil
}

func (r *fakeRouter) Call(ctx context.Context, path, operation string) (json.RawMessage, error) {
	r.mu.Lock()
	r.calls = append(r.calls, routerCall{Path: path, Operation: operation, At: time.Now()})
	if path == r.expireOn {
		if r.expireAfter > 0 {
			r.expireAfter--
		} else {
			r.expired, r.expireOn = true, ""
		}
	}
	blocked, callErr, session, expired := r.blocked[path], r.callErr[path], r.session, r.expired
	reply, known := r.replies[path]
	r.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	time.Sleep(replyLatency)
	if blocked {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if expired {
		return nil, fmt.Errorf("%w (errorcode=timeout)", tpapi.ErrSessionExpired)
	}
	if !session {
		return nil, errNoSession
	}
	if callErr != nil {
		return nil, callErr
	}
	if !known {
		return nil, fmt.Errorf("endpoint %q is not in the poll set", path)
	}
	return reply, nil
}

func (r *fakeRouter) Logout(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logouts = append(r.logouts, time.Now())
	r.session = false
	return nil
}

// fail makes one endpoint answer with err from now on.
func (r *fakeRouter) fail(path string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.callErr[path] = err
}

// mend is the endpoint answering again: the error fail set is dropped.
func (r *fakeRouter) mend(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.callErr, path)
}

// answerWith replaces one endpoint's reply. The request succeeds and the JSON
// is well formed; it is the shape the parser cannot use.
func (r *fakeRouter) answerWith(path string, raw json.RawMessage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.replies[path] = raw
}

// failAll makes every endpoint fail, the session surviving.
func (r *fakeRouter) failAll(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range sources {
		r.callErr[s.Path] = err
	}
}

// block makes one endpoint never answer, so only the caller's context ends the
// request.
func (r *fakeRouter) block(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blocked[path] = true
}

// unblock lets a blocked endpoint answer again.
func (r *fakeRouter) unblock(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.blocked, path)
}

// refuseLogin is a browser on another device holding the web UI: our session is
// gone and a fresh login is refused with "user conflict", the case the firmware
// protects by itself. The sentinel is wrapped, as tpapi.Client wraps it.
func (r *fakeRouter) refuseLogin(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.session = false
	r.loginErr = err
}

// failLogin refuses the next login while leaving the session where it is: the
// poller still holds one until it drops it itself, which is what renewing does.
func (r *fakeRouter) failLogin(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loginErr = err
}

// allowLogin is the browser tab closing again.
func (r *fakeRouter) allowLogin() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loginErr = nil
}

// hangLogin is a router that takes the connection and never finishes the login,
// so only the caller's context ends it.
func (r *fakeRouter) hangLogin() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.session, r.loginHang = false, true
}

// expireAt kills the session when path is polled. That call and every one after
// it answer tpapi.ErrSessionExpired until a login lands: someone has opened the
// web UI and the firmware handed them the session.
func (r *fakeRouter) expireAt(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireOn = path
}

// expireAtEvery is the browser tab staying open on this machine: every login
// takes the session back off the person at it, and the cycle that follows loses
// it again at path.
func (r *fakeRouter) expireAtEvery(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireOn, r.expireEvery, r.expireDelay = path, path, 0
}

// expireAfterOneGoodCycle is the same tab, reopened a cycle later: the session
// the poller takes survives one whole cycle and is gone in the next.
func (r *fakeRouter) expireAfterOneGoodCycle(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireOn, r.expireAfter = path, 1
	r.expireEvery, r.expireDelay = path, 1
}

// stopExpiring is the tab closing: the next session the poller takes stays with
// it.
func (r *fakeRouter) stopExpiring() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireOn, r.expireEvery = "", ""
}

func (r *fakeRouter) callLog() []routerCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]routerCall(nil), r.calls...)
}

func (r *fakeRouter) timesCalled(path string) int {
	return len(r.callTimes(path))
}

func (r *fakeRouter) callTimes(path string) []time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []time.Time
	for _, c := range r.calls {
		if c.Path == path {
			out = append(out, c.At)
		}
	}
	return out
}

// callGaps is the wait between successive requests to one endpoint, which for
// the first source of the poll set is the period of the cycle.
func (r *fakeRouter) callGaps(path string) []time.Duration {
	at := r.callTimes(path)
	gaps := make([]time.Duration, 0, len(at))
	for i := 1; i < len(at); i++ {
		gaps = append(gaps, at[i].Sub(at[i-1]))
	}
	return gaps
}

func (r *fakeRouter) loginTimes() []time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Time(nil), r.logins...)
}

// loginGaps is the wait between successive login attempts.
func (r *fakeRouter) loginGaps() []time.Duration {
	attempts := r.loginTimes()
	gaps := make([]time.Duration, 0, len(attempts))
	for i := 1; i < len(attempts); i++ {
		gaps = append(gaps, attempts[i].Sub(attempts[i-1]))
	}
	return gaps
}

func (r *fakeRouter) logoutCount() int {
	return len(r.logoutTimes())
}

// logoutTimes is when the session was dropped: once per renewal, once on
// shutdown.
func (r *fakeRouter) logoutTimes() []time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Time(nil), r.logouts...)
}

// noLoginCap puts Config.MaxLoginsPerHour out of reach. A test that measures
// retries measures the backoff or the cooldown; the hourly cap has a test of its
// own, and the default of 6 would otherwise stop most of these part way.
const noLoginCap = 1000

// testConfig is shaped like a deployment: a cycle fits inside Interval with room
// to spare, and the backoff range straddles it. The cooldown is four intervals,
// long enough for a test to sit inside it.
func testConfig() Config {
	return Config{
		Interval:         30 * time.Second,
		Timeout:          10 * time.Second,
		MinBackoff:       5 * time.Second,
		MaxBackoff:       2 * time.Minute,
		SessionCooldown:  2 * time.Minute,
		MaxLoginsPerHour: noLoginCap,
	}
}

// startPoller runs the poller in the bubble and returns a stop that cancels it
// and waits for Run to return. stop may be called twice, so a test can shut the
// poller down mid-body and still defer it.
func startPoller(t *testing.T, rt *fakeRouter, cfg Config) (*Poller, func()) {
	t.Helper()
	p := NewPoller(rt, cfg)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	synctest.Wait()
	select {
	case err := <-done:
		t.Fatalf("Run returned before its context was cancelled: %v", err)
	default:
	}

	var once sync.Once
	return p, func() {
		t.Helper()
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil && !errors.Is(err, context.Canceled) {
					t.Errorf("Run reported %v; a cancelled context is a shutdown, not a failure", err)
				}
			case <-time.After(time.Minute):
				t.Error("Run did not return after its context was cancelled")
			}
		})
	}
}

// awaitCycle advances the fake clock until State shows a finished cycle, in
// small steps so a poller that polls at startup is caught after its first cycle
// and one that polls on the first tick is still waited for.
func awaitCycle(t *testing.T, p *Poller, cfg Config) State {
	t.Helper()
	budget := 2*cfg.Interval + 2*cfg.Timeout
	deadline := time.Now().Add(budget)
	for {
		synctest.Wait()
		if st := p.State(); st.Snapshot != nil || st.LastErr != nil || st.PollDuration > 0 {
			return st
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("no cycle finished within %v of Run starting", budget)
		}
		time.Sleep(cfg.Timeout / 20)
	}
}

// A cycle reads every source once, with the operation the firmware expects for
// it, and assembles the lot into one snapshot.
func TestCycleReadsEverySourceIntoOneSnapshot(t *testing.T) {
	rt := newFakeRouter(t)
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		st := awaitCycle(t, p, cfg)
		snap := st.Snapshot
		if snap == nil {
			t.Fatal("a cycle in which every endpoint answered produced no snapshot")
		}
		if snap.TakenAt.IsZero() {
			t.Error("Snapshot.TakenAt is zero; the collector reports snapshot age from it")
		}
		if len(snap.Errors) != 0 {
			t.Errorf("every endpoint answered, yet the snapshot reports errors: %v", snap.Errors)
		}
		if !st.Up {
			t.Error("Up is false after a cycle in which the router answered everything")
		}
		if st.SessionBlocked {
			t.Error("SessionBlocked is set although login succeeded")
		}
		if st.LastErr != nil {
			t.Errorf("LastErr = %v after a clean cycle", st.LastErr)
		}

		for _, section := range snapshotSections(snap) {
			if !section.filled {
				t.Errorf("Snapshot.%s is empty; %s answered with a non-empty fixture", section.name, section.from)
			}
		}

		switch want := fixtureWAN(); {
		case snap.WAN == nil:
			t.Error("no WAN although all three of its sources answered")
		case *snap.WAN != want:
			t.Errorf("WAN = %+v, want %+v — status?form=all carries wan_ipv4_uptime, status?form=internet "+
				"the two states, status?form=wan_speed the sample and its stamp", *snap.WAN, want)
		}

		// The two client endpoints are joined on the normalised MAC.
		thermostat := clientByMAC(t, snap.Clients, macCanonical)
		if !thermostat.ConnectedAt.Equal(time.Unix(1786281883, 0)) || thermostat.Via != "00:00:5e:00:53:15" {
			t.Errorf("thermostat: ConnectedAt %v, Via %q; want %v and %q, which traffic?form=dev_name holds "+
				"for it", thermostat.ConnectedAt, thermostat.Via, time.Unix(1786281883, 0), "00:00:5e:00:53:15")
		}
		if thermostat.Hostname != "thermostat" || thermostat.TrafficBytes != 5278837500 {
			t.Errorf("thermostat lost its game_accelerator half in the merge: %+v", thermostat)
		}

		if snap.Security == nil {
			t.Error("no Security although every one of its sources answered")
		} else {
			want := map[string]bool{"2g": false, "5g": false}
			if !maps.Equal(snap.Security.GuestNetworks, want) {
				t.Errorf("Security.GuestNetworks = %v, want %v — guest_2g_enable and guest_5g_enable arrive "+
					"in status?form=all and belong to the security section", snap.Security.GuestNetworks, want)
			}
			if !maps.Equal(snap.Security.IoTNetworks, want) {
				t.Errorf("Security.IoTNetworks = %v, want %v — the IoT pair rides the same reply as the "+
					"guest one and has to survive the same assembly", snap.Security.IoTNetworks, want)
			}
			for name, v := range securityFlags(snap.Security) {
				if v == nil {
					t.Errorf("Security.%s is nil although its endpoint answered", name)
				}
			}
		}

		seen := map[string]int{}
		for _, c := range rt.callLog() {
			seen[c.Path]++
			want, ok := operationFor(c.Path)
			if !ok {
				t.Errorf("polled %q, which is not in sources", c.Path)
				continue
			}
			if c.Operation != want {
				t.Errorf("%s was called with operation %q, the firmware answers it to %q", c.Path, c.Operation, want)
			}
		}
		for _, s := range sources {
			if seen[s.Path] != 1 {
				t.Errorf("%s was polled %d times in one cycle, want once", s.Path, seen[s.Path])
			}
		}
	})
}

// fixtureWAN is what the three WAN replies in ../tpapi/testdata add up to.
func fixtureWAN() WAN {
	return WAN{
		HaveUptime:    true,
		Uptime:        1117521 * time.Second,
		HaveStatus:    true,
		InternetUp:    true,
		LinkUp:        true,
		State:         "connected",
		HaveSpeed:     true,
		DownBytesPerS: 1546905,
		UpBytesPerS:   23401,
		SpeedTakenAt:  time.Unix(1786802858, 0),
	}
}

// One WAN is built from three replies, and a missing one is not a reading:
// tplink_wan_status 0 for an endpoint that never answered is this exporter's
// headline alert firing on nothing.
func TestWANKeepsWhicheverSourcesAnswered(t *testing.T) {
	noUptime, noStatus, noSpeed := fixtureWAN(), fixtureWAN(), fixtureWAN()
	noUptime.HaveUptime, noUptime.Uptime = false, 0
	noStatus.HaveStatus, noStatus.InternetUp, noStatus.LinkUp, noStatus.State = false, false, false, ""
	noSpeed.HaveSpeed, noSpeed.DownBytesPerS, noSpeed.UpBytesPerS, noSpeed.SpeedTakenAt = false, 0, 0, time.Time{}

	for _, tc := range []struct {
		name string
		lost string
		want WAN
	}{
		{"uptime", srcStatusAll, noUptime},
		{"internet status", srcInternet, noStatus},
		{"speed sample", srcWANSpeed, noSpeed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newFakeRouter(t)
			rt.fail(tc.lost, errors.New("errorcode=00000002"))
			cfg := testConfig()

			synctest.Test(t, func(t *testing.T) {
				p, stop := startPoller(t, rt, cfg)
				defer stop()

				st := awaitCycle(t, p, cfg)
				snap := st.Snapshot
				if snap == nil {
					t.Fatalf("%s failed and the whole snapshot went with it", tc.lost)
				}
				if snap.WAN == nil {
					t.Fatalf("%s failed and took the WAN section with it, though two sources answered", tc.lost)
				}
				if *snap.WAN != tc.want {
					t.Errorf("with %s lost, WAN = %+v, want %+v — a source that did not answer leaves its "+
						"Have flag false and its fields zero, the others are untouched",
						tc.lost, *snap.WAN, tc.want)
				}
				if snap.Errors[tc.lost] == nil {
					t.Errorf("Snapshot.Errors has no entry for %s; it holds %v", tc.lost, snap.Errors)
				}
				if st.EndpointErrors[tc.lost] == 0 {
					t.Errorf("EndpointErrors has no count for %s; it feeds tplink_scrape_errors_total{endpoint}",
						tc.lost)
				}
			})
		})
	}
}

// One endpoint failing costs that section and nothing else; the rest of the
// cycle still lands.
func TestFailedEndpointDoesNotSinkTheCycle(t *testing.T) {
	const broken = "admin/dhcps?form=client"

	rt := newFakeRouter(t)
	rt.fail(broken, errors.New("errorcode=00000002"))
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		st := awaitCycle(t, p, cfg)
		snap := st.Snapshot
		if snap == nil {
			t.Fatal("one failed endpoint discarded the whole snapshot")
		}
		if snap.Errors[broken] == nil {
			t.Errorf("Snapshot.Errors has no entry for %s; it holds %v", broken, snap.Errors)
		}
		if len(snap.Errors) != 1 {
			t.Errorf("one endpoint failed, %d are reported: %v", len(snap.Errors), snap.Errors)
		}
		if st.EndpointErrors[broken] == 0 {
			t.Errorf("EndpointErrors has no count for %s; it feeds tplink_scrape_errors_total{endpoint}", broken)
		}
		for _, section := range snapshotSections(snap) {
			if section.from == broken {
				continue
			}
			if !section.filled {
				t.Errorf("Snapshot.%s was lost because an unrelated endpoint (%s) failed", section.name, broken)
			}
		}
		if rt.timesCalled("admin/imb?form=arp_list") == 0 {
			t.Error("the cycle stopped at the failed endpoint instead of polling the rest")
		}
	})
}

// A reply that arrives and does not parse fails its endpoint the same way a
// refused request does.
func TestUnparsableReplyIsChargedToItsEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name  string
		path  string
		body  json.RawMessage
		empty func(*Snapshot) bool
	}{
		{"a client list wrapped in an object", srcClients, json.RawMessage(`{"deviceList":[]}`),
			func(s *Snapshot) bool { return len(s.Clients) == 0 }},
		{"firmware as a list", srcFirmware, json.RawMessage(`[]`),
			func(s *Snapshot) bool { return s.Firmware == nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newFakeRouter(t)
			rt.answerWith(tc.path, tc.body)
			cfg := testConfig()

			synctest.Test(t, func(t *testing.T) {
				p, stop := startPoller(t, rt, cfg)
				defer stop()

				st := awaitCycle(t, p, cfg)
				snap := st.Snapshot
				if snap == nil {
					t.Fatal("one unparsable reply discarded the whole snapshot")
				}
				if !tc.empty(snap) {
					t.Errorf("%s answered %s and its section filled in regardless", tc.path, tc.body)
				}
				if snap.Errors[tc.path] == nil {
					t.Errorf("Snapshot.Errors has no entry for %s, whose reply did not parse; it holds %v",
						tc.path, snap.Errors)
				}
				if st.EndpointErrors[tc.path] == 0 {
					t.Errorf("EndpointErrors has no count for %s; a parser failure is an endpoint failure "+
						"and tplink_scrape_errors_total{endpoint} is where it shows", tc.path)
				}
			})
		})
	}
}

// status?form=all feeds four parsers and Snapshot.Errors has one slot per path:
// a reply that breaks two of them costs one entry and one count.
func TestOneReplyGetsOneErrorSlot(t *testing.T) {
	rt := newFakeRouter(t)
	// Enough for parseWireless and parseGuestNetworks, nothing for parsePerf or
	// parseWANUptime.
	rt.answerWith(srcStatusAll, json.RawMessage(`{"wireless_2g_enable":"on","wireless_2g_current_channel":"6",
	 "wireless_2g_txpower":"high","guest_2g_enable":"off"}`))
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		st := awaitCycle(t, p, cfg)
		snap := st.Snapshot
		if snap == nil {
			t.Fatal("a reply two parsers could not read discarded the whole snapshot")
		}
		err := snap.Errors[srcStatusAll]
		if err == nil {
			t.Fatalf("no error for %s, whose reply carries neither cpu_usage nor wan_ipv4_uptime", srcStatusAll)
		}
		if !strings.Contains(err.Error(), "cpu_usage") {
			t.Errorf("Snapshot.Errors[%s] = %v; the first failure over a reply is the one kept, and parsePerf "+
				"reads it before parseWANUptime does", srcStatusAll, err)
		}
		cycles := uint64(rt.timesCalled(srcStatusAll))
		if n := st.EndpointErrors[srcStatusAll]; n != cycles {
			t.Errorf("EndpointErrors[%s] = %d over %d cycles; a path takes one count per cycle however many "+
				"parsers read its reply", srcStatusAll, n, cycles)
		}
		if radio, ok := snap.Wireless["2g"]; !ok || radio.Enabled == nil || !*radio.Enabled {
			t.Errorf("Wireless = %v; the parsers that could read the reply still did", snap.Wireless)
		}
	})
}

// A browser taking the web UI is reported, not fought: SessionBlocked set, Up
// false, and the last good snapshot left standing.
func TestSessionBusyIsReportedAndLastSnapshotSurvives(t *testing.T) {
	rt := newFakeRouter(t)
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		first := awaitCycle(t, p, cfg).Snapshot
		if first == nil {
			t.Fatal("the first cycle produced no snapshot")
		}
		takenAt := first.TakenAt

		// Someone opens the web UI.
		rt.refuseLogin(fmt.Errorf("%w (close the browser tab)", tpapi.ErrSessionBusy))

		time.Sleep(4 * cfg.Interval)
		synctest.Wait()

		st := p.State()
		if !st.SessionBlocked {
			t.Errorf("SessionBlocked is false while the router reports ErrSessionBusy; LastErr = %v", st.LastErr)
		}
		if st.Up {
			t.Error("Up is true although the poller could not reach the router's data")
		}
		if !errors.Is(st.LastErr, tpapi.ErrSessionBusy) {
			t.Errorf("LastErr = %v, which does not match tpapi.ErrSessionBusy under errors.Is", st.LastErr)
		}
		if st.Snapshot == nil {
			t.Fatal("the last good snapshot was dropped; the collector decides what to do about its age")
		}
		if !st.Snapshot.TakenAt.Equal(takenAt) {
			t.Errorf("Snapshot.TakenAt moved to %v while the session was blocked; it must keep the time of the cycle that produced it (%v)", st.Snapshot.TakenAt, takenAt)
		}
	})
}

// Anything that is not the session sentinel is a plain outage: Up false,
// SessionBlocked false.
func TestOtherLoginErrorIsNotSessionBlocked(t *testing.T) {
	rt := newFakeRouter(t)
	rt.refuseLogin(errors.New("dial tcp 192.0.2.1:80: connect: no route to host"))
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		st := awaitCycle(t, p, cfg)
		if st.Up {
			t.Error("Up is true although login failed")
		}
		if st.SessionBlocked {
			t.Errorf("SessionBlocked is set for %v; only tpapi.ErrSessionBusy means the web UI is taken", st.LastErr)
		}
		if st.LastErr == nil {
			t.Error("LastErr is nil after a failed login")
		}
		if st.LoginFailures == 0 {
			t.Error("LoginFailures did not count the failed login")
		}
	})
}

// One session, so it is logged into once and reused across cycles.
func TestSessionIsReusedAcrossCycles(t *testing.T) {
	rt := newFakeRouter(t)
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		awaitCycle(t, p, cfg)
		time.Sleep(3 * cfg.Interval)
		synctest.Wait()

		cycles := rt.timesCalled(sources[0].Path)
		if cycles < 3 {
			t.Fatalf("only %d cycles ran in %v; the ticker is not driving the poll", cycles, 3*cfg.Interval)
		}
		if n := len(rt.loginTimes()); n != 1 {
			t.Errorf("logged in %d times over %d cycles; the router has one web session and it must be reused", n, cycles)
		}
		if st := p.State(); st.Logins != 1 {
			t.Errorf("Logins = %d, want 1 login for %d cycles", st.Logins, cycles)
		}
		if rt.logoutCount() != 0 {
			t.Errorf("logged out %d times while still running; the session is dropped only on shutdown", rt.logoutCount())
		}
	})
}

// Shutdown frees the session whatever the last cycle did.
func TestShutdownLogsOut(t *testing.T) {
	for _, tc := range []struct {
		name      string
		breakPoll bool
	}{
		{"after a clean cycle", false},
		{"after a cycle in which every endpoint failed", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newFakeRouter(t)
			if tc.breakPoll {
				rt.failAll(errors.New("errorcode=timeout"))
			}
			cfg := testConfig()

			synctest.Test(t, func(t *testing.T) {
				p, stop := startPoller(t, rt, cfg)
				awaitCycle(t, p, cfg)
				stop()

				if n := rt.logoutCount(); n != 1 {
					t.Errorf("Logout ran %d times, want exactly one on shutdown to free the session", n)
				}
			})
		})
	}
}

// State is read by the collector on every scrape; the maps it hands out must
// not be the poller's own.
func TestStateHandsOutACopy(t *testing.T) {
	const broken = "admin/vpn?form=server"

	rt := newFakeRouter(t)
	rt.fail(broken, errors.New("errorcode=00000002"))
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		st := awaitCycle(t, p, cfg)
		before := st.EndpointErrors[broken]
		if before == 0 {
			t.Fatalf("EndpointErrors has no count for %s, which failed; it holds %v", broken, st.EndpointErrors)
		}

		st.EndpointErrors[broken] = 9999
		st.EndpointErrors["admin/invented?form=x"] = 1
		delete(st.EndpointErrors, broken)

		again := p.State()
		if again.EndpointErrors[broken] != before {
			t.Errorf("EndpointErrors[%s] = %d after a caller edited an earlier State; want %d, the poller's own count", broken, again.EndpointErrors[broken], before)
		}
		if _, ok := again.EndpointErrors["admin/invented?form=x"]; ok {
			t.Error("a key added to a returned State turned up in the poller's counters")
		}
	})
}

// Counters run for the exporter's lifetime: the collector publishes them as
// _total.
func TestCountersOnlyGrow(t *testing.T) {
	t.Run("endpoint errors", func(t *testing.T) {
		const broken = "admin/status?form=wan_speed"

		rt := newFakeRouter(t)
		rt.fail(broken, errors.New("errorcode=00000002"))
		cfg := testConfig()

		synctest.Test(t, func(t *testing.T) {
			p, stop := startPoller(t, rt, cfg)
			defer stop()

			first := awaitCycle(t, p, cfg)
			if first.EndpointErrors[broken] == 0 {
				t.Fatal("the first failure was not counted")
			}
			if first.PollDuration <= 0 {
				t.Error("PollDuration is zero after a finished cycle")
			}

			time.Sleep(3 * cfg.Interval)
			synctest.Wait()

			later := p.State()
			if later.EndpointErrors[broken] <= first.EndpointErrors[broken] {
				t.Errorf("EndpointErrors[%s] went %d -> %d over three more failing cycles; it is a total and only grows",
					broken, first.EndpointErrors[broken], later.EndpointErrors[broken])
			}
			if later.Logins < first.Logins {
				t.Errorf("Logins fell from %d to %d", first.Logins, later.Logins)
			}
			if later.LastAttempt.Before(first.LastAttempt) {
				t.Error("LastAttempt went backwards")
			}
		})
	})

	t.Run("login failures", func(t *testing.T) {
		rt := newFakeRouter(t)
		rt.refuseLogin(fmt.Errorf("%w (close the browser tab)", tpapi.ErrSessionBusy))
		cfg := testConfig()

		synctest.Test(t, func(t *testing.T) {
			p, stop := startPoller(t, rt, cfg)
			defer stop()

			first := awaitCycle(t, p, cfg)
			if first.LoginFailures == 0 {
				t.Fatal("the first failed login was not counted")
			}
			if first.Logins != 0 {
				t.Errorf("Logins = %d although no login succeeded", first.Logins)
			}

			time.Sleep(10 * cfg.MaxBackoff)
			synctest.Wait()

			later := p.State()
			if later.LoginFailures <= first.LoginFailures {
				t.Errorf("LoginFailures went %d -> %d while every login was refused; it is a total and only grows",
					first.LoginFailures, later.LoginFailures)
			}
			if attempts := uint64(len(rt.loginTimes())); later.LoginFailures > attempts {
				t.Errorf("LoginFailures = %d for %d login attempts", later.LoginFailures, attempts)
			}
		})
	})
}

// An endpoint that never answers costs one cycle, not the poller.
func TestBlockedEndpointDoesNotWedgeThePoller(t *testing.T) {
	const stuck = "admin/status?form=all"

	rt := newFakeRouter(t)
	rt.block(stuck)
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		st := awaitCycle(t, p, cfg)
		if st.PollDuration <= 0 {
			t.Error("PollDuration is zero although a cycle finished")
		}
		if slack := cfg.Timeout / 10; st.PollDuration > cfg.Timeout+slack {
			t.Errorf("the cycle ran %v with an endpoint that never answered; Config.Timeout is %v and bounds the whole cycle", st.PollDuration, cfg.Timeout)
		}
		if st.LastErr == nil && st.EndpointErrors[stuck] == 0 {
			t.Errorf("an endpoint that timed out is reported neither in LastErr nor against %s", stuck)
		}

		time.Sleep(3 * cfg.Interval)
		synctest.Wait()

		if n := rt.timesCalled(stuck); n < 3 {
			t.Errorf("%s was tried %d times in %v; a blocked endpoint must not stop the ticker", stuck, n, 3*cfg.Interval)
		}
	})
}

// Login failures are retried on a growing delay, capped.
func TestLoginFailureBacksOff(t *testing.T) {
	rt := newFakeRouter(t)
	rt.refuseLogin(fmt.Errorf("%w (close the browser tab)", tpapi.ErrSessionBusy))

	// Backoff above Interval, so the delays measured below are the backoff and
	// not the ticker.
	cfg := Config{
		Interval:         5 * time.Second,
		Timeout:          2 * time.Second,
		MinBackoff:       10 * time.Second,
		MaxBackoff:       80 * time.Second,
		MaxLoginsPerHour: noLoginCap,
	}

	synctest.Test(t, func(t *testing.T) {
		_, stop := startPoller(t, rt, cfg)
		defer stop()

		const window = 6 * time.Minute
		time.Sleep(window)
		synctest.Wait()

		if n := len(rt.loginTimes()); n < 4 {
			t.Fatalf("%d login attempts in %v; too few to show a backoff", n, window)
		}

		gaps := rt.loginGaps()
		for i, g := range gaps {
			if g < cfg.MinBackoff {
				t.Errorf("retry %d came %v after the previous one, sooner than MinBackoff %v: %v", i+1, g, cfg.MinBackoff, gaps)
			}
			// The gap also carries the failed attempt itself, which
			// Config.Timeout bounds, and a tick the retry may have waited out.
			if slack := cfg.Interval + cfg.Timeout; g > cfg.MaxBackoff+slack {
				t.Errorf("retry %d waited %v, past MaxBackoff %v: %v", i+1, g, cfg.MaxBackoff, gaps)
			}
		}
		if gaps[len(gaps)-1] <= gaps[0] {
			t.Errorf("the wait between retries did not grow: %v", gaps)
		}
	})
}

// Until the first cycle lands the exporter has nothing to serve.
func TestFirstCycleRunsAtStartup(t *testing.T) {
	rt := newFakeRouter(t)
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		st := awaitCycle(t, p, cfg)
		if elapsed := time.Since(start); elapsed >= cfg.Interval {
			t.Errorf("the first cycle finished %v after Run started, a whole Interval of %v away; polling "+
				"begins at startup, not on the first tick", elapsed, cfg.Interval)
		}
		if st.Snapshot == nil {
			t.Error("the first cycle produced no snapshot")
		}
	})
}

func TestRunReturnsNilWhenCancelled(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after time.Duration
	}{
		{"mid-cycle, before the first one finished", 0},
		{"after cycles have run", 90 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newFakeRouter(t)
			cfg := testConfig()

			synctest.Test(t, func(t *testing.T) {
				p := NewPoller(rt, cfg)
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan error, 1)
				go func() { done <- p.Run(ctx) }()

				if tc.after > 0 {
					time.Sleep(tc.after)
				}
				synctest.Wait()
				cancel()

				select {
				case err := <-done:
					if err != nil {
						t.Errorf("Run returned %v; a cancelled context is a clean shutdown and reports nil", err)
					}
				case <-time.After(time.Minute):
					t.Fatal("Run did not return after its context was cancelled")
				}
			})
		})
	}
}

// Config.Timeout covers the login. A router that takes the connection and never
// finishes the login would otherwise wedge the poller for good.
func TestTimeoutBoundsTheCycleIncludingLogin(t *testing.T) {
	rt := newFakeRouter(t)
	rt.hangLogin()
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		st := awaitCycle(t, p, cfg)
		elapsed := time.Since(start)
		if slack := cfg.Timeout / 5; elapsed > cfg.Timeout+slack {
			t.Errorf("the cycle gave up %v after Run started while the login never answered; Config.Timeout "+
				"is %v and bounds the cycle from the login on", elapsed, cfg.Timeout)
		}
		if st.LastErr == nil {
			t.Error("a login that never answered left LastErr nil")
		}
		if st.Up {
			t.Error("Up is true although the login never completed")
		}

		window := 4 * (cfg.Interval + cfg.Timeout)
		time.Sleep(window)
		synctest.Wait()
		if n := len(rt.loginTimes()); n < 2 {
			t.Errorf("%d login attempts in %v; a login that timed out is retried, not fatal", n, window)
		}
	})
}

// The timeout is spent once over the cycle, not per request.
func TestTimeoutIsSpentOncePerCycle(t *testing.T) {
	rt := newFakeRouter(t)
	rt.block("admin/status?form=all")
	rt.block("admin/vpn?form=server")
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		st := awaitCycle(t, p, cfg)
		if st.PollDuration <= 0 {
			t.Fatal("PollDuration is zero although a cycle finished")
		}
		if slack := cfg.Timeout / 5; st.PollDuration > cfg.Timeout+slack {
			t.Errorf("a cycle with two endpoints that never answer ran %v; Config.Timeout is %v and bounds "+
				"the whole cycle, so two dead endpoints cost one timeout between them", st.PollDuration, cfg.Timeout)
		}
	})
}

// The interval is the period of the cycle, not the pause after it.
func TestTheCyclePeriodIsTheInterval(t *testing.T) {
	rt := newFakeRouter(t)
	// An endpoint that never answers costs the whole timeout, a third of the
	// interval, in every cycle.
	rt.block(srcStatusAll)
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		awaitCycle(t, p, cfg)
		window := 4 * cfg.Interval
		time.Sleep(window)
		synctest.Wait()

		gaps := rt.callGaps(sources[0].Path)
		if len(gaps) < 3 {
			t.Fatalf("%d cycles in %v, too few to measure the period: %v", len(gaps)+1, window, gaps)
		}
		slack := cfg.Timeout / 10
		for i, g := range gaps {
			if g < cfg.Interval-slack || g > cfg.Interval+slack {
				t.Errorf("cycle %d began %v after the one before it, want %v: the cycle spends %v of that "+
					"and the wait is what is left. Gaps: %v", i+2, g, cfg.Interval, cfg.Timeout, gaps)
			}
		}
	})
}

func TestBackoffDoublesToTheCap(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want []time.Duration
	}{
		{
			// Interval well under MinBackoff, so max(Interval, backoff) is the
			// backoff throughout.
			name: "the cap is a doubling of the floor",
			cfg: Config{
				Interval:         time.Second,
				Timeout:          2 * time.Second,
				MinBackoff:       10 * time.Second,
				MaxBackoff:       40 * time.Second,
				MaxLoginsPerHour: noLoginCap,
			},
			want: []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 40 * time.Second},
		},
		{
			// It is not, here: the third wait is MaxBackoff itself and not the 40s
			// the doubling would have reached.
			name: "the cap is not a doubling of the floor",
			cfg: Config{
				Interval:         time.Second,
				Timeout:          2 * time.Second,
				MinBackoff:       10 * time.Second,
				MaxBackoff:       25 * time.Second,
				MaxLoginsPerHour: noLoginCap,
			},
			want: []time.Duration{10 * time.Second, 20 * time.Second, 25 * time.Second, 25 * time.Second},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newFakeRouter(t)
			rt.refuseLogin(fmt.Errorf("%w (close the browser tab)", tpapi.ErrSessionBusy))

			synctest.Test(t, func(t *testing.T) {
				_, stop := startPoller(t, rt, tc.cfg)
				defer stop()

				const window = 4 * time.Minute
				time.Sleep(window)
				synctest.Wait()

				gaps := rt.loginGaps()
				if len(gaps) < len(tc.want) {
					t.Fatalf("%d retries in %v, too few to show the doubling: %v", len(gaps), window, gaps)
				}
				// A gap also carries the refused attempt itself and, at worst, a tick
				// the retry waited out.
				slack := tc.cfg.Interval + tc.cfg.Timeout
				for i, w := range tc.want {
					if gaps[i] < w || gaps[i] > w+slack {
						t.Errorf("retry %d came %v after the previous one, want %v: the wait doubles from %v "+
							"and holds at %v, with nothing random on top. Gaps: %v",
							i+1, gaps[i], w, tc.cfg.MinBackoff, tc.cfg.MaxBackoff, gaps)
					}
				}
			})
		})
	}
}

// A cycle that succeeded drops the backoff.
func TestBackoffIsDroppedAfterASuccessfulCycle(t *testing.T) {
	blocked := fmt.Errorf("%w (close the browser tab)", tpapi.ErrSessionBusy)

	rt := newFakeRouter(t)
	rt.refuseLogin(blocked)
	cfg := Config{
		Interval:         5 * time.Second,
		Timeout:          2 * time.Second,
		MinBackoff:       20 * time.Second,
		MaxBackoff:       160 * time.Second,
		MaxLoginsPerHour: noLoginCap,
	}

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		awaitCycle(t, p, cfg)
		// Three refusals in, the wait has doubled twice.
		time.Sleep(130 * time.Second)
		synctest.Wait()

		rt.allowLogin()
		time.Sleep(cfg.MaxBackoff)
		synctest.Wait()
		if st := p.State(); !st.Up {
			t.Fatalf("no cycle succeeded within %v of the router accepting logins again; LastErr = %v",
				cfg.MaxBackoff, st.LastErr)
		}

		rt.refuseLogin(blocked)
		attempts := len(rt.loginTimes())
		window := 4 * cfg.MinBackoff
		time.Sleep(window)
		synctest.Wait()

		if n := len(rt.loginTimes()) - attempts; n < 2 {
			t.Errorf("%d login attempts in the %v after the router went away a second time; the wait had "+
				"grown to %v before it came back, and a cycle that succeeded drops that, so the retries "+
				"start over at MinBackoff %v", n, window, cfg.MaxBackoff, cfg.MinBackoff)
		}
	})
}

// A backoff shorter than the interval must not turn a failure into faster
// polling.
func TestBackoffNeverPollsFasterThanTheInterval(t *testing.T) {
	rt := newFakeRouter(t)
	rt.refuseLogin(fmt.Errorf("%w (close the browser tab)", tpapi.ErrSessionBusy))

	cfg := Config{
		Interval:         30 * time.Second,
		Timeout:          5 * time.Second,
		MinBackoff:       time.Second,
		MaxBackoff:       4 * time.Second,
		MaxLoginsPerHour: noLoginCap,
	}

	synctest.Test(t, func(t *testing.T) {
		_, stop := startPoller(t, rt, cfg)
		defer stop()

		const window = 3 * time.Minute
		time.Sleep(window)
		synctest.Wait()

		gaps := rt.loginGaps()
		if len(gaps) < 3 {
			t.Fatalf("%d retries in %v, too few to measure: %v", len(gaps), window, gaps)
		}
		for i, g := range gaps {
			if g < cfg.Interval {
				t.Errorf("retry %d came %v after the previous one, inside the interval of %v; the wait is "+
					"max(Interval, backoff) and the whole backoff range here (%v..%v) is below it",
					i+1, g, cfg.Interval, cfg.MinBackoff, cfg.MaxBackoff)
			}
		}
	})
}

// Backoff belongs to a refused login or a cycle in which nothing answered, not
// to a partial one.
func TestPartialCycleDoesNotArmBackoff(t *testing.T) {
	const broken = "admin/dhcps?form=client"

	rt := newFakeRouter(t)
	rt.fail(broken, errors.New("errorcode=00000002"))

	// Backoff far above the interval, so an armed one is unmistakable.
	cfg := Config{
		Interval:   5 * time.Second,
		Timeout:    4 * time.Second,
		MinBackoff: time.Minute,
		MaxBackoff: 5 * time.Minute,
	}

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		const window = 30 * time.Second
		time.Sleep(window)
		synctest.Wait()

		cycles := rt.timesCalled(sources[0].Path)
		if want := int(window/cfg.Interval) - 1; cycles < want {
			t.Errorf("%d cycles in %v at an interval of %v, want at least %d; one failed endpoint armed the "+
				"backoff (MinBackoff %v) although the rest of the cycle landed",
				cycles, window, cfg.Interval, want, cfg.MinBackoff)
		}
		if st := p.State(); st.Snapshot == nil {
			t.Error("no snapshot from cycles that lost a single endpoint")
		}
	})
}

// backoffConfig puts the whole backoff range above the interval, twelve cycles
// inside the first wait.
func backoffConfig() Config {
	return Config{
		Interval:         10 * time.Second,
		Timeout:          5 * time.Second,
		MinBackoff:       2 * time.Minute,
		MaxBackoff:       8 * time.Minute,
		SessionCooldown:  30 * time.Minute,
		MaxLoginsPerHour: noLoginCap,
	}
}

// cyclesRun counts the cycles of an outage: each one either attempted the login
// or was held back from it.
func cyclesRun(st State, rt *fakeRouter) uint64 {
	return st.LoginsSuppressed + uint64(len(rt.loginTimes()))
}

// backoffSchedule is when a login was attempted while the backoff was the wait
// itself: the attempts fell on the partial sums of max(Interval, backoff).
func backoffSchedule(cfg Config, window time.Duration) []time.Duration {
	var at []time.Duration
	var backoff time.Duration
	for t := time.Duration(0); t <= window; {
		at = append(at, t)
		switch {
		case backoff == 0:
			backoff = cfg.MinBackoff
		case backoff >= cfg.MaxBackoff/2:
			backoff = cfg.MaxBackoff
		default:
			backoff *= 2
		}
		t += max(cfg.Interval, backoff)
	}
	return at
}

// A refused login sets when the next login is tried; the cycle keeps the
// interval.
func TestRefusedLoginKeepsTheCycleOnTheInterval(t *testing.T) {
	rt := newFakeRouter(t)
	rt.refuseLogin(errors.New("dial tcp 192.0.2.1:80: connect: connection refused"))
	cfg := backoffConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		const window = 20 * time.Minute
		time.Sleep(window)
		synctest.Wait()

		st := p.State()
		want := uint64(window/cfg.Interval) - 1
		if got := cyclesRun(st, rt); got < want {
			t.Errorf("%d cycles in %v at an interval of %v, want at least %d; the backoff (%v..%v) is the "+
				"delay before the next login and not the period of the cycle, and a cycle that skips the "+
				"login still runs, publishes tplink_up 0 and counts itself",
				got, window, cfg.Interval, want, cfg.MinBackoff, cfg.MaxBackoff)
		}
	})
}

// The login keeps the backoff: it is tried when the wait has run out and not on
// the cycles in between.
func TestBackoffStillWithholdsTheLogin(t *testing.T) {
	rt := newFakeRouter(t)
	rt.refuseLogin(errors.New("dial tcp 192.0.2.1:80: connect: connection refused"))
	cfg := backoffConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		const window = 25 * time.Minute
		time.Sleep(window)
		synctest.Wait()

		want := []time.Duration{2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 8 * time.Minute}
		gaps := rt.loginGaps()
		if len(gaps) < len(want) {
			t.Fatalf("%d retries in %v, too few to measure: %v", len(gaps), window, gaps)
		}
		for i, w := range want {
			// The wait runs out between two cycles and the login waits for the
			// next one: at most an interval late, never early.
			if gaps[i] < w || gaps[i] >= w+cfg.Interval {
				t.Errorf("retry %d came %v after the previous one, want %v: the cycle runs every %v while "+
					"the router is away, and the login is what the backoff holds back. Gaps: %v",
					i+1, gaps[i], w, cfg.Interval, gaps)
			}
		}
		if st := p.State(); st.LoginsSuppressed == 0 {
			t.Error("LoginsSuppressed = 0 although the cycles between the retries were held back from " +
				"logging in; a cycle that skips the login counts one")
		}
	})
}

// Separating the cycle from the wait leaves the login schedule where it was,
// and the schedule is what the backoff is for.
func TestBackoffTriesNoMoreLoginsThanTheWaitDid(t *testing.T) {
	t.Run("the attempts keep the schedule they had", func(t *testing.T) {
		rt := newFakeRouter(t)
		rt.refuseLogin(errors.New("dial tcp 192.0.2.1:80: connect: connection refused"))
		cfg := backoffConfig()

		synctest.Test(t, func(t *testing.T) {
			start := time.Now()
			_, stop := startPoller(t, rt, cfg)
			defer stop()

			const window = 40 * time.Minute
			time.Sleep(window)
			synctest.Wait()

			was := backoffSchedule(cfg, window)
			got := rt.loginTimes()
			if len(got) > len(was) {
				t.Errorf("%d login attempts in %v against the %d the wait made before, at %v; the backoff "+
					"still decides when a login is tried, and more of them an hour is what the firmware's "+
					"two-hour lock answers", len(got), window, len(was), was)
			}
			for i, at := range got {
				if i >= len(was) {
					break
				}
				if since := at.Sub(start); since < was[i] {
					t.Errorf("login %d came at %v, before the %v the wait made before it: %v against %v",
						i+1, since, was[i], sinceAll(got, start), was)
				}
			}
		})
	})

	t.Run("no hour carries more than the cap", func(t *testing.T) {
		rt := newFakeRouter(t)
		rt.refuseLogin(errors.New("dial tcp 192.0.2.1:80: connect: connection refused"))
		cfg := Config{
			Interval:         time.Minute,
			Timeout:          30 * time.Second,
			MinBackoff:       time.Minute,
			MaxBackoff:       15 * time.Minute,
			SessionCooldown:  5 * time.Minute,
			MaxLoginsPerHour: 6,
		}

		synctest.Test(t, func(t *testing.T) {
			start := time.Now()
			_, stop := startPoller(t, rt, cfg)
			defer stop()

			const window = 3 * time.Hour
			time.Sleep(window)
			synctest.Wait()

			at := rt.loginTimes()
			if len(at) <= cfg.MaxLoginsPerHour {
				t.Fatalf("%d login attempts in %v against a cap of %d; the cap has to bite more than once "+
					"before there is anything to measure", len(at), window, cfg.MaxLoginsPerHour)
			}
			for i, from := range at {
				n := 0
				for _, other := range at {
					if !other.Before(from) && other.Sub(from) < lossWindow {
						n++
					}
				}
				if n > cfg.MaxLoginsPerHour {
					t.Errorf("%d login attempts in the hour from %v, attempt %d of %v, against a cap of %d; "+
						"the cap is a proxy for the firmware's two-hour lock and a cycle that runs anyway "+
						"must not spend it", n, from.Sub(start), i+1, sinceAll(at, start), cfg.MaxLoginsPerHour)
				}
			}
		})
	})
}

// sinceAll is a run of times as offsets from start, for an error message.
func sinceAll(at []time.Time, start time.Time) []time.Duration {
	out := make([]time.Duration, 0, len(at))
	for _, t := range at {
		out = append(out, t.Sub(start))
	}
	return out
}

// OnCycle, which push sends on, runs once an interval through an outage, inside
// the longest wait as much as the first.
func TestOnCycleKeepsTheIntervalThroughTheBackoff(t *testing.T) {
	rt := newFakeRouter(t)
	rt.refuseLogin(errors.New("dial tcp 192.0.2.1:80: connect: connection refused"))
	cfg := backoffConfig()
	var hook cycleHook
	cfg.OnCycle = hook.fn()

	synctest.Test(t, func(t *testing.T) {
		_, stop := startPoller(t, rt, cfg)
		defer stop()

		// Past the third doubling, so what is measured below sits inside a wait
		// of MaxBackoff.
		time.Sleep(15 * time.Minute)
		synctest.Wait()
		before := hook.count()

		const window = 5 * time.Minute
		time.Sleep(window)
		synctest.Wait()
		got := hook.records()

		if want := int(window/cfg.Interval) - 1; len(got)-before < want {
			t.Errorf("the hook ran %d times over the %v inside a wait of %v, want at least %d; the sends are "+
				"what says the exporter is alive while the router is not, and a window a few cycles wide is "+
				"what an operator alerts on", len(got)-before, window, cfg.MaxBackoff, want)
		}
		for i := before + 1; i < len(got); i++ {
			if gap := got[i].At.Sub(got[i-1].At); gap > cfg.Interval+cfg.Timeout {
				t.Errorf("send %d came %v after the one before it, past the interval of %v; the backoff sets "+
					"the next login, not the next send", i+1, gap, cfg.Interval)
			}
		}
	})
}

// A cycle the backoff held back is still a cycle: Up says the router is not
// answering and LastAttempt moves.
func TestBackoffHeldCycleStillReportsItself(t *testing.T) {
	rt := newFakeRouter(t)
	rt.refuseLogin(errors.New("dial tcp 192.0.2.1:80: connect: connection refused"))
	cfg := backoffConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		// Both samples sit between the second attempt and the third, so nothing
		// between them reached the router.
		const early, late = 3 * time.Minute, 5 * time.Minute
		time.Sleep(early)
		synctest.Wait()
		first := p.State()

		time.Sleep(late - early)
		synctest.Wait()
		second := p.State()

		if n := len(rt.loginTimes()); n != 2 {
			t.Fatalf("%d login attempts by %v, want the two at 0 and %v; the samples have to bracket cycles "+
				"the backoff alone held back", n, late, cfg.MinBackoff)
		}
		if second.Up {
			t.Error("Up is true on a cycle held back from logging in; nothing reached the router")
		}
		if !second.LastAttempt.After(first.LastAttempt) {
			t.Errorf("LastAttempt stood still at %v across %v of the backoff; a cycle that skips the login "+
				"still runs, and tplink_scrape_duration_seconds and the snapshot age come off it",
				first.LastAttempt, late-early)
		}
	})
}

// A cycle the backoff held back is a suppressed login, as under the cooldown
// and the cap: LoginsSuppressed grows, LoginFailures and SessionBlocked do not.
func TestBackoffCountsTheLoginsItHeldBack(t *testing.T) {
	rt := newFakeRouter(t)
	rt.refuseLogin(errors.New("dial tcp 192.0.2.1:80: connect: connection refused"))
	cfg := backoffConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		const early, late = 3 * time.Minute, 5 * time.Minute
		time.Sleep(early)
		synctest.Wait()
		first := p.State()

		time.Sleep(late - early)
		synctest.Wait()
		second := p.State()

		cycles := uint64((late - early) / cfg.Interval)
		if grew := second.LoginsSuppressed - first.LoginsSuppressed; grew < cycles*3/4 {
			t.Errorf("LoginsSuppressed went %d -> %d over the %v between the samples, about %d cycles of %v; "+
				"the backoff holds back one login per cycle and counts one, the way the cooldown and the cap "+
				"already do", first.LoginsSuppressed, second.LoginsSuppressed, late-early, cycles, cfg.Interval)
		}
		if second.LoginFailures != 2 {
			t.Errorf("LoginFailures = %d by %v; the backoff let two attempts through, and a login it held "+
				"back never reached the router and is a suppression, not a failure", second.LoginFailures, late)
		}
		if second.SessionBlocked {
			t.Error("SessionBlocked is set while the backoff is what is holding the login back; the router " +
				"refused the connection outright and no session was taken")
		}
	})
}

// The cooldown outranks the cap, and the cap the backoff, in the reason a hold
// is logged.
func TestHoldReasonsKeepTheirOrder(t *testing.T) {
	now := time.Now()
	spent := []time.Time{now.Add(-time.Minute), now.Add(-2 * time.Minute)}

	for _, tc := range []struct {
		name string
		set  func(*Poller)
		want string
	}{
		{"nothing holds the login back", func(*Poller) {}, ""},
		{"the backoff alone", func(p *Poller) {
			p.loginAfter = now.Add(time.Minute)
		}, holdBackoff},
		{"the cap over the backoff", func(p *Poller) {
			p.loginAfter = now.Add(time.Minute)
			p.loginHistory = spent
		}, holdLoginCap},
		{"the cooldown over both", func(p *Poller) {
			p.loginAfter = now.Add(time.Minute)
			p.loginHistory = spent
			p.quietUntil = now.Add(time.Minute)
		}, holdSessionTaken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.MaxLoginsPerHour = len(spent)
			p := NewPoller(newFakeRouter(t), cfg)
			tc.set(p)

			wait, why := p.holdOff(now)
			if why != tc.want {
				t.Errorf("holdOff reports %q, want %q; the reason is what an operator reads off the log "+
					"line, and the three are not equally serious", why, tc.want)
			}
			want := cfg.Interval
			if tc.want == "" {
				want = 0
			}
			if wait != want {
				t.Errorf("holdOff asks for %v, want %v; a hold returns the interval rather than what is "+
					"left of it, so the cycle keeps its rhythm and its counters", wait, want)
			}
		})
	}
}

// With the cap and the backoff both holding, the log line names the cap.
func TestLoginCapOutranksTheBackoffInTheLog(t *testing.T) {
	logged := captureLog(t, slog.LevelInfo)
	rt := newFakeRouter(t)
	rt.refuseLogin(errors.New("dial tcp 192.0.2.1:80: connect: connection refused"))
	cfg := Config{
		Interval:         time.Minute,
		Timeout:          10 * time.Second,
		MinBackoff:       5 * time.Minute,
		MaxBackoff:       20 * time.Minute,
		SessionCooldown:  time.Hour,
		MaxLoginsPerHour: 2,
	}

	synctest.Test(t, func(t *testing.T) {
		_, stop := startPoller(t, rt, cfg)
		defer stop()

		// The first wait: one attempt made, the cap still has room, so the
		// backoff is the only thing holding.
		time.Sleep(4 * time.Minute)
		synctest.Wait()
		named := logged.count(holdBackoff)
		if named == 0 {
			t.Fatalf("nothing was held back by the backoff in the %v after the first refusal, which arms a "+
				"wait of %v. Log:\n%s", 4*time.Minute, cfg.MinBackoff, logged)
		}
		if n := logged.count(holdLoginCap); n != 0 {
			t.Fatalf("the cap was named %d times after one attempt of %d; there is no priority to measure "+
				"until it is reached. Log:\n%s", n, cfg.MaxLoginsPerHour, logged)
		}

		// The second attempt spends the cap, and it arms a wait of ten minutes:
		// from here both hold.
		time.Sleep(10 * time.Minute)
		synctest.Wait()

		if logged.count(holdLoginCap) == 0 {
			t.Errorf("no cycle named the cap although %d attempts have been made against a cap of %d. "+
				"Log:\n%s", len(rt.loginTimes()), cfg.MaxLoginsPerHour, logged)
		}
		if n := logged.count(holdBackoff) - named; n != 0 {
			t.Errorf("%d cycles named the backoff while the cap was holding the login back too; the cap "+
				"stands for the firmware's two-hour lock and is what an operator has to read. Log:\n%s",
				n, logged)
		}
	})
}

// A cycle that ran out of Config.Timeout is held the way a refused login is.
func TestCycleOutOfTimeHoldsTheLoginNotTheCycle(t *testing.T) {
	// The first source hangs, so the cycle ends on the deadline having gathered
	// nothing.
	stuck := sources[0].Path

	rt := newFakeRouter(t)
	rt.block(stuck)
	cfg := backoffConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		const window = 20 * time.Minute
		time.Sleep(window)
		synctest.Wait()

		st := p.State()
		want := uint64(window/cfg.Interval) - 1
		if got := cyclesRun(st, rt); got < want {
			t.Errorf("%d cycles in %v at an interval of %v, want at least %d; a cycle that ran out of "+
				"Config.Timeout arms the backoff, and the backoff is the delay before the next login, not "+
				"the period of the cycle", got, window, cfg.Interval, want)
		}
		if !errors.Is(st.LastErr, context.DeadlineExceeded) {
			t.Fatalf("LastErr = %v; %s never answers, so the cycles measured here are the ones that ran out "+
				"of the %v deadline", st.LastErr, stuck, cfg.Timeout)
		}
		gaps := rt.loginGaps()
		if len(gaps) < 3 {
			t.Fatalf("%d retries in %v, too few to measure: %v", len(gaps), window, gaps)
		}
		for i, g := range gaps {
			if g < cfg.MinBackoff {
				t.Errorf("retry %d came %v after the previous one, inside MinBackoff %v; a cycle that timed "+
					"out withholds the login exactly as a refused one does. Gaps: %v",
					i+1, g, cfg.MinBackoff, gaps)
			}
		}
	})
}

// The two lines that arm the backoff carry retry_in, the login's wait; the held
// cycles carry next_cycle_in, the interval — two numbers under two names.
func TestTheArmedBackoffIsLogged(t *testing.T) {
	for _, tc := range []struct {
		name, msg string
		setup     func(*fakeRouter)
	}{
		{"a refused login", "login failed", func(rt *fakeRouter) {
			rt.refuseLogin(errors.New("dial tcp 192.0.2.1:80: connect: connection refused"))
		}},
		{"a cycle out of time", "the cycle ran out of time", func(rt *fakeRouter) {
			rt.block(sources[0].Path)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logged := captureLog(t, slog.LevelInfo)
			rt := newFakeRouter(t)
			tc.setup(rt)
			cfg := backoffConfig()

			synctest.Test(t, func(t *testing.T) {
				_, stop := startPoller(t, rt, cfg)
				defer stop()

				const window = 25 * time.Minute
				time.Sleep(window)
				synctest.Wait()

				want := []time.Duration{2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 8 * time.Minute}
				recs := logged.records(tc.msg)
				if len(recs) < len(want) {
					t.Fatalf("%d %q records in %v, too few to read the wait off. Log:\n%s",
						len(recs), tc.msg, window, logged)
				}
				for i, w := range want {
					if attr := "retry_in=" + w.String(); !strings.Contains(recs[i], attr) {
						t.Errorf("record %d carries no %s: %s\nthe wait this cycle armed is the login's, and "+
							"the interval of %v is what the cycles it holds back report", i+1, attr, recs[i],
							cfg.Interval)
					}
				}

				held := logged.records(holdBackoff)
				if len(held) == 0 {
					t.Fatalf("no cycle was held back by the backoff over the %v. Log:\n%s", window, logged)
				}
				for i, rec := range held {
					if attr := "next_cycle_in=" + cfg.Interval.String(); !strings.Contains(rec, attr) {
						t.Errorf("held record %d carries no %s: %s", i+1, attr, rec)
					}
					if strings.Contains(rec, "retry_in=") {
						t.Errorf("held record %d names retry_in: %s\nthe line that armed the wait says "+
							"retry_in=%v and means the login; this one is the interval and means the cycle",
							i+1, rec, want[0])
					}
				}
			})
		})
	}
}

// A cycle in which nothing answered is a lost session however the firmware
// worded it, and is answered the same way: come back once, and go quiet if it
// happens again straight after. Anything else leaves a path by which a browser
// on this machine is evicted every cycle.
func TestCycleWithNothingAnsweringIsALostSession(t *testing.T) {
	rt := newFakeRouter(t)
	rt.failAll(errors.New("errorcode=00000002"))
	cfg := testConfig()
	// Long enough that the whole window below sits inside it.
	cfg.SessionCooldown = 20 * time.Minute

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		// Inside the first cycle's wait: one cycle has reached nothing.
		time.Sleep(cfg.Interval / 2)
		synctest.Wait()

		first := p.State()
		if first.SessionsLost != 1 {
			t.Errorf("SessionsLost = %d after one cycle in which all %d endpoints failed, want 1: nothing "+
				"answering is the session being gone, whatever errorCode came back",
				first.SessionsLost, len(sources))
		}
		if first.SessionBlocked {
			t.Error("SessionBlocked is set after the first such cycle; one loss says nothing")
		}

		// Inside the second cycle's wait.
		time.Sleep(cfg.Interval)
		synctest.Wait()

		if n := len(rt.loginTimes()); n != 2 {
			t.Errorf("%d logins by the second cycle, want 2: the first cycle to reach nothing drops the "+
				"session, and one loss is answered with a login like any other", n)
		}

		window := 6 * cfg.Interval
		time.Sleep(window)
		synctest.Wait()

		st := p.State()
		if n := len(rt.loginTimes()); n != 2 {
			t.Errorf("%d logins in the %v after the second cycle reached nothing too, want 2: it came %v "+
				"after the first, inside the cooldown of %v, so the poller goes quiet rather than logging "+
				"in every cycle — that reflex is what evicts the person at the browser",
				n, window, cfg.Interval, cfg.SessionCooldown)
		}
		if !st.SessionBlocked {
			t.Errorf("SessionBlocked is false after two cycles running in which nothing answered; LastErr = %v",
				st.LastErr)
		}
		if st.SessionsLost != 2 {
			t.Errorf("SessionsLost = %d, want 2", st.SessionsLost)
		}
	})
}

// The other reason nothing answers: our own deadline. One endpoint that never
// replies eats the whole of Config.Timeout, every Call after it fails at once,
// and the cycle collects nothing — which says the router is sick, not that a
// person has the web UI. Calling it a lost session parked the poller and pinned
// tplink_session_blocked at 1, the metric README.md tells operators to silence
// their alerts on.
func TestCycleThatRanOutOfTimeIsNotALostSession(t *testing.T) {
	// The first source is the one that hangs, so nothing is gathered before the
	// deadline and the cycle ends on it rather than on a partial snapshot.
	stuck := sources[0].Path

	rt := newFakeRouter(t)
	rt.block(stuck)

	cfg := Config{
		Interval: 30 * time.Second,
		Timeout:  10 * time.Second,
		// The whole backoff range sits under Interval, so the period below is the
		// ticker and any pause longer than it comes from the session policy.
		MinBackoff:       time.Second,
		MaxBackoff:       5 * time.Second,
		SessionCooldown:  10 * time.Minute,
		MaxLoginsPerHour: noLoginCap,
	}

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		window := 10 * cfg.Interval
		time.Sleep(window)
		synctest.Wait()

		st := p.State()
		cycles := int(window / cfg.Interval)
		if st.SessionsLost != 0 {
			t.Errorf("SessionsLost = %d over %v in which %s never answered; running out of Config.Timeout "+
				"is the exporter's own deadline and leaves the session where it was",
				st.SessionsLost, window, stuck)
		}
		if st.SessionBlocked {
			t.Errorf("SessionBlocked is set although no login was refused and no session was taken; a router "+
				"that stopped answering would silence every alert written as `unless tplink_session_blocked`. "+
				"LastErr = %v", st.LastErr)
		}
		if st.LoginsSuppressed != 0 {
			t.Errorf("LoginsSuppressed = %d; the poller went quiet over a hung endpoint, and the cooldown of "+
				"%v is time an operator spends with no metrics at all", st.LoginsSuppressed, cfg.SessionCooldown)
		}
		if st.Up {
			t.Error("Up is true although no cycle collected anything")
		}
		if !errors.Is(st.LastErr, context.DeadlineExceeded) {
			t.Errorf("LastErr = %v; the cycle ended on Config.Timeout of %v and that is what it reports",
				st.LastErr, cfg.Timeout)
		}
		if st.Snapshot != nil {
			t.Error("a cycle that gathered nothing published a snapshot of its own")
		}
		if st.EndpointErrors[stuck] == 0 {
			t.Errorf("EndpointErrors has no count for %s, which never answered; the endpoint that ate the "+
				"cycle is where tplink_scrape_errors_total{endpoint} points at it", stuck)
		}
		if n := len(rt.loginTimes()); n < cycles-1 {
			t.Errorf("%d logins in %v, about %d cycles of %v; a cycle that timed out backs off like any other "+
				"failure, and the whole backoff range here (%v..%v) is under the interval, so the poller keeps "+
				"asking rather than going quiet for %v at a time",
				n, window, cycles, cfg.Interval, cfg.MinBackoff, cfg.MaxBackoff, cfg.SessionCooldown)
		}
		if n := rt.timesCalled(stuck); n < cycles-1 {
			t.Errorf("%s was tried %d times in %v, about %d cycles of %v; the poller stopped talking to the "+
				"router over its own deadline", stuck, n, window, cycles, cfg.Interval)
		}
	})
}

func TestFailedCycleCountsItsEndpointsAndKeepsTheSnapshot(t *testing.T) {
	rt := newFakeRouter(t)
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		first := awaitCycle(t, p, cfg).Snapshot
		if first == nil {
			t.Fatal("the first cycle produced no snapshot")
		}

		rt.failAll(errors.New("errorcode=00000002"))
		time.Sleep(3 * cfg.Interval)
		synctest.Wait()

		st := p.State()
		if st.Snapshot != first {
			t.Error("a cycle in which nothing answered replaced the last good snapshot")
		}
		for _, s := range sources {
			if st.EndpointErrors[s.Path] == 0 {
				t.Errorf("EndpointErrors has no count for %s, which failed in a cycle that produced nothing; "+
					"a failed cycle still charges the endpoints it lost", s.Path)
			}
		}
	})
}

// The other end of the same rule: a cycle that reached no endpoint publishes
// nothing. An empty snapshot with a fresh TakenAt reads as current.
func TestCycleThatCollectedNothingKeepsTheSnapshot(t *testing.T) {
	rt := newFakeRouter(t)
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		first := awaitCycle(t, p, cfg).Snapshot
		if first == nil {
			t.Fatal("the first cycle produced no snapshot")
		}
		// The session is taken at the cycle's first request, so the cycle ends
		// there with nothing collected.
		rt.expireAt(sources[0].Path)

		// Between that cycle and the one that logs in again and replaces the
		// snapshot for good reasons.
		time.Sleep(cfg.Interval + cfg.Interval/2)
		synctest.Wait()

		st := p.State()
		if st.Snapshot != first {
			t.Errorf("a cycle that collected nothing published a snapshot of its own: %d clients, WAN %v, "+
				"taken at %v. The last good snapshot must stand, as it does when every endpoint fails",
				len(st.Snapshot.Clients), st.Snapshot.WAN, st.Snapshot.TakenAt)
		}
	})
}

// Publishing and counting are two decisions over one cycle. A session taken at
// the very first endpoint gathers nothing, so the last good snapshot stands —
// and the endpoint it died on is charged all the same. Taking the two together
// left the first endpoint uncharged, under-reporting exactly where the trouble
// began.
func TestSessionLostAtTheFirstEndpointIsStillChargedToIt(t *testing.T) {
	died := sources[0].Path

	rt := newFakeRouter(t)
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		first := awaitCycle(t, p, cfg).Snapshot
		if first == nil {
			t.Fatal("the first cycle produced no snapshot")
		}
		rt.expireAt(died)

		// Between the cycle that loses the session at its first request and the
		// one that logs in again.
		time.Sleep(cfg.Interval + cfg.Interval/2)
		synctest.Wait()

		st := p.State()
		if st.SessionsLost != 1 {
			t.Fatalf("SessionsLost = %d after the session was taken at %s, want 1", st.SessionsLost, died)
		}
		if n := st.EndpointErrors[died]; n != 1 {
			t.Errorf("EndpointErrors[%s] = %d, want 1: the session died on that request, so it failed like "+
				"any other and tplink_scrape_errors_total{endpoint} is where the trouble first shows. A "+
				"cycle that publishes nothing still counts what it lost", died, n)
		}
		for _, s := range sources[1:] {
			if n := st.EndpointErrors[s.Path]; n != 0 {
				t.Errorf("EndpointErrors[%s] = %d although the cycle ended before it was asked", s.Path, n)
			}
		}
		if st.Snapshot != first {
			t.Error("a cycle that gathered no reply replaced the last good snapshot; publishing follows the " +
				"count of replies gathered, not the count of errors")
		}
		if st.Up {
			t.Error("Up is true although the cycle ended on a dead session")
		}
	})
}

// A reply that could not be decoded is one endpoint, not the session. The UI
// calls it a dead session because it has nowhere else to go; here it would end
// every cycle early, count a loss, and arm the cooldown over a single endpoint.
func TestUnreadableReplyIsAnOrdinaryEndpointFailure(t *testing.T) {
	const broken = srcPorts

	rt := newFakeRouter(t)
	rt.fail(broken, fmt.Errorf("%w (decrypt reply)", tpapi.ErrReplyUnreadable))
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		st := awaitCycle(t, p, cfg)
		snap := st.Snapshot
		if snap == nil {
			t.Fatal("one reply that could not be decoded discarded the whole snapshot")
		}
		if snap.Errors[broken] == nil {
			t.Errorf("Snapshot.Errors has no entry for %s, whose reply could not be decoded; it holds %v",
				broken, snap.Errors)
		}
		if len(snap.Errors) != 1 {
			t.Errorf("one reply could not be decoded, %d endpoints are reported: %v", len(snap.Errors), snap.Errors)
		}
		if st.EndpointErrors[broken] == 0 {
			t.Errorf("EndpointErrors has no count for %s; an undecodable reply is an endpoint failure and "+
				"tplink_scrape_errors_total{endpoint} is where it shows", broken)
		}
		if rt.timesCalled(srcMesh) == 0 {
			t.Errorf("the cycle ended at %s instead of polling the rest; only a session that is really gone "+
				"takes the endpoints after it", broken)
		}
		if !st.Up {
			t.Errorf("Up is false although every endpoint but %s answered; LastErr = %v", broken, st.LastErr)
		}

		// The policy half: none of this is the session going away.
		window := 4 * cfg.Interval
		time.Sleep(window)
		synctest.Wait()

		later := p.State()
		if later.SessionsLost != 0 {
			t.Errorf("SessionsLost = %d over %v in which %s answered unreadably every cycle; that is one "+
				"endpoint, and a session really gone would have taken every endpoint after it too",
				later.SessionsLost, window, broken)
		}
		if later.SessionBlocked {
			t.Errorf("SessionBlocked is set; the router never refused a login and the session was never lost. "+
				"LastErr = %v", later.LastErr)
		}
		if later.LoginsSuppressed != 0 {
			t.Errorf("LoginsSuppressed = %d; a cooldown was armed and the poller went quiet over one "+
				"undecodable endpoint", later.LoginsSuppressed)
		}
		if n := len(rt.loginTimes()); n != 1 {
			t.Errorf("logged in %d times in %v, want 1: the session was held throughout, so there was never "+
				"anything to take back", n, window)
		}
		if cycles, want := rt.timesCalled(sources[0].Path), int(window/cfg.Interval); cycles < want {
			t.Errorf("%d cycles in %v at an interval of %v, want at least %d; the poll kept its rhythm only "+
				"if nothing backed it off", cycles, window, cfg.Interval, want)
		}
	})
}

// The firmware defends a session against other devices, not against other
// sessions: a login from a second address is refused with "user conflict", one
// from the address that holds the session takes it over in silence. So a single
// loss says nothing, and only a second inside SessionCooldown says the browser
// is on this machine and that coming back is what evicts it.

// One loss costs nothing: it may as well have been a reboot, and a person on
// another device is protected by the firmware rather than by us.
func TestOneLostSessionIsAnsweredWithALogin(t *testing.T) {
	rt := newFakeRouter(t)
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		if awaitCycle(t, p, cfg).Snapshot == nil {
			t.Fatal("the first cycle produced no snapshot")
		}
		rt.expireAt(srcPorts)

		// Between the cycle that loses the session and the one that follows it.
		time.Sleep(cfg.Interval + cfg.Interval/2)
		synctest.Wait()

		lost := p.State()
		if lost.SessionsLost != 1 {
			t.Fatalf("SessionsLost = %d after the session was taken at %s, want 1", lost.SessionsLost, srcPorts)
		}
		if lost.Up {
			t.Error("Up is true although the cycle ended on a dead session")
		}
		if lost.SessionBlocked {
			t.Error("SessionBlocked is set after a single loss; one loss does not say a person is at the " +
				"web UI — the router may have rebooted — and only a second one inside the cooldown does")
		}

		time.Sleep(2 * cfg.Interval)
		synctest.Wait()

		if n := len(rt.loginTimes()); n != 2 {
			t.Errorf("%d logins after one lost session, want 2: the next cycle logs in as usual, so a "+
				"reboot costs one cycle of metrics rather than a whole cooldown of %v", n, cfg.SessionCooldown)
		}
		st := p.State()
		if !st.Up {
			t.Errorf("Up is false two cycles after a single loss; the session was free and one login takes "+
				"it back. LastErr = %v", st.LastErr)
		}
		if st.LoginsSuppressed != 0 {
			t.Errorf("LoginsSuppressed = %d although nothing was ever held back: one loss arms no cooldown",
				st.LoginsSuppressed)
		}
		if st.SessionsLost != 1 {
			t.Errorf("SessionsLost = %d, want 1: the poller lost the session once and took it back", st.SessionsLost)
		}
	})
}

// The eviction that started this: the exporter and the browser on one machine,
// where the firmware hands the session over in silence. Two losses in a row and
// the poller stops asking.
func TestSecondLostSessionInsideTheWindowStopsTheLogins(t *testing.T) {
	rt := newFakeRouter(t)
	// Every login takes the session back off the person at the browser, and the
	// cycle that follows loses it again.
	rt.expireAtEvery(srcPorts)

	cfg := testConfig()
	// Long enough that the whole window below sits inside it.
	cfg.SessionCooldown = 20 * time.Minute

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		window := 20 * cfg.Interval
		time.Sleep(window)
		synctest.Wait()

		if n := len(rt.loginTimes()); n != 2 {
			t.Errorf("logged in %d times in %v, want 2: the first loss is answered with a login, the second "+
				"one %v later says the browser is on this machine, and every login after that is another "+
				"eviction of the person sitting at it. The cooldown is %v",
				n, window, cfg.Interval, cfg.SessionCooldown)
		}
		if n := rt.timesCalled(sources[0].Path); n != 2 {
			t.Errorf("%s was polled %d times in %v, want 2; once the poller has gone quiet the router hears "+
				"nothing from it at all", sources[0].Path, n, window)
		}

		st := p.State()
		if st.SessionsLost != 2 {
			t.Errorf("SessionsLost = %d, want 2: a first loss counts as much as a repeat", st.SessionsLost)
		}
		if !st.SessionBlocked {
			t.Errorf("SessionBlocked is false after two losses inside %v; that pattern is the web UI being "+
				"held on this machine, which is what the metric reports. LastErr = %v",
				cfg.SessionCooldown, st.LastErr)
		}
		if st.Up {
			t.Error("Up is true although the poller holds no session and is not asking for one")
		}
	})
}

// A repeat is a second loss inside lossWindow, however far apart the two are.
// Measuring the gap instead made the person's think time the deciding factor:
// someone who takes longer than SessionCooldown to notice they were thrown out
// and log back in never produced a repeat, so the quiet spell never armed,
// tplink_session_blocked stayed 0, and the exporter evicted them again every
// cooldown for as long as they kept coming back. The slower they were, the
// worse it got.
func TestRepeatedLossIsMeasuredOverTheWindowNotTheGap(t *testing.T) {
	for _, tc := range []struct {
		name          string
		first, second time.Duration // when the browser takes the session, from Run starting
		wantQuiet     bool
		wantLogins    int
	}{
		{"twenty-five minutes apart, both inside the window", 15 * time.Minute, 40 * time.Minute, true, 2},
		{"sixty-five minutes apart, the first one aged out", 5 * time.Minute, 70 * time.Minute, false, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newFakeRouter(t)
			cfg := Config{
				Interval:   time.Minute,
				Timeout:    10 * time.Second,
				MinBackoff: time.Second,
				MaxBackoff: 2 * time.Minute,
				// Both gaps are several cooldowns wide, so an adjacency rule sees
				// neither loss as a repeat.
				SessionCooldown:  5 * time.Minute,
				MaxLoginsPerHour: noLoginCap,
			}

			synctest.Test(t, func(t *testing.T) {
				p, stop := startPoller(t, rt, cfg)
				defer stop()

				// The tab is opened mid-wait, so the cycle that loses the session is
				// the next one and there is no cycle in flight to race with.
				time.Sleep(tc.first + cfg.Interval/2)
				synctest.Wait()
				rt.expireAt(srcPorts)

				time.Sleep(tc.second - tc.first)
				synctest.Wait()

				mid := p.State()
				if mid.SessionsLost != 1 || mid.SessionBlocked || len(rt.loginTimes()) != 2 {
					t.Fatalf("%v after the first loss: SessionsLost %d, SessionBlocked %v, %d logins; want 1, "+
						"false and 2 — one loss costs a cycle and the poller takes the session back",
						tc.second-tc.first, mid.SessionsLost, mid.SessionBlocked, len(rt.loginTimes()))
				}
				rt.expireAt(srcPorts)

				time.Sleep(3 * cfg.Interval)
				synctest.Wait()

				st := p.State()
				gap := tc.second - tc.first
				if st.SessionsLost != 2 {
					t.Fatalf("SessionsLost = %d, want 2: the session was taken twice", st.SessionsLost)
				}
				if tc.wantQuiet {
					if !st.SessionBlocked {
						t.Errorf("SessionBlocked is false after two losses %v apart: past SessionCooldown %v "+
							"but well inside the window of %v, which is what a repeat is counted over. "+
							"LastErr = %v", gap, cfg.SessionCooldown, lossWindow, st.LastErr)
					}
					if st.LoginsSuppressed == 0 {
						t.Errorf("LoginsSuppressed = 0 although a spell of %v was due; every cycle inside it "+
							"holds back the login it would otherwise have made", cfg.SessionCooldown)
					}
				} else {
					if st.SessionBlocked {
						t.Errorf("SessionBlocked is set after two losses %v apart; the first is older than the "+
							"window of %v and no longer counts, so the second is a lone loss", gap, lossWindow)
					}
					if st.LoginsSuppressed != 0 {
						t.Errorf("LoginsSuppressed = %d although no spell was armed and nothing was held back",
							st.LoginsSuppressed)
					}
				}
				if n := len(rt.loginTimes()); n != tc.wantLogins {
					t.Errorf("logged in %d times, want %d: the losses are %v apart against a window of %v. A "+
						"repeat costs a quiet spell of %v — logging back in there evicts the person at the "+
						"browser again — and a lone loss costs the one cycle it happened in",
						n, tc.wantLogins, gap, lossWindow, cfg.SessionCooldown)
				}
			})
		})
	}
}

// The cooldown runs out and the poller tries once. The tab has been closed, so
// it gets the session back and the counters carry over.
func TestPollerTriesAgainAfterTheCooldown(t *testing.T) {
	rt := newFakeRouter(t)
	rt.expireAtEvery(srcPorts)
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		// Two cycles in, the second loss has armed the cooldown.
		time.Sleep(2 * cfg.Interval)
		synctest.Wait()
		quiet := p.State()
		if !quiet.SessionBlocked || len(rt.loginTimes()) != 2 {
			t.Fatalf("after %v: %d logins and SessionBlocked=%v, want 2 and true — the cooldown has to be "+
				"armed before there is anything to come back from", 2*cfg.Interval,
				len(rt.loginTimes()), quiet.SessionBlocked)
		}
		rt.stopExpiring()

		window := 2*cfg.SessionCooldown + 4*cfg.Interval
		time.Sleep(window)
		synctest.Wait()

		if n := len(rt.loginTimes()); n != 3 {
			t.Errorf("%d logins in the %v after the cooldown was armed, want 3: it runs out after %v and the "+
				"poller asks once, not once per cycle", n, window, cfg.SessionCooldown)
		}
		st := p.State()
		if !st.Up {
			t.Fatalf("Up is false %v after the cooldown of %v was armed; the session is free again and one "+
				"login takes it. LastErr = %v", window, cfg.SessionCooldown, st.LastErr)
		}
		if st.SessionBlocked {
			t.Error("SessionBlocked is still set after a cycle in which every endpoint answered")
		}
		if st.Snapshot == nil || len(st.Snapshot.Errors) != 0 {
			t.Errorf("the cycle that took the session back did not produce a whole snapshot: %v",
				st.Snapshot.Errors)
		}
		if st.LoginsSuppressed == 0 {
			t.Error("LoginsSuppressed = 0 although a cycle fell inside the cooldown and did not attempt " +
				"the login it would otherwise have made")
		}
		if st.SessionsLost < quiet.SessionsLost || st.LoginsSuppressed < quiet.LoginsSuppressed {
			t.Errorf("SessionsLost %d -> %d and LoginsSuppressed %d -> %d across a cycle that succeeded; "+
				"both run for the exporter's lifetime and are published as _total",
				quiet.SessionsLost, st.SessionsLost, quiet.LoginsSuppressed, st.LoginsSuppressed)
		}
	})
}

// Someone who leaves the UI open for an hour must not be evicted every cycle:
// each repeat doubles the quiet spell, up to MaxBackoff.
func TestSessionCooldownDoublesAndIsCapped(t *testing.T) {
	rt := newFakeRouter(t)
	rt.expireAtEvery(srcPorts)

	// Interval and the backoff range both well under the cooldown, so the gaps
	// measured below are the cooldown.
	cfg := Config{
		Interval:         5 * time.Second,
		Timeout:          2 * time.Second,
		MinBackoff:       time.Second,
		MaxBackoff:       80 * time.Second,
		SessionCooldown:  20 * time.Second,
		MaxLoginsPerHour: noLoginCap,
	}

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		const window = 6 * time.Minute
		time.Sleep(window)
		synctest.Wait()

		gaps := rt.loginGaps()
		if len(gaps) < 4 {
			t.Fatalf("%d logins in %v, too few to show the doubling: %v", len(gaps)+1, window, gaps)
		}
		// A gap also carries the cycle that lost the session and a tick the retry
		// waited out.
		slack := cfg.Interval + cfg.Timeout
		// The first loss is free, so the poller comes straight back; every gap
		// after it is a quiet spell, one login apiece.
		want := []time.Duration{cfg.Interval, cfg.SessionCooldown, 2 * cfg.SessionCooldown}
		for i, w := range want {
			if gaps[i] < w || gaps[i] > w+slack {
				t.Errorf("login %d came %v after the one before, want %v: the first loss is answered with "+
					"the interval and every repeat doubles the quiet spell from %v. Gaps: %v",
					i+2, gaps[i], w, cfg.SessionCooldown, gaps)
			}
		}
		for i, g := range gaps[len(want):] {
			if g < gaps[len(want)-1] {
				t.Errorf("login %d came %v after the one before, sooner than the %v before that; the quiet "+
					"spell doubles and does not shrink while the session keeps being taken. Gaps: %v",
					i+len(want)+2, g, gaps[len(want)-1], gaps)
			}
			if g > cfg.MaxBackoff+slack {
				t.Errorf("login %d came %v after the one before, past MaxBackoff %v, which caps the "+
					"doubling. Gaps: %v", i+len(want)+2, g, cfg.MaxBackoff, gaps)
			}
		}
		if st, logins := p.State(), len(rt.loginTimes()); st.SessionsLost < uint64(logins-1) {
			t.Errorf("SessionsLost = %d over %d logins, each of which was followed by the session being "+
				"taken again; a first loss counts as much as a repeat", st.SessionsLost, logins)
		}
	})
}

// One good cycle is not the browser closing: coming back, holding the session
// for a cycle and losing it again escalates rather than starting over. The
// comeback always lands a whole cooldown after the loss that caused it, so the
// time that clears the escalation runs from the comeback, not from the loss.
func TestEscalationSurvivesOneGoodCycle(t *testing.T) {
	rt := newFakeRouter(t)
	rt.expireAfterOneGoodCycle(srcPorts)

	cfg := Config{
		Interval:         5 * time.Second,
		Timeout:          2 * time.Second,
		MinBackoff:       time.Second,
		MaxBackoff:       80 * time.Second,
		SessionCooldown:  20 * time.Second,
		MaxLoginsPerHour: noLoginCap,
	}

	synctest.Test(t, func(t *testing.T) {
		_, stop := startPoller(t, rt, cfg)
		defer stop()

		const window = 3 * time.Minute
		time.Sleep(window)
		synctest.Wait()

		gaps := rt.loginGaps()
		if len(gaps) < 3 {
			t.Fatalf("%d logins in %v, too few to show the escalation: %v", len(gaps)+1, window, gaps)
		}
		// A gap carries the good cycle, the cycle that lost the session and a tick
		// the retry waited out.
		slack := 2*cfg.Interval + cfg.Timeout
		for i, w := range []time.Duration{cfg.SessionCooldown, 2 * cfg.SessionCooldown} {
			if got := gaps[i+1]; got < w || got > w+slack {
				t.Errorf("quiet spell %d lasted %v, want %v: the session was held for one cycle and taken "+
					"again, which escalates. A spell that stays at %v evicts the person every %v for as "+
					"long as the tab is open. Gaps: %v", i+1, got, w, cfg.SessionCooldown, got, gaps)
			}
		}
	})
}

// The poller keeps its rhythm while it is quiet. Sleeping the spell out in one
// go freezes State for as long as fifteen minutes and turns
// tplink_login_suppressed_total into one blip per spell.
func TestQuietSpellKeepsTheTickerRunning(t *testing.T) {
	rt := newFakeRouter(t)
	rt.expireAtEvery(srcPorts)

	cfg := testConfig()
	cfg.SessionCooldown = 20 * time.Minute

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		// Two cycles in, the second loss has armed the spell; both samples sit
		// well inside it.
		const early, late = 5 * time.Minute, 15 * time.Minute
		time.Sleep(early)
		synctest.Wait()
		first := p.State()

		time.Sleep(late - early)
		synctest.Wait()
		second := p.State()

		if !second.SessionBlocked {
			t.Fatalf("SessionBlocked is false %v into a quiet spell of %v; there is no spell to measure",
				late, cfg.SessionCooldown)
		}
		cycles := uint64((late - early) / cfg.Interval)
		if grew := second.LoginsSuppressed - first.LoginsSuppressed; grew < cycles*3/4 {
			t.Errorf("LoginsSuppressed went %d -> %d over the %v between the samples, about %d cycles of %v; "+
				"the ticker keeps its rhythm while the poller is quiet and every cycle it holds back counts "+
				"one, so sleeping the spell out in one go is what leaves this at 1",
				first.LoginsSuppressed, second.LoginsSuppressed, late-early, cycles, cfg.Interval)
		}
		if !second.LastAttempt.After(first.LastAttempt) {
			t.Errorf("LastAttempt stood still at %v across %v of a quiet spell; a poller that is not "+
				"polling still runs its cycle, and tplink_scrape_duration_seconds comes off it",
				first.LastAttempt, late-early)
		}
	})
}

// The two-hour lock is what the cap guards against, so it counts attempts and
// not successes: a login refused still went to the router.
func TestHourlyLoginCapHolds(t *testing.T) {
	rt := newFakeRouter(t)
	rt.refuseLogin(errors.New("dial tcp 192.0.2.1:80: connect: connection refused"))

	cfg := Config{
		Interval:         time.Minute,
		Timeout:          10 * time.Second,
		MinBackoff:       time.Minute,
		MaxBackoff:       2 * time.Minute,
		SessionCooldown:  time.Minute,
		MaxLoginsPerHour: 3,
	}

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		const inside = 50 * time.Minute
		time.Sleep(inside)
		synctest.Wait()

		st := p.State()
		if n := len(rt.loginTimes()); n != cfg.MaxLoginsPerHour {
			t.Errorf("%d login attempts in %v against a MaxLoginsPerHour of %d; the backoff of %v would "+
				"have made about %d, and the cap is what stops them", n, inside, cfg.MaxLoginsPerHour,
				cfg.MaxBackoff, int(inside/cfg.MaxBackoff))
		}
		if st.LoginsSuppressed == 0 {
			t.Error("LoginsSuppressed = 0 although the cap stopped every cycle after the third from " +
				"attempting a login")
		}
		if st.LoginFailures != uint64(cfg.MaxLoginsPerHour) {
			t.Errorf("LoginFailures = %d for %d attempts; a login the cap held back never reached the "+
				"router and is a suppression, not a failure", st.LoginFailures, cfg.MaxLoginsPerHour)
		}

		time.Sleep(70*time.Minute - inside)
		synctest.Wait()

		if n := len(rt.loginTimes()); n <= cfg.MaxLoginsPerHour {
			t.Errorf("%d login attempts after 70 minutes, still the %d of the first hour; the cap is over "+
				"an hour, and an attempt older than that no longer counts against it",
				n, cfg.MaxLoginsPerHour)
		}
	})
}

// The cap withholds one login and returns Interval, so the ticker keeps its
// rhythm and the cap is re-read each cycle. Returning what was left of the hour
// slept it out in one piece: State froze for up to an hour, and
// tplink_login_suppressed_total counted one spell here against one cycle on the
// cooldown path — two units in one counter.
func TestLoginCapKeepsTheTickerRunning(t *testing.T) {
	rt := newFakeRouter(t)
	rt.refuseLogin(errors.New("dial tcp 192.0.2.1:80: connect: connection refused"))

	cfg := Config{
		Interval:         time.Minute,
		Timeout:          10 * time.Second,
		MinBackoff:       time.Minute,
		MaxBackoff:       2 * time.Minute,
		SessionCooldown:  time.Minute,
		MaxLoginsPerHour: 3,
	}

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		// The backoff spends the three attempts within five minutes, and the
		// oldest of them ages out of the hour well after the second sample.
		const early, late = 10 * time.Minute, 40 * time.Minute
		time.Sleep(early)
		synctest.Wait()
		first := p.State()

		time.Sleep(late - early)
		synctest.Wait()
		second := p.State()

		if n := len(rt.loginTimes()); n != cfg.MaxLoginsPerHour {
			t.Fatalf("%d login attempts by %v against a cap of %d; the cap has to be holding before there is "+
				"anything to measure", n, late, cfg.MaxLoginsPerHour)
		}
		cycles := uint64((late - early) / cfg.Interval)
		if grew := second.LoginsSuppressed - first.LoginsSuppressed; grew < cycles*3/4 {
			t.Errorf("LoginsSuppressed went %d -> %d over the %v between the samples, about %d cycles of %v; "+
				"the cap holds back one login per cycle and counts one, so sleeping the rest of the hour out "+
				"in one piece is what leaves this at 1",
				first.LoginsSuppressed, second.LoginsSuppressed, late-early, cycles, cfg.Interval)
		}
		if !second.LastAttempt.After(first.LastAttempt) {
			t.Errorf("LastAttempt stood still at %v across %v of the cap holding; the cycle still runs, and "+
				"tplink_scrape_duration_seconds and the snapshot age come off it", first.LastAttempt, late-early)
		}
		if second.SessionBlocked {
			t.Error("SessionBlocked is set while the cap is what is holding the login back; no session was " +
				"ever taken and no login was refused with ErrSessionBusy")
		}
	})
}

// The cycle ends where the session died. What was collected before it is still a
// cycle's worth of data and is published; the endpoints it never reached are not
// charged for a request that was never made.
func TestWhatAnsweredBeforeTheSessionDiedIsPublished(t *testing.T) {
	const expiresAt = srcPorts

	rt := newFakeRouter(t)
	cfg := testConfig()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		first := awaitCycle(t, p, cfg).Snapshot
		if first == nil {
			t.Fatal("the first cycle produced no snapshot")
		}
		rt.expireAt(expiresAt)

		// Between the cycle that loses the session and the one that follows it.
		time.Sleep(cfg.Interval + cfg.Interval/2)
		synctest.Wait()

		st := p.State()
		if st.EndpointErrors[expiresAt] == 0 {
			t.Errorf("EndpointErrors has no count for %s, where the session was taken; the cycle up to that "+
				"point is still a cycle and its errors are charged", expiresAt)
		}
		answered := sources[:slices.IndexFunc(sources, func(s source) bool { return s.Path == expiresAt })]
		for _, s := range answered {
			if n := st.EndpointErrors[s.Path]; n != 0 {
				t.Errorf("EndpointErrors[%s] = %d although it answered before the session was taken", s.Path, n)
			}
		}

		snap := st.Snapshot
		if snap == nil || snap == first {
			t.Fatalf("the %d replies collected before the session was taken were never published; the "+
				"snapshot is still the one from the cycle before", len(answered))
		}
		if len(snap.Errors) != 1 || snap.Errors[expiresAt] == nil {
			t.Errorf("Snapshot.Errors = %v, want the one entry for %s, where the session was taken: the "+
				"endpoints after it were never asked and did not fail", snap.Errors, expiresAt)
		}
		reached := make(map[string]bool, len(answered))
		for _, s := range answered {
			reached[s.Path] = true
		}
		for _, section := range snapshotSections(snap) {
			if reached[section.from] && !section.filled {
				t.Errorf("Snapshot.%s is empty although %s answered before the session was taken",
					section.name, section.from)
			}
		}
		if len(snap.Ports) != 0 {
			t.Errorf("Snapshot.Ports holds %d ports although %s is where the session was taken",
				len(snap.Ports), expiresAt)
		}
		if len(snap.ARP) != 0 || len(snap.Mesh) != 0 {
			t.Errorf("Snapshot carries sections from endpoints the cycle never reached: %d ARP entries, "+
				"%d mesh nodes", len(snap.ARP), len(snap.Mesh))
		}
	})
}

// A session that ends on its own looks exactly like a person taking it at the
// web UI. Two such losses inside lossWindow read as a repeat, and the poller
// goes quiet and reports tplink_session_blocked over nobody. Config.SessionRenew
// replaces the session first, so a loss means what the metric says again.

// The renewal is the last thing a good cycle does. The poll runs on the session
// the poller already holds and has just used, and only once its snapshot is
// recorded does the poller log out and log in again: the router is left without
// a session for the gap between those two, not for a cycle.
func TestSessionIsRenewedAfterTheCycleThatPolledOnIt(t *testing.T) {
	rt := newFakeRouter(t)
	cfg := testConfig()
	// Due half way between two ticks, so the same cycle renews whether the age of
	// the session is read at the start of a cycle or at its end.
	cfg.SessionRenew = 2*cfg.Interval + cfg.Interval/2

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		time.Sleep(cfg.SessionRenew)
		synctest.Wait()

		held := p.State()
		if held.Snapshot == nil {
			t.Fatalf("no snapshot %v into a run against a router that answered everything; LastErr = %v",
				cfg.SessionRenew, held.LastErr)
		}
		if n := rt.logoutCount(); n != 0 {
			t.Fatalf("logged out %d times before the session reached SessionRenew (%v); until then it is reused",
				n, cfg.SessionRenew)
		}

		time.Sleep(cfg.Interval)
		synctest.Wait()

		logouts, logins := rt.logoutTimes(), rt.loginTimes()
		if len(logouts) != 1 {
			t.Fatalf("logged out %d times by %v, want 1: the session passed SessionRenew (%v) in the cycle that "+
				"has just run and is replaced there", len(logouts), cfg.SessionRenew+cfg.Interval, cfg.SessionRenew)
		}
		if len(logins) != 2 {
			t.Fatalf("logged in %d times, want 2: a renewal is a logout followed by a login", len(logins))
		}
		renewed := logouts[0]

		if logins[1].Before(renewed) {
			t.Errorf("logged in at %v, before the logout at %v; a login from the address that holds the session "+
				"replaces it in silence, so the old one has to be given back first", logins[1], renewed)
		}
		if gap := logins[1].Sub(renewed); gap > cfg.Interval/4 {
			t.Errorf("the router was left without a session for %v; the renewal logs back in at once, and the "+
				"gap is the two requests, not the %v to the next cycle", gap, cfg.Interval)
		}

		last := lastCallBefore(t, rt.callLog(), renewed)
		if want := sources[len(sources)-1].Path; last.Path != want {
			t.Errorf("the last endpoint polled before the renewal was %s, want %s: the poll runs to the end of "+
				"the set on the session the poller already holds, and the renewal follows it", last.Path, want)
		}
		if gap := renewed.Sub(last.At); gap > cfg.Interval/4 {
			t.Errorf("the renewal logged out %v after the last request before it, a cycle of polling away; it "+
				"belongs to the end of a cycle that has just succeeded, not to the start of the next one", gap)
		}

		st := p.State()
		if !st.Up {
			t.Errorf("Up is false after a cycle that polled everything and then renewed its session; the "+
				"renewal cannot cost the cycle what it collected. LastErr = %v", st.LastErr)
		}
		if st.Snapshot == nil || st.Snapshot == held.Snapshot {
			t.Error("the cycle that renewed the session published no snapshot of its own; it polled first, on " +
				"the session it already had, and that snapshot is recorded before anything is given back")
		}
		if st.Logins != 2 {
			t.Errorf("Logins = %d after one renewal, want 2: tplink_logins_total counts a renewal like any "+
				"other login", st.Logins)
		}

		time.Sleep(cfg.Interval)
		synctest.Wait()

		next, ok := firstCallAfter(rt.callLog(), renewed)
		if !ok {
			t.Fatalf("nothing was polled in the %v after the renewal; the fresh session is used by the cycles "+
				"that follow", 2*cfg.Interval)
		}
		if gap := next.At.Sub(renewed); gap < cfg.Interval/2 {
			t.Errorf("the poller polled again %v after renewing the session; the cycle that renewed had already "+
				"taken its snapshot, and the next one is an interval of %v away", gap, cfg.Interval)
		}
		if n := rt.logoutCount(); n != 1 {
			t.Errorf("logged out %d times by %v; the fresh session is held for SessionRenew (%v) like any other",
				n, cfg.SessionRenew+2*cfg.Interval, cfg.SessionRenew)
		}
	})
}

// A renewal that cannot log back in costs the session and nothing else: the
// cycle it belongs to has already polled and published. The next cycle logs in
// through the ordinary path, and what answers it there is the ordinary case.
func TestFailedRenewalKeepsTheCycleAndItsSnapshot(t *testing.T) {
	// The first login, the renewal that failed, and the ordinary one in the cycle
	// after it.
	const wantLogins = 3

	for _, tc := range []struct {
		name        string
		renewErr    error
		recovers    bool // the login refused at the renewal succeeds in the next cycle
		wantUp      bool
		wantBlocked bool
	}{
		{
			name:     "the next cycle logs in as usual",
			renewErr: errors.New("dial tcp 192.0.2.1:80: connect: connection refused"),
			recovers: true,
			wantUp:   true,
		},
		{
			name:        "a session taken in the gap is the ordinary blocked case",
			renewErr:    fmt.Errorf("%w (close the browser tab)", tpapi.ErrSessionBusy),
			wantBlocked: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newFakeRouter(t)
			cfg := testConfig()
			cfg.SessionRenew = 2*cfg.Interval + cfg.Interval/2

			synctest.Test(t, func(t *testing.T) {
				p, stop := startPoller(t, rt, cfg)
				defer stop()

				time.Sleep(cfg.SessionRenew)
				synctest.Wait()
				good := p.State()
				if good.Snapshot == nil {
					t.Fatalf("no snapshot before the renewal was due; LastErr = %v", good.LastErr)
				}
				rt.failLogin(tc.renewErr)

				time.Sleep(cfg.Interval)
				synctest.Wait()

				if n := len(rt.loginTimes()); n != 2 {
					t.Fatalf("%d logins by the time the session was due for renewal, want 2: the poller gave "+
						"the old session back and asked for a new one", n)
				}
				if n := rt.logoutCount(); n != 1 {
					t.Fatalf("logged out %d times, want 1: the renewal drops the session before it asks for "+
						"another", n)
				}

				st := p.State()
				if !st.Up {
					t.Errorf("Up is false after a cycle that polled everything and could not renew its session "+
						"afterwards; a renewal that fails leaves the poller without a session, not the cycle "+
						"without its data. LastErr = %v", st.LastErr)
				}
				if st.Snapshot == nil || st.Snapshot == good.Snapshot {
					t.Error("the cycle whose renewal failed published no snapshot; it polled on the session it " +
						"held and recorded the result before renewing anything")
				}
				if st.SessionsLost != 0 {
					t.Errorf("SessionsLost = %d after a session the poller gave back itself; a renewal is not a "+
						"loss however it ends, and counting it as one is what reports a person at the web UI "+
						"who is not there", st.SessionsLost)
				}
				if st.LoginsSuppressed != 0 {
					t.Errorf("LoginsSuppressed = %d; a failed renewal arms no quiet spell, so the next cycle "+
						"logs in through the ordinary path", st.LoginsSuppressed)
				}
				// Pinned for the plain failure only: a renewal refused with
				// ErrSessionBusy has a session to report, and reporting it a cycle
				// later is what the contract asks for.
				if !errors.Is(tc.renewErr, tpapi.ErrSessionBusy) && st.SessionBlocked {
					t.Errorf("SessionBlocked is set although no login was refused with ErrSessionBusy and no "+
						"session was taken; the renewal failed with %v", tc.renewErr)
				}
				renewed := st.Snapshot

				if tc.recovers {
					rt.allowLogin()
				}
				time.Sleep(cfg.Interval)
				synctest.Wait()

				st = p.State()
				if n := len(rt.loginTimes()); n != wantLogins {
					t.Errorf("%d logins in all, want %d: the cycle after a failed renewal logs in through the "+
						"ordinary path, and the poller does not sit out a cooldown for a session it gave back "+
						"itself", n, wantLogins)
				}
				if st.Up != tc.wantUp {
					t.Errorf("Up = %v after the cycle following the failed renewal, want %v; LastErr = %v",
						st.Up, tc.wantUp, st.LastErr)
				}
				if st.SessionBlocked != tc.wantBlocked {
					t.Errorf("SessionBlocked = %v, want %v: the login in the cycle after the renewal answered "+
						"%v", st.SessionBlocked, tc.wantBlocked, tc.renewErr)
				}
				if st.SessionsLost != 0 {
					t.Errorf("SessionsLost = %d; the session was never taken from the poller — it handed one "+
						"back and asked for another", st.SessionsLost)
				}
				switch {
				case tc.recovers && st.Snapshot == renewed:
					t.Error("the cycle that logged in again published no snapshot")
				case !tc.recovers && st.Snapshot != renewed:
					t.Error("the snapshot from the last good cycle was dropped by a cycle whose login was " +
						"refused; it is the only data the exporter has left to serve")
				}
				if n := rt.logoutCount(); n != 1 {
					t.Errorf("logged out %d times in all, want the one the renewal made; a poller holding no "+
						"session has none to give back", n)
				}
			})
		})
	}
}

// A session the poller hands back is not a session taken from it. Routing the
// renewal through the loss path arms the cooldown on the second renewal and
// reports tplink_session_blocked over a person who is not there — the very
// failure the renewal exists to prevent.
func TestRenewalIsNotALostSession(t *testing.T) {
	rt := newFakeRouter(t)
	cfg := testConfig()
	cfg.SessionRenew = 2*cfg.Interval + cfg.Interval/2

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		window := 20*cfg.Interval + cfg.Interval/2
		time.Sleep(window)
		synctest.Wait()

		st := p.State()
		if st.SessionsLost != 0 {
			t.Errorf("SessionsLost = %d over %v of renewing a session every %v; tplink_sessions_lost_total "+
				"counts sessions taken from the poller, and it took none of these from itself",
				st.SessionsLost, window, cfg.SessionRenew)
		}
		if st.SessionBlocked {
			t.Errorf("SessionBlocked is set although every session was replaced on schedule and no login was "+
				"refused; the metric says a person is holding the web UI. LastErr = %v", st.LastErr)
		}
		if st.LoginsSuppressed != 0 {
			t.Errorf("LoginsSuppressed = %d; a renewal arms no cooldown, so no cycle ever holds its login back",
				st.LoginsSuppressed)
		}
		if !st.Up {
			t.Errorf("Up is false after %v against a router that answered everything; LastErr = %v", window, st.LastErr)
		}

		logins := len(rt.loginTimes())
		if logins < 5 {
			t.Errorf("%d logins in %v with SessionRenew at %v, want one per renewal and one to start; a second "+
				"renewal read as a repeated loss stops the logins at 2 for a quiet spell of %v",
				logins, window, cfg.SessionRenew, cfg.SessionCooldown)
		}
		if n := rt.logoutCount(); n != logins-1 {
			t.Errorf("logged out %d times against %d logins; every login but the first replaces a session the "+
				"poller gave back", n, logins)
		}
		if cycles, want := rt.timesCalled(sources[0].Path), int(window/cfg.Interval); cycles < want {
			t.Errorf("%d cycles in %v at an interval of %v, want at least %d; a poller that read its own "+
				"renewals as losses would have stopped polling altogether", cycles, window, cfg.Interval, want)
		}
	})
}

// SessionRenew is a period, not a chore for every cycle: one session serves
// every cycle that fits inside it. Zero leaves the session to the firmware.
func TestSessionIsRenewedOnSchedule(t *testing.T) {
	base := testConfig()

	for _, tc := range []struct {
		name        string
		renew       time.Duration
		window      time.Duration
		wantLogins  int
		wantLogouts int
	}{
		{
			// Half an interval short of ten, so the cycle that carries the session
			// past SessionRenew is the tenth however the age is read.
			name:        "one logout and one extra login per ten cycles",
			renew:       9*base.Interval + base.Interval/2,
			window:      25*base.Interval + base.Interval/2,
			wantLogins:  3,
			wantLogouts: 2,
		},
		{
			// Three times the thirty minutes the flag defaults to, so a zero read
			// as "take the default" shows up as renewals.
			name:        "zero leaves the session alone",
			renew:       0,
			window:      90 * time.Minute,
			wantLogins:  1,
			wantLogouts: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newFakeRouter(t)
			cfg := base
			cfg.SessionRenew = tc.renew

			synctest.Test(t, func(t *testing.T) {
				p, stop := startPoller(t, rt, cfg)
				defer stop()

				time.Sleep(tc.window)
				synctest.Wait()

				if n := len(rt.loginTimes()); n != tc.wantLogins {
					t.Errorf("%d logins in %v with SessionRenew at %v, want %d: a session is replaced once it "+
						"has been held that long and is reused by every cycle until then",
						n, tc.window, tc.renew, tc.wantLogins)
				}
				if n := rt.logoutCount(); n != tc.wantLogouts {
					t.Errorf("logged out %d times in %v, want %d: the session is given back when it is replaced "+
						"and on shutdown, never in an ordinary cycle", n, tc.window, tc.wantLogouts)
				}

				st := p.State()
				if st.Logins != uint64(tc.wantLogins) {
					t.Errorf("Logins = %d against the %d logins this run is worth; tplink_logins_total counts a "+
						"renewal like any other login", st.Logins, tc.wantLogins)
				}
				if !st.Up || st.Snapshot == nil {
					t.Errorf("Up = %v and Snapshot = %v after %v against a router that answered everything; "+
						"LastErr = %v", st.Up, st.Snapshot, tc.window, st.LastErr)
				}
				if cycles, want := rt.timesCalled(sources[0].Path), int(tc.window/cfg.Interval); cycles < want {
					t.Errorf("%d cycles in %v at an interval of %v, want at least %d; replacing the session "+
						"costs no cycle", cycles, tc.window, cfg.Interval, want)
				}

				if tc.renew == 0 {
					return
				}
				gaps := rt.loginGaps()
				for i, g := range gaps {
					if g < tc.renew {
						t.Errorf("session %d was replaced after %v, before it had been held for SessionRenew "+
							"(%v): %v", i+1, g, tc.renew, gaps)
					}
					if slack := cfg.Interval + cfg.Timeout; g > tc.renew+slack {
						t.Errorf("session %d was replaced after %v, more than the cycle it waits for past "+
							"SessionRenew (%v): %v", i+1, g, tc.renew, gaps)
					}
				}
			})
		})
	}
}

// The two-hour "multiple login" lock counts logins and not reasons, so a
// renewal is an ordinary attempt against MaxLoginsPerHour.
func TestRenewalCountsAgainstTheLoginCap(t *testing.T) {
	rt := newFakeRouter(t)
	cfg := Config{
		Interval:         time.Minute,
		Timeout:          10 * time.Second,
		MinBackoff:       time.Minute,
		MaxBackoff:       2 * time.Minute,
		SessionCooldown:  time.Minute,
		SessionRenew:     2*time.Minute + 30*time.Second,
		MaxLoginsPerHour: 3,
	}

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		const inside = 50 * time.Minute
		time.Sleep(inside)
		synctest.Wait()

		st := p.State()
		if n := len(rt.loginTimes()); n != cfg.MaxLoginsPerHour {
			t.Errorf("%d logins in %v against a MaxLoginsPerHour of %d; a session replaced every %v would have "+
				"made about %d of them, and the cap is what stops them — the lock does not care that the poller "+
				"logged itself out first", n, inside, cfg.MaxLoginsPerHour, cfg.SessionRenew,
				int(inside/cfg.SessionRenew))
		}
		if st.Logins != uint64(cfg.MaxLoginsPerHour) {
			t.Errorf("Logins = %d, want %d: every login the router answered counts, renewal or not",
				st.Logins, cfg.MaxLoginsPerHour)
		}
		if st.LoginFailures != 0 {
			t.Errorf("LoginFailures = %d although the router refused nothing; a renewal the cap holds back "+
				"never reaches it", st.LoginFailures)
		}
		if !st.Up {
			t.Errorf("Up is false while the cap is holding a renewal back; the login that would replace the "+
				"session is the one being withheld, so the session in hand is the one the poller keeps polling "+
				"on. LastErr = %v", st.LastErr)
		}

		time.Sleep(70*time.Minute - inside)
		synctest.Wait()

		if n := len(rt.loginTimes()); n <= cfg.MaxLoginsPerHour {
			t.Errorf("%d logins after 70 minutes, still the %d of the first hour; the cap is over an hour, and "+
				"a renewal it held back is made once the oldest attempt has aged out", n, cfg.MaxLoginsPerHour)
		}
	})
}

// A renewal gives one session back and takes another; shutdown still frees
// exactly the one in hand, once.
func TestShutdownLogsOutAfterARenewal(t *testing.T) {
	rt := newFakeRouter(t)
	cfg := testConfig()
	cfg.SessionRenew = 2*cfg.Interval + cfg.Interval/2

	synctest.Test(t, func(t *testing.T) {
		_, stop := startPoller(t, rt, cfg)
		defer stop()

		window := cfg.SessionRenew + cfg.Interval
		time.Sleep(window)
		synctest.Wait()
		if n := rt.logoutCount(); n != 1 {
			t.Fatalf("logged out %d times in %v with SessionRenew at %v, want the one the renewal made; there "+
				"is no renewal here to shut down after otherwise", n, window, cfg.SessionRenew)
		}
		logins := rt.loginTimes()
		if len(logins) != 2 {
			t.Fatalf("logged in %d times, want 2: the renewal took a fresh session", len(logins))
		}
		stop()

		logouts := rt.logoutTimes()
		if len(logouts) != 2 {
			t.Fatalf("logged out %d times in all, want 2: one to renew the session and exactly one on shutdown",
				len(logouts))
		}
		if logouts[1].Before(logins[1]) {
			t.Errorf("the logout on shutdown came at %v, before the session it frees was taken at %v; the "+
				"router holds the session it last handed out until it times out", logouts[1], logins[1])
		}
	})
}

// Two of the poller's decisions show in the log and nowhere else: that it is
// polling again after a spell of not polling, and that a cycle came back mostly
// empty. slog.SetDefault is process-wide, so a test that reads the log installs
// its own handler, restores the one it found, and never runs in parallel.
const (
	recoveredMsg = "polling again"
	truncatedMsg = "most of the cycle did not answer"
)

// logCapture is the default logger's output for the length of one test. The
// poller logs from Run's goroutine, so both sides of the buffer are locked.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

// count is how many records carry msg. TextHandler writes one record per line,
// and neither message under test is part of any other line the poller writes.
func (c *logCapture) count(msg string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Count(c.buf.String(), msg)
}

// records is the lines carrying msg, so a record can be read for the level and
// the attributes it went in with.
func (c *logCapture) records(msg string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, line := range strings.Split(c.buf.String(), "\n") {
		if strings.Contains(line, msg) {
			out = append(out, line)
		}
	}
	return out
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// captureLog collects records at and above level until the test ends. The level
// is part of the assertion: the exporter runs at info, so a record the handler
// drops here is one an operator never sees.
//
// slog.SetDefault points the log package at the same handler and clears its
// flags; restoring the logger does not put either back, so both are saved.
func captureLog(t *testing.T, level slog.Level) *logCapture {
	t.Helper()
	c := &logCapture{}
	prev, out, flags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewTextHandler(c, &slog.HandlerOptions{Level: level})))
	t.Cleanup(func() {
		slog.SetDefault(prev)
		log.SetOutput(out)
		log.SetFlags(flags)
	})
	return c
}

// The recovery is announced when the poller comes back, once, and the cycles
// that follow are ordinary. Keying the line on the escalation counter announced
// one every minute for an hour: the cooldown outlives a good cycle by design,
// so it says nothing about whether the cycle before this one polled.
func TestRecoveryIsAnnouncedOnce(t *testing.T) {
	for _, tc := range []struct {
		name       string
		lose, mend func(*fakeRouter)
	}{
		{
			name: "a login refused while the web UI was held",
			lose: func(rt *fakeRouter) {
				rt.refuseLogin(fmt.Errorf("%w (close the browser tab)", tpapi.ErrSessionBusy))
			},
			mend: func(rt *fakeRouter) { rt.allowLogin() },
		},
		{
			// The case it was reported on: the quiet spell ends but the escalation
			// it armed stays for the hour the losses take to age out.
			name: "the session taken twice, which arms the cooldown",
			lose: func(rt *fakeRouter) { rt.expireAtEvery(srcPorts) },
			mend: func(rt *fakeRouter) { rt.stopExpiring() },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newFakeRouter(t)
			tc.lose(rt)
			cfg := testConfig()
			logged := captureLog(t, slog.LevelInfo)

			synctest.Test(t, func(t *testing.T) {
				p, stop := startPoller(t, rt, cfg)
				defer stop()

				// Three cycles that poll nothing. For the taken session that is two
				// losses and a cycle inside the quiet spell they buy.
				broken := 2*cfg.Interval + cfg.Interval/2
				time.Sleep(broken)
				synctest.Wait()

				if n := logged.count(recoveredMsg); n != 0 {
					t.Errorf("a recovery was announced %d times in the %v before the router was mended, in "+
						"which no cycle polled anything. Log:\n%s", n, broken, logged)
				}
				polled := rt.timesCalled(sources[0].Path)
				tc.mend(rt)

				// Past the quiet spell the second loss armed, with room for several
				// good cycles after it and well inside the hour in which the losses
				// age out and the escalation clears.
				good := cfg.SessionCooldown + 8*cfg.Interval
				time.Sleep(good)
				synctest.Wait()

				st := p.State()
				cycles := rt.timesCalled(sources[0].Path) - polled
				if !st.Up || st.Snapshot == nil || cycles < 5 {
					t.Fatalf("%d cycles polled in the %v after the router was mended, Up=%v: there has to be a "+
						"run of good cycles for the announcement to be counted over. LastErr = %v",
						cycles, good, st.Up, st.LastErr)
				}
				if n := logged.count(recoveredMsg); n != 1 {
					t.Errorf("a recovery was announced %d times over the %d cycles that polled once the router "+
						"was mended, want once: the exporter came back from not polling one time, and every "+
						"cycle after that one is ordinary. Log:\n%s", n, cycles, logged)
				}
			})
		})
	}
}

// A poller that never stopped polling has no recovery to announce.
func TestSteadyPollingAnnouncesNoRecovery(t *testing.T) {
	rt := newFakeRouter(t)
	cfg := testConfig()
	logged := captureLog(t, slog.LevelInfo)

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		awaitCycle(t, p, cfg)
		window := 10 * cfg.Interval
		time.Sleep(window)
		synctest.Wait()

		st := p.State()
		cycles := rt.timesCalled(sources[0].Path)
		if !st.Up || cycles < 10 {
			t.Fatalf("%d cycles in %v, Up=%v; this measures a healthy run and there is none. LastErr = %v",
				cycles, window, st.Up, st.LastErr)
		}
		if n := logged.count(recoveredMsg); n != 0 {
			t.Errorf("a recovery was announced %d times over %d cycles from a clean start, every one of which "+
				"answered in full: nothing was ever held back, refused, cut short or lost, so there is nothing "+
				"to have come back from. Log:\n%s", n, cycles, logged)
		}
	})
}

// A cycle that lost most of its sources is a success by design — the snapshot
// is published and Up stays true — so the log is the only place it shows.
func TestTruncatedCycleIsWarnedAbout(t *testing.T) {
	// len(sources) is odd, so half of it rounded down is under half and one more
	// is over: written this way the boundary holds if the poll set changes.
	for _, tc := range []struct {
		name     string
		failing  int
		wantWarn bool
	}{
		{"a couple of endpoints", 2, false},
		{"just under half the poll set", len(sources) / 2, false},
		{"just over half of it", len(sources)/2 + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newFakeRouter(t)
			for _, s := range sources[:tc.failing] {
				rt.fail(s.Path, errors.New("errorcode=00000002"))
			}
			cfg := testConfig()
			logged := captureLog(t, slog.LevelWarn)

			synctest.Test(t, func(t *testing.T) {
				p, stop := startPoller(t, rt, cfg)
				defer stop()

				awaitCycle(t, p, cfg)
				time.Sleep(2 * cfg.Interval)
				synctest.Wait()

				st := p.State()
				if !st.Up || st.Snapshot == nil {
					t.Fatalf("a cycle that lost %d of %d endpoints left Up=%v and a snapshot=%v; a partial cycle "+
						"publishes what answered. LastErr = %v", tc.failing, len(sources), st.Up,
						st.Snapshot != nil, st.LastErr)
				}
				if n := len(st.Snapshot.Errors); n != tc.failing {
					t.Fatalf("%d endpoints failed in the last cycle, want the %d the test broke; the count is "+
						"what the warning is decided on: %v", n, tc.failing, st.Snapshot.Errors)
				}

				switch n := logged.count(truncatedMsg); {
				case tc.wantWarn && n == 0:
					t.Errorf("%d of %d endpoints failed and nothing was logged at warn; the cycle counts as a "+
						"success — Up stays true and the snapshot is published — so a cycle that came back "+
						"mostly empty shows nowhere else. Log:\n%s", tc.failing, len(sources), logged)
				case !tc.wantWarn && n != 0:
					t.Errorf("%d of %d endpoints failed and the cycle was warned about %d times; the warning is "+
						"for a cycle that lost more than half its sources, and a few dead endpoints already "+
						"show in tplink_scrape_errors_total. Log:\n%s", tc.failing, len(sources), n, logged)
				}
			})
		})
	}
}

// An endpoint that stopped answering used to show only in
// tplink_scrape_errors_total: its error went into Snapshot.Errors and no line
// was written at any level, so a fibre-terminal reboot that took
// admin/status?form=all away for part of an outage left neither a name nor a
// reason anywhere an operator reads. The report is edge-triggered — the
// transition, not the state — or an endpoint dead for an hour writes sixty
// copies of one line.
const (
	endpointDeadMsg = "endpoint stopped answering"
	endpointBackMsg = "endpoint answering again"
)

// namesEndpoint says whether a record carries path as its endpoint attribute.
// Every source path holds a '=', which TextHandler quotes; the bare form is
// matched too, at a boundary, so the check does not rest on that.
func namesEndpoint(record, path string) bool {
	return strings.Contains(record, `endpoint="`+path+`"`) ||
		strings.Contains(record, "endpoint="+path+" ") ||
		strings.HasSuffix(record, "endpoint="+path)
}

// endpointRecords is the records carrying msg that name path.
func endpointRecords(c *logCapture, msg, path string) []string {
	var out []string
	for _, rec := range c.records(msg) {
		if namesEndpoint(rec, path) {
			out = append(out, rec)
		}
	}
	return out
}

// The line the outage needed. One endpoint fails while the rest of the cycle
// lands, cycle after cycle: it is announced once, with its name and what it
// failed with.
func TestDeadEndpointIsReportedOnce(t *testing.T) {
	const broken = srcStatusAll
	// The half of the outage that was being lost: the counter said something
	// failed, nothing said what it answered.
	failure := errors.New("errorcode=00000002 (no WAN while the fibre terminal rebooted)")

	rt := newFakeRouter(t)
	cfg := testConfig()
	// Warn, so the record proves an operator at the exporter's own level sees it.
	logged := captureLog(t, slog.LevelWarn)

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		awaitCycle(t, p, cfg)
		polled := rt.timesCalled(broken)
		rt.fail(broken, failure)

		window := 12*cfg.Interval + cfg.Interval/2
		time.Sleep(window)
		synctest.Wait()

		st := p.State()
		cycles := rt.timesCalled(broken) - polled
		if !st.Up || st.Snapshot == nil || cycles < 10 {
			t.Fatalf("%d cycles asked %s in the %v after it broke, Up=%v; the endpoint has to fail over a run "+
				"of cycles that otherwise succeed for the count below to mean anything. LastErr = %v",
				cycles, broken, window, st.Up, st.LastErr)
		}
		if st.Snapshot.Errors[broken] == nil {
			t.Fatalf("Snapshot.Errors has no entry for %s in the last cycle; it holds %v: the endpoint mended "+
				"itself part way and there is no run of failures to count over", broken, st.Snapshot.Errors)
		}

		recs := logged.records(endpointDeadMsg)
		if len(recs) != 1 {
			t.Fatalf("%s was reported as gone %d times over the %d cycles it failed in, want once: the "+
				"transition is what is logged, and an endpoint that stays dead for an hour otherwise writes "+
				"a line a minute. Log:\n%s", broken, len(recs), cycles, logged)
		}
		rec := recs[0]
		if !namesEndpoint(rec, broken) {
			t.Errorf("the record names no endpoint, or names another one: %s\nwhich endpoint went away is "+
				"what tplink_scrape_errors_total already could not be traced back to", rec)
		}
		if !strings.Contains(rec, "err=") || !strings.Contains(rec, failure.Error()) {
			t.Errorf("the record carries no err attribute holding %q: %s\nthe reason went into "+
				"Snapshot.Errors and nowhere else", failure, rec)
		}
		if !strings.Contains(rec, "level=WARN") {
			t.Errorf("the record is not at warn: %s\nan endpoint going away is a warning; info is where it "+
				"comes back", rec)
		}
	})
}

// The endpoint answering again is announced once too, at info: an operator
// reading warn is told what broke and reads the counter for the rest.
func TestEndpointComingBackIsReportedOnce(t *testing.T) {
	const broken = srcStatusAll

	for _, tc := range []struct {
		name     string
		level    slog.Level
		wantBack int
	}{
		{"an operator reading info", slog.LevelInfo, 1},
		{"one reading warn", slog.LevelWarn, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newFakeRouter(t)
			rt.fail(broken, errors.New("errorcode=00000002 (no WAN while the fibre terminal rebooted)"))
			cfg := testConfig()
			logged := captureLog(t, tc.level)

			synctest.Test(t, func(t *testing.T) {
				p, stop := startPoller(t, rt, cfg)
				defer stop()

				awaitCycle(t, p, cfg)
				// Half way between two cycles, so nothing is in flight when the
				// endpoint mends and no cycle sees it both ways.
				time.Sleep(3*cfg.Interval + cfg.Interval/2)
				synctest.Wait()
				mended := rt.timesCalled(broken)
				rt.mend(broken)

				window := 10 * cfg.Interval
				time.Sleep(window)
				synctest.Wait()

				st := p.State()
				cycles := rt.timesCalled(broken) - mended
				if !st.Up || st.Snapshot == nil || cycles < 8 {
					t.Fatalf("%d cycles asked %s in the %v after it mended, Up=%v; there has to be a run of "+
						"cycles it answered in. LastErr = %v", cycles, broken, window, st.Up, st.LastErr)
				}
				if n := len(st.Snapshot.Errors); n != 0 {
					t.Fatalf("the last cycle still lost %d endpoints: %v; %s has to answer for a recovery to "+
						"be reported at all", n, st.Snapshot.Errors, broken)
				}
				if n := len(logged.records(endpointDeadMsg)); n != 1 {
					t.Errorf("%s going away was reported %d times, want once. Log:\n%s", broken, n, logged)
				}

				back := logged.records(endpointBackMsg)
				if len(back) != tc.wantBack {
					t.Fatalf("%s answering again was reported %d times over %d cycles to a handler at %v, "+
						"want %d: the recovery is one info line, so it is written once and a handler at warn "+
						"drops it. Log:\n%s", broken, len(back), cycles, tc.level, tc.wantBack, logged)
				}
				if tc.wantBack == 0 {
					return
				}
				if rec := back[0]; !namesEndpoint(rec, broken) {
					t.Errorf("the record names no endpoint, or names another one: %s", rec)
				} else if !strings.Contains(rec, "level=INFO") {
					t.Errorf("the record is not at info: %s", rec)
				}
			})
		})
	}
}

// Endpoints are remembered one at a time: one coming back and one going away in
// the same cycle are both reported, and one that was down before and is down
// still is not mentioned again.
func TestEndpointsAreReportedApart(t *testing.T) {
	const (
		comesBack = srcClients
		goesAway  = srcARP
		staysDown = srcTunnels
	)
	failure := errors.New("errorcode=00000002")

	rt := newFakeRouter(t)
	rt.fail(comesBack, failure)
	rt.fail(staysDown, failure)
	cfg := testConfig()
	// Debug: an endpoint that did not change has to be silent at every level,
	// and the failure that started this was invisible at all of them.
	logged := captureLog(t, slog.LevelDebug)

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		awaitCycle(t, p, cfg)
		time.Sleep(3*cfg.Interval + cfg.Interval/2)
		synctest.Wait()
		if n := len(logged.records(endpointDeadMsg)); n != 2 {
			t.Fatalf("%d endpoints were reported as gone, want the two broken from the start (%s, %s). "+
				"Log:\n%s", n, comesBack, staysDown, logged)
		}

		rt.mend(comesBack)
		rt.fail(goesAway, failure)

		window := 10 * cfg.Interval
		time.Sleep(window)
		synctest.Wait()

		st := p.State()
		if !st.Up || st.Snapshot == nil {
			t.Fatalf("no cycle came back in the %v after the swap; LastErr = %v", window, st.LastErr)
		}
		if st.Snapshot.Errors[comesBack] != nil || st.Snapshot.Errors[goesAway] == nil ||
			st.Snapshot.Errors[staysDown] == nil {
			t.Fatalf("the last cycle lost %v; want %s answering, %s and %s failing",
				st.Snapshot.Errors, comesBack, goesAway, staysDown)
		}

		for _, want := range []struct {
			what       string
			path       string
			dead, back int
			why        string
		}{
			{"the endpoint that came back", comesBack, 1, 1,
				"it went away once and answered again once"},
			{"the endpoint that went away in the same cycle", goesAway, 1, 0,
				"a second endpoint failing is its own transition, not a repeat of the first"},
			{"the endpoint that was down throughout", staysDown, 1, 0,
				"nothing changed for it, and a line a cycle over an endpoint nobody has fixed is the noise " +
					"the report exists to keep out"},
		} {
			if n := len(endpointRecords(logged, endpointDeadMsg, want.path)); n != want.dead {
				t.Errorf("%s (%s) was reported as gone %d times, want %d: %s. Log:\n%s",
					want.what, want.path, n, want.dead, want.why, logged)
			}
			if n := len(endpointRecords(logged, endpointBackMsg, want.path)); n != want.back {
				t.Errorf("%s (%s) was reported as answering again %d times, want %d: %s. Log:\n%s",
					want.what, want.path, n, want.back, want.why, logged)
			}
		}
		if n := len(logged.records(endpointDeadMsg)); n != 3 {
			t.Errorf("%d endpoints were reported as gone in all, want the 3 that broke; a record naming "+
				"anything else sends an operator after an endpoint that answered. Log:\n%s", n, logged)
		}
		if n := len(logged.records(endpointBackMsg)); n != 1 {
			t.Errorf("%d endpoints were reported as answering again in all, want the 1 that mended. Log:\n%s",
				n, logged)
		}
	})
}

// A healthy exporter says nothing about its endpoints.
func TestHealthyPollingReportsNoEndpoints(t *testing.T) {
	rt := newFakeRouter(t)
	cfg := testConfig()
	logged := captureLog(t, slog.LevelDebug)

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		awaitCycle(t, p, cfg)
		window := 10*cfg.Interval + cfg.Interval/2
		time.Sleep(window)
		synctest.Wait()

		st := p.State()
		cycles := rt.timesCalled(sources[0].Path)
		if st.Snapshot == nil {
			t.Fatalf("no snapshot after %d cycles in %v; LastErr = %v", cycles, window, st.LastErr)
		}
		if !st.Up || cycles < 10 || len(st.Snapshot.Errors) != 0 {
			t.Fatalf("%d cycles in %v, Up=%v, %d endpoints lost in the last one: this measures a run in "+
				"which everything answered and there is none. LastErr = %v",
				cycles, window, st.Up, len(st.Snapshot.Errors), st.LastErr)
		}

		for _, msg := range []string{endpointDeadMsg, endpointBackMsg} {
			if n := len(logged.records(msg)); n != 0 {
				t.Errorf("%q was written %d times over %d cycles in which every endpoint answered; the report "+
					"is made on a change and a clean run has none. Log:\n%s", msg, n, cycles, logged)
			}
		}
	})
}

// A cycle that did not succeed forgets which endpoints were failing, and says
// nothing while it does. Nothing was repaired one endpoint at a time — the
// login came back, or the session did — so a set kept across the outage
// announces a recovery for every endpoint in it.
func TestUnsuccessfulCycleForgetsTheFailingEndpointsQuietly(t *testing.T) {
	const broken = srcStatusAll

	for _, tc := range []struct {
		name         string
		lose, mend   func(*fakeRouter)
		outageCycles int
		during       func(*testing.T, State)
	}{
		{
			name: "a login refused while the web UI was held",
			lose: func(rt *fakeRouter) {
				rt.refuseLogin(fmt.Errorf("%w (close the browser tab)", tpapi.ErrSessionBusy))
			},
			mend:         func(rt *fakeRouter) { rt.allowLogin() },
			outageCycles: 5,
			during: func(t *testing.T, st State) {
				t.Helper()
				if st.LoginFailures == 0 {
					t.Fatalf("no login was refused, so no cycle failed on one. LastErr = %v", st.LastErr)
				}
			},
		},
		{
			name:         "the session taken at an endpoint",
			lose:         func(rt *fakeRouter) { rt.expireAt(srcPorts) },
			mend:         func(rt *fakeRouter) {},
			outageCycles: 2,
			during: func(t *testing.T, st State) {
				t.Helper()
				if st.SessionsLost == 0 {
					t.Fatalf("the session was never lost. LastErr = %v", st.LastErr)
				}
			},
		},
		{
			name:         "a cycle that ran out of Timeout",
			lose:         func(rt *fakeRouter) { rt.block(sources[0].Path) },
			mend:         func(rt *fakeRouter) { rt.unblock(sources[0].Path) },
			outageCycles: 4,
			during: func(t *testing.T, st State) {
				t.Helper()
				if !errors.Is(st.LastErr, context.DeadlineExceeded) {
					t.Fatalf("LastErr = %v; the cycle was meant to end on Config.Timeout", st.LastErr)
				}
			},
		},
		{
			name:         "a login held back after the session was taken twice",
			lose:         func(rt *fakeRouter) { rt.expireAtEvery(srcPorts) },
			mend:         func(rt *fakeRouter) { rt.stopExpiring() },
			outageCycles: 4,
			during: func(t *testing.T, st State) {
				t.Helper()
				if st.LoginsSuppressed == 0 {
					t.Fatalf("no login was held back; SessionsLost = %d, SessionBlocked = %v",
						st.SessionsLost, st.SessionBlocked)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newFakeRouter(t)
			rt.fail(broken, errors.New("errorcode=00000002 (no WAN while the fibre terminal rebooted)"))
			cfg := testConfig()
			logged := captureLog(t, slog.LevelDebug)

			synctest.Test(t, func(t *testing.T) {
				p, stop := startPoller(t, rt, cfg)
				defer stop()

				awaitCycle(t, p, cfg)
				time.Sleep(3*cfg.Interval + cfg.Interval/2)
				synctest.Wait()
				if n := len(logged.records(endpointDeadMsg)); n != 1 {
					t.Fatalf("%s was reported as gone %d times before the outage, want once. Log:\n%s",
						broken, n, logged)
				}

				// The endpoint answers again and the router goes away in the same
				// breath, half way between two cycles: no cycle that succeeds ever
				// sees it answer.
				rt.mend(broken)
				tc.lose(rt)

				time.Sleep(time.Duration(tc.outageCycles) * cfg.Interval)
				synctest.Wait()
				tc.during(t, p.State())
				if n := len(logged.records(endpointBackMsg)); n != 0 {
					t.Fatalf("%s was reported as answering again %d times during the outage, in which no "+
						"cycle succeeded. Log:\n%s", broken, n, logged)
				}

				tc.mend(rt)
				mendedAt := time.Now()
				full := rt.timesCalled(srcMesh)

				// Long enough for a backoff, or a quiet spell that doubled, to run
				// out with several cycles to spare after it.
				time.Sleep(2*cfg.SessionCooldown + 10*cfg.Interval)
				synctest.Wait()

				st := p.State()
				if st.Snapshot == nil || !st.Up {
					t.Fatalf("the poller never came back; Up=%v, LastErr = %v", st.Up, st.LastErr)
				}
				cycles := rt.timesCalled(srcMesh) - full
				if !st.Snapshot.TakenAt.After(mendedAt) || cycles < 3 || len(st.Snapshot.Errors) != 0 {
					t.Fatalf("%d whole cycles ran after the router was mended and the last one, taken at %v, "+
						"lost %v; the report is made on a cycle that succeeded, so there have to be some",
						cycles, st.Snapshot.TakenAt, st.Snapshot.Errors)
				}
				if n := len(logged.records(endpointBackMsg)); n != 0 {
					t.Errorf("%s was reported as answering again %d times; it was failing when the outage "+
						"began and answering when it ended, and nothing in between was a cycle that "+
						"succeeded. Log:\n%s", broken, n, logged)
				}
				if n := len(logged.records(endpointDeadMsg)); n != 1 {
					t.Errorf("%d endpoints were reported as gone in all, want the 1 that broke before the "+
						"outage: a cycle that did not succeed reports nothing. Log:\n%s", n, logged)
				}
			})
		})
	}
}

// The endpoints still broken when the router comes back are reported again. The
// set went with the outage, so the first good cycle says what is actually
// broken; keeping it leaves an endpoint that is down and was mentioned once,
// hours ago.
func TestEndpointStillBrokenAfterAnOutageIsReportedAgain(t *testing.T) {
	const broken = srcStatusAll
	failure := errors.New("errorcode=00000002 (no WAN while the fibre terminal rebooted)")

	rt := newFakeRouter(t)
	rt.fail(broken, failure)
	cfg := testConfig()
	logged := captureLog(t, slog.LevelDebug)

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		awaitCycle(t, p, cfg)
		time.Sleep(3*cfg.Interval + cfg.Interval/2)
		synctest.Wait()
		if n := len(logged.records(endpointDeadMsg)); n != 1 {
			t.Fatalf("%s was reported as gone %d times before the outage, want once. Log:\n%s",
				broken, n, logged)
		}

		// The web UI is taken and the poller stops polling at all. The endpoint is
		// still dead when it gets the session back.
		rt.refuseLogin(fmt.Errorf("%w (close the browser tab)", tpapi.ErrSessionBusy))
		time.Sleep(5 * cfg.Interval)
		synctest.Wait()
		if st := p.State(); st.LoginFailures == 0 {
			t.Fatalf("no login was refused, so there is no outage. LastErr = %v", st.LastErr)
		}
		rt.allowLogin()
		mendedAt := time.Now()

		time.Sleep(2*cfg.SessionCooldown + 10*cfg.Interval)
		synctest.Wait()

		st := p.State()
		if st.Snapshot == nil || !st.Up {
			t.Fatalf("the poller never came back; Up=%v, LastErr = %v", st.Up, st.LastErr)
		}
		if !st.Snapshot.TakenAt.After(mendedAt) || st.Snapshot.Errors[broken] == nil {
			t.Fatalf("the last cycle was taken at %v and lost %v; it has to be one from after the outage, "+
				"with %s failing in it", st.Snapshot.TakenAt, st.Snapshot.Errors, broken)
		}
		if n := len(logged.records(endpointDeadMsg)); n != 2 {
			t.Errorf("%s was reported as gone %d times, want twice — once before the outage and once after "+
				"it. Nothing repaired it while the poller was away, and the endpoints it remembered went "+
				"with the outage. Log:\n%s", broken, n, logged)
		}
		if n := len(logged.records(endpointBackMsg)); n != 0 {
			t.Errorf("%s was reported as answering again %d times, and it never answered. Log:\n%s",
				broken, n, logged)
		}
	})
}

// The two login paths on their own. Every other way to a cycle that cannot log
// in goes through a lost session, which is a failed cycle in its own right; a
// renewal hands the session back instead, so the refusal and the cap are the
// only failures in the run and SessionsLost stays 0. The endpoint is still
// broken when a login lands again, and is reported again.
func TestLoginThatNeverLandsForgetsTheFailingEndpoints(t *testing.T) {
	const broken = srcStatusAll

	for _, tc := range []struct {
		name         string
		loginCap     int
		refuseWith   error
		outageCycles int
		ageOut       bool // the cap frees only once the oldest attempt leaves lossWindow
		during       func(*testing.T, State)
	}{
		{
			name:         "the login that would replace it is refused",
			loginCap:     noLoginCap,
			refuseWith:   fmt.Errorf("%w (close the browser tab)", tpapi.ErrSessionBusy),
			outageCycles: 4,
			during: func(t *testing.T, st State) {
				t.Helper()
				if st.LoginFailures == 0 {
					t.Fatalf("no login was refused. LastErr = %v", st.LastErr)
				}
			},
		},
		{
			// Two attempts: the one at startup and the one the renewal made.
			name:         "the login that would replace it is held back by the hourly cap",
			loginCap:     2,
			refuseWith:   errors.New("dial tcp 192.0.2.1:80: connect: connection refused"),
			outageCycles: 4,
			ageOut:       true,
			during: func(t *testing.T, st State) {
				t.Helper()
				if st.LoginsSuppressed == 0 {
					t.Fatalf("no login was held back; LoginFailures = %d, LastErr = %v",
						st.LoginFailures, st.LastErr)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newFakeRouter(t)
			rt.fail(broken, errors.New("errorcode=00000002 (no WAN while the fibre terminal rebooted)"))
			cfg := testConfig()
			cfg.MaxLoginsPerHour = tc.loginCap
			// Due in the cycle after the run the report below is counted over.
			cfg.SessionRenew = 3*cfg.Interval + cfg.Interval/2
			logged := captureLog(t, slog.LevelDebug)

			synctest.Test(t, func(t *testing.T) {
				p, stop := startPoller(t, rt, cfg)
				defer stop()

				awaitCycle(t, p, cfg)
				time.Sleep(3*cfg.Interval + cfg.Interval/2)
				synctest.Wait()
				if n := len(logged.records(endpointDeadMsg)); n != 1 {
					t.Fatalf("%s was reported as gone %d times before the renewal, want once. Log:\n%s",
						broken, n, logged)
				}
				rt.failLogin(tc.refuseWith)

				time.Sleep(time.Duration(tc.outageCycles) * cfg.Interval)
				synctest.Wait()
				during := p.State()
				tc.during(t, during)
				if during.SessionsLost != 0 {
					t.Fatalf("SessionsLost = %d; the poller handed its session back and this measures what "+
						"happens when the login that follows does not land", during.SessionsLost)
				}
				if n := len(logged.records(endpointBackMsg)); n != 0 {
					t.Fatalf("%s was reported as answering again %d times while the poller held no session. "+
						"Log:\n%s", broken, n, logged)
				}

				rt.allowLogin()
				allowedAt := time.Now()
				settle := 10 * cfg.Interval
				if tc.ageOut {
					settle += lossWindow
				}
				time.Sleep(settle)
				synctest.Wait()

				st := p.State()
				if st.Snapshot == nil || !st.Up {
					t.Fatalf("the poller never logged in again in the %v after the router allowed it; Up=%v, "+
						"LoginsSuppressed = %d, LastErr = %v", settle, st.Up, st.LoginsSuppressed, st.LastErr)
				}
				if !st.Snapshot.TakenAt.After(allowedAt) || st.Snapshot.Errors[broken] == nil {
					t.Fatalf("the last cycle was taken at %v and lost %v; it has to be one from after the "+
						"login landed, with %s failing in it", st.Snapshot.TakenAt, st.Snapshot.Errors, broken)
				}
				if st.SessionsLost != 0 {
					t.Fatalf("SessionsLost = %d by the end; the session was never taken from the poller",
						st.SessionsLost)
				}
				if n := len(logged.records(endpointDeadMsg)); n != 2 {
					t.Errorf("%s was reported as gone %d times, want twice — once before the cycles that "+
						"could not log in, once after them. Nothing repaired it in between, and a set kept "+
						"across those cycles leaves it down and unmentioned. Log:\n%s", broken, n, logged)
				}
				if n := len(logged.records(endpointBackMsg)); n != 0 {
					t.Errorf("%s was reported as answering again %d times, and it never answered. Log:\n%s",
						broken, n, logged)
				}
			})
		})
	}
}

// Config.OnCycle is the seam push hangs on. It runs once per cycle whatever the
// cycle produced, carries the time that cycle's data claims, and is handed a
// context that outlives both the cycle's budget and the shutdown.

// hookCall is one OnCycle call as the callee saw it.
type hookCall struct {
	TakenAt time.Time
	At      time.Time // when the hook ran
	CtxErr  error     // ctx.Err() on entry
	Seen    State     // what a scrape would have seen from inside the hook
}

// cycleHook is a Config.OnCycle that records its arguments. Run calls it from
// its own goroutine, so the log is read under the mutex.
type cycleHook struct {
	// peek is read inside the hook, as the sender's collector reads State; set
	// before Run's goroutine starts. nil leaves State unread.
	peek func() State

	mu     sync.Mutex
	logged []hookCall
}

func (h *cycleHook) fn() func(context.Context, time.Time) {
	return func(ctx context.Context, takenAt time.Time) {
		var seen State
		if h.peek != nil {
			seen = h.peek()
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		h.logged = append(h.logged, hookCall{TakenAt: takenAt, At: time.Now(), CtxErr: ctx.Err(), Seen: seen})
	}
}

func (h *cycleHook) records() []hookCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]hookCall(nil), h.logged...)
}

func (h *cycleHook) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.logged)
}

// A cycle that published a snapshot hands over that snapshot's own time, once,
// and has published it before the hook runs.
func TestOnCycleRunsAfterEveryCycle(t *testing.T) {
	rt := newFakeRouter(t)
	cfg := testConfig()
	var hook cycleHook

	synctest.Test(t, func(t *testing.T) {
		start := time.Now()

		// Started by hand: the hook reads p, which must be assigned before the
		// goroutine that calls it starts.
		var p *Poller
		hook.peek = func() State { return p.State() }
		cfg.OnCycle = hook.fn()
		p = NewPoller(rt, cfg)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- p.Run(ctx) }()
		defer func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Run reported %v; a cancelled context is a shutdown, not a failure", err)
				}
			case <-time.After(time.Minute):
				t.Error("Run did not return after its context was cancelled")
			}
		}()

		st := awaitCycle(t, p, cfg)
		if st.Snapshot == nil {
			t.Fatal("the first cycle produced no snapshot")
		}
		first := hook.records()
		if len(first) != 1 {
			t.Fatalf("the hook ran %d times over one cycle, want once", len(first))
		}
		// The first cycle logs in, so the snapshot is taken a login after the
		// cycle began and the two times tell each other apart.
		if !st.Snapshot.TakenAt.After(start) {
			t.Fatalf("the snapshot claims %v and the cycle began at %v; with the two alike this proves "+
				"nothing about which one the hook was handed", st.Snapshot.TakenAt, start)
		}
		if !first[0].TakenAt.Equal(st.Snapshot.TakenAt) {
			t.Errorf("the hook was handed %v while the cycle's snapshot says %v; what is pushed carries the "+
				"snapshot's own time, or a scrape and a push of one cycle disagree about when it happened",
				first[0].TakenAt, st.Snapshot.TakenAt)
		}
		if first[0].CtxErr != nil {
			t.Errorf("the hook got a context already carrying %v", first[0].CtxErr)
		}

		window := 3*cfg.Interval + cfg.Interval/2
		time.Sleep(window)
		synctest.Wait()

		got := hook.records()
		cycles := rt.timesCalled(sources[0].Path)
		if len(got) != cycles {
			t.Errorf("the hook ran %d times over %d cycles in %v; one cycle ends in one call", len(got), cycles, window)
		}
		last, snap := got[len(got)-1], p.State().Snapshot
		if !last.TakenAt.Equal(snap.TakenAt) {
			t.Errorf("the last call was handed %v while the last snapshot says %v", last.TakenAt, snap.TakenAt)
		}

		// The state is published before the hook runs: a hook running first would
		// send the previous cycle's data under this cycle's time.
		for i, c := range got {
			if c.Seen.Snapshot == nil {
				t.Errorf("call %d found State carrying no snapshot at all, although its own cycle "+
					"published one taken at %v", i+1, c.TakenAt)
				continue
			}
			if !c.Seen.Snapshot.TakenAt.Equal(c.TakenAt) {
				t.Errorf("call %d was handed %v while State read inside the hook still showed the snapshot "+
					"taken at %v; the cycle publishes its state and drops the lock before the hook runs, or "+
					"a push carries this cycle's time on the last cycle's data",
					i+1, c.TakenAt, c.Seen.Snapshot.TakenAt)
			}
		}
	})
}

// A cycle that reached nothing still ends in the hook, stamped with its own
// start: the cycle a dark router produced has to travel too, or the router that
// went dark reads downstream as the exporter going dark.
func TestOnCycleRunsForACycleThatPublishedNothing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*fakeRouter)
	}{
		{"the login is refused", func(rt *fakeRouter) {
			rt.refuseLogin(fmt.Errorf("login: %w", tpapi.ErrSessionBusy))
		}},
		{"nothing answers", func(rt *fakeRouter) {
			rt.failAll(errors.New("dial tcp 192.0.2.1:80: connect: connection refused"))
		}},
		{"the session is taken at the first endpoint", func(rt *fakeRouter) {
			rt.expireAtEvery(sources[0].Path)
		}},
		{"the cycle runs out of time", func(rt *fakeRouter) {
			for _, s := range sources {
				rt.block(s.Path)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newFakeRouter(t)
			tc.setup(rt)
			cfg := testConfig()
			var hook cycleHook
			cfg.OnCycle = hook.fn()

			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				p, stop := startPoller(t, rt, cfg)
				defer stop()

				st := awaitCycle(t, p, cfg)
				if st.Snapshot != nil {
					t.Fatalf("the cycle published a snapshot taken at %v; this case is one where nothing "+
						"is collected", st.Snapshot.TakenAt)
				}
				got := hook.records()
				if len(got) == 0 {
					t.Fatalf("a cycle that collected nothing never reached the hook; LastErr = %v, and "+
						"tplink_up = 0 is exactly what has to travel", st.LastErr)
				}
				if got[0].TakenAt.IsZero() {
					t.Fatal("the hook was handed a zero time; a cycle without a snapshot carries its own start")
				}
				if d := got[0].TakenAt.Sub(start); d < 0 || d > replyLatency {
					t.Errorf("the hook was handed %v, %v off the cycle start %v; a cycle that published no "+
						"snapshot is stamped with the moment it began, not the moment it ended (%v)",
						got[0].TakenAt, d, start, got[0].At)
				}
				if got[0].CtxErr != nil {
					t.Errorf("the hook got a context already carrying %v", got[0].CtxErr)
				}
			})
		})
	}
}

// What a cycle collected before the session was taken is published, and the
// hook follows the snapshot rather than the cycle start.
func TestOnCycleFollowsThePartialSnapshot(t *testing.T) {
	rt := newFakeRouter(t)
	// Every login is answered by taking the session away again at srcPorts, so
	// the first cycle is the one that publishes a part of the poll set. expireAt
	// alone would not do: a login re-arms the expiry from expireEvery, and the
	// first cycle's own login would clear it.
	rt.expireAtEvery(srcPorts)
	cfg := testConfig()
	var hook cycleHook
	cfg.OnCycle = hook.fn()

	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		st := awaitCycle(t, p, cfg)
		if st.Snapshot == nil {
			t.Fatalf("the cycle published nothing although it lost the session at %s, part way through the "+
				"poll set", srcPorts)
		}
		if len(st.Snapshot.Errors) != 1 || st.Snapshot.Errors[srcPorts] == nil {
			t.Fatalf("Snapshot.Errors = %v, want the one entry for %s; this case is the cycle that ends "+
				"part way through the poll set", st.Snapshot.Errors, srcPorts)
		}
		// The cycle logs in before it polls, so the snapshot is taken a login
		// after the cycle began and the two times tell each other apart.
		if !st.Snapshot.TakenAt.After(start) {
			t.Fatalf("the snapshot claims %v and the cycle began at %v; with the two alike this proves "+
				"nothing", st.Snapshot.TakenAt, start)
		}
		got := hook.records()
		if len(got) == 0 {
			t.Fatal("the cycle that lost the session never reached the hook")
		}
		if !got[0].TakenAt.Equal(st.Snapshot.TakenAt) {
			t.Errorf("the hook was handed %v while the partial snapshot it published says %v; a cycle that "+
				"published one is stamped with its time, whatever ended the cycle",
				got[0].TakenAt, st.Snapshot.TakenAt)
		}
	})
}

// Config.Timeout is the cycle's whole budget and a slow cycle ends with none of
// it left. The hook's context is not the cycle's, so the sender still has its
// own time to spend.
func TestOnCycleGetsAContextTheCycleDidNotSpend(t *testing.T) {
	rt := newFakeRouter(t)
	rt.block(sources[0].Path)
	cfg := testConfig()
	var hook cycleHook
	cfg.OnCycle = hook.fn()

	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		awaitCycle(t, p, cfg)
		got := hook.records()
		if len(got) == 0 {
			t.Fatal("the hook never ran")
		}
		if spent := got[0].At.Sub(start); spent < cfg.Timeout {
			t.Fatalf("the cycle ended %v after it began while Config.Timeout is %v; it never ran out of "+
				"time, so this proves nothing", spent, cfg.Timeout)
		}
		if got[0].CtxErr != nil {
			t.Errorf("the hook got a context carrying %v after a cycle that spent all %v of Config.Timeout; "+
				"the cycle's budget is not the sender's, or every slow cycle would fail to send",
				got[0].CtxErr, cfg.Timeout)
		}
	})
}

// The cycle a shutdown cuts short is the last one there will be, and it travels:
// the hook runs before Run reads its cancelled context, on a context with that
// cancellation removed.
func TestOnCycleRunsForTheCycleAShutdownInterrupts(t *testing.T) {
	rt := newFakeRouter(t)
	// The cycle sits on this endpoint until something ends the request, so the
	// cancellation lands mid-cycle rather than in the wait between cycles.
	rt.block(sources[0].Path)
	cfg := testConfig()
	var hook cycleHook
	cfg.OnCycle = hook.fn()

	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		p := NewPoller(rt, cfg)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- p.Run(ctx) }()

		time.Sleep(cfg.Timeout / 2)
		synctest.Wait()
		if n := hook.count(); n != 0 {
			t.Fatalf("the hook ran %d times %v into the first cycle, which is still running; the shutdown "+
				"below would not be landing mid-cycle", n, cfg.Timeout/2)
		}
		cancel()

		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run returned %v; a cancelled context is a clean shutdown and reports nil", err)
			}
		case <-time.After(time.Minute):
			t.Fatal("Run did not return after its context was cancelled")
		}

		got := hook.records()
		if len(got) != 1 {
			t.Fatalf("the hook ran %d times, want once: the cycle a shutdown cut short is still a cycle, and "+
				"the last one before a docker stop has to reach the sender", len(got))
		}
		if got[0].CtxErr != nil {
			t.Errorf("the hook got a context carrying %v; the shutdown's cancellation is removed from it, or "+
				"the send it exists to make dies where it starts", got[0].CtxErr)
		}
		if d := got[0].TakenAt.Sub(start); d < 0 || d > replyLatency {
			t.Errorf("the interrupted cycle was stamped %v, %v off the moment it began, %v",
				got[0].TakenAt, d, start)
		}
	})
}

// A cycle held back from logging in never touches the router and still ends in
// the hook: while the poller stays away from a session someone else is using,
// the series has to keep saying so.
func TestOnCycleRunsWhileTheLoginIsHeldBack(t *testing.T) {
	rt := newFakeRouter(t)
	rt.expireAtEvery(srcPorts)
	cfg := testConfig()
	cfg.SessionCooldown = 20 * time.Minute
	var hook cycleHook
	cfg.OnCycle = hook.fn()

	synctest.Test(t, func(t *testing.T) {
		p, stop := startPoller(t, rt, cfg)
		defer stop()

		// Two cycles in, the second loss has armed the spell; both samples sit
		// well inside it.
		const early, late = 5 * time.Minute, 15 * time.Minute
		time.Sleep(early)
		synctest.Wait()
		first, ran := p.State(), hook.count()

		time.Sleep(late - early)
		synctest.Wait()
		second, got := p.State(), hook.records()

		if !second.SessionBlocked {
			t.Fatalf("SessionBlocked is false %v into a quiet spell of %v; there is no spell to measure",
				late, cfg.SessionCooldown)
		}
		suppressed := int(second.LoginsSuppressed - first.LoginsSuppressed)
		if suppressed == 0 {
			t.Fatalf("no login was held back between %v and %v of a %v spell; there is nothing to measure",
				early, late, cfg.SessionCooldown)
		}
		if grew := len(got) - ran; grew < suppressed {
			t.Errorf("the hook ran %d times over the %v in which %d cycles were held back from logging in; a "+
				"cycle that never reached the router is still a cycle and still has to travel",
				grew, late-early, suppressed)
		}
		if n := len(got); n >= 2 && got[n-1].TakenAt.Equal(got[n-2].TakenAt) {
			t.Errorf("two held-back cycles in a row were both stamped %v; each carries its own start",
				got[n-1].TakenAt)
		}
	})
}

// lastCallBefore and firstCallAfter bracket a moment in the call log: what the
// poller had polled by then and what it polled next.
func lastCallBefore(t *testing.T, calls []routerCall, at time.Time) routerCall {
	t.Helper()
	for i := len(calls) - 1; i >= 0; i-- {
		if calls[i].At.Before(at) {
			return calls[i]
		}
	}
	t.Fatalf("nothing was polled before %v; the poller made %d requests in all", at, len(calls))
	return routerCall{}
}

func firstCallAfter(calls []routerCall, at time.Time) (routerCall, bool) {
	for _, c := range calls {
		if c.At.After(at) {
			return c, true
		}
	}
	return routerCall{}, false
}

// snapshotSection is one part of a snapshot and the endpoint that fills it.
type snapshotSection struct {
	name   string
	from   string
	filled bool
}

// snapshotSections lists what a cycle over the fixtures must produce. Every
// endpoint named here answers with a non-empty fixture, so an empty section
// means the cycle lost it. The three empty fixtures — upnp?form=service,
// nat?form=vs and nat?form=pt — say the reference device has no mapping and no
// forwarding rule, so they pin no section of their own.
func snapshotSections(s *Snapshot) []snapshotSection {
	return []snapshotSection{
		{"Clients", "admin/smart_network?form=game_accelerator", len(s.Clients) > 0},
		{"Leases", "admin/dhcps?form=client", len(s.Leases) > 0},
		{"Reservations", "admin/dhcps?form=reservation", len(s.Reservations) > 0},
		{"DHCP", "admin/dhcps?form=setting", s.DHCP != nil},
		{"Perf", "admin/status?form=all", s.Perf != nil},
		{"Wireless", "admin/status?form=all", len(s.Wireless) > 0},
		{"Ports", "admin/status?form=router", len(s.Ports) > 0},
		{"WAN", "admin/status?form=internet", s.WAN != nil},
		{"Tunnels", "admin/vpn?form=server", len(s.Tunnels) > 0},
		{"VPNUsers", "admin/vpn?form=vpn_user_list", len(s.VPNUsers) > 0},
		{"VPNServer", "admin/vpn?form=enable", s.VPNServer != nil},
		{"Firmware", "admin/firmware?form=upgrade", s.Firmware != nil},
		{"Router", "admin/time?form=settings", s.Router != nil},
		{"Security", "admin/security_settings?form=new_enable", s.Security != nil},
		{"ARP", "admin/imb?form=arp_list", len(s.ARP) > 0},
		{"Mesh", "admin/easymesh_network?form=get_mesh_device_list_all", len(s.Mesh) > 0},
	}
}

// operationFor answers from the fixture table, not from the poll set the test
// is checking.
func operationFor(path string) (string, bool) {
	src, ok := sourceFixture[path]
	return src.operation, ok
}
