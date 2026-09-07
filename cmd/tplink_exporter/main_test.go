package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/akentyev/tplink_archer_exporter/internal/exporter"
	"github.com/akentyev/tplink_archer_exporter/internal/push"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	collectorpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/protobuf/proto"
)

// The command line is the one seam the exporter tests cannot reach: they build
// exporter.Config themselves. -session-renew was parsed, range-checked and
// logged, then left out of the Config literal, and a zero SessionRenew means
// "renewal off" rather than "give me the default", so NewPoller could not cover
// for it.
//
// README's "Configuration" table is the source of truth for flag names,
// environment variables and defaults here; a disagreement with the code stays
// red.

// flagSpec is one row of that table. def is the documented default, "—" read as
// the zero value. arg and envArg are the same field set two ways, with three
// distinct values per row so precedence and cross-wiring both show. An empty env
// is a dash in README's env column: the row has no envArg and no envWant, and the
// fallback test asserts the variable it would have been named after is ignored.
type flagSpec struct {
	flag    string
	env     string
	field   string // the options field it lands in
	def     any
	arg     string
	want    any
	envArg  string
	envWant any
}

// TPLINK_PASSWORD and TZ are in the table with no flag beside them and belong
// to main, not here: a password flag is visible in ps, and TZ is read by the
// runtime.
var flagTable = []flagSpec{
	{
		flag: "host", env: "TPLINK_HOST", field: "Host", def: "",
		arg: "http://192.0.2.1", want: "http://192.0.2.1",
		envArg: "http://192.0.2.9", envWant: "http://192.0.2.9",
	},
	{
		flag: "user", env: "TPLINK_USER", field: "User", def: "admin",
		arg: "operator", want: "operator",
		envArg: "monitor", envWant: "monitor",
	},
	{
		flag: "password-file", env: "TPLINK_PASSWORD_FILE", field: "PasswordFile", def: "",
		arg: "/run/secrets/tplink_password", want: "/run/secrets/tplink_password",
		envArg: "/etc/tplink/password", envWant: "/etc/tplink/password",
	},
	{
		flag: "listen", env: "TPLINK_LISTEN", field: "Listen", def: "127.0.0.1:9110",
		arg: "0.0.0.0:9110", want: "0.0.0.0:9110",
		envArg: "192.0.2.10:9111", envWant: "192.0.2.10:9111",
	},
	{
		flag: "log-level", env: "TPLINK_LOG_LEVEL", field: "LogLevel", def: "info",
		arg: "debug", want: "debug",
		envArg: "warn", envWant: "warn",
	},
	{
		flag: "interval", env: "TPLINK_INTERVAL", field: "Interval", def: 60 * time.Second,
		arg: "45s", want: 45 * time.Second,
		envArg: "90s", envWant: 90 * time.Second,
	},
	{
		flag: "timeout", env: "TPLINK_TIMEOUT", field: "Timeout", def: 30 * time.Second,
		arg: "25s", want: 25 * time.Second,
		envArg: "20s", envWant: 20 * time.Second,
	},
	{
		flag: "request-timeout", env: "TPLINK_REQUEST_TIMEOUT", field: "RequestTimeout", def: 10 * time.Second,
		arg: "8s", want: 8 * time.Second,
		envArg: "12s", envWant: 12 * time.Second,
	},
	{
		flag: "min-backoff", env: "TPLINK_MIN_BACKOFF", field: "MinBackoff", def: time.Minute,
		arg: "90s", want: 90 * time.Second,
		envArg: "30s", envWant: 30 * time.Second,
	},
	{
		flag: "max-backoff", env: "TPLINK_MAX_BACKOFF", field: "MaxBackoff", def: 15 * time.Minute,
		arg: "12m", want: 12 * time.Minute,
		envArg: "20m", envWant: 20 * time.Minute,
	},
	{
		flag: "session-cooldown", env: "TPLINK_SESSION_COOLDOWN", field: "SessionCooldown", def: 5 * time.Minute,
		arg: "7m", want: 7 * time.Minute,
		envArg: "3m", envWant: 3 * time.Minute,
	},
	{
		flag: "session-renew", env: "TPLINK_SESSION_RENEW", field: "SessionRenew", def: 30 * time.Minute,
		arg: "21m", want: 21 * time.Minute,
		envArg: "40m", envWant: 40 * time.Minute,
	},
	{
		flag: "push-url", env: "TPLINK_PUSH_URL", field: "PushURL", def: "",
		arg: "http://192.0.2.50:8428/opentelemetry/v1/metrics", want: "http://192.0.2.50:8428/opentelemetry/v1/metrics",
		envArg: "http://192.0.2.60:4318/v1/metrics", envWant: "http://192.0.2.60:4318/v1/metrics",
	},
	// -push-label repeats, so its field is a labelList rather than a string:
	// the first flag replaces what the variable seeded and later ones append.
	{
		flag: "push-label", env: "TPLINK_PUSH_LABELS", field: "PushLabels", def: labelList{},
		arg: "site=home", want: labelList{pairs: "site=home", flagged: true},
		envArg: "env=prod", envWant: labelList{pairs: "env=prod"},
	},
	{
		flag: "push-buffer", env: "TPLINK_PUSH_BUFFER", field: "PushBuffer", def: push.DefaultBuffer,
		arg: "512", want: 512,
		envArg: "120", envWant: 120,
	},
	{
		flag: "push-timeout", env: "TPLINK_PUSH_TIMEOUT", field: "PushTimeout", def: 10 * time.Second,
		arg: "9s", want: 9 * time.Second,
		envArg: "7s", envWant: 7 * time.Second,
	},
	// -version has no environment variable: it is a question to the binary,
	// answered and gone, not a setting a container carries.
	{
		flag: "version", env: "", field: "Version", def: false,
		arg: "true", want: true,
	},
}

// bind declares the flags on a private FlagSet. The global flag.CommandLine
// carries the real binary's flags and the testing package's own.
func bind(t *testing.T) (*flag.FlagSet, *options, *env) {
	t.Helper()
	fs := flag.NewFlagSet("tplink_exporter", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	e := &env{}
	return fs, bindFlags(fs, e), e
}

func parse(t *testing.T, fs *flag.FlagSet, args ...string) {
	t.Helper()
	if err := fs.Parse(args); err != nil {
		t.Fatalf("Parse(%q): %v", args, err)
	}
}

// field reads an options field by name.
func field(t *testing.T, o *options, name string) any {
	t.Helper()
	v := reflect.ValueOf(*o).FieldByName(name)
	if !v.IsValid() {
		t.Fatalf("options has no field %s", name)
	}
	return v.Interface()
}

// clearEnv drops every TPLINK_ variable for the test. t.Setenv registers the
// restore; without it the developer's own environment decides what a default
// looks like.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(key, "TPLINK_") {
			t.Setenv(key, "")
			os.Unsetenv(key)
		}
	}
}

func TestBindFlagsDefaults(t *testing.T) {
	clearEnv(t)
	fs, o, e := bind(t)
	parse(t, fs)

	for _, spec := range flagTable {
		if fs.Lookup(spec.flag) == nil {
			t.Errorf("no -%s flag; README's Configuration table documents one", spec.flag)
			continue
		}
		if got := field(t, o, spec.field); got != spec.def {
			t.Errorf("-%s defaults to %v, README says %v", spec.flag, got, spec.def)
		}
	}
	if len(e.errs) != 0 {
		t.Errorf("an empty environment recorded %v", e.errs)
	}

	documented := map[string]bool{}
	for _, spec := range flagTable {
		documented[spec.flag] = true
	}
	fs.VisitAll(func(f *flag.Flag) {
		if !documented[f.Name] {
			t.Errorf("-%s is declared but missing from README's Configuration table", f.Name)
		}
	})

	// The other direction: an options field with no flag is one the command
	// line cannot reach.
	wired := map[string]bool{}
	for _, spec := range flagTable {
		wired[spec.field] = true
	}
	for _, f := range reflect.VisibleFields(reflect.TypeFor[options]()) {
		if !wired[f.Name] {
			t.Errorf("options.%s has no flag in README's Configuration table", f.Name)
		}
	}
}

// Every flag at once, each with a value no other flag carries: a flag bound to
// the wrong field moves two values instead of one.
func TestBindFlagsParsesEachFlagIntoItsOwnField(t *testing.T) {
	clearEnv(t)
	fs, o, e := bind(t)

	args := make([]string, 0, len(flagTable))
	for _, spec := range flagTable {
		args = append(args, "-"+spec.flag+"="+spec.arg)
	}
	parse(t, fs, args...)

	for _, spec := range flagTable {
		if got := field(t, o, spec.field); got != spec.want {
			t.Errorf("-%s=%s left options.%s at %v, want %v", spec.flag, spec.arg, spec.field, got, spec.want)
		}
	}
	if len(e.errs) != 0 {
		t.Errorf("parsing the flags recorded %v", e.errs)
	}
}

func TestBindFlagsEnvFallbackAndFlagPrecedence(t *testing.T) {
	for _, spec := range flagTable {
		t.Run(spec.flag, func(t *testing.T) {
			clearEnv(t)
			// A dash in README's env column is a claim to check, not a reason to
			// skip: the flag has to ignore the variable it would have been named
			// after. Skipping would excuse a row that simply lost its env.
			if spec.env == "" {
				absent := "TPLINK_" + strings.ToUpper(strings.ReplaceAll(spec.flag, "-", "_"))
				t.Setenv(absent, spec.arg)

				fs, o, e := bind(t)
				parse(t, fs)
				if got := field(t, o, spec.field); got != spec.def {
					t.Errorf("%s=%s left options.%s at %v, want the default %v: README documents no variable for -%s",
						absent, spec.arg, spec.field, got, spec.def, spec.flag)
				}
				if len(e.errs) != 0 {
					t.Errorf("declaring the flags recorded %v", e.errs)
				}
				return
			}
			t.Setenv(spec.env, spec.envArg)

			fs, o, e := bind(t)
			parse(t, fs)
			if got := field(t, o, spec.field); got != spec.envWant {
				t.Errorf("%s=%s left options.%s at %v, want %v", spec.env, spec.envArg, spec.field, got, spec.envWant)
			}
			if len(e.errs) != 0 {
				t.Errorf("%s=%s recorded %v", spec.env, spec.envArg, e.errs)
			}
			for _, other := range flagTable {
				if other.field == spec.field {
					continue
				}
				if got := field(t, o, other.field); got != other.def {
					t.Errorf("%s=%s also moved options.%s to %v, want the default %v",
						spec.env, spec.envArg, other.field, got, other.def)
				}
			}

			// README: the flag wins when both are set.
			arg := "-" + spec.flag + "=" + spec.arg
			fs, o, _ = bind(t)
			parse(t, fs, arg)
			if got := field(t, o, spec.field); got != spec.want {
				t.Errorf("%s lost to %s=%s: options.%s = %v, want %v",
					arg, spec.env, spec.envArg, spec.field, got, spec.want)
			}
		})
	}
}

// fullOptions is a command line with every field set and no two fields alike,
// so a dropped assignment in pollerConfig leaves a zero and a swapped pair
// lands on the wrong value.
func fullOptions() *options {
	return &options{
		Host:            "http://192.0.2.1",
		User:            "operator",
		PasswordFile:    "/run/secrets/tplink_password",
		Listen:          "0.0.0.0:9110",
		LogLevel:        "debug",
		Interval:        45 * time.Second,
		Timeout:         25 * time.Second,
		RequestTimeout:  8 * time.Second,
		MinBackoff:      90 * time.Second,
		MaxBackoff:      12 * time.Minute,
		SessionRenew:    21 * time.Minute,
		SessionCooldown: 7 * time.Minute,
		// A push command line: -push-url is what selects the mode, and the tests
		// below read the wiring it turns on through these options.
		PushURL:     "http://192.0.2.50:8428/opentelemetry/v1/metrics",
		PushLabels:  labelList{pairs: "site=home", flagged: true},
		PushBuffer:  512,
		PushTimeout: 9 * time.Second,
		// Not a poller setting; set because assertDistinct reads a zero field as
		// an assignment that was dropped.
		Version: true,
	}
}

// Func fields cannot be compared with ==, so they are checked for nil-ness;
// the value is whether fullOptions, which carries -push-url, must set them.
var wantConfigSet = map[string]bool{"OnCycle": true}

// What fullOptions must produce, by exporter.Config field name. MaxLoginsPerHour
// has no flag and is still set here rather than left to NewPoller.
var wantConfig = map[string]any{
	"Interval":         45 * time.Second,
	"Timeout":          25 * time.Second,
	"MinBackoff":       90 * time.Second,
	"MaxBackoff":       12 * time.Minute,
	"SessionCooldown":  7 * time.Minute,
	"SessionRenew":     21 * time.Minute,
	"MaxLoginsPerHour": exporter.DefaultMaxLoginsPerHour,
}

// Driven by reflect over exporter.Config: a field added there and not wired in
// pollerConfig fails here instead of taking a silent default.
func TestPollerConfigSetsEveryField(t *testing.T) {
	o := fullOptions()
	assertDistinct(t, o)

	cfg := reflect.ValueOf(pollerConfig(o, &fakePusher{}))
	for _, f := range reflect.VisibleFields(cfg.Type()) {
		if !f.IsExported() {
			continue
		}
		if want, ok := wantConfigSet[f.Name]; ok {
			if set := !cfg.FieldByIndex(f.Index).IsNil(); set != want {
				t.Errorf("pollerConfig().%s is set = %v for a command line carrying -push-url, want %v",
					f.Name, set, want)
			}
			continue
		}
		want, ok := wantConfig[f.Name]
		if !ok {
			t.Errorf("exporter.Config.%s is not wired here; pollerConfig must set every field, or a "+
				"forgotten one takes NewPoller's fallback in silence", f.Name)
			continue
		}
		if got := cfg.FieldByIndex(f.Index).Interface(); got != want {
			t.Errorf("pollerConfig().%s = %v, want %v", f.Name, got, want)
		}
	}
	for name := range wantConfig {
		if _, ok := cfg.Type().FieldByName(name); !ok {
			t.Errorf("exporter.Config no longer has %s", name)
		}
	}
	for name := range wantConfigSet {
		if _, ok := cfg.Type().FieldByName(name); !ok {
			t.Errorf("exporter.Config no longer has %s", name)
		}
	}
}

// The shipped bug inverted: zero means renewal off, so nothing may put
// DefaultSessionRenew in its place.
func TestPollerConfigKeepsSessionRenewOff(t *testing.T) {
	o := fullOptions()
	o.SessionRenew = 0

	cfg := pollerConfig(o, &fakePusher{})
	if cfg.SessionRenew != 0 {
		t.Errorf("-session-renew=0 produced SessionRenew = %v; zero is renewal off, not a request for "+
			"the default", cfg.SessionRenew)
	}
	if cfg.Interval != o.Interval {
		t.Errorf("Interval = %v, want %v: only SessionRenew was zeroed", cfg.Interval, o.Interval)
	}
}

// assertDistinct keeps the input to pollerConfig honest. A bool has one
// non-zero value, so the second bool ever added to options fails here as a
// swap of the first: widen the check then rather than weaken it.
func assertDistinct(t *testing.T, o *options) {
	t.Helper()
	v := reflect.ValueOf(*o)
	seen := map[any]string{}
	for _, f := range reflect.VisibleFields(v.Type()) {
		got := v.FieldByIndex(f.Index)
		if got.IsZero() {
			t.Errorf("options.%s is zero; a dropped assignment would produce the same value", f.Name)
			continue
		}
		if other, dup := seen[got.Interface()]; dup {
			t.Errorf("options.%s and options.%s are both %v; a swapped assignment would go unseen",
				other, f.Name, got.Interface())
			continue
		}
		seen[got.Interface()] = f.Name
	}
}

// README's log table says the starting line leads with the build. It is the one
// place the build reaches the log, and a container that never gets past start-up
// is read from the top.
func TestStartupAttrsLeadWithTheBuild(t *testing.T) {
	attrs := startupAttrs(fullOptions(),
		exporter.BuildInfo{Version: "2026.8.0", Revision: "1a2b3c4", GoVersion: "go1.26.6"},
		"http://192.0.2.1")

	if len(attrs)%2 != 0 {
		t.Fatalf("startupAttrs returned %d values; slog reads them as key/value pairs", len(attrs))
	}
	want := []any{"version", "2026.8.0", "revision", "1a2b3c4", "host", "http://192.0.2.1"}
	for i, w := range want {
		if attrs[i] != w {
			t.Errorf("attribute %d is %v, want %v", i, attrs[i], w)
		}
	}
}

// --- push mode -------------------------------------------------------------

// testHost is the router's address as tpapi.New normalizes it: what instance
// and service.instance.id carry in push mode.
const testHost = "http://192.0.2.1"

var testBuild = exporter.BuildInfo{Version: "2026.8.0", Revision: "1a2b3c4", GoVersion: "go1.26.6"}

// fakePusher stands in for push.Sender. The hook must reach it once per cycle,
// carrying the cycle's own time and context.
type fakePusher struct {
	calls   int
	ctx     context.Context
	takenAt time.Time
	err     error
}

func (f *fakePusher) Push(ctx context.Context, takenAt time.Time) error {
	f.calls++
	f.ctx, f.takenAt = ctx, takenAt
	return f.err
}

// stubSource is the collector's input; a zero State still publishes
// tplink_up, which is all the /metrics test reads.
type stubSource struct{}

func (stubSource) State() exporter.State { return exporter.State{} }

// The shipped bug's shape, with -push-url in place of -session-renew: the flag
// is parsed, the sender is built, and the hook that drives it never reaches the
// poller. Nothing else would notice — push simply never runs.
func TestPollerConfigWiresTheSenderIntoOnCycle(t *testing.T) {
	p := &fakePusher{}
	cfg := pollerConfig(fullOptions(), p)
	if cfg.OnCycle == nil {
		t.Fatal("pollerConfig left OnCycle nil for a command line carrying -push-url; the sender would be built and never called")
	}

	type key struct{}
	ctx := context.WithValue(context.Background(), key{}, "the cycle's own")
	takenAt := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	cfg.OnCycle(ctx, takenAt)

	if p.calls != 1 {
		t.Fatalf("one cycle reached the sender %d times, want once", p.calls)
	}
	if !p.takenAt.Equal(takenAt) {
		t.Errorf("the sender was handed %v, want the cycle's own %v", p.takenAt, takenAt)
	}
	if p.ctx == nil || p.ctx.Value(key{}) != "the cycle's own" {
		t.Errorf("the sender was handed a context of the hook's own making, not the cycle's")
	}
}

// Pull mode: nothing runs after a cycle, so the poller behaves as it did before
// push existed.
func TestPollerConfigLeavesOnCycleNilWithoutPushURL(t *testing.T) {
	o := fullOptions()
	o.PushURL = ""

	if cfg := pollerConfig(o, nil); cfg.OnCycle != nil {
		t.Error("pollerConfig set OnCycle without -push-url; pull mode runs nothing at the end of a cycle")
	}
}

// Sender logs a failure when it starts, the recovery when it ends and every
// refusal. A line here would put those back one per cycle: 300 of them across a
// five-hour outage.
func TestOnCycleKeepsQuietAboutWhatTheSenderReported(t *testing.T) {
	var buf strings.Builder
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(restore) })

	cfg := pollerConfig(fullOptions(), &fakePusher{err: errors.New("push snapshot: 503 Service Unavailable")})
	cfg.OnCycle(context.Background(), time.Now())

	if buf.Len() != 0 {
		t.Errorf("the hook logged %q; the sender has already said it, once for the outage rather than once a cycle", buf.String())
	}
}

// What fullOptions must produce, by push.Config field name.
var wantPushConfig = map[string]any{
	"Endpoint": "http://192.0.2.50:8428/opentelemetry/v1/metrics",
	"Labels":   map[string]string{"job": "tplink_exporter", "instance": testHost, "site": "home"},
	"Resource": map[string]string{"service.name": "tplink_exporter", "service.instance.id": testHost},
	// Reserved for credentials, which will be read from a file the way the
	// router's password is. Nothing on the command line fills it, and this is
	// the line a source has to change.
	"Headers": map[string]string(nil),
	"Buffer":  512,
	"Timeout": 9 * time.Second,
}

// Driven by reflect over push.Config, as pollerConfig's test is over
// exporter.Config: a field added there and not wired here goes out as a zero.
func TestPushConfigSetsEveryField(t *testing.T) {
	o := fullOptions()
	assertDistinct(t, o)
	e := &env{}

	cfg := reflect.ValueOf(pushConfig(o, testHost, pushLabels(o.PushLabels, e)))
	if len(e.errs) != 0 {
		t.Fatalf("a well-formed command line recorded %v", e.errs)
	}
	for _, f := range reflect.VisibleFields(cfg.Type()) {
		if !f.IsExported() {
			continue
		}
		want, ok := wantPushConfig[f.Name]
		if !ok {
			t.Errorf("push.Config.%s is not wired here; pushConfig must set every field, or a forgotten one "+
				"travels as a zero", f.Name)
			continue
		}
		if got := cfg.FieldByIndex(f.Index).Interface(); !reflect.DeepEqual(got, want) {
			t.Errorf("pushConfig().%s = %v, want %v", f.Name, got, want)
		}
	}
	for name := range wantPushConfig {
		if _, ok := cfg.Type().FieldByName(name); !ok {
			t.Errorf("push.Config no longer has %s", name)
		}
	}
}

// -push-label is repeatable, and job and instance are ordinary labels: the
// defaults are what a scrape would have added, and a pair of the same name wins.
func TestPushLabelsRepeatAndOverrideTheDefaults(t *testing.T) {
	clearEnv(t)
	fs, o, e := bind(t)
	parse(t, fs, "-push-label=site=home", "-push-label=instance=lab-router", "-push-label=job=routers")

	got := pushConfig(o, testHost, pushLabels(o.PushLabels, e)).Labels
	want := map[string]string{"job": "routers", "instance": "lab-router", "site": "home"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("labels = %v, want %v", got, want)
	}
	if len(e.errs) != 0 {
		t.Errorf("three well-formed pairs recorded %v", e.errs)
	}
}

// A comma separates pairs in the variable, which cannot repeat. In the value of
// a flag, which can, it is an ordinary character: splitting there would invent a
// pair the user never wrote and report it as their mistake.
func TestACommaInAPushLabelIsPartOfItsValue(t *testing.T) {
	clearEnv(t)
	fs, o, e := bind(t)
	parse(t, fs, "-push-label=site=a,b")

	got := pushLabels(o.PushLabels, e)
	if want := map[string]string{"site": "a,b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("labels = %v, want %v", got, want)
	}
	if len(e.errs) != 0 {
		t.Errorf("one well-formed pair recorded %v", e.errs)
	}
}

// A pair without "=" is a configuration fault, reported with the rest rather
// than thrown: one restart names every mistake on the line.
func TestPushLabelsReportEveryMalformedPair(t *testing.T) {
	clearEnv(t)
	fs, o, e := bind(t)
	parse(t, fs, "-push-label=site=home", "-push-label=oops", "-push-label=also-bad")

	labels := pushLabels(o.PushLabels, e)
	if len(e.errs) != 2 {
		t.Fatalf("recorded %v, want one fault per malformed pair", e.errs)
	}
	all := fmt.Sprint(e.errs)
	for _, want := range []string{"-push-label", "oops", "also-bad"} {
		if !strings.Contains(all, want) {
			t.Errorf("the report %q does not name %q", all, want)
		}
	}
	if labels["site"] != "home" {
		t.Errorf("the pairs that parse were dropped: %v", labels)
	}
}

// The environment carries the same list as one string, since a variable cannot
// repeat.
func TestPushLabelsFromTheEnvironment(t *testing.T) {
	clearEnv(t)
	t.Setenv("TPLINK_PUSH_LABELS", "site=home,env=prod")
	fs, o, e := bind(t)
	parse(t, fs)

	got := pushLabels(o.PushLabels, e)
	want := map[string]string{"site": "home", "env": "prod"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("labels = %v, want %v", got, want)
	}
	if len(e.errs) != 0 {
		t.Errorf("a well-formed variable recorded %v", e.errs)
	}
}

// Every fault at once. A start that names one costs a restart to learn the next.
func TestValidateReportsEveryFaultAtOnce(t *testing.T) {
	o := &options{
		LogLevel:        "info",
		Interval:        30 * time.Second,
		Timeout:         0,
		RequestTimeout:  10 * time.Second,
		MinBackoff:      time.Minute,
		MaxBackoff:      30 * time.Second,
		SessionRenew:    -time.Minute,
		SessionCooldown: 5 * time.Minute,
		PushURL:         "http://192.0.2.50:4318/v1/metrics",
		PushBuffer:      0,
		PushTimeout:     0,
	}
	e := &env{}
	validate(o, e, nil)

	if len(e.errs) != 6 {
		t.Fatalf("six faults produced %d: %v", len(e.errs), e.errs)
	}
	all := fmt.Sprint(e.errs)
	for _, want := range []string{"-host", "-session-renew", "-timeout", "-max-backoff", "-push-timeout", "-push-buffer"} {
		if !strings.Contains(all, want) {
			t.Errorf("the report %q does not name %s", all, want)
		}
	}
}

// A TPLINK_* value that does not parse is recorded in bindFlags, ahead of all
// of this, and is not pinned here.
func TestConfigureReportsTheEssentialsThenTheSettingsThenTheLabels(t *testing.T) {
	// With TPLINK_PASSWORD set, readPassword reports "both are set" instead.
	clearEnv(t)
	fs, o, e := bind(t)
	parse(t, fs,
		"-log-level=shout",
		"-password-file="+filepath.Join(t.TempDir(), "absent"),
		"-min-backoff=2s", "-max-backoff=1s",
		"-push-label=oops",
	)

	configure(o, e)

	// The intervals keep their defaults and push mode is off, so nothing else
	// joins the report.
	want := []string{"-log-level", "router address", "password file", "-max-backoff", "-push-label"}
	if len(e.errs) != len(want) {
		t.Fatalf("five faults produced %d: %v", len(e.errs), e.errs)
	}
	for i, name := range want {
		if !strings.Contains(e.errs[i].Error(), name) {
			t.Fatalf("fault %d is %q, want the one naming %q; the report ran %v\n"+
				"configure holds the report's order in one place because it moved once unnoticed: "+
				"validate took the -host check's place in main and the password fault slid to the end",
				i, e.errs[i], name, e.errs)
		}
	}
}

// Nothing downstream refuses an address: otlpmetrichttp keeps its own default
// for a URL it cannot parse and takes an empty host as it is, so a start that
// accepted one would push into the void a cycle at a time.
func TestValidateRefusesAPushURLThatIsNotOne(t *testing.T) {
	cases := []struct {
		url     string
		refused bool
	}{
		{"http://vm:8428/opentelemetry/v1/metrics", false},
		{"https://192.0.2.50:8428/opentelemetry/v1/metrics", false},
		{"vm:8428/opentelemetry/v1/metrics", true}, // no scheme
		{"grpc://vm:4317", true},                   // the receiver's other port; this exporter speaks OTLP/HTTP
		{"192.0.2.50:8428/v1/metrics", true},
		{"://bad", true},
		{"http://", true}, // no host
		{"/opentelemetry/v1/metrics", true},
	}
	for _, c := range cases {
		t.Run(c.url, func(t *testing.T) {
			o := fullOptions()
			o.PushURL = c.url

			e := &env{}
			validate(o, e, nil)
			if refused := len(e.errs) > 0; refused != c.refused {
				t.Errorf("-push-url %q: refused = %v (%v), want %v", c.url, refused, e.errs, c.refused)
			}
			if c.refused && len(e.errs) > 0 && !strings.Contains(e.errs[0].Error(), "-push-url") {
				t.Errorf("the fault %q does not name the flag", e.errs[0])
			}
		})
	}
}

// The push rules configure nothing without -push-url, so a pull deployment is
// never refused over a flag it does not use.
func TestValidateAppliesThePushRulesOnlyInPushMode(t *testing.T) {
	o := fullOptions()
	o.PushURL = ""
	o.PushTimeout = 0
	o.PushBuffer = -1
	o.Timeout = o.Interval // the sum rule would fire on this

	e := &env{}
	validate(o, e, nil)
	if len(e.errs) != 0 {
		t.Errorf("pull mode was refused with %v", e.errs)
	}
}

// A cycle has to fit the poll and the send it ends with, or the next tick is
// already late. Both are called Timeout and they are different quantities.
func TestValidateRefusesACycleTooShortForBothTimeouts(t *testing.T) {
	cases := []struct {
		name                       string
		interval, timeout, pushOut time.Duration
		refused                    bool
	}{
		{"below the interval", 60 * time.Second, 30 * time.Second, 10 * time.Second, false},
		{"equal to the interval", 40 * time.Second, 30 * time.Second, 10 * time.Second, true},
		{"above the interval", 30 * time.Second, 25 * time.Second, 10 * time.Second, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := fullOptions()
			o.Interval, o.Timeout, o.PushTimeout = c.interval, c.timeout, c.pushOut

			e := &env{}
			validate(o, e, nil)
			if refused := len(e.errs) > 0; refused != c.refused {
				t.Errorf("-interval %s with -timeout %s and -push-timeout %s: refused = %v (%v), want %v",
					c.interval, c.timeout, c.pushOut, refused, e.errs, c.refused)
			}
		})
	}
}

// The defaults have to be a configuration that starts, in both modes: the sum
// rule reads three of them at once.
func TestValidateAcceptsWhatTheDefaultsProduce(t *testing.T) {
	for _, args := range [][]string{
		{"-host=192.0.2.1"},
		{"-host=192.0.2.1", "-push-url=http://192.0.2.50:8428/opentelemetry/v1/metrics"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			clearEnv(t)
			fs, o, e := bind(t)
			parse(t, fs, args...)

			validate(o, e, nil)
			if len(e.errs) != 0 {
				t.Errorf("the shipped defaults do not start: %v", e.errs)
			}
		})
	}
}

// TPLINK_PUSH_BUFFER is the one number among the variables; a value that is not
// one is reported with the rest and leaves the default in place.
func TestPushBufferFromTheEnvironmentIsANumber(t *testing.T) {
	clearEnv(t)
	t.Setenv("TPLINK_PUSH_BUFFER", "many")
	fs, o, e := bind(t)
	parse(t, fs)

	if len(e.errs) != 1 {
		t.Fatalf("recorded %v, want one fault", e.errs)
	}
	if !strings.Contains(e.errs[0].Error(), "TPLINK_PUSH_BUFFER") {
		t.Errorf("the fault %q does not name the variable", e.errs[0])
	}
	if o.PushBuffer != push.DefaultBuffer {
		t.Errorf("PushBuffer = %d, want the default %d left in place", o.PushBuffer, push.DefaultBuffer)
	}
}

// No port is the point of push: the listener is not started, not bound to
// loopback.
func TestNoListenerInPushMode(t *testing.T) {
	srv := metricsServer(fullOptions(), testBuild, prometheus.NewRegistry(), prometheus.NewRegistry())
	if srv != nil {
		t.Errorf("push mode built a listener on %q; -push-url is what removes the incoming surface", srv.Addr)
	}
}

// The split into two registries is invisible from a scrape: /metrics gathers
// both, and the landing page is where it was.
func TestMetricsServesBothRegistries(t *testing.T) {
	o := fullOptions()
	o.PushURL = ""

	snapshot := prometheus.NewRegistry()
	snapshot.MustRegister(exporter.NewCollector(stubSource{}, time.Minute, testBuild))
	process := prometheus.NewRegistry()
	process.MustRegister(collectors.NewGoCollector())

	srv := metricsServer(o, testBuild, snapshot, process)
	if srv == nil {
		t.Fatal("pull mode built no listener")
	}
	if srv.Addr != o.Listen {
		t.Errorf("listening on %q, want -listen %q", srv.Addr, o.Listen)
	}

	body := get(t, srv, "/metrics")
	for _, name := range []string{"tplink_up", "go_goroutines"} {
		if !strings.Contains(body, name) {
			t.Errorf("/metrics does not carry %s; a scrape reads both registries or the split shows", name)
		}
	}
	if landing := get(t, srv, "/"); !strings.Contains(landing, "/metrics") {
		t.Errorf("the landing page at / lost its link to /metrics: %q", landing)
	}
}

func get(t *testing.T, srv *http.Server, path string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s answered %d", path, rec.Code)
	}
	return rec.Body.String()
}

// The starting line is the whole of a push deployment's local view: there is no
// /metrics to read it back from.
func TestStartupAttrsNamePushInsteadOfTheListener(t *testing.T) {
	o := fullOptions()
	pushed := attrMap(t, startupAttrs(o, testBuild, testHost))
	if _, ok := pushed["listen"]; ok {
		t.Error("the push starting line names a listener; there is none")
	}
	for key, want := range map[string]any{"push_url": o.PushURL, "push_buffer": o.PushBuffer, "push_timeout": o.PushTimeout} {
		if got := pushed[key]; got != want {
			t.Errorf("%s = %v, want %v", key, got, want)
		}
	}

	o.PushURL = ""
	pulled := attrMap(t, startupAttrs(o, testBuild, testHost))
	if got := pulled["listen"]; got != o.Listen {
		t.Errorf("listen = %v, want %v", got, o.Listen)
	}
	for _, key := range []string{"push_url", "push_buffer", "push_timeout"} {
		if _, ok := pulled[key]; ok {
			t.Errorf("the pull starting line carries %s", key)
		}
	}
}

// attrMap folds slog's alternating key/value list into a map.
func attrMap(t *testing.T, attrs []any) map[string]any {
	t.Helper()
	if len(attrs)%2 != 0 {
		t.Fatalf("startupAttrs returned %d values; slog reads them as key/value pairs", len(attrs))
	}
	m := make(map[string]any, len(attrs)/2)
	for i := 0; i < len(attrs); i += 2 {
		key, ok := attrs[i].(string)
		if !ok {
			t.Fatalf("attribute %d is a %T, not a key", i, attrs[i])
		}
		m[key] = attrs[i+1]
	}
	return m
}

// --- the binary in push mode ------------------------------------------------

// Push mode assembled and run: the hook drives the sender, a refused cycle
// travels with a scraper's labels, and -listen is not bound.
func TestPushModeSendsACycleAndBindsNothing(t *testing.T) {
	batches := make(chan map[string]map[string]string, 8)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var envelope collectorpb.ExportMetricsServiceRequest
		if err := proto.Unmarshal(body, &envelope); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		select {
		case batches <- pointsOf(&envelope):
		default:
		}
		answer, _ := proto.Marshal(&collectorpb.ExportMetricsServiceResponse{})
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(answer)
	}))
	defer receiver.Close()

	listen, router := closedPort(t), closedPort(t)
	stderr := &lockedBuffer{}
	cmd := exec.Command(goBuild(t),
		"-host=http://"+router, "-listen="+listen,
		"-push-url="+receiver.URL+"/opentelemetry/v1/metrics",
		"-interval=3s", "-timeout=1s", "-request-timeout=500ms", "-push-timeout=500ms",
	)
	cmd.Env = append(cleanEnv(), "TPLINK_PASSWORD=secret")
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the exporter: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	// The router's address is refused at once, so the first cycle fails and is
	// pushed: a dead router and a dead exporter must not look alike.
	up, deadline := map[string]string(nil), time.After(30*time.Second)
	for up == nil {
		select {
		case batch := <-batches:
			up = batch["tplink_up"]
		case <-deadline:
			t.Fatalf("no batch carrying tplink_up reached the receiver\nstderr: %s", stderr.String())
		}
	}
	for label, want := range map[string]string{"job": "tplink_exporter", "instance": "http://" + router} {
		if got := up[label]; got != want {
			t.Errorf("tplink_up carries %s=%q, want %q: in push the exporter sets what a scraper would have",
				label, got, want)
		}
	}

	// A batch has arrived, so the run is past the point where pull mode binds.
	if conn, err := net.DialTimeout("tcp", listen, time.Second); err == nil {
		conn.Close()
		t.Errorf("something answers on %s; push mode removes the incoming surface, it does not narrow it", listen)
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signalling the exporter: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the run ended with %v, want a clean exit\nstderr: %s", err, stderr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("SIGTERM did not end the run; the poller, the last push and the drain deadlock\nstderr: %s",
			stderr.String())
	}
	if !strings.Contains(stderr.String(), "stopped") {
		t.Errorf("the run never reported stopping:\n%s", stderr.String())
	}
}

// The same address measured on the binary: an endpoint with no scheme starts a
// healthy-looking run that pushes nowhere, so the start has to end instead.
func TestAPushURLWithNoSchemeEndsTheRun(t *testing.T) {
	// The failure this guards against is a start that does not end, so the run
	// is bounded: without the context it would hang to the suite's timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, goBuild(t), "-host=192.0.2.1", "-push-url=vm:8428/opentelemetry/v1/metrics")
	cmd.Env = append(cleanEnv(), "TPLINK_PASSWORD=secret")
	var out, errs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errs

	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("the exporter started and kept running; an endpoint nothing can post to has to end the start\nstderr: %s",
			errs.String())
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("the run ended with %v, want a non-zero exit\nstderr: %s", err, errs.String())
	}
	if !strings.Contains(errs.String(), "-push-url") {
		t.Errorf("stderr never names -push-url:\n%s", errs.String())
	}
}

// A malformed pair is wrong on its face, so it is reported whatever the mode: a
// pull start that ignored it would hide the mistake until push is turned on.
func TestAMalformedPushLabelIsNamedWithoutPushURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, goBuild(t), "-push-label=oops")
	cmd.Env = cleanEnv()
	var out, errs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errs

	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("the exporter started and kept running\nstderr: %s", errs.String())
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("a malformed -push-label ended the run with %v, want a non-zero exit\nstderr: %s", err, errs.String())
	}
	for _, want := range []string{"-push-label", "oops"} {
		if !strings.Contains(errs.String(), want) {
			t.Errorf("stderr never names %q:\n%s", want, errs.String())
		}
	}
}

// pointsOf reduces one OTLP batch to the attributes on each metric's first
// point, which is what the wiring above has to get right.
func pointsOf(envelope *collectorpb.ExportMetricsServiceRequest) map[string]map[string]string {
	batch := map[string]map[string]string{}
	for _, rm := range envelope.GetResourceMetrics() {
		for _, sm := range rm.GetScopeMetrics() {
			for _, m := range sm.GetMetrics() {
				points := m.GetGauge().GetDataPoints()
				if len(points) == 0 {
					points = m.GetSum().GetDataPoints()
				}
				if len(points) == 0 {
					continue
				}
				attrs := map[string]string{}
				for _, kv := range points[0].GetAttributes() {
					attrs[kv.GetKey()] = kv.GetValue().GetStringValue()
				}
				batch[m.GetName()] = attrs
			}
		}
	}
	return batch
}

// closedPort is an address nothing is listening on.
func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("releasing %s: %v", addr, err)
	}
	return addr
}

// lockedBuffer collects the child's stderr, which the test reads while the
// child is still writing to it.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// The control for the case above, and the whole of pull mode assembled: the
// listener comes up on -listen, /metrics carries both registries, and the run
// ends on a signal.
func TestPullModeServesMetricsAndStops(t *testing.T) {
	listen, router := closedPort(t), closedPort(t)
	stderr := &lockedBuffer{}
	cmd := exec.Command(goBuild(t),
		"-host=http://"+router, "-listen="+listen,
		"-interval=3s", "-timeout=1s", "-request-timeout=500ms",
	)
	cmd.Env = append(cleanEnv(), "TPLINK_PASSWORD=secret")
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the exporter: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	body := await(t, "http://"+listen+"/metrics", stderr)
	for _, name := range []string{"tplink_up", "tplink_exporter_build_info", "go_goroutines"} {
		if !strings.Contains(body, name) {
			t.Errorf("/metrics does not carry %s; a scrape reads one exposition, whatever the registries behind it", name)
		}
	}
	// Nothing about delivery: they are the sender's, and no sender exists here.
	if strings.Contains(body, "tplink_push_") {
		t.Errorf("/metrics carries tplink_push_* without -push-url; pull mode builds no sender:\n%s", body)
	}
	if landing := await(t, "http://"+listen+"/", stderr); !strings.Contains(landing, "/metrics") {
		t.Errorf("the landing page lost its link to /metrics:\n%s", landing)
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signalling the exporter: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the run ended with %v, want a clean exit\nstderr: %s", err, stderr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("SIGTERM did not end the run in 30s\nstderr: %s", stderr.String())
	}
}

// What the receiver could not take is sent at shutdown, not dropped with the
// process. The interval is long enough that no later cycle can be what arrives.
func TestShutdownSendsWhatTheBufferHolds(t *testing.T) {
	var mu sync.Mutex
	accepting := false
	drained := make(chan map[string]map[string]string, 4)

	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		mu.Lock()
		ok := accepting
		mu.Unlock()
		if !ok {
			// Transient, so the batch is kept rather than dropped.
			http.Error(w, "storage is down", http.StatusServiceUnavailable)
			return
		}
		var envelope collectorpb.ExportMetricsServiceRequest
		if err := proto.Unmarshal(body, &envelope); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		select {
		case drained <- pointsOf(&envelope):
		default:
		}
		answer, _ := proto.Marshal(&collectorpb.ExportMetricsServiceResponse{})
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(answer)
	}))
	defer receiver.Close()

	stderr := &lockedBuffer{}
	cmd := exec.Command(goBuild(t),
		"-host=http://"+closedPort(t), "-listen="+closedPort(t),
		"-push-url="+receiver.URL+"/opentelemetry/v1/metrics",
		"-interval=10m", "-timeout=1s", "-request-timeout=500ms", "-push-timeout=500ms",
	)
	cmd.Env = append(cleanEnv(), "TPLINK_PASSWORD=secret")
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the exporter: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	// The first cycle is refused and buffered; the next one is ten minutes off,
	// so anything that arrives after the receiver comes back is the drain.
	waitFor(t, stderr, "push failed")
	mu.Lock()
	accepting = true
	mu.Unlock()

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signalling the exporter: %v", err)
	}
	select {
	case batch := <-drained:
		if _, ok := batch["tplink_up"]; !ok {
			t.Errorf("the drained batch carries %v, want the buffered cycle", batch)
		}
	case <-time.After(30 * time.Second):
		t.Errorf("nothing was sent at shutdown; the buffer went with the process\nstderr: %s", stderr.String())
	}

	// Bounded: a jam between the last push and the drain would otherwise hang to
	// the package timeout.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the run ended with %v, want a clean exit\nstderr: %s", err, stderr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("SIGTERM did not end the run; the poller, the last push and the drain deadlock\nstderr: %s",
			stderr.String())
	}
}

// await polls url until it answers 200, and gives up rather than hanging.
func await(t *testing.T, url string, stderr *lockedBuffer) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := http.Get(url)
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				t.Fatalf("reading %s: %v", url, readErr)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s answered %d", url, resp.StatusCode)
			}
			return string(body)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never answered: %v\nstderr: %s", url, err, stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitFor blocks until the child has logged want.
func waitFor(t *testing.T, stderr *lockedBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(stderr.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("the log never carried %q:\n%s", want, stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// --- the stop sequence ------------------------------------------------------

// stopStep is one step of a stop and the budget its context carried. Exported
// fields: fmt prints an unexported Duration as nanoseconds.
type stopStep struct {
	Name   string
	Budget time.Duration
}

// stopLog records the steps in the order they ran. The sequence writes it from
// its own goroutine while the test reads it.
type stopLog struct {
	mu    sync.Mutex
	steps []stopStep
}

func (l *stopLog) add(s stopStep) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.steps = append(l.steps, s)
}

func (l *stopLog) taken() []stopStep {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.steps)
}

// fakeShutdowner stands in for the listener and for the sender. It records when
// its Shutdown was called and what deadline it carried; a non-nil held keeps it
// inside the call until the test closes that channel.
type fakeShutdowner struct {
	steps *stopLog
	name  string
	held  chan struct{}
}

func (f *fakeShutdowner) Shutdown(ctx context.Context) error {
	step := stopStep{Name: f.name}
	if deadline, ok := ctx.Deadline(); ok {
		step.Budget = time.Until(deadline)
	}
	f.steps.add(step)
	if f.held != nil {
		<-f.held
	}
	return nil
}

// The sender is drained after the poller's join and before the stop returns:
// push.Sender.Shutdown closes the OTLP exporter, so a drain before the join
// answers the last push with "HTTP exporter is shutdown"; a drain the stop
// does not wait out dies with the process.
func TestStopSequenceDrainsTheSenderOnlyOnceThePollerIsJoined(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		steps := &stopLog{}
		pollerDone := make(chan struct{})
		release := make(chan struct{})
		seq := stopSequence{
			cancel:     func() { steps.add(stopStep{Name: "cancel"}) },
			server:     &fakeShutdowner{steps: steps, name: "server"},
			pollerDone: pollerDone,
			sender:     &fakeShutdowner{steps: steps, name: "sender", held: release},
			timeout:    shutdownTimeout,
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			seq.run()
		}()

		// Everything else in the bubble is blocked, so the sequence has run as
		// far as it can: it is standing on the poller, which a real one would
		// still be finishing a cycle and a push behind.
		synctest.Wait()
		waiting := []stopStep{{Name: "cancel"}, {Name: "server", Budget: shutdownTimeout}}
		if got := steps.taken(); !slices.Equal(got, waiting) {
			t.Errorf("with the poller still running the stop had taken %v, want %v: the sender is drained after the join, not before",
				got, waiting)
		}
		select {
		case <-done:
			t.Errorf("the stop returned without waiting for the poller")
		default:
		}

		// The poller is in, and the drain is now in flight and held there.
		close(pollerDone)
		synctest.Wait()
		stopping := []stopStep{
			{Name: "cancel"},
			{Name: "server", Budget: shutdownTimeout},
			{Name: "sender", Budget: shutdownTimeout},
		}
		if got := steps.taken(); !slices.Equal(got, stopping) {
			t.Errorf("with the poller joined the stop had taken %v, want %v", got, stopping)
		}
		select {
		case <-done:
			t.Errorf("the stop returned with the drain still in flight; main would log stopped and the process would exit out from under it")
		default:
		}

		close(release)
		synctest.Wait()
		<-done

		if got := steps.taken(); !slices.Equal(got, stopping) {
			t.Errorf("the stop took %v, want %v", got, stopping)
		}
	})
}

// Each mode builds one of the two parts; the constructor keeps a typed nil
// out of the interface fields.
func TestNewStopSequenceKeepsTheAbsentPartNil(t *testing.T) {
	pollerDone := make(chan struct{})
	close(pollerDone)

	cancelled := false
	seq := newStopSequence(func() { cancelled = true }, nil, nil, pollerDone, shutdownTimeout)
	if seq.server != nil || seq.sender != nil {
		t.Fatalf("newStopSequence kept a typed nil: server=%v, sender=%v", seq.server, seq.sender)
	}
	seq.run()
	if !cancelled {
		t.Error("the stop never cancelled the poller's context; nothing would end the run")
	}
}

// The other half of the same wiring: each part lands in its own step.
func TestNewStopSequenceWiresBothParts(t *testing.T) {
	sender, err := push.New(push.Config{
		Endpoint: "http://127.0.0.1:1/opentelemetry/v1/metrics",
		Buffer:   1,
		Timeout:  time.Second,
	}, prometheus.NewRegistry(), prometheus.NewRegistry())
	if err != nil {
		t.Fatalf("building a sender: %v", err)
	}
	srv := &http.Server{}

	seq := newStopSequence(func() {}, srv, sender, make(chan struct{}), shutdownTimeout)
	if seq.server != srv {
		t.Errorf("the listener's step holds %T, want the *http.Server", seq.server)
	}
	if seq.sender != sender {
		t.Errorf("the sender's step holds %T, want the *push.Sender", seq.sender)
	}
	if seq.timeout != shutdownTimeout {
		t.Errorf("a step is bounded by %s, want %s", seq.timeout, shutdownTimeout)
	}
}
