package main

import (
	"flag"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/akentyev/tplink_archer_exporter/internal/exporter"
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
		// Not a poller setting; set because assertDistinct reads a zero field as
		// an assignment that was dropped.
		Version: true,
	}
}

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

	cfg := reflect.ValueOf(pollerConfig(o))
	for _, f := range reflect.VisibleFields(cfg.Type()) {
		if !f.IsExported() {
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
}

// The shipped bug inverted: zero means renewal off, so nothing may put
// DefaultSessionRenew in its place.
func TestPollerConfigKeepsSessionRenewOff(t *testing.T) {
	o := fullOptions()
	o.SessionRenew = 0

	cfg := pollerConfig(o)
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
