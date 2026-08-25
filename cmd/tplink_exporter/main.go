// Command tplink_exporter serves Prometheus metrics for a TP-Link Archer
// router. Polling runs on its own ticker and a scrape reads the last snapshot,
// so no scrape reaches the device.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/akentyev/tplink_archer_exporter/internal/exporter"
	"github.com/akentyev/tplink_archer_exporter/internal/tpapi"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	// minInterval is the floor for this hardware. Below it the exporter still
	// starts, with a warning.
	minInterval = 30 * time.Second

	// shutdownTimeout bounds the HTTP shutdown; the poller's logout runs
	// alongside it on its own timeout.
	shutdownTimeout = 10 * time.Second

	// staleAfter is how many intervals a snapshot may go unrefreshed before the
	// collector stops serving it and leaves only the exporter's own health.
	staleAfter = 5
)

// -X sets these at link time; go run and a plain go build leave the defaults.
var (
	version  = "dev"
	revision = "unknown"
)

func buildInfo() exporter.BuildInfo { return exporter.NewBuildInfo(version, revision) }

// buildLine is what -version prints and what the landing page shows, so the two
// cannot disagree. BuildInfo.String normalizes, so neither can print a gap.
func buildLine(b exporter.BuildInfo) string { return "tplink_exporter " + b.String() }

func main() {
	e := &env{}
	o := bindFlags(flag.CommandLine, e)
	flag.Usage = usage
	flag.Parse()

	build := buildInfo()
	if o.Version {
		fmt.Println(buildLine(build))
		return
	}

	// Everything wrong with the configuration is collected and reported
	// together. A start that names one fault costs a restart to learn the next.
	logger, err := newLogger(o.LogLevel)
	e.add(err)
	if o.Host == "" {
		e.addf("router address is required: -host or TPLINK_HOST, e.g. -host 192.168.0.1")
	}
	// no -password flag: a flag shows up in ps and in the
	// container's process list.
	password, err := readPassword(o.PasswordFile)
	e.add(err)
	if o.SessionRenew < 0 {
		e.addf("-session-renew cannot be negative; 0 switches the renewal off")
	}
	if o.Interval <= 0 || o.Timeout <= 0 || o.RequestTimeout <= 0 || o.MinBackoff <= 0 || o.SessionCooldown <= 0 {
		e.addf("-interval, -timeout, -request-timeout, -min-backoff and -session-cooldown must be positive")
	}
	if o.MaxBackoff < o.MinBackoff {
		e.addf("-max-backoff (%s) is below -min-backoff (%s)", o.MaxBackoff, o.MinBackoff)
	}
	if len(e.errs) > 0 {
		for _, err := range e.errs {
			errorf("%v", err)
		}
		os.Exit(1)
	}
	slog.SetDefault(logger)

	if o.Interval < minInterval {
		slog.Warn("poll interval is below the floor for this hardware; the router serves one web session and shares it with whoever opens the UI",
			"interval", o.Interval, "floor", minInterval)
	}

	client, err := tpapi.New(o.Host, o.User, password, o.RequestTimeout)
	if err != nil {
		fatalf("client: %v", err)
	}
	// Force stays false, so a busy session backs the poller off and raises
	// tplink_session_blocked instead of evicting the UI.

	poller := exporter.NewPoller(client, pollerConfig(o))

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		exporter.NewCollector(poller, staleAfter*o.Interval, build),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	slog.Info("starting", startupAttrs(o, build, client.Host)...)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pollerDone := make(chan struct{})
	go func() {
		defer close(pollerDone)
		if err := poller.Run(ctx); err != nil {
			slog.Error("poller stopped", "err", err)
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
		ErrorLog:      logAdapter{},
		Registry:      reg, // counts scrape errors instead of only logging them
	}))
	mux.HandleFunc("GET /{$}", landing(o.Interval, build))

	srv := &http.Server{
		Addr:              o.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	var exitErr error
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			exitErr = fmt.Errorf("listen on %s: %w", o.Listen, err)
		}
	case <-ctx.Done():
		slog.Info("signal received, shutting down")
	}

	// Cancelling unwinds the poller, which logs out and frees the router's
	// session. It also restores default signal handling, so a second signal
	// kills the process outright.
	stop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("http shutdown", "err", err)
	}
	<-pollerDone

	if exitErr != nil {
		fatalf("%v", exitErr)
	}
	slog.Info("stopped")
}

// options is the command line once parsed.
type options struct {
	Host           string
	User           string
	PasswordFile   string
	Listen         string
	LogLevel       string
	Interval       time.Duration
	Timeout        time.Duration
	RequestTimeout time.Duration
	MinBackoff     time.Duration
	MaxBackoff     time.Duration
	// 0 means the renewal is off, not "use the default", so nothing may fill it
	// in later.
	SessionRenew    time.Duration
	SessionCooldown time.Duration
	// Version configures nothing: it is answered and the process is gone.
	Version bool
}

// bindFlags declares every flag on fs, parsing straight into the returned
// options. Nothing is copied out of the flags afterwards, so a flag cannot be
// read and then dropped on the way to a field.
func bindFlags(fs *flag.FlagSet, e *env) *options {
	o := &options{}
	fs.StringVar(&o.Host, "host", e.str("TPLINK_HOST", ""),
		"router address, e.g. 192.168.0.1 or http://192.168.0.1 (env TPLINK_HOST)")
	// The firmware hardcodes admin and the local login has no user field; the
	// flag is here for a device that differs.
	fs.StringVar(&o.User, "user", e.str("TPLINK_USER", "admin"),
		"web UI username (env TPLINK_USER)")
	fs.StringVar(&o.PasswordFile, "password-file", e.str("TPLINK_PASSWORD_FILE", ""),
		"read the password from this file instead of TPLINK_PASSWORD (env TPLINK_PASSWORD_FILE)")
	// Loopback by default: the metrics carry the network's MAC addresses, IP
	// addresses and host names, and nothing authenticates a scrape.
	fs.StringVar(&o.Listen, "listen", e.str("TPLINK_LISTEN", "127.0.0.1:9110"),
		"address to serve /metrics on (env TPLINK_LISTEN)")
	fs.DurationVar(&o.Interval, "interval", e.dur("TPLINK_INTERVAL", exporter.DefaultInterval),
		"how often to poll the router (env TPLINK_INTERVAL)")
	fs.DurationVar(&o.Timeout, "timeout", e.dur("TPLINK_TIMEOUT", exporter.DefaultTimeout),
		"bounds one whole poll cycle (env TPLINK_TIMEOUT)")
	fs.DurationVar(&o.RequestTimeout, "request-timeout", e.dur("TPLINK_REQUEST_TIMEOUT", 10*time.Second),
		"per HTTP request to the router (env TPLINK_REQUEST_TIMEOUT)")
	fs.DurationVar(&o.MinBackoff, "min-backoff", e.dur("TPLINK_MIN_BACKOFF", exporter.DefaultMinBackoff),
		"first wait after a failed cycle (env TPLINK_MIN_BACKOFF)")
	fs.DurationVar(&o.MaxBackoff, "max-backoff", e.dur("TPLINK_MAX_BACKOFF", exporter.DefaultMaxBackoff),
		"ceiling for the backoff and the session cooldown (env TPLINK_MAX_BACKOFF)")
	fs.DurationVar(&o.SessionRenew, "session-renew", e.dur("TPLINK_SESSION_RENEW", exporter.DefaultSessionRenew),
		"replace the session after this long; 0 switches the renewal off (env TPLINK_SESSION_RENEW)")
	fs.DurationVar(&o.SessionCooldown, "session-cooldown", e.dur("TPLINK_SESSION_COOLDOWN", exporter.DefaultSessionCooldown),
		"how long to stay away once losing the session starts repeating (env TPLINK_SESSION_COOLDOWN)")
	fs.StringVar(&o.LogLevel, "log-level", e.str("TPLINK_LOG_LEVEL", "info"),
		"debug, info, warn or error (env TPLINK_LOG_LEVEL)")
	// No environment variable behind this one: a container carrying it would
	// print and exit instead of polling.
	fs.BoolVar(&o.Version, "version", false, "print the version and exit")
	return o
}

func pollerConfig(o *options) exporter.Config {
	return exporter.Config{
		Interval:         o.Interval,
		Timeout:          o.Timeout,
		MinBackoff:       o.MinBackoff,
		MaxBackoff:       o.MaxBackoff,
		SessionCooldown:  o.SessionCooldown,
		SessionRenew:     o.SessionRenew,
		MaxLoginsPerHour: exporter.DefaultMaxLoginsPerHour,
	}
}

// startupAttrs is what the starting line carries. It lives out here because main
// is the seam the package tests cannot reach, and the build leads because a
// crash-looping container is read from the top of its log.
func startupAttrs(o *options, b exporter.BuildInfo, host string) []any {
	return []any{
		"version", b.Version, "revision", b.Revision,
		"host", host, "user", o.User, "password_from", passwordSource(o.PasswordFile),
		"listen", o.Listen, "interval", o.Interval, "timeout", o.Timeout,
		"request_timeout", o.RequestTimeout, "min_backoff", o.MinBackoff, "max_backoff", o.MaxBackoff,
		"session_cooldown", o.SessionCooldown, "session_renew", o.SessionRenew,
	}
}

// landing serves two paragraphs at / , one linking /metrics. The build's strings
// come from build arguments, so they are escaped.
func landing(interval time.Duration, b exporter.BuildInfo) http.HandlerFunc {
	page := fmt.Sprintf(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>tplink_archer_exporter</title></head>
<body>
<h1>tplink_archer_exporter</h1>
<p>Prometheus metrics for a TP-Link Archer router, at <a href="/metrics">/metrics</a>.
The router serves a single web session, so it is polled every %s on the exporter's
own ticker and a scrape reads the last snapshot rather than the device. The age of
that snapshot is <code>time() - tplink_snapshot_timestamp_seconds</code>; when the
router's UI holds the session, <code>tplink_session_blocked</code> is 1.</p>
<p>%s</p>
</body>
</html>
`, interval, html.EscapeString(buildLine(b)))
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	}
}

// readPassword takes the secret from the environment or a file, never both.
func readPassword(file string) (string, error) {
	env := os.Getenv("TPLINK_PASSWORD")
	switch {
	case env != "" && file != "":
		return "", errors.New("TPLINK_PASSWORD and -password-file are both set; use one or the other")
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("password file: %w", err)
		}
		// Only the trailing newline goes: spaces can be part of a password.
		s := strings.TrimRight(string(b), "\r\n")
		if s == "" {
			return "", fmt.Errorf("password file %s is empty", file)
		}
		return s, nil
	case env != "":
		// An env_file keeps the newline it was written with.
		return strings.TrimRight(env, "\r\n"), nil
	}
	return "", errors.New("password is required: set TPLINK_PASSWORD, or -password-file to read it from a file (there is no flag for the password itself)")
}

func passwordSource(file string) string {
	if file != "" {
		return "file " + file
	}
	return "TPLINK_PASSWORD"
}

func newLogger(level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("-log-level %q: want debug, info, warn or error", level)
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})), nil
}

// logAdapter carries promhttp's errors into slog; promhttp.Logger predates
// log/slog and wants Println.
type logAdapter struct{}

func (logAdapter) Println(v ...any) { slog.Error("metrics handler", "err", fmt.Sprint(v...)) }

// env resolves flag defaults from the environment, collecting what it could not
// parse rather than exiting on the spot. A default is evaluated as the flag is
// declared, before flag.Parse; exiting there would take the built-in -h with it,
// hiding the usage that explains the mistake. main reports e.errs after Parse.
type env struct{ errs []error }

// add keeps a non-nil err for the report; addf makes one from a message.
func (e *env) add(err error) {
	if err != nil {
		e.errs = append(e.errs, err)
	}
}

func (e *env) addf(format string, a ...any) {
	e.errs = append(e.errs, fmt.Errorf(format, a...))
}

func (e *env) str(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func (e *env) dur(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s=%q: not a duration, e.g. 60s or 5m", key, v))
		return def
	}
	return d
}

func usage() {
	out := flag.CommandLine.Output()
	_, _ = fmt.Fprintf(out, `tplink_exporter serves Prometheus metrics for a TP-Link Archer router.

Usage: %s -host 192.168.0.1

Every flag that names an environment variable in its description falls back to
it, and the defaults below show what those variables resolved to — unless one
failed to parse, which is reported at start-up rather than here. The password
has no flag, since a flag is visible in ps: it comes from TPLINK_PASSWORD, or
from the file named by -password-file for a Docker secret.

`, os.Args[0])
	flag.PrintDefaults()
}

// errorf reports without leaving, so one run names every fault.
func errorf(format string, a ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
}

func fatalf(format string, a ...any) {
	errorf(format, a...)
	os.Exit(1)
}
