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
	"maps"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/akentyev/tplink_archer_exporter/internal/exporter"
	"github.com/akentyev/tplink_archer_exporter/internal/push"
	"github.com/akentyev/tplink_archer_exporter/internal/tpapi"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
)

const (
	// minInterval is the floor for this hardware. Below it the exporter still
	// starts, with a warning.
	minInterval = 30 * time.Second

	// shutdownTimeout bounds the HTTP shutdown in pull mode and the sender's
	// last drain in push; the poller's logout runs on its own timeout.
	shutdownTimeout = 10 * time.Second

	// staleAfter is how many intervals a snapshot may go unrefreshed before the
	// collector stops serving it and leaves only the exporter's own health.
	staleAfter = 5

	// pushJob is the job label a push carries, and its OTLP service.name. It
	// matches README's scrape_configs example, so job reads the same in both modes.
	pushJob = "tplink_exporter"
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
	logger, password, labels := configure(o, e)
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

	// Two registries: a push stamps the snapshot with the cycle's time and process
	// metrics with the send time, and no name prefix separates the two.
	snapshot := prometheus.NewRegistry()
	process := prometheus.NewRegistry()
	process.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	var sender *push.Sender
	if o.pushMode() {
		// The bridge reports a failed collection through otel.Handle, whose default
		// handler writes to stderr past slog.
		otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
			slog.Error("push metrics", "err", err)
		}))
		sender, err = push.New(pushConfig(o, client.Host, labels), snapshot, process)
		if err != nil {
			fatalf("push: %v", err)
		}
	}

	poller := exporter.NewPoller(client, pollerConfig(o, sender))
	snapshot.MustRegister(exporter.NewCollector(poller, staleAfter*o.Interval, build))

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

	srv := metricsServer(o, build, snapshot, process)

	// serveErr stays nil in push mode, and a nil channel never fires: with no
	// listener, only a signal ends the run.
	var serveErr chan error
	if srv != nil {
		serveErr = make(chan error, 1)
		go func() { serveErr <- srv.ListenAndServe() }()
	}

	var exitErr error
	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			exitErr = fmt.Errorf("listen on %s: %w", o.Listen, err)
		}
	case <-ctx.Done():
		slog.Info("signal received, shutting down")
	}

	// stop unwinds the poller, which logs out and frees the router's session,
	// and restores default signal handling, so a second signal kills the
	// process outright.
	newStopSequence(stop, srv, sender, pollerDone, shutdownTimeout).run()

	if exitErr != nil {
		fatalf("%v", exitErr)
	}
	slog.Info("stopped")
}

// shutdowner is the HTTP server and the sender as the stop sequence uses them.
type shutdowner interface {
	Shutdown(ctx context.Context) error
}

// stopSequence is the shutdown with each part injectable for the tests. The
// fields are in the order they run.
type stopSequence struct {
	cancel     func()          // the signal context's stop
	server     shutdowner      // nil in push mode, which binds nothing
	pollerDone <-chan struct{} // closed once the poller has logged out
	sender     shutdowner      // nil in pull mode, which builds none
	timeout    time.Duration   // per part
}

// newStopSequence takes the concrete types: a nil *http.Server or *push.Sender
// put straight into an interface field would test non-nil.
func newStopSequence(cancel func(), srv *http.Server, sender *push.Sender, pollerDone <-chan struct{}, timeout time.Duration) stopSequence {
	s := stopSequence{cancel: cancel, pollerDone: pollerDone, timeout: timeout}
	if srv != nil {
		s.server = srv
	}
	if sender != nil {
		s.sender = sender
	}
	return s
}

// run cancels first, which ends the poller, and joins it before the sender
// closes: closing the OTLP exporter under a send in flight answers "HTTP
// exporter is shutdown" and drops what the drain exists to deliver.
func (s stopSequence) run() {
	s.cancel()
	if s.server != nil {
		s.shutdown("http shutdown", s.server)
	}
	<-s.pollerDone
	if s.sender != nil {
		s.shutdown("push shutdown", s.sender)
	}
}

func (s stopSequence) shutdown(what string, part shutdowner) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	if err := part.Shutdown(ctx); err != nil {
		slog.Warn(what, "err", err)
	}
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
	// PushURL selects the mode: set, and metrics go out to an OTLP receiver.
	PushURL     string
	PushLabels  labelList
	PushBuffer  int
	PushTimeout time.Duration
	// Version configures nothing: it is answered and the process is gone.
	Version bool
}

// pushMode decides the validation, the hook and the listener alike.
func (o *options) pushMode() bool { return o.PushURL != "" }

// labelList is the repeatable -push-label: the first flag replaces what
// TPLINK_PUSH_LABELS seeded, later ones append. Pairs are one NUL-joined string
// so options stays comparable; the comma is the separator in the variable only,
// and ordinary text in a flag's value.
type labelList struct {
	pairs   string
	flagged bool
}

const (
	labelSep   = "\x00"
	labelComma = ","
)

func (l *labelList) String() string { return strings.ReplaceAll(l.pairs, labelSep, labelComma) }

func (l *labelList) Set(v string) error {
	if l.flagged {
		l.pairs += labelSep + v
		return nil
	}
	l.pairs, l.flagged = v, true
	return nil
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
		"first wait before the next login, after a failed login or a cycle that ran out of -timeout (env TPLINK_MIN_BACKOFF)")
	fs.DurationVar(&o.MaxBackoff, "max-backoff", e.dur("TPLINK_MAX_BACKOFF", exporter.DefaultMaxBackoff),
		"ceiling for the backoff and the session cooldown (env TPLINK_MAX_BACKOFF)")
	fs.DurationVar(&o.SessionRenew, "session-renew", e.dur("TPLINK_SESSION_RENEW", exporter.DefaultSessionRenew),
		"replace the session after this long; 0 switches the renewal off (env TPLINK_SESSION_RENEW)")
	fs.DurationVar(&o.SessionCooldown, "session-cooldown", e.dur("TPLINK_SESSION_COOLDOWN", exporter.DefaultSessionCooldown),
		"how long to stay away once losing the session starts repeating (env TPLINK_SESSION_COOLDOWN)")
	fs.StringVar(&o.PushURL, "push-url", e.str("TPLINK_PUSH_URL", ""),
		"OTLP receiver, e.g. http://vm:8428/opentelemetry/v1/metrics; set it and no listener is started (env TPLINK_PUSH_URL)")
	o.PushLabels = labelList{pairs: strings.ReplaceAll(e.str("TPLINK_PUSH_LABELS", ""), labelComma, labelSep)}
	fs.Var(&o.PushLabels, "push-label",
		"label on every pushed point, name=value, repeatable; job and instance are ordinary cases of it (env TPLINK_PUSH_LABELS, comma-separated)")
	fs.IntVar(&o.PushBuffer, "push-buffer", e.num("TPLINK_PUSH_BUFFER", push.DefaultBuffer),
		"cycles kept unsent while the receiver is down (env TPLINK_PUSH_BUFFER)")
	fs.DurationVar(&o.PushTimeout, "push-timeout", e.dur("TPLINK_PUSH_TIMEOUT", 10*time.Second),
		"one send, its drain of the buffer included (env TPLINK_PUSH_TIMEOUT)")
	fs.StringVar(&o.LogLevel, "log-level", e.str("TPLINK_LOG_LEVEL", "info"),
		"debug, info, warn or error (env TPLINK_LOG_LEVEL)")
	// No environment variable behind this one: a container carrying it would
	// print and exit instead of polling.
	fs.BoolVar(&o.Version, "version", false, "print the version and exit")
	return o
}

// configure collects every configuration fault and returns what had to be read
// on the way. The order of the report is set here; a TPLINK_* value that does
// not parse is recorded earlier, in bindFlags.
func configure(o *options, e *env) (*slog.Logger, string, map[string]string) {
	logger, err := newLogger(o.LogLevel)
	e.add(err)
	// no -password flag: a flag shows up in ps and in the container's process
	// list.
	password, pwErr := readPassword(o.PasswordFile)
	validate(o, e, pwErr)
	labels := pushLabels(o.PushLabels, e)
	return logger, password, labels
}

// validate records every fault at once. The -push-* rules apply in push mode
// only: without a receiver they configure nothing.
func validate(o *options, e *env, pwErr error) {
	if o.Host == "" {
		e.addf("router address is required: -host or TPLINK_HOST, e.g. -host 192.168.0.1")
	}
	e.add(pwErr)
	if o.SessionRenew < 0 {
		e.addf("-session-renew cannot be negative; 0 switches the renewal off")
	}
	if o.Interval <= 0 || o.Timeout <= 0 || o.RequestTimeout <= 0 || o.MinBackoff <= 0 || o.SessionCooldown <= 0 {
		e.addf("-interval, -timeout, -request-timeout, -min-backoff and -session-cooldown must be positive")
	}
	if o.MaxBackoff < o.MinBackoff {
		e.addf("-max-backoff (%s) is below -min-backoff (%s)", o.MaxBackoff, o.MinBackoff)
	}
	if !o.pushMode() {
		return
	}
	// otlpmetrichttp keeps its default -- localhost:4318 over HTTPS -- for a URL it
	// cannot parse and takes an empty host as it is, so nothing downstream refuses
	// a bad address; it would fail once a cycle, buffered and lost at the stop.
	if u, err := url.Parse(o.PushURL); err != nil {
		e.addf("-push-url %q: %v", o.PushURL, err)
	} else if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		e.addf("-push-url %q: want a full URL, e.g. http://vm:8428/opentelemetry/v1/metrics", o.PushURL)
	}
	if o.PushTimeout <= 0 {
		e.addf("-push-timeout must be positive; it bounds one send and the request inside it")
	}
	if o.PushBuffer <= 0 {
		e.addf("-push-buffer counts cycles and must be positive; 0 would be read as the default of %d rather than as no buffer",
			push.DefaultBuffer)
	}
	// A cycle ends with the push it feeds, so the interval has to hold both.
	if o.Timeout+o.PushTimeout >= o.Interval {
		e.addf("-timeout (%s) plus -push-timeout (%s) is not below -interval (%s); cycles would drift",
			o.Timeout, o.PushTimeout, o.Interval)
	}
}

// pusher is the sender as the hook uses it, testable without an OTLP client.
type pusher interface {
	Push(ctx context.Context, takenAt time.Time) error
}

// pollerConfig is the only place an exporter.Config is built, and sets every
// field. OnCycle hangs on the same predicate that built sender.
func pollerConfig(o *options, sender pusher) exporter.Config {
	cfg := exporter.Config{
		Interval:         o.Interval,
		Timeout:          o.Timeout,
		MinBackoff:       o.MinBackoff,
		MaxBackoff:       o.MaxBackoff,
		SessionCooldown:  o.SessionCooldown,
		SessionRenew:     o.SessionRenew,
		MaxLoginsPerHour: exporter.DefaultMaxLoginsPerHour,
	}
	if o.pushMode() {
		cfg.OnCycle = pushCycle(sender)
	}
	return cfg
}

// pushCycle hands each cycle to the sender. The error is dropped: Sender has
// logged it already, once per outage rather than once per cycle.
func pushCycle(sender pusher) func(context.Context, time.Time) {
	return func(ctx context.Context, takenAt time.Time) {
		_ = sender.Push(ctx, takenAt)
	}
}

// pushConfig is the only place a push.Config is built, and sets every field.
// job and instance are what a scrape would have added, and a -push-label of the
// same name replaces them; instance is the router, the thing being watched.
func pushConfig(o *options, host string, labels map[string]string) push.Config {
	all := map[string]string{"job": pushJob, "instance": host}
	maps.Copy(all, labels)
	return push.Config{
		Endpoint: o.PushURL,
		Labels:   all,
		Resource: map[string]string{"service.name": pushJob, "service.instance.id": host},
		Headers:  nil, // no flag fills it; push.Config says what it is reserved for
		Buffer:   o.PushBuffer,
		Timeout:  o.PushTimeout,
	}
}

// pushLabels splits the pairs into a map, reporting every malformed one.
func pushLabels(l labelList, e *env) map[string]string {
	labels := map[string]string{}
	for _, raw := range strings.Split(l.pairs, labelSep) {
		if raw == "" {
			continue
		}
		name, value, ok := strings.Cut(raw, "=")
		if !ok {
			e.addf("-push-label %q: want name=value, e.g. -push-label site=home", raw)
			continue
		}
		labels[name] = value
	}
	return labels
}

// metricsServer is the pull-mode listener, nil in push mode. /metrics gathers
// both registries, the one place the split shows.
func metricsServer(o *options, build exporter.BuildInfo, snapshot, process *prometheus.Registry) *http.Server {
	if o.pushMode() {
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(prometheus.Gatherers{snapshot, process}, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
		ErrorLog:      logAdapter{},
		Registry:      process, // counts scrape errors; they describe this process, not the router
	}))
	mux.HandleFunc("GET /{$}", landing(o.Interval, build))

	return &http.Server{
		Addr:              o.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// startupAttrs is what the starting line carries. The build leads because a
// crash-looping container is read from the top of its log; in push mode the
// tail names the receiver instead of the listener.
func startupAttrs(o *options, b exporter.BuildInfo, host string) []any {
	attrs := []any{
		"version", b.Version, "revision", b.Revision,
		"host", host, "user", o.User, "password_from", passwordSource(o.PasswordFile),
		"interval", o.Interval, "timeout", o.Timeout,
		"request_timeout", o.RequestTimeout, "min_backoff", o.MinBackoff, "max_backoff", o.MaxBackoff,
		"session_cooldown", o.SessionCooldown, "session_renew", o.SessionRenew,
	}
	if !o.pushMode() {
		return append(attrs, "listen", o.Listen)
	}
	return append(attrs, "push_url", o.PushURL, "push_labels", o.PushLabels.String(),
		"push_buffer", o.PushBuffer, "push_timeout", o.PushTimeout)
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

func (e *env) num(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s=%q: not a whole number, e.g. 300", key, v))
		return def
	}
	return n
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
