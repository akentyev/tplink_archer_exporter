package exporter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"sync"
	"time"

	"github.com/akentyev/tplink_archer_exporter/internal/tpapi"
)

// The router allows one web session: polling runs on its own ticker and a
// scrape reads the last cycle's result, so scrape frequency never reaches the
// device. A browser holding the session backs the poller off and sets
// SessionBlocked rather than evicting it — a different condition from Up.

// State is what a scrape sees: a value copied under the poller's lock. The map
// is cloned; Snapshot is shared by pointer and must never be modified after
// record publishes it.
type State struct {
	// Snapshot is the last cycle that produced anything, nil before the first
	// success. The collector publishes its TakenAt and stops serving it once it
	// is too old.
	Snapshot *Snapshot

	Up bool

	// SessionBlocked means the web UI is presumed busy: either a login was
	// refused with tpapi.ErrSessionBusy, or the session was taken from us and
	// the poller is staying away.
	SessionBlocked bool
	LastAttempt    time.Time
	LastErr        error

	// Counters run for the exporter's lifetime and are never reset.
	// EndpointErrors is keyed by "path?form=x"; State hands out a copy.
	Logins         uint64
	LoginFailures  uint64
	EndpointErrors map[string]uint64

	// SessionsLost counts cycles that ended with the session gone. Someone
	// opening the web UI is the usual cause, but a cycle that reached nothing
	// counts too. LoginsSuppressed counts the logins not attempted because of
	// that, because of the hourly cap, or inside the backoff.
	SessionsLost     uint64
	LoginsSuppressed uint64

	PollDuration time.Duration // the last finished cycle, full or partial
}

// Config carries the knobs. The floor on Interval is the binary's, which warns
// under 30s and starts regardless; nothing here refuses a short one.
type Config struct {
	Interval time.Duration

	// Timeout bounds one whole cycle, login included. Per-request timeouts come
	// from the http.Client in tpapi.New.
	Timeout time.Duration

	// Backoff is when the next login is tried, max(Interval, backoff) after the
	// cycle that failed, doubling from MinBackoff to MaxBackoff, no jitter. The
	// cycle keeps the interval throughout. Armed by any failed login and by a
	// cycle that ran out of Timeout. A cycle where nothing answered is treated as
	// a lost session instead; a partial one arms nothing.
	MinBackoff time.Duration
	MaxBackoff time.Duration

	// SessionCooldown is how long the poller stays away after a second lost
	// session inside lossWindow, doubling up to MaxBackoff. A single loss costs
	// one cycle; sessionLost says why.
	SessionCooldown time.Duration

	// SessionRenew is how long a session is used before the poller replaces it
	// on purpose, at the end of a cycle that already has its snapshot. A session
	// that goes away on its own is indistinguishable from one a person took, so
	// replacing it on a schedule keeps that signal meaning what it says. Zero
	// switches the renewal off.
	SessionRenew time.Duration

	// MaxLoginsPerHour caps login attempts. The firmware carries a "multiple
	// login" lock that disables the router for two hours, and this device
	// certifies into the group that has it.
	MaxLoginsPerHour int

	// OnCycle runs after every cycle, failed ones included, once the state is
	// published: what it reads is this cycle's data. Nil is pull mode. takenAt is
	// the snapshot's time when the cycle published one, the cycle start otherwise.
	// ctx has Run's cancellation removed; the callee bounds its own time, which
	// comes out of the wait before the next cycle.
	OnCycle func(ctx context.Context, takenAt time.Time)
}

// lossWindow is how far back a lost session still counts as a repeat, and how
// far back a login counts against the cap. Long enough that a person who wants
// the web UI is still at it.
const lossWindow = time.Hour

// Defaults for a zero Config, deliberately slow. cmd/tplink_exporter takes its
// flag defaults from here, so -help, the environment fallbacks and a zero
// Config cannot drift apart. DefaultSessionRenew is the exception NewPoller
// cannot apply: a zero SessionRenew means renewal off, not "give me the
// default", so only the flag carries it.
const (
	DefaultInterval         = 60 * time.Second
	DefaultTimeout          = 30 * time.Second
	DefaultMinBackoff       = time.Minute
	DefaultMaxBackoff       = 15 * time.Minute
	DefaultSessionCooldown  = 5 * time.Minute
	DefaultSessionRenew     = 30 * time.Minute
	DefaultMaxLoginsPerHour = 6
)

// Poller owns the tpapi client and the current State.
type Poller struct {
	client Router
	cfg    Config

	// Critical sections stay short and make no blocking call. A test runs the
	// poller inside a synctest bubble, where a goroutine waiting on this mutex
	// while the holder sleeps stops the clock instead of deadlocking: the binary
	// dies on the package timeout with the blame pointing elsewhere.
	mu    sync.Mutex
	state State

	// Touched only from Run's goroutine.
	polledOK     bool
	loggedIn     bool
	loggedInAt   time.Time
	backoff      time.Duration
	cooldown     time.Duration // grows while losing the session keeps repeating
	quietUntil   time.Time     // no login attempt before this, after a lost session
	loginAfter   time.Time     // no login attempt before this, after a failed cycle
	lossHistory  []time.Time   // sessions lost inside the last hour
	loginHistory []time.Time   // attempts inside the last hour, for the cap

	// Endpoints that did not answer the previous good cycle, so a failure is
	// reported when it starts and when it ends rather than every minute.
	failing map[string]bool
}

// Why a login is being held back, as logged.
const (
	holdSessionTaken = "the session was taken; staying away so the web UI keeps it"
	holdLoginCap     = "hourly login cap reached"
	holdBackoff      = "backing off after a failed login or a cycle that ran out of time"
)

// NewPoller does not connect; Run does.
func NewPoller(client Router, cfg Config) *Poller {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MinBackoff <= 0 {
		cfg.MinBackoff = DefaultMinBackoff
	}
	// Raised, never lowered: a ceiling under the floor would poll faster the
	// longer the router stays down.
	if cfg.MaxBackoff < cfg.MinBackoff {
		cfg.MaxBackoff = max(DefaultMaxBackoff, cfg.MinBackoff)
	}
	if cfg.SessionCooldown <= 0 {
		cfg.SessionCooldown = DefaultSessionCooldown
	}
	if cfg.SessionRenew < 0 {
		cfg.SessionRenew = 0
	}
	if cfg.MaxLoginsPerHour <= 0 {
		cfg.MaxLoginsPerHour = DefaultMaxLoginsPerHour
	}
	return &Poller{
		client: client,
		cfg:    cfg,
		state:  State{EndpointErrors: map[string]uint64{}},
		// A clean start is not a recovery: the zero value made the first cycle
		// of a healthy exporter announce "polling again".
		polledOK: true,
	}
}

// Router is the part of tpapi.Client the poller uses, kept as an interface so a
// cycle can be tested without a device. wiring.go asserts *tpapi.Client
// satisfies it.
type Router interface {
	Login(ctx context.Context) error
	Call(ctx context.Context, path, operation string) (json.RawMessage, error)
	Logout(ctx context.Context) error
}

// Run polls until ctx is cancelled, then logs out to free the session. Poll
// failures are recorded in State, not returned. The first cycle runs at
// startup, not on the first tick; cancellation returns nil.
func (p *Poller) Run(ctx context.Context) error {
	defer func() {
		out, cancel := context.WithTimeout(context.Background(), p.cfg.Timeout)
		defer cancel()
		if err := p.logout(out); err != nil {
			slog.Warn("logout failed; the router holds the session until it times out", "err", err)
		}
	}()

	for {
		start := time.Now()
		wait, takenAt := p.cycle(ctx)
		// Before the cancellation check: the cycle a shutdown cut short still travels.
		if p.cfg.OnCycle != nil {
			p.cfg.OnCycle(context.WithoutCancel(ctx), takenAt)
		}
		if ctx.Err() != nil {
			return nil
		}
		// wait runs from the start of the cycle rather than its end, so a slow
		// cycle eats into the sleep instead of pushing the next one out. One that
		// outlasted the wait does not sleep at all.
		timer := time.NewTimer(max(0, wait-time.Since(start)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// State returns a copy of the current state.
func (p *Poller) State() State {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.state
	out.EndpointErrors = maps.Clone(p.state.EndpointErrors)
	return out
}

// cycle logs in if needed, polls once, and returns how long to wait before the
// next attempt and the time this cycle's data carries, for Config.OnCycle.
func (p *Poller) cycle(ctx context.Context) (time.Duration, time.Time) {
	start := time.Now()
	// Below the deadline, a cancelled parent and a spent Timeout are the same
	// ctx.Err(), and they mean opposite things.
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()

	if wait, why := p.holdOff(start); why != "" {
		p.polledOK = false
		p.failing = nil
		p.suppress(start, why == holdSessionTaken)
		slog.Info("not logging in", "why", why, "next_cycle_in", wait)
		return wait, start
	}

	if err := p.login(ctx); err != nil {
		if parent.Err() != nil {
			// A shutdown, not a refusal: nothing to retry.
			return p.cfg.Interval, start
		}
		p.polledOK = false
		p.failing = nil
		p.record(start, nil, 0, err, false)
		retry := p.growBackoff()
		p.loginAfter = start.Add(retry)
		slog.Warn("login failed", "err", err, "retry_in", retry,
			"session_blocked", errors.Is(err, tpapi.ErrSessionBusy))
		return p.cfg.Interval, start
	}

	snap, gathered, err := p.poll(ctx)
	switch {
	case err == nil:
		p.record(start, snap, gathered, nil, false)
		// Only on the first success after a wait: the cooldown deliberately
		// outlives a good cycle.
		if !p.polledOK {
			slog.Info("polling again", "after", max(p.backoff, p.cooldown))
		}
		p.polledOK = true
		if len(snap.Errors)*2 > len(sources) {
			slog.Warn("most of the cycle did not answer", "failed", len(snap.Errors),
				"of", len(sources), "took", time.Since(start))
		}
		p.backoff = 0
		// The escalation outlives a good cycle and only clears once the window
		// has run dry, or a session taken again right after we come back would
		// start the count over.
		p.lossHistory = within(p.lossHistory, time.Now(), lossWindow)
		if len(p.lossHistory) == 0 {
			p.cooldown = 0
		}
		p.reportEndpoints(snap.Errors)
		slog.Debug("polled", "took", time.Since(start), "failed_endpoints", len(snap.Errors))
		p.renew(ctx)
		return p.cfg.Interval, snap.TakenAt

	case ctx.Err() != nil:
		// Our own deadline, not the router's doing. One endpoint that never
		// answers eats the whole cycle, and calling that a lost session would
		// park the exporter and raise SessionBlocked over a sick router.
		p.polledOK = false
		p.loggedIn = false
		p.failing = nil
		p.record(start, snap, gathered, err, false)
		retry := p.growBackoff()
		p.loginAfter = start.Add(retry)
		slog.Warn("the cycle ran out of time", "err", err, "retry_in", retry)
		return p.cfg.Interval, publishedAt(snap, gathered, start)

	default:
		// Nothing answered, or the router said the session is gone. The firmware
		// has more than one way to say so, and treating them alike keeps the one
		// reflex that evicts a person out of every path.
		p.polledOK = false
		p.loggedIn = false
		p.failing = nil
		wait, blocked := p.sessionLost()
		p.record(start, snap, gathered, err, blocked)
		return wait, publishedAt(snap, gathered, start)
	}
}

// publishedAt is the time a cycle's data carries. The condition is record's, so
// a push and a scrape cannot disagree about which snapshot is current.
func publishedAt(snap *Snapshot, gathered int, start time.Time) time.Time {
	if snap != nil && gathered > 0 {
		return snap.TakenAt
	}
	return start
}

// holdOff reports how long to wait before the next cycle and why the login is
// being held back; "" means go ahead. A hold returns Interval rather than what
// is left of it, so the cycle keeps its rhythm and counts.
func (p *Poller) holdOff(now time.Time) (time.Duration, string) {
	if p.loggedIn {
		return 0, ""
	}
	if now.Before(p.quietUntil) {
		return p.cfg.Interval, holdSessionTaken
	}
	if p.capReached(now) {
		// Interval, not the remaining hour: holdOff is what enforces the cap, and
		// sleeping the window out in one piece would freeze the counters with it.
		return p.cfg.Interval, holdLoginCap
	}
	// The logged reason is the first that applies, and this is the least serious
	// of the three: the cooldown is a person at the web UI, the cap the
	// firmware's two-hour lock, this only a router that did not answer.
	if now.Before(p.loginAfter) {
		return p.cfg.Interval, holdBackoff
	}
	return 0, ""
}

// sessionLost decides whether to come back or to stay away, and reports whether
// the web UI should be called busy.
//
// The signal is the rate of losses, not the gap between them. A router that
// reboots loses the session once an hour; a person competing for it loses it
// again and again, however long they take to notice they were thrown out — and
// measuring the gap made their think time the deciding factor, which told us
// nothing about the router. So one loss in the window is an accident and costs
// nothing; a second says someone wants this session more than we do.
func (p *Poller) sessionLost() (time.Duration, bool) {
	now := time.Now()
	p.lossHistory = within(p.lossHistory, now, lossWindow)
	repeat := len(p.lossHistory) > 0
	p.lossHistory = append(p.lossHistory, now)

	p.mu.Lock()
	p.state.SessionsLost++
	p.mu.Unlock()

	if !repeat {
		slog.Warn("the session was taken; logging in again next cycle")
		return p.cfg.Interval, false
	}

	if p.cooldown == 0 {
		p.cooldown = p.cfg.SessionCooldown
	} else {
		// The ceiling has to clear the floor, or a cooldown longer than
		// MaxBackoff would shrink on its first doubling.
		p.cooldown = min(p.cooldown*2, max(p.cfg.MaxBackoff, p.cfg.SessionCooldown))
	}
	p.quietUntil = now.Add(p.cooldown)
	slog.Warn("the session was taken again; staying away so the web UI keeps it",
		"quiet_for", p.cooldown)
	// The ticker keeps its rhythm; holdOff is the one place that withholds a
	// login, so every cycle inside the quiet spell is counted.
	return p.cfg.Interval, true
}

// within drops what is older than d, keeping the slice's storage.
func within(times []time.Time, now time.Time, d time.Duration) []time.Time {
	kept := times[:0]
	for _, t := range times {
		if now.Sub(t) < d {
			kept = append(kept, t)
		}
	}
	return kept
}

// suppress records a cycle that never reached the router because a login was
// held back.
func (p *Poller) suppress(start time.Time, blocked bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state.LoginsSuppressed++
	p.state.LastAttempt = start
	p.state.PollDuration = time.Since(start)
	p.state.Up = false
	if blocked {
		p.state.SessionBlocked = true
	}
}

// capReached reports whether the hour's login budget is spent, pruning as it
// goes. The firmware's two-hour lock does not care why a login was made, so
// every path that logs in asks this.
func (p *Poller) capReached(now time.Time) bool {
	p.loginHistory = within(p.loginHistory, now, lossWindow)
	return len(p.loginHistory) >= p.cfg.MaxLoginsPerHour
}

// reportEndpoints logs an endpoint that started failing and one that answered
// again, once each.
// level: its error text reaches Snapshot.Errors and nothing else, and only the
// tplink_scrape_errors_total counter moves.
func (p *Poller) reportEndpoints(errs map[string]error) {
	for path, err := range errs {
		if !p.failing[path] {
			slog.Warn("endpoint stopped answering", "endpoint", path, "err", err)
		}
	}
	for path := range p.failing {
		if _, still := errs[path]; !still {
			slog.Info("endpoint answering again", "endpoint", path)
		}
	}
	if len(errs) == 0 {
		p.failing = nil
		return
	}
	p.failing = make(map[string]bool, len(errs))
	for path := range errs {
		p.failing[path] = true
	}
}

// renew replaces a session on a schedule rather than holding one until
// something ends it. A session lost on its own is indistinguishable from one a
// person took, so pre-empting the case is what keeps that signal honest.
//
// It runs after the snapshot is recorded, on a session that has just been used
// successfully, so a renewal that fails costs no data: the poller is simply
// logged out, and the next cycle logs in through the ordinary path.
func (p *Poller) renew(ctx context.Context) {
	if p.cfg.SessionRenew <= 0 || !p.loggedIn || time.Since(p.loggedInAt) < p.cfg.SessionRenew {
		return
	}
	// Checked before the logout: a renewal held back keeps the session it
	// cannot replace, where logging out first would darken the exporter for the
	// rest of the hour.
	if p.capReached(time.Now()) {
		slog.Info("not renewing the session", "why", holdLoginCap)
		return
	}
	held := time.Since(p.loggedInAt)
	if err := p.logout(ctx); err != nil {
		slog.Warn("renewing the session: logout failed", "err", err, "held", held)
	}
	if err := p.login(ctx); err != nil {
		// Not a lost session and not a failed cycle: the snapshot is already
		// recorded, and the next cycle logs in like any other.
		slog.Warn("renewing the session: login failed", "err", err)
		return
	}
	slog.Info("session renewed", "held", held)
}

// login reuses the session it already holds; the router keeps only one.
func (p *Poller) login(ctx context.Context) error {
	if p.loggedIn {
		return nil
	}
	p.loginHistory = append(p.loginHistory, time.Now())
	if err := p.client.Login(ctx); err != nil {
		p.mu.Lock()
		p.state.LoginFailures++
		p.mu.Unlock()
		return err
	}
	p.loggedIn = true
	p.loggedInAt = time.Now()
	p.mu.Lock()
	p.state.Logins++
	p.mu.Unlock()
	return nil
}

// logout frees the router's session. The caller owns the context: at shutdown
// the poller's own is already cancelled, so Run passes a fresh one.
func (p *Poller) logout(ctx context.Context) error {
	err := p.client.Logout(ctx)
	p.loggedIn = false
	return err
}

// growBackoff doubles the wait and returns it: how long after the start of the
// cycle that failed the next login may be tried.
func (p *Poller) growBackoff() time.Duration {
	switch {
	case p.backoff == 0:
		p.backoff = p.cfg.MinBackoff
	case p.backoff >= p.cfg.MaxBackoff/2:
		p.backoff = p.cfg.MaxBackoff
	default:
		p.backoff *= 2
	}
	return max(p.cfg.Interval, p.backoff)
}

// record publishes one finished cycle in a single critical section, so a scrape
// cannot land between "up is false" and "the web UI is busy". A cycle that
// reached nothing leaves the previous snapshot and its TakenAt in place.
func (p *Poller) record(start time.Time, snap *Snapshot, gathered int, err error, blocked bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state.LastAttempt = start
	p.state.PollDuration = time.Since(start)
	p.state.LastErr = err
	p.state.Up = err == nil
	p.state.SessionBlocked = blocked || errors.Is(err, tpapi.ErrSessionBusy)
	if snap == nil {
		return
	}
	for path := range snap.Errors {
		p.state.EndpointErrors[path]++
	}
	if gathered > 0 {
		p.state.Snapshot = snap
	}
}

// poll runs one cycle: every source in sources, assembled into a Snapshot.
// An endpoint that fails lands in Snapshot.Errors and the cycle carries on —
// a partial snapshot beats none.
//
// A session dying mid-cycle ends the cycle. The poller does not log in again to
// finish it: a login from the address that already holds the session takes it
// back in silence, so reconnecting is what evicts a person browsing from this
// machine. What answered before that point is kept.
func (p *Poller) poll(ctx context.Context) (snap *Snapshot, gathered int, err error) {
	snap = &Snapshot{TakenAt: time.Now(), Errors: map[string]error{}}
	replies := make(map[string]json.RawMessage, len(sources))

	for _, s := range sources {
		raw, err := p.client.Call(ctx, s.Path, s.Operation)
		if errors.Is(err, tpapi.ErrSessionExpired) {
			// Whatever answered before the session died is still good; what
			// comes after it would need a login, which is not ours to take.
			snapError(snap, s.Path, err)
			assemble(snap, replies)
			return snap, len(replies), err
		}
		if err != nil {
			snap.Errors[s.Path] = err
			continue
		}
		replies[s.Path] = raw
	}
	if len(replies) == 0 {
		// sources[0] necessarily failed, and its error carries the sentinel a
		// blocked session needs.
		return snap, 0, fmt.Errorf("no endpoint answered, %d attempted: %w",
			len(sources), snap.Errors[sources[0].Path])
	}
	assemble(snap, replies)
	return snap, len(replies), nil
}
