package push

import (
	"bytes"
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"

	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// testConfig is a working push.Config for a receiver at endpoint, with job
// and instance set the way README documents the push defaults. extra adds
// more -push-label style entries.
func testConfig(endpoint string, extra map[string]string) Config {
	labels := map[string]string{"job": "tplink_exporter", "instance": "192.0.2.1"}
	for k, v := range extra {
		labels[k] = v
	}
	return Config{Endpoint: endpoint, Labels: labels, Timeout: 5 * time.Second}
}

// datapointsOf returns every NumberDataPoint of the metric named name, gauge
// or sum alike, from every accepted ResourceMetrics in rms.
func datapointsOf(rms []*metricspb.ResourceMetrics, name string) []*metricspb.NumberDataPoint {
	var out []*metricspb.NumberDataPoint
	for _, rm := range rms {
		for _, sm := range rm.GetScopeMetrics() {
			for _, m := range sm.GetMetrics() {
				if m.GetName() != name {
					continue
				}
				if g := m.GetGauge(); g != nil {
					out = append(out, g.GetDataPoints()...)
				}
				if s := m.GetSum(); s != nil {
					out = append(out, s.GetDataPoints()...)
				}
			}
		}
	}
	return out
}

// summaryPointsOf is datapointsOf for Summary metrics, whose points are a
// different protobuf message.
func summaryPointsOf(rms []*metricspb.ResourceMetrics, name string) []*metricspb.SummaryDataPoint {
	var out []*metricspb.SummaryDataPoint
	for _, rm := range rms {
		for _, sm := range rm.GetScopeMetrics() {
			for _, m := range sm.GetMetrics() {
				if m.GetName() != name {
					continue
				}
				if s := m.GetSummary(); s != nil {
					out = append(out, s.GetDataPoints()...)
				}
			}
		}
	}
	return out
}

// startTimesOf returns the StartTimeUnixNano of every point of the named
// metric, in the order its ResourceMetrics arrived.
func startTimesOf(rms []*metricspb.ResourceMetrics, name string) []uint64 {
	dps := datapointsOf(rms, name)
	out := make([]uint64, len(dps))
	for i, dp := range dps {
		out[i] = dp.GetStartTimeUnixNano()
	}
	return out
}

// isMonotonicSum reports whether name was found and every occurrence of it
// across rms is a cumulative, monotonic Sum -- the shape rate() expects.
func isMonotonicSum(rms []*metricspb.ResourceMetrics, name string) bool {
	found := false
	for _, rm := range rms {
		for _, sm := range rm.GetScopeMetrics() {
			for _, m := range sm.GetMetrics() {
				if m.GetName() != name {
					continue
				}
				s := m.GetSum()
				if s == nil || !s.GetIsMonotonic() ||
					s.GetAggregationTemporality() != metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE {
					return false
				}
				found = true
			}
		}
	}
	return found
}

// Every snapshot point carries job, instance, every -push-label, and its time
// is takenAt, not the send time.
func TestSenderPushStampsLabelsAndTime(t *testing.T) {
	rcv := newFakeReceiver(t)
	snapshot := prometheus.NewRegistry()
	up := prometheus.NewGauge(prometheus.GaugeOpts{Name: "tplink_up", Help: "test"})
	up.Set(1)
	if err := snapshot.Register(up); err != nil {
		t.Fatalf("register tplink_up: %v", err)
	}
	process := prometheus.NewRegistry() // empty: keeps this push to one body

	s, err := New(testConfig(rcv.url(), map[string]string{"env": "prod"}), snapshot, process)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	takenAt := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	if err := s.Push(context.Background(), takenAt); err != nil {
		t.Fatalf("Push: %v", err)
	}

	dps := datapointsOf(rcv.requests(), "tplink_up")
	if len(dps) != 1 {
		t.Fatalf("tplink_up data points = %d, want 1", len(dps))
	}
	dp := dps[0]
	for _, want := range []struct{ key, value string }{
		{"job", "tplink_exporter"},
		{"instance", "192.0.2.1"},
		{"env", "prod"},
	} {
		if got := attr(dp.GetAttributes(), want.key); got != want.value {
			t.Errorf("%s = %q, want %q", want.key, got, want.value)
		}
	}
	if got := time.Unix(0, int64(dp.GetTimeUnixNano())).UTC(); !got.Equal(takenAt) {
		t.Errorf("time = %s, want %s", got, takenAt)
	}
}

// Process metrics travel as a separate body, stamped with the send time
// rather than takenAt.
func TestSenderPushSendsProcessMetricsAsSeparateBody(t *testing.T) {
	rcv := newFakeReceiver(t)
	snapshot := prometheus.NewRegistry()
	up := prometheus.NewGauge(prometheus.GaugeOpts{Name: "tplink_up", Help: "test"})
	if err := snapshot.Register(up); err != nil {
		t.Fatalf("register tplink_up: %v", err)
	}

	process := prometheus.NewRegistry()
	goroutines := prometheus.NewGauge(prometheus.GaugeOpts{Name: "process_test_goroutines", Help: "test"})
	goroutines.Set(7)
	if err := process.Register(goroutines); err != nil {
		t.Fatalf("register process_test_goroutines: %v", err)
	}

	s, err := New(testConfig(rcv.url(), nil), snapshot, process)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	before := time.Now()
	takenAt := before.Add(-time.Hour) // clearly not the send time
	if err := s.Push(context.Background(), takenAt); err != nil {
		t.Fatalf("Push: %v", err)
	}
	after := time.Now()

	if got, want := rcv.calls(), 2; got != want {
		t.Fatalf("calls() = %d, want %d: snapshot and process must be separate bodies", got, want)
	}

	dps := datapointsOf(rcv.requests(), "process_test_goroutines")
	if len(dps) != 1 {
		t.Fatalf("process_test_goroutines data points = %d, want 1", len(dps))
	}
	if got := dps[0].GetAsDouble(); got != 7 {
		t.Errorf("value = %v, want 7", got)
	}
	got := time.Unix(0, int64(dps[0].GetTimeUnixNano())).UTC()
	if got.Before(before) || got.After(after) {
		t.Errorf("time = %s, want between %s and %s (the send time, not takenAt)", got, before, after)
	}
}

// process points carry the same job/instance/-push-label set as the
// snapshot: without it, process metrics from two exporters writing to one
// receiver collapse into one indistinguishable series.
func TestSenderPushProcessMetricsCarryLabels(t *testing.T) {
	rcv := newFakeReceiver(t)
	snapshot := prometheus.NewRegistry()
	up := prometheus.NewGauge(prometheus.GaugeOpts{Name: "tplink_up", Help: "test"})
	if err := snapshot.Register(up); err != nil {
		t.Fatalf("register tplink_up: %v", err)
	}

	// The process gatherer emits Gauges, Sums and one Summary
	// (go_gc_duration_seconds); the Summary is its own protobuf message, so it
	// gets a point of its own.
	process := prometheus.NewRegistry()
	goroutines := prometheus.NewGauge(prometheus.GaugeOpts{Name: "process_test_goroutines", Help: "test"})
	if err := process.Register(goroutines); err != nil {
		t.Fatalf("register process_test_goroutines: %v", err)
	}
	gcSeconds := prometheus.NewSummary(prometheus.SummaryOpts{Name: "process_test_gc_seconds", Help: "test"})
	gcSeconds.Observe(0.5)
	if err := process.Register(gcSeconds); err != nil {
		t.Fatalf("register process_test_gc_seconds: %v", err)
	}

	s, err := New(testConfig(rcv.url(), map[string]string{"env": "prod"}), snapshot, process)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	before := time.Now()
	if err := s.Push(context.Background(), before.Add(-time.Hour)); err != nil {
		t.Fatalf("Push: %v", err)
	}
	after := time.Now()

	wantLabels := []struct{ key, value string }{
		{"job", "tplink_exporter"},
		{"instance", "192.0.2.1"},
		{"env", "prod"},
	}

	dps := datapointsOf(rcv.requests(), "process_test_goroutines")
	if len(dps) != 1 {
		t.Fatalf("process_test_goroutines data points = %d, want 1", len(dps))
	}
	for _, want := range wantLabels {
		if got := attr(dps[0].GetAttributes(), want.key); got != want.value {
			t.Errorf("gauge %s = %q, want %q", want.key, got, want.value)
		}
	}

	sdps := summaryPointsOf(rcv.requests(), "process_test_gc_seconds")
	if len(sdps) != 1 {
		t.Fatalf("process_test_gc_seconds data points = %d, want 1", len(sdps))
	}
	for _, want := range wantLabels {
		if got := attr(sdps[0].GetAttributes(), want.key); got != want.value {
			t.Errorf("summary %s = %q, want %q", want.key, got, want.value)
		}
	}
	got := time.Unix(0, int64(sdps[0].GetTimeUnixNano())).UTC()
	if got.Before(before) || got.After(after) {
		t.Errorf("summary time = %s, want between %s and %s (the send time, not takenAt)", got, before, after)
	}
}

// A cycle where the router did not answer is still sent -- tplink_up arrives
// at 0 rather than being withheld.
func TestSenderPushSendsEvenWhenRouterIsDown(t *testing.T) {
	rcv := newFakeReceiver(t)
	snapshot := prometheus.NewRegistry()
	up := prometheus.NewGauge(prometheus.GaugeOpts{Name: "tplink_up", Help: "test"})
	up.Set(0) // the router did not answer this cycle
	if err := snapshot.Register(up); err != nil {
		t.Fatalf("register tplink_up: %v", err)
	}
	process := prometheus.NewRegistry()

	s, err := New(testConfig(rcv.url(), nil), snapshot, process)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := s.Push(context.Background(), time.Now()); err != nil {
		t.Fatalf("Push: %v", err)
	}

	dps := datapointsOf(rcv.requests(), "tplink_up")
	if len(dps) != 1 {
		t.Fatalf("tplink_up data points = %d, want 1", len(dps))
	}
	if got := dps[0].GetAsDouble(); got != 0 {
		t.Errorf("tplink_up = %v, want 0: a failed cycle must still arrive", got)
	}
}

// duplicateCollector emits one series twice: what a reply carrying a MAC twice
// makes of every metric but clients, the only ones parseClients deduplicates.
type duplicateCollector struct{ desc *prometheus.Desc }

func (c *duplicateCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *duplicateCollector) Collect(ch chan<- prometheus.Metric) {
	for range 2 {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, 1, "00:00:5e:00:53:01")
	}
}

// The bridge drops a gatherer's whole output on any error; one duplicate series
// would leave push empty while a scrape served the rest under ContinueOnError.
func TestSenderPushSendsWhatAPartialGatherLeaves(t *testing.T) {
	logs := captureLog(t, slog.LevelInfo)
	rcv := newFakeReceiver(t)
	snapshot := snapshotRegistry(t)
	dup := &duplicateCollector{desc: prometheus.NewDesc("tplink_arp_entry_info", "test", []string{"mac"}, nil)}
	if err := snapshot.Register(dup); err != nil {
		t.Fatalf("register tplink_arp_entry_info: %v", err)
	}
	if _, err := snapshot.Gather(); err == nil {
		t.Fatal("Gather() reported no error; the registry under test has to produce one")
	}

	s, err := New(testConfig(rcv.url(), nil), snapshot, prometheus.NewRegistry())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := s.Push(context.Background(), time.Now()); err != nil {
		t.Fatalf("Push: %v", err)
	}

	if got := rcv.calls(); got != 1 {
		t.Fatalf("the receiver handled %d requests, want 1: the cycle has to travel", got)
	}
	if got := lastValueOf(t, rcv.requests(), "tplink_up", ""); got != 1 {
		t.Errorf("tplink_up = %v, want 1: the healthy series travels beside the broken one", got)
	}
	if got := len(datapointsOf(rcv.requests(), "tplink_arp_entry_info")); got != 1 {
		t.Errorf("tplink_arp_entry_info data points = %d, want the 1 the registry kept", got)
	}
	if got := logs.count("push gather"); got != 1 {
		t.Errorf("the gather error reached slog %d times, want 1; the log is the only record of it\n%s", got, logs)
	}
	if !strings.Contains(logs.String(), "was collected before with the same name and label values") {
		t.Errorf("the log does not carry what the registry reported\n%s", logs)
	}
}

// The exporter's own retry is disabled -- one refusal is one call, not the
// five a minute-long backoff would produce.
func TestSenderPushDoesNotRetry(t *testing.T) {
	rcv := newFakeReceiver(t)
	rcv.respond(http.StatusServiceUnavailable)
	snapshot := prometheus.NewRegistry()
	up := prometheus.NewGauge(prometheus.GaugeOpts{Name: "tplink_up", Help: "test"})
	if err := snapshot.Register(up); err != nil {
		t.Fatalf("register tplink_up: %v", err)
	}
	process := prometheus.NewRegistry() // empty: isolates the call count to the snapshot body

	cfg := testConfig(rcv.url(), nil)
	// Long enough that a real retry (5s initial backoff) would fit a second
	// attempt inside it; short enough the test still runs fast when correct.
	cfg.Timeout = 8 * time.Second
	s, err := New(cfg, snapshot, process)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := s.Push(context.Background(), time.Now()); err == nil {
		t.Fatal("Push returned nil, want an error from the 503")
	}
	if got, want := rcv.calls(), 1; got != want {
		t.Errorf("calls() = %d, want %d: the exporter's own retry must be disabled", got, want)
	}
}

// tplink_scrape_errors_total arrives as a cumulative monotonic sum, and its
// StartTime does not move between pushes -- a moving StartTime reads as a
// counter reset to the receiver.
func TestSenderPushCounterStartTimeIsStable(t *testing.T) {
	rcv := newFakeReceiver(t)
	snapshot := prometheus.NewRegistry()
	errs := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tplink_scrape_errors_total",
		Help: "test",
	}, []string{"endpoint"})
	errs.WithLabelValues("status").Inc() // one label combination: one point per push
	if err := snapshot.Register(errs); err != nil {
		t.Fatalf("register tplink_scrape_errors_total: %v", err)
	}
	process := prometheus.NewRegistry()

	s, err := New(testConfig(rcv.url(), nil), snapshot, process)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t1 := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Minute)
	if err := s.Push(context.Background(), t1); err != nil {
		t.Fatalf("Push #1: %v", err)
	}
	errs.WithLabelValues("status").Inc()
	if err := s.Push(context.Background(), t2); err != nil {
		t.Fatalf("Push #2: %v", err)
	}

	reqs := rcv.requests()
	starts := startTimesOf(reqs, "tplink_scrape_errors_total")
	if len(starts) != 2 {
		t.Fatalf("tplink_scrape_errors_total data points across two pushes = %d, want 2", len(starts))
	}
	if starts[0] != starts[1] {
		t.Errorf("StartTime moved between pushes: %v then %v -- reads as a reset", starts[0], starts[1])
	}
	if !isMonotonicSum(reqs, "tplink_scrape_errors_total") {
		t.Error("tplink_scrape_errors_total did not arrive as a cumulative monotonic sum")
	}
}

// newRing(0) panics on its first push (modulo by zero), so New resolves a
// zero Buffer before the ring ever sees it.
func TestSenderNewResolvesZeroBufferBeforeRingSeesIt(t *testing.T) {
	rcv := newFakeReceiver(t)
	snapshot := prometheus.NewRegistry()
	process := prometheus.NewRegistry()

	cfg := testConfig(rcv.url(), nil)
	cfg.Buffer = 0
	s, err := New(cfg, snapshot, process)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ring.push panicked: %v -- Config{Buffer: 0} was not resolved to DefaultBuffer before newRing saw it", r)
		}
	}()
	s.ring.push(&metricdata.ResourceMetrics{})
	if got, want := s.Buffered(), 1; got != want {
		t.Errorf("Buffered() = %d, want %d", got, want)
	}
	if got, want := s.Dropped(), uint64(0); got != want {
		t.Errorf("Dropped() = %d, want %d: a 300-capacity ring must not evict on its first entry", got, want)
	}
}

// The four delivery metric names travel in the pushed batch.
func TestSenderPushSendsDeliveryMetrics(t *testing.T) {
	rcv := newFakeReceiver(t)
	snapshot := prometheus.NewRegistry()
	up := prometheus.NewGauge(prometheus.GaugeOpts{Name: "tplink_up", Help: "test"})
	if err := snapshot.Register(up); err != nil {
		t.Fatalf("register tplink_up: %v", err)
	}
	process := prometheus.NewRegistry()

	s, err := New(testConfig(rcv.url(), nil), snapshot, process)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Push(context.Background(), time.Now()); err != nil {
		t.Fatalf("Push: %v", err)
	}

	reqs := rcv.requests()
	for _, name := range []string{
		"tplink_push_total",
		"tplink_push_dropped_total",
		"tplink_push_buffered",
		"tplink_push_last_success_timestamp_seconds",
	} {
		if len(datapointsOf(reqs, name)) == 0 {
			t.Errorf("%s did not travel in the pushed batch", name)
		}
	}
}

// cfg.Resource travels as resource attributes and cfg.Headers as request
// headers; nothing else pins either field.
func TestSenderPushCarriesResourceAndHeaders(t *testing.T) {
	rcv := newFakeReceiver(t)
	snapshot := prometheus.NewRegistry()
	up := prometheus.NewGauge(prometheus.GaugeOpts{Name: "tplink_up", Help: "test"})
	if err := snapshot.Register(up); err != nil {
		t.Fatalf("register tplink_up: %v", err)
	}
	process := prometheus.NewRegistry() // empty: keeps this push to one body

	cfg := testConfig(rcv.url(), nil)
	cfg.Resource = map[string]string{
		"service.name":        "tplink_exporter",
		"service.instance.id": "192.0.2.1",
	}
	cfg.Headers = map[string]string{"Authorization": "Bearer test-token"}
	s, err := New(cfg, snapshot, process)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Push(context.Background(), time.Now()); err != nil {
		t.Fatalf("Push: %v", err)
	}

	reqs := rcv.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests() = %d entries, want 1", len(reqs))
	}
	res := reqs[0].GetResource()
	for _, want := range []struct{ key, value string }{
		{"service.name", "tplink_exporter"},
		{"service.instance.id", "192.0.2.1"},
	} {
		if got := attr(res.GetAttributes(), want.key); got != want.value {
			t.Errorf("resource %s = %q, want %q", want.key, got, want.value)
		}
	}

	hdrs := rcv.headers()
	if len(hdrs) != 1 {
		t.Fatalf("headers() = %d entries, want 1", len(hdrs))
	}
	if got, want := hdrs[0].Get("Authorization"), "Bearer test-token"; got != want {
		t.Errorf("Authorization header = %q, want %q", got, want)
	}
}

// timestampsOf returns the tplink_up time of each accepted snapshot batch, in
// arrival order; bodies without tplink_up (the process batch) are skipped.
func timestampsOf(rms []*metricspb.ResourceMetrics) []time.Time {
	var out []time.Time
	for _, rm := range rms {
		dps := datapointsOf([]*metricspb.ResourceMetrics{rm}, "tplink_up")
		if len(dps) == 0 {
			continue
		}
		out = append(out, time.Unix(0, int64(dps[0].GetTimeUnixNano())).UTC())
	}
	return out
}

// equalTimes reports whether got and want hold the same instants in the same
// order.
func equalTimes(got, want []time.Time) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if !got[i].Equal(want[i]) {
			return false
		}
	}
	return true
}

// lastValueOf returns the newest arrived value of name, restricted to result=
// when given, and fails the test if the metric never travelled.
func lastValueOf(t *testing.T, rms []*metricspb.ResourceMetrics, name, result string) float64 {
	t.Helper()
	value, found := 0.0, false
	for _, dp := range datapointsOf(rms, name) {
		if result != "" && attr(dp.GetAttributes(), "result") != result {
			continue
		}
		value, found = dp.GetAsDouble(), true
	}
	if !found {
		t.Fatalf("%s{result=%q} did not travel", name, result)
	}
	return value
}

// snapshotRegistry returns a registry carrying tplink_up, the metric the
// failure tests use to tell one batch from another.
func snapshotRegistry(t *testing.T) *prometheus.Registry {
	t.Helper()
	reg := prometheus.NewRegistry()
	up := prometheus.NewGauge(prometheus.GaugeOpts{Name: "tplink_up", Help: "test"})
	up.Set(1)
	if err := reg.Register(up); err != nil {
		t.Fatalf("register tplink_up: %v", err)
	}
	return reg
}

// failureSender builds a Sender over a snapshot registry carrying tplink_up
// and an empty process registry, so every request the receiver sees is one
// snapshot batch and calls() counts snapshot attempts.
func failureSender(t *testing.T, rcv *fakeReceiver, buffer int) *Sender {
	t.Helper()
	cfg := testConfig(rcv.url(), nil)
	cfg.Buffer = buffer
	s, err := New(cfg, snapshotRegistry(t), prometheus.NewRegistry())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// cycleTimes returns n times a minute apart, the takenAt of consecutive poll
// cycles.
func cycleTimes(n int) []time.Time {
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	out := make([]time.Time, n)
	for i := range out {
		out[i] = base.Add(time.Duration(i) * time.Minute)
	}
	return out
}

// A 503 buffers the batch, and the next Push sends it first, with its
// original time.
func TestSenderFailureBuffersOn503(t *testing.T) {
	rcv := newFakeReceiver(t)
	s := failureSender(t, rcv, 0)
	ts := cycleTimes(2)

	rcv.respond(http.StatusServiceUnavailable)
	if err := s.Push(context.Background(), ts[0]); err == nil {
		t.Fatal("Push returned nil, want an error from the 503")
	}
	if got, want := s.Buffered(), 1; got != want {
		t.Errorf("Buffered() after a 503 = %d, want %d", got, want)
	}
	if got, want := s.Dropped(), uint64(0); got != want {
		t.Errorf("Dropped() after a 503 = %d, want %d: a temporary failure loses nothing", got, want)
	}

	rcv.respond(http.StatusOK)
	if err := s.Push(context.Background(), ts[1]); err != nil {
		t.Fatalf("Push after the receiver came back: %v", err)
	}
	if got := timestampsOf(rcv.requests()); !equalTimes(got, ts) {
		t.Errorf("order = %v, want oldest first %v", got, ts)
	}
	if got, want := s.Buffered(), 0; got != want {
		t.Errorf("Buffered() after the drain = %d, want %d", got, want)
	}
}

// A 400 refuses the payload for good -- it is dropped and counted, never
// buffered, and the next cycle sends the fresh batch.
func TestSenderFailureDropsRefusedBatch(t *testing.T) {
	rcv := newFakeReceiver(t)
	s := failureSender(t, rcv, 0)
	ts := cycleTimes(2)

	rcv.respond(http.StatusBadRequest)
	if err := s.Push(context.Background(), ts[0]); err == nil {
		t.Fatal("Push returned nil, want an error from the 400")
	}
	if got, want := s.Buffered(), 0; got != want {
		t.Errorf("buffered after a refused payload = %d, want %d", got, want)
	}
	if got, want := s.Dropped(), uint64(1); got != want {
		t.Errorf("Dropped() after a refused payload = %d, want %d", got, want)
	}

	rcv.respond(http.StatusOK)
	if err := s.Push(context.Background(), ts[1]); err != nil {
		t.Fatalf("Push after the receiver came back: %v", err)
	}
	if got, want := timestampsOf(rcv.requests()), ts[1:]; !equalTimes(got, want) {
		t.Errorf("arrived = %v, want only the fresh batch %v", got, want)
	}

	// The refusal reaches tplink_push_dropped_total, not only Dropped():
	// the counter's Help promises both sources.
	dps := datapointsOf(rcv.requests(), "tplink_push_dropped_total")
	if len(dps) == 0 {
		t.Fatal("tplink_push_dropped_total did not travel")
	}
	if got, want := dps[len(dps)-1].GetAsDouble(), 1.0; got != want {
		t.Errorf("tplink_push_dropped_total = %v, want %v after one refused batch", got, want)
	}
}

// A failure in the middle of the drain stops it, and the fresh batch goes to
// the ring rather than ahead of the queue. rate() survives a counter reset,
// not samples out of order.
func TestSenderFailureMidDrainKeepsOrder(t *testing.T) {
	rcv := newFakeReceiver(t)
	s := failureSender(t, rcv, 0)
	ts := cycleTimes(5)

	rcv.respond(http.StatusServiceUnavailable)
	for _, at := range ts[:3] {
		if err := s.Push(context.Background(), at); err == nil {
			t.Fatalf("Push(%s) returned nil, want an error from the 503", at)
		}
	}
	if got, want := s.Buffered(), 3; got != want {
		t.Fatalf("Buffered() after three failed cycles = %d, want %d", got, want)
	}

	// The receiver takes two batches and then breaks again, mid-drain.
	rcv.answerThen(2, http.StatusOK, http.StatusServiceUnavailable)
	before := rcv.calls()
	if err := s.Push(context.Background(), ts[3]); err == nil {
		t.Fatal("Push returned nil, want the error that stopped the drain")
	}
	if got, want := rcv.calls()-before, 3; got != want {
		t.Errorf("attempts = %d, want %d: the fresh batch must not be sent behind a broken drain", got, want)
	}
	if got, want := s.Buffered(), 2; got != want {
		t.Errorf("Buffered() after the broken drain = %d, want %d: the unsent batch plus the fresh one", got, want)
	}

	rcv.respond(http.StatusOK)
	if err := s.Push(context.Background(), ts[4]); err != nil {
		t.Fatalf("Push after the receiver came back: %v", err)
	}
	if got := timestampsOf(rcv.requests()); !equalTimes(got, ts) {
		t.Errorf("order = %v, want oldest first %v", got, ts)
	}
}

// A full buffer evicts the oldest batch and counts it; what remains still
// arrives oldest first.
func TestSenderFailureEvictsOldestWhenFull(t *testing.T) {
	rcv := newFakeReceiver(t)
	s := failureSender(t, rcv, 2)
	ts := cycleTimes(4)

	rcv.respond(http.StatusServiceUnavailable)
	for _, at := range ts[:3] {
		if err := s.Push(context.Background(), at); err == nil {
			t.Fatalf("Push(%s) returned nil, want an error from the 503", at)
		}
	}
	if got, want := s.Buffered(), 2; got != want {
		t.Errorf("Buffered() with a capacity of 2 = %d, want %d", got, want)
	}
	if got, want := s.Dropped(), uint64(1); got != want {
		t.Errorf("Dropped() after one eviction = %d, want %d", got, want)
	}

	rcv.respond(http.StatusOK)
	if err := s.Push(context.Background(), ts[3]); err != nil {
		t.Fatalf("Push after the receiver came back: %v", err)
	}
	if got, want := timestampsOf(rcv.requests()), ts[1:]; !equalTimes(got, want) {
		t.Errorf("arrived = %v, want the two newest then the fresh one %v", got, want)
	}
}

// Process metrics that failed are not buffered -- replaying hour-old GC
// statistics describes a moment that is gone.
func TestSenderFailureDropsProcessBatch(t *testing.T) {
	rcv := newFakeReceiver(t)
	process := prometheus.NewRegistry()
	goroutines := prometheus.NewGauge(prometheus.GaugeOpts{Name: "process_test_goroutines", Help: "test"})
	goroutines.Set(7)
	if err := process.Register(goroutines); err != nil {
		t.Fatalf("register process_test_goroutines: %v", err)
	}
	s, err := New(testConfig(rcv.url(), nil), snapshotRegistry(t), process)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := cycleTimes(2)

	rcv.respond(http.StatusServiceUnavailable)
	if err := s.Push(context.Background(), ts[0]); err == nil {
		t.Fatal("Push returned nil, want an error from the 503")
	}
	if got, want := s.Buffered(), 1; got != want {
		t.Errorf("Buffered() after a failed cycle = %d, want %d: only the snapshot is buffered", got, want)
	}

	goroutines.Set(9)
	rcv.respond(http.StatusOK)
	if err := s.Push(context.Background(), ts[1]); err != nil {
		t.Fatalf("Push after the receiver came back: %v", err)
	}
	for _, dp := range datapointsOf(rcv.requests(), "process_test_goroutines") {
		if dp.GetAsDouble() == 7 {
			t.Error("the process batch that failed was replayed; it must be dropped")
		}
	}
	if got := timestampsOf(rcv.requests()); !equalTimes(got, ts) {
		t.Errorf("snapshot order = %v, want oldest first %v", got, ts)
	}
}

// A batch already in the buffer that the receiver refuses for good leaves the
// ring too: parked at the head it would block every later batch for the whole
// retention while the receiver is healthy.
func TestSenderFailureRefusedBatchDoesNotBlockTheBuffer(t *testing.T) {
	rcv := newFakeReceiver(t)
	s := failureSender(t, rcv, 0)
	ts := cycleTimes(4)

	rcv.respond(http.StatusServiceUnavailable)
	for _, at := range ts[:2] {
		if err := s.Push(context.Background(), at); err == nil {
			t.Fatalf("Push(%s) returned nil, want an error from the 503", at)
		}
	}
	if got, want := s.Buffered(), 2; got != want {
		t.Fatalf("Buffered() after two failed cycles = %d, want %d", got, want)
	}

	rcv.respond(http.StatusBadRequest)
	if err := s.Push(context.Background(), ts[2]); err == nil {
		t.Fatal("Push returned nil, want an error from the 400")
	}
	if got, want := s.Buffered(), 0; got != want {
		t.Errorf("Buffered() after the receiver refused everything = %d, want %d", got, want)
	}
	if got, want := s.Dropped(), uint64(3); got != want {
		t.Errorf("Dropped() = %d, want %d: two buffered batches and the fresh one", got, want)
	}

	rcv.respond(http.StatusOK)
	if err := s.Push(context.Background(), ts[3]); err != nil {
		t.Fatalf("Push after the receiver came back: %v", err)
	}
	if got, want := timestampsOf(rcv.requests()), ts[3:]; !equalTimes(got, want) {
		t.Errorf("arrived = %v, want only the fresh batch %v", got, want)
	}
}

// A send that made no request is not a refusal: a 4xx from an earlier request
// must not classify a send the dead context stopped.
func TestSenderFailureStaleCodeDoesNotRefuseABatch(t *testing.T) {
	rcv := newFakeReceiver(t)
	s := failureSender(t, rcv, 0)

	rcv.respond(http.StatusBadRequest)
	resp, err := s.status.RoundTrip(httptest.NewRequest(http.MethodPost, rcv.url(), nil))
	if err != nil {
		t.Fatalf("priming the transport with a 400: %v", err)
	}
	resp.Body.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := rcv.calls()
	err = s.send(ctx, &metricdata.ResourceMetrics{})
	if err == nil {
		t.Fatal("send returned nil, want the context error")
	}
	if got := rcv.calls() - before; got != 0 {
		t.Fatalf("the receiver saw %d requests, want none: Export abandons a send on a dead context", got)
	}
	if errors.Is(err, errRefused) {
		t.Error("a send that made no request was classified as refused")
	}
	if got, want := s.Dropped(), uint64(0); got != want {
		t.Errorf("Dropped() = %d, want %d", got, want)
	}
}

// Buffered and Dropped are read from other goroutines while Push moves batches;
// the reader spins for the whole run so -race sees the overlap.
func TestSenderFailureAccessorsAreSafeDuringAPush(t *testing.T) {
	rcv := newFakeReceiver(t)
	s := failureSender(t, rcv, 2)
	rcv.respond(http.StatusServiceUnavailable)

	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			s.Buffered()
			s.Dropped()
		}
	}()

	for _, at := range cycleTimes(5) {
		_ = s.Push(context.Background(), at)
	}
	close(stop)
	<-done
}

// A slow receiver can spend the whole deadline in the drain; the fresh batch
// still has to reach the buffer, not vanish uncollected.
func TestSenderFailureDeadlineDuringDrainKeepsTheCycle(t *testing.T) {
	rcv := newFakeReceiver(t)
	cfg := testConfig(rcv.url(), nil)
	cfg.Timeout = 200 * time.Millisecond
	s, err := New(cfg, snapshotRegistry(t), prometheus.NewRegistry())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := cycleTimes(4)

	rcv.respond(http.StatusServiceUnavailable)
	if err := s.Push(context.Background(), ts[0]); err == nil {
		t.Fatal("Push returned nil, want an error from the 503")
	}

	rcv.delay(500 * time.Millisecond) // the receiver takes the request and goes quiet
	for _, at := range ts[1:3] {
		if err := s.Push(context.Background(), at); err == nil {
			t.Fatalf("Push(%s) returned nil, want the deadline error", at)
		}
	}
	if got, want := s.Buffered(), 3; got != want {
		t.Errorf("Buffered() = %d, want %d: a cycle whose drain spent the deadline is buffered, not lost", got, want)
	}
	if got, want := s.Dropped(), uint64(0); got != want {
		t.Errorf("Dropped() = %d, want %d: a deadline loses nothing", got, want)
	}

	rcv.delay(0)
	rcv.respond(http.StatusOK)
	if err := s.Push(context.Background(), ts[3]); err != nil {
		t.Fatalf("Push after the receiver came back: %v", err)
	}
	if got := timestampsOf(rcv.requests()); !equalTimes(got, ts) {
		t.Errorf("order = %v, want oldest first %v", got, ts)
	}
}

// A payload the receiver refuses during the drain reaches the caller, body
// and all: it is a configuration error, logged every cycle, and a fresh batch
// going through in the same cycle must not hide it.
func TestSenderFailureRefusedDrainReachesTheCaller(t *testing.T) {
	rcv := newFakeReceiver(t)
	s := failureSender(t, rcv, 0)
	ts := cycleTimes(2)

	rcv.respond(http.StatusServiceUnavailable)
	if err := s.Push(context.Background(), ts[0]); err == nil {
		t.Fatal("Push returned nil, want an error from the 503")
	}

	rcv.answerThen(1, http.StatusBadRequest, http.StatusOK) // the buffered batch refused, the fresh one taken
	err := s.Push(context.Background(), ts[1])
	if err == nil {
		t.Fatal("Push returned nil after the receiver refused a buffered batch")
	}
	if !errors.Is(err, errRefused) {
		t.Errorf("error = %v, want one carrying errRefused", err)
	}
	if got := err.Error(); !strings.Contains(got, "400 Bad Request") || !strings.Contains(got, "body:") {
		t.Errorf("error = %q, want the status and the body the receiver answered", got)
	}
	if got, want := s.Buffered(), 0; got != want {
		t.Errorf("Buffered() = %d, want %d", got, want)
	}
	if got, want := s.Dropped(), uint64(1); got != want {
		t.Errorf("Dropped() = %d, want %d", got, want)
	}
	if got, want := timestampsOf(rcv.requests()), ts[1:]; !equalTimes(got, want) {
		t.Errorf("arrived = %v, want only the fresh batch %v", got, want)
	}
}

// The delivery metrics carry values, not just names: a recovery that drained
// three buffered batches and sent its own counts four successes, not one.
func TestSenderFailureDeliveryMetricsCarryTheirValues(t *testing.T) {
	rcv := newFakeReceiver(t)
	s := failureSender(t, rcv, 0)
	ts := cycleTimes(5)

	rcv.respond(http.StatusServiceUnavailable)
	for _, at := range ts[:3] {
		if err := s.Push(context.Background(), at); err == nil {
			t.Fatalf("Push(%s) returned nil, want an error from the 503", at)
		}
	}

	rcv.respond(http.StatusOK)
	before := time.Now()
	if err := s.Push(context.Background(), ts[3]); err != nil {
		t.Fatalf("Push after the receiver came back: %v", err)
	}
	after := time.Now()

	// The batch of cycle N carries the numbers of cycle N-1, so the recovery
	// is read off the cycle that follows it.
	if err := s.Push(context.Background(), ts[4]); err != nil {
		t.Fatalf("Push: %v", err)
	}
	reqs := rcv.requests()

	if got, want := lastValueOf(t, reqs, "tplink_push_total", "ok"), 4.0; got != want {
		t.Errorf(`tplink_push_total{result="ok"} = %v, want %v: three drained batches and the fresh one`, got, want)
	}
	if got, want := lastValueOf(t, reqs, "tplink_push_total", "failed"), 3.0; got != want {
		t.Errorf(`tplink_push_total{result="failed"} = %v, want %v: one attempt per failed cycle`, got, want)
	}
	if got, want := lastValueOf(t, reqs, "tplink_push_buffered", ""), 0.0; got != want {
		t.Errorf("tplink_push_buffered = %v, want %v after the drain emptied the ring", got, want)
	}
	if got, want := lastValueOf(t, reqs, "tplink_push_dropped_total", ""), 0.0; got != want {
		t.Errorf("tplink_push_dropped_total = %v, want %v: nothing was evicted or refused", got, want)
	}
	last := time.Unix(int64(lastValueOf(t, reqs, "tplink_push_last_success_timestamp_seconds", "")), 0)
	if last.Before(before.Truncate(time.Second)) || last.After(after) {
		t.Errorf("tplink_push_last_success_timestamp_seconds = %s, want the recovery between %s and %s", last, before, after)
	}
}

// logCapture is the default logger's output for the length of one test. Push
// logs from whatever goroutine polls and Shutdown from the one stopping the
// process, so both sides of the buffer are locked.
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
// and no message under test is a substring of another.
func (c *logCapture) count(msg string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Count(c.buf.String(), msg)
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// captureLog collects records at and above level until the test ends.
// slog.SetDefault is process-wide, points the log package at the same handler
// and clears its flags; restoring the logger puts back neither, so all three
// are saved.
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

// bufferBatches parks n cycles in the ring by pushing them at a receiver
// answering 503, and returns the times they were stamped with.
func bufferBatches(t *testing.T, s *Sender, rcv *fakeReceiver, n int) []time.Time {
	t.Helper()
	ts := cycleTimes(n)
	rcv.respond(http.StatusServiceUnavailable)
	for _, at := range ts {
		if err := s.Push(context.Background(), at); err == nil {
			t.Fatalf("Push(%s) returned nil, want an error from the 503", at)
		}
	}
	if got := s.Buffered(); got != n {
		t.Fatalf("Buffered() = %d, want %d before the drain under test", got, n)
	}
	return ts
}

// waitForCalls blocks until the receiver has handled n requests, so a test can
// act while a send is in flight instead of guessing at the timing.
func waitForCalls(t *testing.T, rcv *fakeReceiver, n int) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); rcv.calls() < n; {
		if time.Now().After(deadline) {
			t.Fatalf("the receiver handled %d requests, want %d", rcv.calls(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// Shutdown sends what the buffer holds, oldest first, inside the context it
// was given.
func TestSenderShutdownDrainsTheBuffer(t *testing.T) {
	rcv := newFakeReceiver(t)
	s := failureSender(t, rcv, 0)
	ts := bufferBatches(t, s, rcv, 3)

	rcv.respond(http.StatusOK)
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if got := timestampsOf(rcv.requests()); !equalTimes(got, ts) {
		t.Errorf("arrived = %v, want the whole buffer oldest first %v", got, ts)
	}
	if got, want := s.Buffered(), 0; got != want {
		t.Errorf("Buffered() = %d, want %d after Shutdown drained it", got, want)
	}
}

// Shutdown stops at its deadline instead of waiting out a receiver that went
// quiet, and says how many batches it lost.
func TestSenderShutdownStopsAtTheDeadline(t *testing.T) {
	logs := captureLog(t, slog.LevelInfo)
	rcv := newFakeReceiver(t)
	s := failureSender(t, rcv, 0)
	bufferBatches(t, s, rcv, 4)

	rcv.respond(http.StatusOK)
	rcv.delay(300 * time.Millisecond) // the receiver takes the request and goes quiet

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := s.Shutdown(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Shutdown returned nil, want the error the deadline cut the drain with")
	}
	if want := 900 * time.Millisecond; elapsed > want {
		t.Errorf("Shutdown took %s, want under %s: four batches at 300ms each is not what the 100ms deadline allows",
			elapsed, want)
	}
	if s.Buffered() == 0 {
		t.Error("Buffered() = 0, want the batches the deadline left unsent")
	}
	if got := logs.count("push buffer lost at shutdown"); got != 1 {
		t.Errorf("loss lines = %d, want 1: what the deadline left is logged, not silently dropped:\n%s", got, logs)
	}
}

// The close after a drain that spent the context is not a second complaint
// about it: the OTLP client returns ctx.Err() from its own Shutdown.
func TestSenderShutdownClosesTheExporterOnASpentContext(t *testing.T) {
	rcv := newFakeReceiver(t)
	s := failureSender(t, rcv, 0)
	ts := bufferBatches(t, s, rcv, 1)

	rcv.respond(http.StatusOK)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := s.Shutdown(ctx)
	if err == nil {
		t.Fatal("Shutdown returned nil, want the error of a drain that could not run")
	}
	if got := strings.Count(err.Error(), context.Canceled.Error()); got != 1 {
		t.Errorf("error %q names the cancellation %d times, want 1: closing the exporter must not report the context the drain spent",
			err, got)
	}

	calls := rcv.calls()
	if err := s.Push(context.Background(), ts[0].Add(time.Minute)); err == nil {
		t.Error("Push after Shutdown returned nil, want the closed exporter's error")
	}
	if got := rcv.calls(); got != calls {
		t.Errorf("calls after Shutdown = %d, want %d: a closed exporter makes no request", got, calls)
	}
}

// Two drains at once send one batch twice and remove another unsent, which
// -race cannot see: the ring's mutex guards fields, not the oldest/send/
// removeOldest cycle. The receiver is slow enough that the two overlap.
func TestSenderShutdownDoesNotInterleaveWithPush(t *testing.T) {
	rcv := newFakeReceiver(t)
	s := failureSender(t, rcv, 8)
	ts := bufferBatches(t, s, rcv, 6)

	rcv.respond(http.StatusOK)
	rcv.delay(20 * time.Millisecond)

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_ = s.Push(context.Background(), ts[len(ts)-1].Add(time.Minute))
	}()
	go func() {
		defer wg.Done()
		<-start
		_ = s.Shutdown(context.Background())
	}()
	close(start)
	wg.Wait()

	arrived := timestampsOf(rcv.requests())
	for i := 1; i < len(arrived); i++ {
		if !arrived[i].After(arrived[i-1]) {
			t.Fatalf("arrival order = %v: a batch arrived twice or ahead of an older one", arrived)
		}
	}
	if got, want := len(arrived)+s.Buffered(), len(ts)+1; got != want {
		t.Errorf("%d batches arrived and %d are still buffered, %d in all, want %d: one was removed unsent",
			len(arrived), s.Buffered(), got, want)
	}
	if got, want := s.Dropped(), uint64(0); got != want {
		t.Errorf("Dropped() = %d, want %d: the ring had room for every batch", got, want)
	}
}

// An eviction between a drain's oldest and its removeOldest deletes the batch
// after the one being sent and counts the delivered one as evicted. Here the
// cycle's own drain is refused, so its fresh batch evicts from a full ring.
func TestSenderEvictionWaitsForTheDrainInFlight(t *testing.T) {
	rcv := newFakeReceiver(t)
	const parked = 4
	s := failureSender(t, rcv, parked) // the ring is exactly full once parked
	ts := bufferBatches(t, s, rcv, parked)
	base := rcv.calls()

	// the cycle's own drain is refused, everything after it accepted
	rcv.answerThen(1, http.StatusServiceUnavailable, http.StatusOK)
	rcv.delay(100 * time.Millisecond)

	fresh := ts[len(ts)-1].Add(time.Minute)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Push(context.Background(), fresh)
	}()
	waitForCalls(t, rcv, base+1) // the drain that will fail is on the wire

	err := s.Shutdown(context.Background())
	<-done

	if err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if got, want := s.Dropped(), uint64(1); got != want {
		t.Fatalf("Dropped() = %d, want %d: the fresh batch had to evict from a full ring, or this test guards nothing", got, want)
	}
	arrived := timestampsOf(rcv.requests())
	// The ring evicts its oldest, so ts[0] is the batch counted dropped and cannot
	// also have been delivered.
	if slices.ContainsFunc(arrived, ts[0].Equal) {
		t.Errorf("%s was delivered and counted evicted as well: the eviction landed inside a drain", ts[0])
	}
	if want := append(ts[1:], fresh); !equalTimes(arrived, want) {
		t.Errorf("arrived = %v, want %v: everything the eviction spared, oldest first", arrived, want)
	}
	if got, want := s.Buffered(), 0; got != want {
		t.Errorf("Buffered() = %d, want %d", got, want)
	}
}

// The token spans the fresh batch's send and its trip to the ring: a Shutdown
// draining in between would find the ring empty, close the exporter, and lose
// the batch buffered a moment later.
func TestSenderShutdownWaitsForTheCycleToDisposeOfItsBatch(t *testing.T) {
	rcv := newFakeReceiver(t)
	s := failureSender(t, rcv, 0)
	ts := bufferBatches(t, s, rcv, 1)
	base := rcv.calls()

	// the buffered batch is taken, the fresh one refused, 150ms each
	rcv.answerThen(1, http.StatusOK, http.StatusServiceUnavailable)
	rcv.delay(150 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Push(context.Background(), ts[0].Add(time.Minute))
	}()
	waitForCalls(t, rcv, base+2) // the drain is through, the fresh batch is on the wire

	err := s.Shutdown(context.Background())
	<-done

	if got, want := rcv.calls()-base, 3; got != want {
		t.Errorf("requests = %d, want %d: the shutdown drain skipped the batch the cycle was still buffering", got, want)
	}
	if err == nil {
		t.Error("Shutdown returned nil, want the 503 that stopped its drain")
	}
	if got, want := s.Buffered(), 1; got != want {
		t.Errorf("Buffered() = %d, want %d: the batch the receiver refused stays", got, want)
	}
}

// Nothing bounds one request except the caller's context (see New), so a
// Shutdown on a context with no deadline would wait out a quiet receiver.
func TestSenderShutdownIsBoundedByTheConfiguredTimeout(t *testing.T) {
	rcv := newFakeReceiver(t)
	cfg := testConfig(rcv.url(), nil)
	cfg.Timeout = 100 * time.Millisecond
	s, err := New(cfg, snapshotRegistry(t), prometheus.NewRegistry())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rcv.respond(http.StatusServiceUnavailable)
	if err := s.Push(context.Background(), cycleTimes(1)[0]); err == nil {
		t.Fatal("Push returned nil, want an error from the 503")
	}

	rcv.respond(http.StatusOK)
	rcv.delay(700 * time.Millisecond) // takes the request and goes quiet

	done := make(chan error, 1)
	go func() { done <- s.Shutdown(context.Background()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Shutdown returned nil, want the timeout that cut its drain")
		}
	case <-time.After(400 * time.Millisecond):
		t.Fatal("Shutdown outlived cfg.Timeout on a context that never ends: the request has no ceiling of its own")
	}
}

// An outage is one line when it starts and one when it ends, not one per cycle.
func TestSenderLogsAFailureOnceAndTheRecovery(t *testing.T) {
	logs := captureLog(t, slog.LevelInfo)
	rcv := newFakeReceiver(t)
	s := failureSender(t, rcv, 0)
	ts := cycleTimes(7)

	rcv.respond(http.StatusServiceUnavailable)
	for _, at := range ts[:5] {
		if err := s.Push(context.Background(), at); err == nil {
			t.Fatalf("Push(%s) returned nil, want an error from the 503", at)
		}
	}
	if got := logs.count("push failed"); got != 1 {
		t.Errorf("failure lines = %d, want 1 for five identical failures:\n%s", got, logs)
	}
	// The exporter's text for a 503 is "retry-able request failure", the code
	// itself only in the body it quotes.
	if want := http.StatusText(http.StatusServiceUnavailable); !strings.Contains(logs.String(), want) {
		t.Errorf("the failure line does not carry %q, what the receiver answered:\n%s", want, logs)
	}
	if got := logs.count("push recovered"); got != 0 {
		t.Errorf("recovery lines = %d, want 0 while the receiver is still down:\n%s", got, logs)
	}

	rcv.respond(http.StatusOK)
	if err := s.Push(context.Background(), ts[5]); err != nil {
		t.Fatalf("Push after the receiver came back: %v", err)
	}
	if got := logs.count("push recovered"); got != 1 {
		t.Errorf("recovery lines = %d, want 1:\n%s", got, logs)
	}

	if err := s.Push(context.Background(), ts[6]); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if got := logs.count("push recovered"); got != 1 {
		t.Errorf("recovery lines = %d after a second good cycle, want 1: the recovery is a change of state:\n%s", got, logs)
	}
	if got := logs.count("push failed"); got != 1 {
		t.Errorf("failure lines = %d at the end, want 1:\n%s", got, logs)
	}
}

// A 4xx is a configuration error, logged every cycle with the receiver's body:
// it will not pass on its own.
func TestSenderLogsEveryRefusal(t *testing.T) {
	logs := captureLog(t, slog.LevelInfo)
	rcv := newFakeReceiver(t)
	s := failureSender(t, rcv, 0)

	rcv.respond(http.StatusBadRequest)
	for _, at := range cycleTimes(3) {
		if err := s.Push(context.Background(), at); err == nil {
			t.Fatalf("Push(%s) returned nil, want an error from the 400", at)
		}
	}
	if got := logs.count("push refused"); got != 3 {
		t.Errorf("refusal lines = %d, want one per cycle:\n%s", got, logs)
	}
	if got := logs.count("body:"); got != 3 {
		t.Errorf("lines carrying the receiver's body = %d, want 3:\n%s", got, logs)
	}
	if got := logs.count("push failed"); got != 0 {
		t.Errorf("failure lines = %d, want 0: a refusal is a configuration error, not an outage:\n%s", got, logs)
	}
}

// The drain Shutdown waits for may be one another goroutine holds; the token
// is given up when ctx ends rather than waiting the drain out.
func TestSenderShutdownDoesNotWaitOutADrainInFlight(t *testing.T) {
	rcv := newFakeReceiver(t)
	s := failureSender(t, rcv, 0)
	ts := bufferBatches(t, s, rcv, 6)

	rcv.respond(http.StatusOK)
	rcv.delay(100 * time.Millisecond) // six batches is 600ms of drain

	sent := rcv.calls()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Push(context.Background(), ts[len(ts)-1].Add(time.Minute))
	}()
	waitForCalls(t, rcv, sent+1) // the drain is under way and holds the token

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := s.Shutdown(ctx)
	elapsed := time.Since(start)
	<-done

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want one carrying context.DeadlineExceeded", err)
	}
	if want := 400 * time.Millisecond; elapsed > want {
		t.Errorf("Shutdown took %s, want under %s rather than the drain's remaining 600ms", elapsed, want)
	}
}
