package push

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	otelprom "go.opentelemetry.io/contrib/bridges/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
)

// DefaultBuffer is how many unsent snapshots the ring keeps when Config.Buffer
// is zero.
const DefaultBuffer = 300

// errRefused marks a batch the receiver refused for good, as permanent
// classifies it. It is dropped rather than buffered: at the head of the ring
// it would block every later batch for the whole retention.
var errRefused = errors.New("receiver refused the batch")

// Registry is what Sender needs of the snapshot side: it reads that registry
// and adds its own delivery metrics to it.
type Registry interface {
	prometheus.Gatherer
	prometheus.Registerer
}

// Config is what Sender needs to reach an OTLP receiver.
type Config struct {
	Endpoint string            // full URL, e.g. http://vm:8428/opentelemetry/v1/metrics
	Labels   map[string]string // job, instance and every -push-label, on every datapoint
	Resource map[string]string // service.name, service.instance.id
	Headers  map[string]string // reserved for credentials read from a file
	Buffer   int               // unsent snapshots kept, in cycles; 0 means DefaultBuffer
	Timeout  time.Duration     // one Push; the poller's cycle budget is separate
}

// Sender collects from two gatherers and sends both as OTLP. Its delivery
// metrics register into the snapshot registry; metrics.go says why that one.
type Sender struct {
	cfg Config

	exporter *otlpmetrichttp.Exporter
	status   *statusTransport

	snapshot *sdkmetric.ManualReader
	process  *sdkmetric.ManualReader

	metrics *pushMetrics
	ring    *ring
	refused atomic.Uint64 // batches the receiver refused for good; the ring counts its own evictions

	// drainToken holds one entry and is taken for the whole of a drain, which
	// Push and Shutdown run from different goroutines.
	drainToken chan struct{}
	failing    atomic.Bool // last cycle failed; report logs the change of state, not the state

	start time.Time // Sender's own construction time, stamped as every snapshot point's StartTime
}

// New builds a Sender over snapshot and process. cfg.Labels goes on every point
// of both bodies: without it two exporters writing to one receiver share one
// go_*/process_* series.
func New(cfg Config, snapshot Registry, process prometheus.Gatherer) (*Sender, error) {
	buffer := cfg.Buffer
	if buffer == 0 {
		buffer = DefaultBuffer
	}

	status := newStatusTransport(http.DefaultTransport)
	exp, err := otlpmetrichttp.New(context.Background(),
		otlpmetrichttp.WithEndpointURL(cfg.Endpoint),
		otlpmetrichttp.WithHeaders(cfg.Headers),
		// The client's Timeout is a request's only ceiling: WithTimeout is ignored
		// once WithHTTPClient is given, the retry is off, and DefaultTransport sets
		// no response deadline.
		otlpmetrichttp.WithHTTPClient(&http.Client{Timeout: cfg.Timeout, Transport: status}),
		// The buffer replaces this: the default retries inside Export, which
		// blocks the poll cycle and still drops the batch after a minute.
		otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{Enabled: false}),
	)
	if err != nil {
		return nil, fmt.Errorf("build OTLP exporter: %w", err)
	}

	metrics, err := newPushMetrics(snapshot)
	if err != nil {
		return nil, err
	}

	res := resource.NewSchemaless(keyValuesOf(cfg.Resource)...)
	snapshotReader := newManualReader(snapshot)
	processReader := newManualReader(process)
	// NewMeterProvider is what hands a reader its producer and the resource; no
	// Meter is ever requested, so the provider itself is dropped.
	sdkmetric.NewMeterProvider(sdkmetric.WithReader(snapshotReader), sdkmetric.WithResource(res))
	sdkmetric.NewMeterProvider(sdkmetric.WithReader(processReader), sdkmetric.WithResource(res))

	return &Sender{
		cfg:      cfg,
		exporter: exp,
		status:   status,
		snapshot: snapshotReader,
		process:  processReader,
		metrics:  metrics,
		ring:     newRing(buffer),

		drainToken: make(chan struct{}, 1),
		start:      time.Now(),
	}, nil
}

// newManualReader wraps g as an on-demand reader fed by the Prometheus bridge.
// Temporality is pinned to cumulative: rate() reads a counter reset correctly,
// while delta would need the receiver to sum and the sender to remember.
func newManualReader(g prometheus.Gatherer) *sdkmetric.ManualReader {
	return sdkmetric.NewManualReader(
		sdkmetric.WithProducer(otelprom.NewMetricProducer(otelprom.WithGatherer(continueOnError{g}))),
		sdkmetric.WithTemporalitySelector(func(sdkmetric.InstrumentKind) metricdata.Temporality {
			return metricdata.CumulativeTemporality
		}),
	)
}

// continueOnError passes on what a gatherer collected beside its error, as
// promhttp.ContinueOnError does in pull mode; the bridge would drop the whole
// output on any error, so one duplicate series would empty every push.
type continueOnError struct{ g prometheus.Gatherer }

// Gather logs the error and swallows it: the log is its only record.
func (c continueOnError) Gather() ([]*dto.MetricFamily, error) {
	mfs, err := c.g.Gather()
	if err != nil {
		slog.Error("push gather", "err", err)
	}
	return mfs, nil
}

// Push sends one cycle within cfg.Timeout: the buffer oldest first, then the
// snapshot stamped with takenAt, then process metrics stamped with the send
// time. A drain that fails stops, and the fresh batch queues behind the unsent
// ones -- rate() survives a counter reset, not samples out of order. The
// snapshot is collected before the drain: Collect refuses a spent context, so
// a drain that used the deadline would otherwise lose the cycle unbuffered.
func (s *Sender) Push(ctx context.Context, takenAt time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	rm := &metricdata.ResourceMetrics{}
	if err := s.snapshot.Collect(ctx, rm); err != nil {
		return fmt.Errorf("collect snapshot: %w", err)
	}
	stampSnapshot(rm, takenAt, s.start, s.cfg.Labels)

	refusedErr, drainErr, sendErr := s.deliver(ctx, rm)

	prm := &metricdata.ResourceMetrics{}
	if err := s.process.Collect(ctx, prm); err == nil && len(prm.ScopeMetrics) > 0 {
		stampProcess(prm, time.Now(), s.cfg.Labels)
		_ = s.exporter.Export(ctx, prm) // dropped, unbuffered, on failure: it describes a moment already gone
	}

	s.metrics.syncBuffer(s.ring.len(), s.Dropped())

	// Refusals and failures stay apart to the caller: report logs them on
	// different rules, and either can occur while the other half went through.
	var refusals, failures []error
	if refusedErr != nil {
		refusals = append(refusals, fmt.Errorf("drop buffered batch: %w", refusedErr))
	}
	if drainErr != nil {
		failures = append(failures, fmt.Errorf("drain buffer: %w", drainErr))
	}
	if sendErr != nil {
		if errors.Is(sendErr, errRefused) {
			refusals = append(refusals, fmt.Errorf("push snapshot: %w", sendErr))
		} else {
			failures = append(failures, fmt.Errorf("push snapshot: %w", sendErr))
		}
	}
	refused, failed := errors.Join(refusals...), errors.Join(failures...)
	s.report(refused, failed)
	return errors.Join(refused, failed)
}

// deliver drains the buffer and then sends rm, holding the drain token from the
// first buffered batch to the fresh one's trip to the ring; the ring's mutex
// covers its fields, not a whole drain. The wait for the token is unbounded:
// a cycle that gave up would be a cycle lost.
func (s *Sender) deliver(ctx context.Context, rm *metricdata.ResourceMetrics) (refused, drainErr, sendErr error) {
	s.drainToken <- struct{}{}
	defer func() { <-s.drainToken }()

	refused, drainErr = s.drainRing(ctx)
	switch {
	case len(rm.ScopeMetrics) == 0:
	case drainErr != nil:
		s.ring.push(rm)
	default:
		sendErr = s.send(ctx, rm)
		if sendErr != nil && !errors.Is(sendErr, errRefused) {
			s.ring.push(rm)
		}
	}
	return refused, drainErr, sendErr
}

// drainRing runs ring.drain with send, reporting the first refusal apart from
// the error that stopped it: a refused batch leaves the ring like a sent one.
// The caller holds the drain token.
func (s *Sender) drainRing(ctx context.Context) (refused, err error) {
	err = s.ring.drain(func(rm *metricdata.ResourceMetrics) error {
		sendErr := s.send(ctx, rm)
		if errors.Is(sendErr, errRefused) {
			if refused == nil {
				refused = sendErr
			}
			return nil
		}
		return sendErr
	})
	return refused, err
}

// report logs a failure when it starts and the recovery when it ends -- five
// hours of outage would otherwise be 300 identical warnings. A refusal is
// logged every cycle: a configuration error does not pass on its own.
func (s *Sender) report(refused, failed error) {
	if refused != nil {
		slog.Warn("push refused", "err", refused)
	}
	switch {
	case failed != nil:
		if !s.failing.Swap(true) {
			slog.Warn("push failed", "err", failed, "buffered", s.ring.len())
		}
	case refused == nil: // a cycle clean of both is what ends an outage
		if s.failing.Swap(false) {
			slog.Info("push recovered", "buffered", s.ring.len())
		}
	}
}

// send exports one snapshot batch and counts the attempt; a failure permanent
// classifies is counted as refused and wrapped in errRefused.
func (s *Sender) send(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	s.status.reset()
	if err := s.exporter.Export(ctx, rm); err != nil {
		s.metrics.failed()
		if permanent(s.status.lastStatus()) {
			s.refused.Add(1)
			return fmt.Errorf("%w: %w", errRefused, err)
		}
		return err
	}
	s.metrics.succeeded(time.Now())
	return nil
}

// Shutdown drains the buffer within ctx, logs what ctx left unsent, and closes
// the exporter. The close runs with ctx's cancellation removed: the OTLP client
// returns ctx.Err() from its own Shutdown, so a drain that spent the deadline
// would otherwise report a close that did not fail.
func (s *Sender) Shutdown(ctx context.Context) error {
	refused, left, drainErr := s.drainWithin(ctx)

	var errs []error
	if refused != nil {
		errs = append(errs, fmt.Errorf("drop buffered batch: %w", refused))
	}
	if drainErr != nil {
		errs = append(errs, fmt.Errorf("drain buffer: %w", drainErr))
	}
	if err := s.exporter.Shutdown(context.WithoutCancel(ctx)); err != nil {
		errs = append(errs, fmt.Errorf("close OTLP exporter: %w", err))
	}

	// A drain another goroutine holds goes on delivering until the close above
	// stops it, so what it leaves is counted after the close, not before.
	if left < 0 {
		left = s.ring.len()
	}
	// left > 0 implies drainErr != nil: only a stopped drain leaves batches.
	if left > 0 {
		slog.Warn("push buffer lost at shutdown", "batches", left, "err", drainErr)
	}
	return errors.Join(errs...)
}

// drainWithin drains under the token, giving up when ctx ends before the token
// is free. left is the ring's size read before the token is released -- after
// it another cycle may have moved batches -- or -1 when the drain never ran.
func (s *Sender) drainWithin(ctx context.Context) (refused error, left int, err error) {
	select {
	case s.drainToken <- struct{}{}:
	case <-ctx.Done():
		return nil, -1, fmt.Errorf("wait for the drain in flight: %w", ctx.Err())
	}
	defer func() { <-s.drainToken }()
	refused, err = s.drainRing(ctx)
	return refused, s.ring.len(), err
}

// Buffered reports how many batches are waiting to be sent.
func (s *Sender) Buffered() int { return s.ring.len() }

// Dropped reports how many batches were dropped unsent since the sender was
// created: evicted from the buffer or refused by the receiver.
func (s *Sender) Dropped() uint64 { return s.ring.dropped() + s.refused.Load() }

// stampSnapshot overwrites what the bridge stamps -- its own collection time,
// and for gauges no StartTime at all -- with takenAt and start, and merges
// labels into every point's attributes.
func stampSnapshot(rm *metricdata.ResourceMetrics, takenAt, start time.Time, labels map[string]string) {
	extra := keyValuesOf(labels)
	eachPoint(rm, func(attrs *attribute.Set, pStart, pTime *time.Time) {
		*pStart = start
		*pTime = takenAt
		mergeLabels(attrs, extra)
	})
}

// stampProcess stamps Time only; StartTime stays as the bridge set it.
func stampProcess(rm *metricdata.ResourceMetrics, now time.Time, labels map[string]string) {
	extra := keyValuesOf(labels)
	eachPoint(rm, func(attrs *attribute.Set, _, pTime *time.Time) {
		*pTime = now
		mergeLabels(attrs, extra)
	})
}

func mergeLabels(attrs *attribute.Set, extra []attribute.KeyValue) {
	*attrs = attribute.NewSet(append(attrs.ToSlice(), extra...)...)
}

func keyValuesOf(m map[string]string) []attribute.KeyValue {
	kvs := make([]attribute.KeyValue, 0, len(m))
	for k, v := range m {
		kvs = append(kvs, attribute.String(k, v))
	}
	return kvs
}

// eachPoint calls fn once per data point. The bridge emits only float64
// instruments, so the int64 variants are not handled.
func eachPoint(rm *metricdata.ResourceMetrics, fn func(attrs *attribute.Set, start, t *time.Time)) {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch d := m.Data.(type) {
			case metricdata.Gauge[float64]:
				eachNumberPoint(d.DataPoints, fn)
			case metricdata.Sum[float64]:
				eachNumberPoint(d.DataPoints, fn)
			case metricdata.Histogram[float64]:
				for i := range d.DataPoints {
					dp := &d.DataPoints[i]
					fn(&dp.Attributes, &dp.StartTime, &dp.Time)
				}
			case metricdata.ExponentialHistogram[float64]:
				for i := range d.DataPoints {
					dp := &d.DataPoints[i]
					fn(&dp.Attributes, &dp.StartTime, &dp.Time)
				}
			case metricdata.Summary:
				for i := range d.DataPoints {
					dp := &d.DataPoints[i]
					fn(&dp.Attributes, &dp.StartTime, &dp.Time)
				}
			}
		}
	}
}

func eachNumberPoint(dps []metricdata.DataPoint[float64], fn func(attrs *attribute.Set, start, t *time.Time)) {
	for i := range dps {
		fn(&dps[i].Attributes, &dps[i].StartTime, &dps[i].Time)
	}
}
