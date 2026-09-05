package push

import (
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// pushMetrics are the sender's delivery counters, registered into the snapshot
// registry rather than the process one so they ride the buffer through an
// outage and explain it afterwards.
type pushMetrics struct {
	total       *prometheus.CounterVec
	dropped     prometheus.Counter
	buffered    prometheus.Gauge
	lastSuccess prometheus.Gauge

	lastDropped uint64 // the dropped total as of the previous syncBuffer call
}

// newPushMetrics registers the delivery metrics into reg. Both result values
// are touched at zero so the series exist from the first batch.
func newPushMetrics(reg prometheus.Registerer) (*pushMetrics, error) {
	m := &pushMetrics{
		total: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tplink_push_total",
			Help: "Attempts to send one snapshot batch to the OTLP receiver, by result. A cycle counts one per batch it tries -- the buffered ones it drains and its own -- so anything from none to the whole buffer.",
		}, []string{"result"}),
		dropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tplink_push_dropped_total",
			Help: "Batches dropped unsent: evicted from the buffer or refused by the receiver.",
		}),
		buffered: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tplink_push_buffered",
			Help: "Batches currently waiting in the buffer.",
		}),
		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tplink_push_last_success_timestamp_seconds",
			Help: "Unix time of the last batch an OTLP receiver accepted.",
		}),
	}
	m.total.WithLabelValues("ok")
	m.total.WithLabelValues("failed")

	for _, c := range []prometheus.Collector{m.total, m.dropped, m.buffered, m.lastSuccess} {
		if err := reg.Register(c); err != nil {
			return nil, fmt.Errorf("register push metrics: %w", err)
		}
	}
	return m, nil
}

func (m *pushMetrics) succeeded(at time.Time) {
	m.total.WithLabelValues("ok").Inc()
	m.lastSuccess.Set(float64(at.Unix()))
}

func (m *pushMetrics) failed() {
	m.total.WithLabelValues("failed").Inc()
}

// syncBuffer publishes the buffer's size and adds to the dropped counter what
// Sender.Dropped grew by since the last call.
func (m *pushMetrics) syncBuffer(buffered int, dropped uint64) {
	m.buffered.Set(float64(buffered))
	if dropped > m.lastDropped {
		m.dropped.Add(float64(dropped - m.lastDropped))
		m.lastDropped = dropped
	}
}
