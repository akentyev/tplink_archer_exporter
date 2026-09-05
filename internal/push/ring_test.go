package push

import (
	"errors"
	"slices"
	"testing"

	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// batch builds a ResourceMetrics carrying one gauge data point valued n. The
// ring is agnostic to what it carries; batch and id only need to round-trip a
// value so the tests can tell entries apart.
func batch(n int) *metricdata.ResourceMetrics {
	return &metricdata.ResourceMetrics{
		ScopeMetrics: []metricdata.ScopeMetrics{{
			Metrics: []metricdata.Metrics{{
				Data: metricdata.Gauge[int64]{
					DataPoints: []metricdata.DataPoint[int64]{{Value: int64(n)}},
				},
			}},
		}},
	}
}

// id reads back the value batch wrote.
func id(rm *metricdata.ResourceMetrics) int {
	g := rm.ScopeMetrics[0].Metrics[0].Data.(metricdata.Gauge[int64])
	return int(g.DataPoints[0].Value)
}

func TestRingEvictsOldest(t *testing.T) {
	r := newRing(2)
	r.push(batch(1))
	r.push(batch(2))
	r.push(batch(3))
	// the oldest entry is evicted, the drop counter grows
	if got, want := r.len(), 2; got != want {
		t.Errorf("len = %d, want %d", got, want)
	}
	if got, want := r.dropped(), uint64(1); got != want {
		t.Errorf("dropped = %d, want %d", got, want)
	}
	var seen []int
	r.drain(func(rm *metricdata.ResourceMetrics) error {
		seen = append(seen, id(rm))
		return nil
	})
	if want := []int{2, 3}; !slices.Equal(seen, want) {
		t.Errorf("drain order = %v, want %v", seen, want)
	}
}

func TestRingDrainStopsOnError(t *testing.T) {
	r := newRing(10)
	r.push(batch(1))
	r.push(batch(2))
	r.push(batch(3))
	sent := 0
	err := r.drain(func(rm *metricdata.ResourceMetrics) error {
		sent++
		if id(rm) == 2 {
			return errors.New("receiver down")
		}
		return nil
	})
	if err == nil {
		t.Fatal("drain returned nil, want the send error")
	}
	// the first error stops the drain; what remains unsent keeps its order
	if got, want := sent, 2; got != want {
		t.Errorf("sends = %d, want %d", got, want)
	}
	if got, want := r.len(), 2; got != want {
		t.Errorf("len after failed drain = %d, want %d", got, want)
	}
}
