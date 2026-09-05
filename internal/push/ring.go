package push

import (
	"sync"

	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// ring is a fixed-capacity FIFO of unsent batches: push evicts the oldest once
// full, drain sends from the head. The mutex covers the fields, never the send
// inside a drain, so a drain is not atomic: one at a time.
type ring struct {
	mu      sync.Mutex
	buf     []*metricdata.ResourceMetrics
	head    int // index of the oldest entry
	size    int // number of entries currently held
	evicted uint64
}

func newRing(capacity int) *ring {
	return &ring{buf: make([]*metricdata.ResourceMetrics, capacity)}
}

func (r *ring) push(rm *metricdata.ResourceMetrics) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size == len(r.buf) {
		r.head = (r.head + 1) % len(r.buf)
		r.size--
		r.evicted++
	}
	r.buf[(r.head+r.size)%len(r.buf)] = rm
	r.size++
}

// drain sends from the head until send fails; what remains keeps its order.
func (r *ring) drain(send func(*metricdata.ResourceMetrics) error) error {
	for {
		rm, ok := r.oldest()
		if !ok {
			return nil
		}
		if err := send(rm); err != nil {
			return err
		}
		r.removeOldest()
	}
}

// oldest peeks at the head; the lock is not held across the caller's send.
func (r *ring) oldest() (*metricdata.ResourceMetrics, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size == 0 {
		return nil, false
	}
	return r.buf[r.head], true
}

func (r *ring) removeOldest() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size == 0 {
		return
	}
	r.buf[r.head] = nil
	r.head = (r.head + 1) % len(r.buf)
	r.size--
}

func (r *ring) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size
}

func (r *ring) dropped() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.evicted
}
