package push

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	collectorpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"
)

// fakeReceiver is an OTLP/HTTP metrics endpoint for the sender's tests. It
// decodes every request body as an ExportMetricsServiceRequest and keeps the
// ResourceMetrics from every request it accepts (2xx), in arrival order.
// calls and headers count and record every attempt, accepted or not.
type fakeReceiver struct {
	srv *httptest.Server

	mu         sync.Mutex
	reqs       []*metricspb.ResourceMetrics
	n          int
	code       int
	firstN     int // requests still answered code before thenCode takes over
	thenCode   int // answered once firstN runs out; 0 means code stands for every request
	pause      time.Duration
	reqHeaders []http.Header
}

// newFakeReceiver starts a server answering 200 OK until respond says
// otherwise. It closes when t ends.
func newFakeReceiver(t *testing.T) *fakeReceiver {
	t.Helper()
	r := &fakeReceiver{code: http.StatusOK}
	r.srv = httptest.NewServer(http.HandlerFunc(r.handle))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *fakeReceiver) handle(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.n++
	code := r.code
	if r.thenCode != 0 {
		if r.firstN > 0 {
			r.firstN--
		} else {
			code = r.thenCode
		}
	}
	pause := r.pause
	r.reqHeaders = append(r.reqHeaders, req.Header.Clone())
	r.mu.Unlock()

	time.Sleep(pause) // a receiver that took the request and went quiet

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

	if code < 200 || code >= 300 {
		http.Error(w, http.StatusText(code), code)
		return
	}

	r.mu.Lock()
	r.reqs = append(r.reqs, envelope.GetResourceMetrics()...)
	r.mu.Unlock()

	resp, err := proto.Marshal(&collectorpb.ExportMetricsServiceResponse{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.Write(resp)
}

// url is the receiver's base URL, the value for push.Config.Endpoint in
// tests that exercise a full export.
func (r *fakeReceiver) url() string { return r.srv.URL }

// requests returns every ResourceMetrics from an accepted (2xx) request, in
// arrival order. A batch answered with a non-2xx code — even one that
// decoded cleanly — was not accepted and never appears here.
func (r *fakeReceiver) requests() []*metricspb.ResourceMetrics {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.reqs)
}

// respond changes the status code answered to every request from here on and
// cancels a pending answerThen. A delay stands until delay clears it.
func (r *fakeReceiver) respond(code int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.code = code
	r.firstN, r.thenCode = 0, 0
}

// answerThen answers first to the next n requests and then to every request
// after them: how a test breaks a drain in the middle rather than at its
// head, or refuses what is buffered while taking what is fresh.
func (r *fakeReceiver) answerThen(n, first, then int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.code, r.firstN, r.thenCode = first, n, then
}

// delay makes the handler sit on every request for d before answering, the
// shape of a receiver slow enough to spend a sender's deadline.
func (r *fakeReceiver) delay(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pause = d
}

// calls returns the number of requests handled so far, decoded or not.
func (r *fakeReceiver) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

// headers returns the headers of every request received, decoded or not, in
// arrival order.
func (r *fakeReceiver) headers() []http.Header {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.reqHeaders)
}

// gaugeMetric builds one ResourceMetrics carrying a single-point gauge, the
// shape a real export uses: one metric, one point, string attributes.
func gaugeMetric(name string, value float64, timeUnixNano uint64, attrs map[string]string) *metricspb.ResourceMetrics {
	kvs := make([]*commonpb.KeyValue, 0, len(attrs))
	for k, v := range attrs {
		kvs = append(kvs, &commonpb.KeyValue{
			Key:   k,
			Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}},
		})
	}
	return &metricspb.ResourceMetrics{
		ScopeMetrics: []*metricspb.ScopeMetrics{{
			Metrics: []*metricspb.Metric{{
				Name: name,
				Data: &metricspb.Metric_Gauge{
					Gauge: &metricspb.Gauge{
						DataPoints: []*metricspb.NumberDataPoint{{
							Attributes:   kvs,
							TimeUnixNano: timeUnixNano,
							Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: value},
						}},
					},
				},
			}},
		}},
	}
}

// attr returns the string value of the attribute named key, or "" if absent.
func attr(kvs []*commonpb.KeyValue, key string) string {
	for _, kv := range kvs {
		if kv.GetKey() == key {
			return kv.GetValue().GetStringValue()
		}
	}
	return ""
}

// post marshals req and sends it to the receiver, the way otlpmetrichttp
// does: one blocking POST, protobuf body.
func post(t *testing.T, url string, req *collectorpb.ExportMetricsServiceRequest) *http.Response {
	t.Helper()
	body, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := http.Post(url, "application/x-protobuf", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	resp.Body.Close()
	return resp
}

func TestFakeReceiver(t *testing.T) {
	r := newFakeReceiver(t)

	const takenAt = uint64(1735689600_000000000) // 2025-01-01T00:00:00Z, in nanoseconds
	want := gaugeMetric("tplink_up", 1, takenAt, map[string]string{
		"job":      "tplink_exporter",
		"instance": "192.0.2.1",
	})
	resp := post(t, r.url(), &collectorpb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{want},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	got := r.requests()
	if len(got) != 1 {
		t.Fatalf("requests() = %d entries, want 1", len(got))
	}
	metric := got[0].GetScopeMetrics()[0].GetMetrics()[0]
	if metric.GetName() != "tplink_up" {
		t.Errorf("metric name = %q, want %q", metric.GetName(), "tplink_up")
	}
	point := metric.GetGauge().GetDataPoints()[0]
	if point.GetAsDouble() != 1 {
		t.Errorf("value = %v, want 1", point.GetAsDouble())
	}
	if point.GetTimeUnixNano() != takenAt {
		t.Errorf("time_unix_nano = %d, want %d", point.GetTimeUnixNano(), takenAt)
	}
	if got := attr(point.GetAttributes(), "job"); got != "tplink_exporter" {
		t.Errorf("job attribute = %q, want %q", got, "tplink_exporter")
	}
	if got := attr(point.GetAttributes(), "instance"); got != "192.0.2.1" {
		t.Errorf("instance attribute = %q, want %q", got, "192.0.2.1")
	}
	if got, want := r.calls(), 1; got != want {
		t.Errorf("calls() = %d, want %d", got, want)
	}
}

func TestFakeReceiverRespond(t *testing.T) {
	r := newFakeReceiver(t)
	req := &collectorpb.ExportMetricsServiceRequest{}

	if got, want := post(t, r.url(), req).StatusCode, http.StatusOK; got != want {
		t.Errorf("default status = %d, want %d", got, want)
	}

	r.respond(http.StatusServiceUnavailable)
	if got, want := post(t, r.url(), req).StatusCode, http.StatusServiceUnavailable; got != want {
		t.Errorf("status after respond(503) = %d, want %d", got, want)
	}

	r.respond(http.StatusBadRequest)
	if got, want := post(t, r.url(), req).StatusCode, http.StatusBadRequest; got != want {
		t.Errorf("status after respond(400) = %d, want %d", got, want)
	}

	r.respond(http.StatusOK)
	if got, want := post(t, r.url(), req).StatusCode, http.StatusOK; got != want {
		t.Errorf("status after respond(200) = %d, want %d", got, want)
	}
}

func TestFakeReceiverRequestsOnlyAccepted(t *testing.T) {
	r := newFakeReceiver(t)
	req := &collectorpb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{
			gaugeMetric("tplink_up", 1, 1, map[string]string{"job": "tplink_exporter"}),
		},
	}

	r.respond(http.StatusServiceUnavailable)
	post(t, r.url(), req)
	if got, want := r.calls(), 1; got != want {
		t.Fatalf("calls() after a 503 = %d, want %d", got, want)
	}
	if got := r.requests(); len(got) != 0 {
		t.Fatalf("requests() after a 503 = %d entries, want 0: a refused batch was not accepted", len(got))
	}

	r.respond(http.StatusOK)
	post(t, r.url(), req)
	if got, want := r.calls(), 2; got != want {
		t.Fatalf("calls() after a 200 = %d, want %d", got, want)
	}
	if got := r.requests(); len(got) != 1 {
		t.Fatalf("requests() after a 200 = %d entries, want 1", len(got))
	}
}

func TestFakeReceiverCalls(t *testing.T) {
	r := newFakeReceiver(t)
	if got, want := r.calls(), 0; got != want {
		t.Fatalf("calls() before any request = %d, want %d", got, want)
	}

	req := &collectorpb.ExportMetricsServiceRequest{}
	for range 3 {
		post(t, r.url(), req)
	}
	if got, want := r.calls(), 3; got != want {
		t.Errorf("calls() after 3 requests = %d, want %d", got, want)
	}
}
