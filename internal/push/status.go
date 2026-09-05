package push

import (
	"net/http"
	"sync"
)

// statusTransport remembers the status code of the last response:
// otlpmetrichttp.Exporter.Export returns the code only inside its error's
// text, not as a value to branch on.
type statusTransport struct {
	base http.RoundTripper

	mu   sync.Mutex
	last int
}

func newStatusTransport(base http.RoundTripper) *statusTransport {
	return &statusTransport{base: base}
}

func (t *statusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	code := 0
	if err == nil {
		code = resp.StatusCode
	}
	t.mu.Lock()
	t.last = code
	t.mu.Unlock()
	return resp, err
}

// reset clears the code before a send: Export on a spent context makes no
// request at all, and the previous request's code would classify that failure.
func (t *statusTransport) reset() {
	t.mu.Lock()
	t.last = 0
	t.mu.Unlock()
}

func (t *statusTransport) lastStatus() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.last
}

// permanent reports whether code is a refusal no retry will fix: 4xx other
// than 408 (request timeout) and 429 (rate limited).
func permanent(code int) bool {
	if code < 400 || code >= 500 {
		return false
	}
	return code != 408 && code != 429
}
