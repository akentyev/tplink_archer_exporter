package push

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPermanentClassification(t *testing.T) {
	for _, tc := range []struct {
		code int
		want bool
	}{
		{0, false}, {200, false},
		{400, true}, {404, true}, {413, true},
		{408, false}, {429, false},
		{500, false}, {502, false}, {503, false},
	} {
		if got := permanent(tc.code); got != tc.want {
			t.Errorf("permanent(%d) = %v, want %v", tc.code, got, tc.want)
		}
	}
}

func TestStatusTransportRemembersCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusTeapot)
	}))
	defer srv.Close()
	tr := newStatusTransport(http.DefaultTransport)
	resp, err := tr.RoundTrip(httptest.NewRequest("POST", srv.URL, nil))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got, want := tr.lastStatus(), http.StatusTeapot; got != want {
		t.Errorf("lastStatus = %d, want %d", got, want)
	}
}

func TestStatusTransportResetsAfterNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", 400)
	}))
	tr := newStatusTransport(http.DefaultTransport)

	resp, err := tr.RoundTrip(httptest.NewRequest("POST", srv.URL, nil))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got, want := tr.lastStatus(), 400; got != want {
		t.Fatalf("lastStatus after a response = %d, want %d", got, want)
	}

	srv.Close() // listener is gone; the next RoundTrip fails before a response arrives
	if _, err := tr.RoundTrip(httptest.NewRequest("POST", srv.URL, nil)); err == nil {
		t.Fatal("RoundTrip against a closed server returned a nil error")
	}
	if got, want := tr.lastStatus(), 0; got != want {
		t.Errorf("lastStatus after a network error = %d, want %d, stale code must not survive", got, want)
	}
}
