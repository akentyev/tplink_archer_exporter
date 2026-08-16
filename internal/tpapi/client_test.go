package tpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// notCiphertext is valid base64 that is not a whole number of AES blocks, so the
// session key cannot turn it back into an envelope.
var notCiphertext = base64.StdEncoding.EncodeToString([]byte("raw base64, not a sealed envelope"))

// fakeRouter implements the server half of the scheme, so the whole client flow
// runs end to end. Every step was read out of the router's JS bundle, so it pins
// the wire format we emit.
type fakeRouter struct {
	key      *rsa.PrivateKey
	certs    []string
	seq      int64
	username string
	password string
	stok     string

	// busy makes the first login attempt report the single-session conflict.
	busy bool

	cipher *Cipher // server-side session key, learned from the login signature
	t      *testing.T
}

func (f *fakeRouter) features() Features { return FeaturesFor(f.certs) }

func (f *fakeRouter) keyHex() (string, string) {
	return f.key.N.Text(16), strconv.FormatInt(int64(f.key.E), 16)
}

// rsaDecrypt reverses LoginSignature: fixed-width blocks, OAEP or v1.5.
func (f *fakeRouter) rsaDecrypt(hexStr string) string {
	f.t.Helper()
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		f.t.Fatalf("signature is not hex: %v", err)
	}
	k := f.key.Size()
	if len(raw) == 0 || len(raw)%k != 0 {
		f.t.Fatalf("signature of %d bytes is not a multiple of %d", len(raw), k)
	}
	var out bytes.Buffer
	for i := 0; i < len(raw); i += k {
		var (
			part []byte
			err  error
		)
		if f.features().OAEP {
			part, err = rsa.DecryptOAEP(sha1.New(), nil, f.key, raw[i:i+k], nil)
		} else {
			part, err = rsa.DecryptPKCS1v15(nil, f.key, raw[i:i+k])
		}
		if err != nil {
			f.t.Fatalf("signature block %d does not decrypt: %v", i/k, err)
		}
		out.Write(part)
	}
	return out.String()
}

// unpackLogin validates the login request and returns its plaintext body,
// adopting the AES key the signature carries.
func (f *fakeRouter) unpackLogin(r *http.Request) string {
	f.t.Helper()
	if !f.features().Encrypt {
		return f.plainBody(r)
	}
	sign, data := f.sealed(r)

	fields := map[string]string{}
	for _, kv := range strings.Split(f.rsaDecrypt(sign), "&") {
		k, v, _ := strings.Cut(kv, "=")
		fields[k] = v
	}
	for _, want := range []string{"k", "i", "h", "s"} {
		if fields[want] == "" {
			f.t.Fatalf("login signature is missing %q (got %v)", want, fields)
		}
	}
	if got := CredHash(f.username, f.password, f.features().SHA256Hash); fields["h"] != got {
		f.t.Fatalf("credential hash mismatch: %q vs %q", fields["h"], got)
	}
	f.checkSeq(fields["s"], data)

	f.cipher = &Cipher{Key: []byte(fields["k"]), IV: []byte(fields["i"])}
	if len(f.cipher.Key) != aesKeyLen || len(f.cipher.IV) != aesKeyLen {
		f.t.Fatalf("key/iv must be %d chars, got %d/%d", aesKeyLen, len(f.cipher.Key), len(f.cipher.IV))
	}
	plain, err := f.cipher.Decrypt(data)
	if err != nil {
		f.t.Fatalf("server could not decrypt login body: %v", err)
	}
	return plain
}

// unpackSession validates the HMAC signature of a post-login request.
func (f *fakeRouter) unpackSession(r *http.Request) string {
	f.t.Helper()
	if !f.features().Encrypt {
		return f.plainBody(r)
	}
	sign, data := f.sealed(r)
	if f.cipher == nil {
		f.t.Fatal("request arrived before login established a key")
	}
	if strings.ContainsAny(sign, "=&") {
		f.t.Fatalf("session signature should be a bare hex MAC, got %q", truncate(sign, 80))
	}
	want := SessionSignature(f.cipher, DataHash(data), f.seq+int64(len(data)))
	if sign != want {
		f.t.Fatalf("session signature mismatch:\n got %s\nwant %s", sign, want)
	}
	plain, err := f.cipher.Decrypt(data)
	if err != nil {
		f.t.Fatalf("server could not decrypt body: %v", err)
	}
	return plain
}

func (f *fakeRouter) sealed(r *http.Request) (sign, data string) {
	f.t.Helper()
	if err := r.ParseForm(); err != nil {
		f.t.Fatal(err)
	}
	sign, data = r.PostForm.Get("sign"), r.PostForm.Get("data")
	if sign == "" || data == "" {
		f.t.Fatalf("missing sign or data in %q", r.URL)
	}
	return sign, data
}

func (f *fakeRouter) plainBody(r *http.Request) string {
	f.t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(raw)
}

func (f *fakeRouter) checkSeq(s, data string) {
	f.t.Helper()
	got, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		f.t.Fatalf("bad s: %v", err)
	}
	if want := f.seq + int64(len(data)); got != want {
		f.t.Fatalf("s = %d, want seq+len(data) = %d", got, want)
	}
}

// reply seals the whole envelope and returns a bare {"data":"<base64>"}, or
// sends it in the clear on devices that do not encrypt.
func (f *fakeRouter) reply(w http.ResponseWriter, env map[string]any) {
	f.t.Helper()
	if !f.features().Encrypt {
		_ = json.NewEncoder(w).Encode(env)
		return
	}
	body, err := json.Marshal(env)
	if err != nil {
		f.t.Fatal(err)
	}
	enc, err := f.cipher.Encrypt(string(body))
	if err != nil {
		f.t.Fatal(err)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": enc})
}

func (f *fakeRouter) ok(w http.ResponseWriter, data any) {
	f.reply(w, map[string]any{"success": true, "data": data})
}

// unsealed writes a body verbatim, bypassing the sealing reply does. Some errors
// arrive in the clear, and the cases below turn on what the wrapper carries
// rather than on what is inside it.
func (f *fakeRouter) unsealed(w http.ResponseWriter, status int, body map[string]any) {
	f.t.Helper()
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = json.NewEncoder(w).Encode(body)
}

// seal encrypts a payload with the session key without wrapping it in an
// envelope first.
func (f *fakeRouter) seal(plain string) string {
	f.t.Helper()
	enc, err := f.cipher.Encrypt(plain)
	if err != nil {
		f.t.Fatal(err)
	}
	return enc
}

func plainReply(w http.ResponseWriter, data any) {
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": data})
}

func newFakeRouter(t *testing.T, certs []string) (*httptest.Server, *fakeRouter) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRouter{
		key: key, certs: certs, seq: 576798567,
		username: "admin", password: "s3cr3t", stok: "deadbeef", t: t,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/cgi-bin/luci/", func(w http.ResponseWriter, r *http.Request) {
		nHex, eHex := f.keyHex()
		q := r.URL.Query()
		path := r.URL.Path

		switch {
		case strings.HasSuffix(path, ";stok=/device_config") && q.Get("form") == "config":
			plainReply(w, map[string]any{"certification": f.certs, "productModel": "Archer AX80"})

		case strings.HasSuffix(path, ";stok=/login") && q.Get("form") == "keys":
			// The real firmware adds unrelated scalars here.
			plainReply(w, map[string]any{
				"password": []string{nHex, eHex}, "mode": "router", "username": ""})

		case strings.HasSuffix(path, ";stok=/login") && q.Get("form") == "auth":
			plainReply(w, map[string]any{"key": []string{nHex, eHex}, "seq": f.seq})

		case strings.HasSuffix(path, ";stok=/login") && q.Get("form") == "login":
			f.handleLogin(w, r)

		case strings.Contains(path, ";stok="+f.stok+"/admin/dhcps") && q.Get("form") == "client":
			if body := f.unpackSession(r); body != "operation=load" {
				f.t.Fatalf("unexpected body %q", body)
			}
			f.ok(w, map[string]any{"dhcp_clients": []map[string]string{
				{"macaddr": "AA-BB-CC-DD-EE-FF", "ipaddr": "192.0.2.42", "name": "laptop", "leasetime": "01:59:12"},
			}})

		case strings.Contains(path, ";stok="+f.stok+"/admin/system") && q.Get("form") == "logout":
			if body := f.unpackSession(r); body != "" {
				f.t.Fatalf("logout should carry an empty body, got %q", body)
			}
			f.ok(w, nil)

		case strings.Contains(path, ";stok="+f.stok+"/admin/wireless") && q.Get("form") == "wireless_2g":
			f.unpackSession(r)
			f.ok(w, map[string]any{
				"ssid": "home", "psk_key": "hunter2hunter2", "psk_version": "wpa2"})

		case strings.Contains(path, ";stok="+f.stok+"/admin/stale"):
			// What a stok the firmware no longer honours comes back as.
			f.unpackSession(r)
			f.reply(w, map[string]any{"success": false, "errorCode": errSessionExpired})

		case strings.Contains(path, ";stok="+f.stok+"/admin/boom"):
			// 500 with a sealed body; the code inside beats the status.
			f.unpackSession(r)
			w.WriteHeader(http.StatusInternalServerError)
			f.reply(w, map[string]any{"success": false, "errorcode": "00000282"})

		// Matched on the whole path, not on a substring: forbidden and garbled are
		// prefixes of forbidden_code and garbled_500.
		case strings.HasSuffix(path, ";stok="+f.stok+"/admin/forbidden"):
			// 403 with nothing in the envelope to explain it.
			f.unpackSession(r)
			f.unsealed(w, http.StatusForbidden, map[string]any{"success": false})

		case strings.HasSuffix(path, ";stok="+f.stok+"/admin/forbidden_code"):
			// 403 the envelope does explain.
			f.unpackSession(r)
			f.unsealed(w, http.StatusForbidden,
				map[string]any{"success": false, "errorCode": "permission denied"})

		case strings.HasSuffix(path, ";stok="+f.stok+"/admin/garbled"):
			f.unpackSession(r)
			f.unsealed(w, http.StatusOK, map[string]any{"data": notCiphertext})

		case strings.HasSuffix(path, ";stok="+f.stok+"/admin/garbled_500"):
			// The same body under a server error.
			f.unpackSession(r)
			f.unsealed(w, http.StatusInternalServerError, map[string]any{"data": notCiphertext})

		case strings.HasSuffix(path, ";stok="+f.stok+"/admin/no_data"):
			// An unsealed reply with no payload. json.Unmarshal of null leaves the
			// string empty without reporting an error, and len("null") is 4.
			f.unpackSession(r)
			f.unsealed(w, http.StatusOK, map[string]any{"data": nil})

		case strings.HasSuffix(path, ";stok="+f.stok+"/admin/not_json"):
			// Decrypts with the session key; the plaintext is not an envelope.
			f.unpackSession(r)
			f.unsealed(w, http.StatusOK, map[string]any{"data": f.seal("not json")})

		default:
			f.unpackSession(r)
			f.reply(w, map[string]any{"success": false, "errorcode": "not supported"})
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, f
}

func (f *fakeRouter) handleLogin(w http.ResponseWriter, r *http.Request) {
	f.t.Helper()
	body := f.unpackLogin(r)
	if !strings.HasPrefix(body, "operation=login&password=") {
		f.t.Fatalf("unexpected login body %q", body)
	}
	forced := strings.HasSuffix(body, "&confirm=true")
	if f.busy && !forced {
		f.reply(w, map[string]any{"success": false, "errorCode": errUserConflict})
		return
	}

	enc := strings.TrimSuffix(strings.TrimPrefix(body, "operation=login&password="), "&confirm=true")
	raw, err := hex.DecodeString(enc)
	if err != nil {
		f.t.Fatalf("password is not hex: %v", err)
	}
	// PKCS#1 v1.5 even where the signature uses OAEP.
	got, err := rsa.DecryptPKCS1v15(nil, f.key, raw)
	if err != nil {
		f.t.Fatalf("password does not decrypt: %v", err)
	}
	if string(got) != f.password {
		f.t.Fatalf("password decrypted to %q, want %q", got, f.password)
	}
	http.SetCookie(w, &http.Cookie{Name: "sysauth", Value: "abc123", Path: "/"})
	f.ok(w, map[string]string{"stok": f.stok})
}

func runFlow(t *testing.T, certs []string) {
	t.Helper()
	srv, f := newFakeRouter(t, certs)

	c, err := New(srv.URL, f.username, f.password, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("login: %v", err)
	}
	if c.stok != f.stok {
		t.Fatalf("stok = %q, want %q", c.stok, f.stok)
	}
	if got, want := c.Features(), f.features(); got.SHA256Hash != want.SHA256Hash ||
		got.Encrypt != want.Encrypt || got.ReplaceHash != want.ReplaceHash || got.OAEP != want.OAEP {
		t.Fatalf("features = %+v, want %+v", got, want)
	}

	data, err := c.Call(context.Background(), "admin/dhcps?form=client", "load")
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	var out struct {
		Clients []struct {
			IP        string `json:"ipaddr"`
			Name      string `json:"name"`
			LeaseTime string `json:"leasetime"`
		} `json:"dhcp_clients"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("payload did not decode into JSON: %v (%s)", err, data)
	}
	if len(out.Clients) != 1 || out.Clients[0].IP != "192.0.2.42" || out.Clients[0].LeaseTime != "01:59:12" {
		t.Fatalf("unexpected payload: %+v", out)
	}

	if _, err := c.Call(context.Background(), "admin/nope?form=nope", "read"); err == nil {
		t.Fatal("expected an error for an unsupported endpoint")
	}
	if err := c.Logout(context.Background()); err != nil {
		t.Fatalf("logout: %v", err)
	}
}

// The AX80 as it ships: SHA-256 hash, AES bodies, OAEP login signature and
// per-request hash replacement.
func TestEndToEndSGCertified(t *testing.T) {
	runFlow(t, []string{CertSGL1S2})
}

// Firmware advertising nothing relevant: plain form bodies, plain replies.
func TestEndToEndUncertified(t *testing.T) {
	runFlow(t, []string{CertFCC})
}

func TestLoginEvictsExistingSessionOnlyWhenForced(t *testing.T) {
	for _, tc := range []struct {
		name  string
		force bool
	}{{"refuses", false}, {"evicts", true}} {
		t.Run(tc.name, func(t *testing.T) {
			srv, f := newFakeRouter(t, []string{CertSGL1S2})
			f.busy = true

			c, err := New(srv.URL, f.username, f.password, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			c.Force = tc.force

			err = c.Login(context.Background())
			if tc.force {
				if err != nil {
					t.Fatalf("forced login should have succeeded: %v", err)
				}
				return
			}
			// Must be matchable, not just readable: a poller branches on it.
			if !errors.Is(err, ErrSessionBusy) {
				t.Fatalf("expected ErrSessionBusy, got %v", err)
			}
		})
	}
}

// A live PSK must not survive Call, whatever the caller does with the payload.
func TestCallNeverReturnsSecrets(t *testing.T) {
	srv, f := newFakeRouter(t, []string{CertSGL1S2})
	c, err := New(srv.URL, f.username, f.password, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := c.Call(context.Background(), "admin/wireless?form=wireless_2g", "read")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "hunter2hunter2") {
		t.Fatalf("the Wi-Fi key reached the caller: %s", data)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["psk_key"] != Mask {
		t.Fatalf("psk_key = %v, want %q", got["psk_key"], Mask)
	}
	if got["ssid"] != "home" || got["psk_version"] != "wpa2" {
		t.Fatalf("recon value was lost: %v", got)
	}
}

// A sealed non-200 must be reported by its errorcode, not echoed as ciphertext.
func TestSealedErrorOnNon200(t *testing.T) {
	srv, f := newFakeRouter(t, []string{CertSGL1S2})
	c, err := New(srv.URL, f.username, f.password, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err = c.Call(context.Background(), "admin/boom?form=x", "read")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "00000282") {
		t.Fatalf("error should carry the router's code, got %v", err)
	}
	if strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("the code beats the status once the body is readable, got %v", err)
	}
}

// Two sentinels split what the UI lumps together as a dead session, because a
// poller can act on the difference: a session really gone takes every later
// endpoint with it, one unreadable reply takes one endpoint. Every case below
// must land in exactly one class, so both are asserted every time.
func TestCallReportsAnExpiredSession(t *testing.T) {
	for _, tc := range []struct {
		name       string
		path       string
		expired    bool
		unreadable bool
	}{
		{name: "errorCode timeout", path: "admin/stale?form=x", expired: true},
		{name: "any other errorcode", path: "admin/nope?form=nope"},
		{name: "sealed error on a non-200", path: "admin/boom?form=x"},
		{name: "403 with no readable errorCode", path: "admin/forbidden?form=x", expired: true},
		{name: "403 carrying an errorCode", path: "admin/forbidden_code?form=x"},
		{name: "reply will not decrypt", path: "admin/garbled?form=x", unreadable: true},
		{name: `{"data":null}`, path: "admin/no_data?form=x"},
		{name: "500 with an undecryptable body", path: "admin/garbled_500?form=x"},
		{name: "decrypts, plaintext is not JSON", path: "admin/not_json?form=x", unreadable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, f := newFakeRouter(t, []string{CertSGL1S2})
			c, err := New(srv.URL, f.username, f.password, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Login(context.Background()); err != nil {
				t.Fatal(err)
			}

			_, err = c.Call(context.Background(), tc.path, "read")
			if err == nil {
				t.Fatal("expected an error")
			}
			expired, unreadable := errors.Is(err, ErrSessionExpired), errors.Is(err, ErrReplyUnreadable)
			if expired != tc.expired || unreadable != tc.unreadable {
				t.Fatalf("%v\n  errors.Is ErrSessionExpired  = %v, want %v\n  errors.Is ErrReplyUnreadable = %v, "+
					"want %v\nThe session is gone on errorCode %q and on an HTTP 403 the envelope does not "+
					"explain. A reply is unreadable when it will not decrypt under HTTP 200, or decrypts into "+
					"something that is not JSON. Everything else — any other errorCode, a sealed or an "+
					"undecryptable body on a non-200, and a reply carrying no payload at all — is a plain error.",
					err, expired, tc.expired, unreadable, tc.unreadable, errSessionExpired)
			}
		})
	}
}

// The keys object carries scalars next to the pair, so it cannot be decoded as
// map[string][]string. This is the bug that started the rewrite.
func TestFetchKeyIgnoresExtraScalars(t *testing.T) {
	srv, f := newFakeRouter(t, []string{CertSGL1S2})
	c, err := New(srv.URL, f.username, f.password, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.fetchFeatures(context.Background()); err != nil {
		t.Fatal(err)
	}
	k, err := c.fetchKey(context.Background(), "keys", "password")
	if err != nil {
		t.Fatalf("fetchKey: %v", err)
	}
	if k.N.Cmp(f.key.N) != 0 {
		t.Fatal("wrong modulus")
	}
	if k.N.BitLen() != 2048 {
		t.Fatalf("expected a 2048-bit modulus, got %d", k.N.BitLen())
	}
}

func TestFetchKeyMissingFieldNamesWhatArrived(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainReply(w, map[string]any{"mode": "router", "username": ""})
	}))
	t.Cleanup(srv.Close)

	c, _ := New(srv.URL, "admin", "x", 5*time.Second)
	_, err := c.fetchKey(context.Background(), "keys", "password")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "mode") || !strings.Contains(err.Error(), "username") {
		t.Fatalf("error should list the fields that did arrive, got %v", err)
	}
}
