package tpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"time"
)

type Client struct {
	Host     string // e.g. http://192.168.0.1
	Username string
	Password string
	Debug    bool

	// Force sends confirm=true on "user conflict", evicting the other session.
	// The UI does the same after asking.
	Force bool

	http     *http.Client
	cipher   *Cipher
	signKey  *PubKey
	features Features
	seq      int64
	hash     string
	stok     string
}

func New(host, username, password string, timeout time.Duration) (*Client, error) {
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "http://" + host
	}
	host = strings.TrimRight(host, "/")

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	c, err := NewCipher()
	if err != nil {
		return nil, err
	}
	return &Client{
		Host:     host,
		Username: username,
		Password: password,
		http:     &http.Client{Jar: jar, Timeout: timeout},
		cipher:   c,
	}, nil
}

// Features reports what the device said about itself during Login.
func (c *Client) Features() Features { return c.features }

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

// reqMode picks how a request is sealed. The firmware keeps a NO_ENCRYPT_URL
// list (the bootstrap endpoints are on it) and signs login differently from
// everything after.
type reqMode int

const (
	modePlain   reqMode = iota // raw form body, plain reply
	modeLogin                  // AES body + RSA signature carrying the AES key
	modeSession                // AES body + HMAC signature
)

// envelope is the reply wrapper. The error field has four spellings across
// endpoints; formatResponse in the UI accepts all of them.
type envelope struct {
	Success      bool            `json:"success"`
	ErrorCode    json.RawMessage `json:"errorCode"`
	ErrorCodeAlt json.RawMessage `json:"errorcode"`
	Error        json.RawMessage `json:"error"`
	ErrorSnake   json.RawMessage `json:"error_code"`
	Data         json.RawMessage `json:"data"`
}

func (e *envelope) errCode() string {
	for _, raw := range []json.RawMessage{e.ErrorCode, e.Error, e.ErrorSnake, e.ErrorCodeAlt} {
		s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
		if s != "" && s != "null" {
			return s
		}
	}
	return "unspecified"
}

// rawPost does not judge the status: error replies are sealed too, so a 500
// still carries a readable envelope once decrypted.
func (c *Client) rawPost(ctx context.Context, rawURL, body string) ([]byte, int, error) {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Referer", c.Host+"/webpages/index.html")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if c.Debug {
		fmt.Printf("  <- %d %s\n", resp.StatusCode, truncate(string(raw), 200))
	}
	return raw, resp.StatusCode, nil
}

// call sends one request and returns the decrypted envelope. With encryption
// on the reply body is only {"data":"<base64>"} whose plaintext is the real
// envelope, so even success cannot be read before decrypting.
func (c *Client) call(ctx context.Context, rawURL, body string, mode reqMode) (*envelope, error) {
	if !c.features.Encrypt {
		mode = modePlain
	}

	wire := body
	if mode != modePlain {
		data, err := c.cipher.Encrypt(body)
		if err != nil {
			return nil, err
		}
		// Replaced before signing; the new hash sticks for later requests too.
		if mode == modeSession && c.features.ReplaceHash && c.stok != "" {
			c.hash = DataHash(data)
		}
		var sign string
		if mode == modeLogin {
			sign, err = LoginSignature(c.signKey, c.cipher, c.hash, c.seq+int64(len(data)), c.features.OAEP)
			if err != nil {
				return nil, err
			}
		} else {
			sign = SessionSignature(c.cipher, c.hash, c.seq+int64(len(data)))
		}
		// sign before data, as the UI posts them
		wire = "sign=" + url.QueryEscape(sign) + "&data=" + url.QueryEscape(data)
	}

	if c.Debug {
		fmt.Printf("  -> POST %s  body=%q\n", rawURL, body)
	}
	raw, status, err := c.rawPost(ctx, rawURL, wire)
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("HTTP %d, reply is not JSON: %s", status, truncate(string(raw), 200))
	}
	if mode == modePlain {
		return &env, httpErr(status, &env)
	}

	var blob string
	// Some errors come back unsealed, and an unsealed reply with no payload is
	// {"data":null} — which unmarshals into a string without complaint.
	if len(env.Data) == 0 || json.Unmarshal(env.Data, &blob) != nil || blob == "" {
		return &env, httpErr(status, &env)
	}
	plain, err := c.cipher.Decrypt(blob)
	if err != nil {
		// The UI never decrypts a non-2xx at all: axios rejects it first, and a
		// 500 gets an error toast rather than a trip to the login page.
		if status != http.StatusOK {
			return &env, httpErr(status, &env)
		}
		return nil, fmt.Errorf("HTTP %d, decrypt reply (%v): %w", status, err, ErrReplyUnreadable)
	}
	var inner envelope
	if err := json.Unmarshal([]byte(plain), &inner); err != nil {
		// Not echoed: it decrypted fine, so it is real router data, and unparsed
		// data cannot be redacted field by field. A wrong IV against the right
		// key lands here rather than above, so it classifies the same way.
		return nil, fmt.Errorf("HTTP %d, decrypted reply is not JSON (%d bytes): %w",
			status, len(plain), ErrReplyUnreadable)
	}
	return &inner, httpErr(status, &inner)
}

// httpErr surfaces a non-200 only when the envelope says nothing: the router's
// errorcode is the better message.
func httpErr(status int, env *envelope) error {
	if status == http.StatusOK {
		return nil
	}
	if env != nil && !env.Success && env.errCode() != "unspecified" {
		return nil
	}
	// 403 is the transport-level half of a dead session; the UI drops its keys
	// and returns to the login page on it, exactly as it does on "timeout".
	if status == http.StatusForbidden {
		return fmt.Errorf("HTTP 403: %w", ErrSessionExpired)
	}
	return fmt.Errorf("HTTP %d", status)
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

// errUserConflict is the errorCode the router returns when someone else already
// holds the single web session.
const errUserConflict = "user conflict"

// ErrSessionBusy reports the router's one web session is taken, usually by a
// browser tab. A sentinel so a poller can tell it from "router unreachable" and
// back off instead of evicting the user.
//
// The firmware defends a session against other devices, not against other
// sessions: a login from the address that already holds one replaces it in
// silence, with no user conflict and no warning in the UI. Measured on an AX80.
var ErrSessionBusy = errors.New("another web session is already open on the router")

// errSessionExpired is the errorCode for a stok the router no longer honours,
// and the only value the UI compares an errorCode against.
const errSessionExpired = "timeout"

// ErrSessionExpired reports the session died: idle timeout, reboot, or eviction
// by the next login, which the firmware does not distinguish. Reported for
// errorCode "timeout" and for HTTP 403, the two the UI answers by dropping its
// keys and returning to the login page. Derived from the UI, not observed: none
// of the 164 sweep entries carries either.
var ErrSessionExpired = errors.New("the router no longer accepts this session")

// ErrReplyUnreadable reports a reply that could not be turned back into JSON:
// it would not decrypt, or the plaintext was not JSON. The UI calls both a dead
// session because it has nowhere else to go. A caller does: a session really
// gone takes every later endpoint with it, while one unreadable reply is one
// endpoint, and treating it as a lost session costs a login nobody needed.
var ErrReplyUnreadable = errors.New("the reply could not be decoded")

func (c *Client) Login(ctx context.Context) error {
	if err := c.fetchFeatures(ctx); err != nil {
		return fmt.Errorf("read device config: %w", err)
	}
	pwdKey, err := c.fetchKey(ctx, "keys", "password")
	if err != nil {
		return fmt.Errorf("fetch password key: %w", err)
	}
	if err := c.fetchAuth(ctx); err != nil {
		return fmt.Errorf("fetch auth key: %w", err)
	}

	// The UI hardcodes "admin"; the local login has no user name field.
	c.hash = CredHash(c.Username, c.Password, c.features.SHA256Hash)

	cryptedPwd, err := pwdKey.EncryptPKCS1v15(c.Password)
	if err != nil {
		return fmt.Errorf("encrypt password: %w", err)
	}

	loginURL := c.Host + "/cgi-bin/luci/;stok=/login?form=login"
	body := "operation=login&password=" + cryptedPwd

	env, err := c.call(ctx, loginURL, body, modeLogin)
	if err != nil {
		return err
	}
	if !env.Success && env.errCode() == errUserConflict {
		if !c.Force {
			return fmt.Errorf("%w (close the browser tab, or set Force to evict it)", ErrSessionBusy)
		}
		fmt.Println("another web session was open; evicting it")
		if env, err = c.call(ctx, loginURL, body+"&confirm=true", modeLogin); err != nil {
			return err
		}
	}
	if !env.Success {
		return fmt.Errorf("login rejected: %s", env.errCode())
	}

	var out struct {
		Stok string `json:"stok"`
	}
	if err := json.Unmarshal(env.Data, &out); err != nil || out.Stok == "" {
		// Name the fields, not the payload: stok is itself a session credential.
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(env.Data, &fields)
		return fmt.Errorf("no stok in login response; fields: %s", strings.Join(sortedKeys(fields), ", "))
	}
	c.stok = out.Stok
	return nil
}

// fetchFeatures reads the certification list that decides the encoding below.
// Unauthenticated and unencrypted; firmware without the endpoint falls back to
// all-false, same as the UI.
func (c *Client) fetchFeatures(ctx context.Context) error {
	env, err := c.call(ctx, c.Host+"/cgi-bin/luci/;stok=/device_config?form=config", "operation=read", modePlain)
	if err != nil {
		return err
	}
	var d struct {
		Certification []string `json:"certification"`
	}
	if len(env.Data) > 0 {
		_ = json.Unmarshal(env.Data, &d)
	}
	c.features = FeaturesFor(d.Certification)
	return nil
}

func (c *Client) fetchKey(ctx context.Context, form, field string) (*PubKey, error) {
	u := fmt.Sprintf("%s/cgi-bin/luci/;stok=/login?form=%s", c.Host, form)
	env, err := c.call(ctx, u, "operation=read", modePlain)
	if err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, fmt.Errorf("router refused: %s", env.errCode())
	}
	// The object carries unrelated scalars beside the key pair ("mode",
	// "username"), so pick out one field rather than decoding the whole map.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(env.Data, &fields); err != nil {
		return nil, fmt.Errorf("expected an object, got %s", truncate(string(env.Data), 160))
	}
	raw, ok := fields[field]
	if !ok {
		return nil, fmt.Errorf("no %q field; got %s", field, strings.Join(sortedKeys(fields), ", "))
	}
	var pair []string
	if err := json.Unmarshal(raw, &pair); err != nil || len(pair) < 2 {
		return nil, fmt.Errorf("%q is not a [modulus, exponent] pair: %s", field, truncate(string(raw), 160))
	}
	return ParsePubKey(pair[0], pair[1])
}

func (c *Client) fetchAuth(ctx context.Context) error {
	u := c.Host + "/cgi-bin/luci/;stok=/login?form=auth"
	env, err := c.call(ctx, u, "operation=read", modePlain)
	if err != nil {
		return err
	}
	if !env.Success {
		return fmt.Errorf("router refused: %s", env.errCode())
	}
	var d struct {
		Seq int64    `json:"seq"`
		Key []string `json:"key"`
	}
	if err := json.Unmarshal(env.Data, &d); err != nil {
		return fmt.Errorf("unexpected shape: %s", truncate(string(env.Data), 160))
	}
	if len(d.Key) < 2 {
		return fmt.Errorf("no [modulus, exponent] pair in auth response: %s", truncate(string(env.Data), 160))
	}
	k, err := ParsePubKey(d.Key[0], d.Key[1])
	if err != nil {
		return err
	}
	c.signKey, c.seq = k, d.Seq
	return nil
}

// ---------------------------------------------------------------------------
// Authenticated requests
// ---------------------------------------------------------------------------

// Call issues one authenticated request. path is everything after the stok,
// e.g. "admin/dhcps?form=client"; operation is typically read / load / list.
func (c *Client) Call(ctx context.Context, path, operation string) (json.RawMessage, error) {
	if c.stok == "" {
		return nil, errors.New("not logged in")
	}
	u := fmt.Sprintf("%s/cgi-bin/luci/;stok=%s/%s", c.Host, c.stok, path)
	env, err := c.call(ctx, u, "operation="+operation, modeSession)
	if err != nil {
		return nil, err
	}
	if !env.Success {
		// The UI also treats HTTP 403 as a dead session; call keeps only the
		// envelope's code once there is one, so that path is not covered here.
		if env.errCode() == errSessionExpired {
			return nil, fmt.Errorf("%s: %w", path, ErrSessionExpired)
		}
		return nil, fmt.Errorf("errorcode=%s", env.errCode())
	}
	// Masked here, not at the writer, so no caller can leak a PSK. See redact.go.
	return Redact(env.Data), nil
}

// Logout frees the router's single web session. The UI sends no body at all,
// so the payload is an encrypted empty string.
func (c *Client) Logout(ctx context.Context) error {
	if c.stok == "" {
		return nil
	}
	u := fmt.Sprintf("%s/cgi-bin/luci/;stok=%s/admin/system?form=logout", c.Host, c.stok)
	_, err := c.call(ctx, u, "", modeSession)
	c.stok = ""
	return err
}

func sortedKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
