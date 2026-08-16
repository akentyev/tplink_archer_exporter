package tpapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

func TestAESRoundTrip(t *testing.T) {
	c, err := NewCipher()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Key) != 16 || len(c.IV) != 16 {
		t.Fatalf("key/iv must be 16 ASCII bytes, got %d/%d", len(c.Key), len(c.IV))
	}
	// generateRandomIntString emits digits, not hex, and the router reads the
	// key back out of the signature, so the alphabet must match.
	for _, b := range append(append([]byte{}, c.Key...), c.IV...) {
		if b < '0' || b > '9' {
			t.Fatalf("key/iv must be decimal digits, saw %q", b)
		}
	}

	const plain = "operation=read"
	enc, err := c.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(enc)
	// "operation=read" is 14 bytes, so PKCS#7 pads it to exactly one block.
	if len(raw) != 16 {
		t.Fatalf("expected one 16-byte block, got %d", len(raw))
	}
	if len(enc) != 24 {
		t.Fatalf("expected 24 base64 chars (cf. RX+zVWhOOOeGbtMCIT2/pg==), got %d", len(enc))
	}

	back, err := c.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if back != plain {
		t.Fatalf("round trip: got %q", back)
	}
}

// Logout carries no body, so the empty string must survive as one padding block.
func TestAESEmptyBody(t *testing.T) {
	c, _ := NewCipher()
	enc, err := c.Encrypt("")
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := base64.StdEncoding.DecodeString(enc); len(raw) != 16 {
		t.Fatalf("expected one padding block, got %d bytes", len(raw))
	}
	back, err := c.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if back != "" {
		t.Fatalf("got %q, want empty", back)
	}
}

func TestAESRejectsGarbage(t *testing.T) {
	c, _ := NewCipher()
	if _, err := c.Decrypt("Ml48QjvcV9noPpGtL+Bc2xoAs2LarTFV1qJCctKgDTmc0EzyV4LFm5Jc8MvGA8grHxrs77hOnHGXuu9gtDk8UA=="); err == nil {
		t.Fatal("decrypting someone else's blob with our key should fail padding")
	}
	if _, err := c.Decrypt(""); err == nil {
		t.Fatal("an empty ciphertext is not a valid one")
	}
}

func TestFormattedKey(t *testing.T) {
	c := &Cipher{Key: []byte("0123456789012345"), IV: []byte("5432109876543210")}
	if got, want := c.FormattedKey(), "k=0123456789012345&i=5432109876543210"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// gen512 builds a real 512-bit RSA key. crypto/rsa refuses anything under 1024
// bits, which is why PubKey keeps a hand-rolled v1.5 path — and why this test
// rolls its own key.
func gen512(t *testing.T) (n, e, d *big.Int) {
	t.Helper()
	e = big.NewInt(65537)
	for {
		p, err := rand.Prime(rand.Reader, 256)
		if err != nil {
			t.Fatal(err)
		}
		q, err := rand.Prime(rand.Reader, 256)
		if err != nil {
			t.Fatal(err)
		}
		if p.Cmp(q) == 0 {
			continue
		}
		n = new(big.Int).Mul(p, q)
		if n.BitLen() != 512 {
			continue
		}
		phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
		if new(big.Int).GCD(nil, nil, e, phi).Cmp(big.NewInt(1)) != 0 {
			continue
		}
		d = new(big.Int).ModInverse(e, phi)
		return n, e, d
	}
}

// Long enough to span several 53-char chunks.
func sampleSignPlaintext() string {
	return "k=0123456789012345&i=5432109876543210&h=" + strings.Repeat("a", 64) + "&s=576798591"
}

func TestSmallKeyPKCS1v15(t *testing.T) {
	n, e, d := gen512(t)
	pub, err := ParsePubKey(n.Text(16), e.Text(16))
	if err != nil {
		t.Fatal(err)
	}
	if pub.byteLen() != 64 {
		t.Fatalf("expected a 64-byte modulus, got %d", pub.byteLen())
	}

	msg := sampleSignPlaintext()
	out, err := LoginSignature(pub, &Cipher{Key: []byte("0123456789012345"), IV: []byte("5432109876543210")},
		strings.Repeat("a", 64), 576798591, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := ((len(msg) + signatureChunk - 1) / signatureChunk) * 64 * 2; len(out) != want {
		t.Fatalf("expected %d hex chars, got %d", want, len(out))
	}

	raw, err := hex.DecodeString(out)
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	for i := 0; i < len(raw); i += 64 {
		m := new(big.Int).Exp(new(big.Int).SetBytes(raw[i:i+64]), d, n)
		em := make([]byte, 64)
		m.FillBytes(em)
		if em[0] != 0x00 || em[1] != 0x02 {
			t.Fatalf("block %d: bad PKCS#1 header %x %x", i/64, em[0], em[1])
		}
		sep := bytes.IndexByte(em[2:], 0x00)
		if sep < 8 {
			t.Fatalf("block %d: padding string too short (%d)", i/64, sep)
		}
		got.Write(em[2+sep+1:])
	}
	if got.String() != msg {
		t.Fatalf("round trip mismatch:\n got %q\nwant %q", got.String(), msg)
	}
}

// The AX80's key size, with node-rsa's default padding.
func TestLoginSignatureOAEP(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePubKey(key.N.Text(16), "010001")
	if err != nil {
		t.Fatal(err)
	}
	c := &Cipher{Key: []byte("0123456789012345"), IV: []byte("5432109876543210")}

	out, err := LoginSignature(pub, c, strings.Repeat("a", 64), 576798591, true)
	if err != nil {
		t.Fatal(err)
	}
	msg := sampleSignPlaintext()
	blocks := (len(msg) + signatureChunk - 1) / signatureChunk
	if want := blocks * 256 * 2; len(out) != want {
		t.Fatalf("expected %d hex chars over %d blocks, got %d", want, blocks, len(out))
	}

	raw, err := hex.DecodeString(out)
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	for i := 0; i < len(raw); i += 256 {
		part, err := rsa.DecryptOAEP(sha1.New(), nil, key, raw[i:i+256], nil)
		if err != nil {
			t.Fatalf("block %d: %v", i/256, err)
		}
		got.Write(part)
	}
	if got.String() != msg {
		t.Fatalf("round trip mismatch:\n got %q\nwant %q", got.String(), msg)
	}
}

// After login: one HMAC-SHA256 per 53-char chunk, keyed with "k=...&i=...",
// hex-concatenated. No RSA.
func TestSessionSignature(t *testing.T) {
	c := &Cipher{Key: []byte("0123456789012345"), IV: []byte("5432109876543210")}
	hash := strings.Repeat("a", 64)
	plain := "h=" + hash + "&s=576798591"
	if len(plain) <= signatureChunk {
		t.Fatalf("test message should span more than one chunk, got %d", len(plain))
	}

	got := SessionSignature(c, hash, 576798591)
	var want strings.Builder
	for i := 0; i < len(plain); i += signatureChunk {
		end := i + signatureChunk
		if end > len(plain) {
			end = len(plain)
		}
		m := hmac.New(sha256.New, []byte(c.FormattedKey()))
		m.Write([]byte(plain[i:end]))
		want.WriteString(hex.EncodeToString(m.Sum(nil)))
	}
	if got != want.String() {
		t.Fatalf("got %s, want %s", got, want.String())
	}
	if n := ((len(plain) + signatureChunk - 1) / signatureChunk) * 64; len(got) != n {
		t.Fatalf("expected %d hex chars, got %d", n, len(got))
	}
}

func TestCredHash(t *testing.T) {
	// md5("admin" + "password")
	const wantMD5 = "e3274be5c857fb42ab72d786e281b4b8"
	if h := CredHash("admin", "password", false); h != wantMD5 {
		t.Fatalf("md5: got %q, want %q", h, wantMD5)
	}
	// sha256("admin" + "password")
	sum := sha256.Sum256([]byte("adminpassword"))
	if h, want := CredHash("admin", "password", true), hex.EncodeToString(sum[:]); h != want {
		t.Fatalf("sha256: got %q, want %q", h, want)
	}
}

func TestDataHash(t *testing.T) {
	sum := sha256.Sum256([]byte("RX+zVWhOOOeGbtMCIT2/pg=="))
	if got, want := DataHash("RX+zVWhOOOeGbtMCIT2/pg=="), hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestParsePubKeyRejectsJunk(t *testing.T) {
	for _, tc := range []struct{ n, e string }{
		{"", "010001"},
		{"zz", "010001"},
		{"c5", ""},
		{"c5", "0"},
	} {
		if _, err := ParsePubKey(tc.n, tc.e); err == nil {
			t.Fatalf("ParsePubKey(%q, %q) should have failed", tc.n, tc.e)
		}
	}
}

// The AX80 hands out uppercase hex; the padStart width comes from the string
// the router sent.
func TestPubKeyPadsToRouterHexWidth(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePubKey(strings.ToUpper(key.N.Text(16)), "010001")
	if err != nil {
		t.Fatal(err)
	}
	out, err := pub.EncryptPKCS1v15("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 512 {
		t.Fatalf("expected 512 hex chars, got %d", len(out))
	}
	raw, err := hex.DecodeString(out)
	if err != nil {
		t.Fatal(err)
	}
	back, err := rsa.DecryptPKCS1v15(nil, key, raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != "hunter2" {
		t.Fatalf("got %q", back)
	}
}

func TestFeaturesFor(t *testing.T) {
	sg := FeaturesFor([]string{CertSGL1S2})
	if !sg.SHA256Hash || !sg.Encrypt || !sg.ReplaceHash || !sg.OAEP {
		t.Fatalf("SG CLS L1 STAGE2 should enable everything, got %+v", sg)
	}
	red := FeaturesFor([]string{CertCERED})
	if !red.SHA256Hash || !red.Encrypt {
		t.Fatalf("EU CE RED should encrypt and use sha256, got %+v", red)
	}
	if red.ReplaceHash || red.OAEP {
		t.Fatalf("EU CE RED should not replace the hash or use OAEP, got %+v", red)
	}
	for _, certs := range [][]string{nil, {}, {CertFCC}, {CertCE, CertKC}} {
		if f := FeaturesFor(certs); f.SHA256Hash || f.Encrypt || f.ReplaceHash || f.OAEP {
			t.Fatalf("%v should enable nothing, got %+v", certs, f)
		}
	}
	if f := FeaturesFor([]string{CertRG}); !f.SHA256Hash || f.Encrypt {
		t.Fatalf("IMDA RG-SEC is sha256 but not gdpr, got %+v", f)
	}
}
