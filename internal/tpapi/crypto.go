package tpapi

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

// Mirrors the router's webpages/js bundle: AES and RSA helpers in the
// "update-store" chunk, login flow in "index-J8_BmDcf". Names below refer to it.

// ---------------------------------------------------------------------------
// AES
// ---------------------------------------------------------------------------

const aesKeyLen = 16 // KEY_LEN = 128/8, IV_LEN = 16

// Cipher is the per-session AES-128-CBC key and IV.
//
// generateRandomIntString builds both as 16 decimal digits whose ASCII bytes
// are the key. That is 10^16 of key space, not 2^128, but the router reads the
// key back out of the login signature and expects exactly this.
type Cipher struct {
	Key []byte // 16 ASCII digits
	IV  []byte // 16 ASCII digits
}

func NewCipher() (*Cipher, error) {
	k, err := randomDigits(aesKeyLen)
	if err != nil {
		return nil, err
	}
	iv, err := randomDigits(aesKeyLen)
	if err != nil {
		return nil, err
	}
	return &Cipher{Key: k, IV: iv}, nil
}

func randomDigits(n int) ([]byte, error) {
	out := make([]byte, n)
	for i := range out {
		v, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return nil, err
		}
		out[i] = byte('0' + v.Int64())
	}
	return out, nil
}

// FormattedKey is AES.getFormattedKey(): carried in the login signature, then
// used as the HMAC key for every later request.
func (c *Cipher) FormattedKey() string {
	return fmt.Sprintf("k=%s&i=%s", c.Key, c.IV)
}

func pkcs7Pad(b []byte, blockSize int) []byte {
	n := blockSize - len(b)%blockSize
	return append(b, bytes.Repeat([]byte{byte(n)}, n)...)
}

func pkcs7Unpad(b []byte, blockSize int) ([]byte, error) {
	if len(b) == 0 || len(b)%blockSize != 0 {
		return nil, fmt.Errorf("bad padded length %d", len(b))
	}
	n := int(b[len(b)-1])
	if n == 0 || n > blockSize || n > len(b) {
		return nil, fmt.Errorf("bad padding byte %d", n)
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, errors.New("inconsistent padding")
		}
	}
	return b[:len(b)-n], nil
}

// Encrypt returns base64(AES-128-CBC(PKCS7(plain))).
func (c *Cipher) Encrypt(plain string) (string, error) {
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return "", err
	}
	src := pkcs7Pad([]byte(plain), aes.BlockSize)
	dst := make([]byte, len(src))
	cipher.NewCBCEncrypter(block, c.IV).CryptBlocks(dst, src)
	return base64.StdEncoding.EncodeToString(dst), nil
}

// Decrypt reverses Encrypt.
func (c *Cipher) Decrypt(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("base64: %w", err)
	}
	if len(raw) == 0 || len(raw)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext length %d is not a positive multiple of %d", len(raw), aes.BlockSize)
	}
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return "", err
	}
	dst := make([]byte, len(raw))
	cipher.NewCBCDecrypter(block, c.IV).CryptBlocks(dst, raw)
	out, err := pkcs7Unpad(dst, aes.BlockSize)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// ---------------------------------------------------------------------------
// RSA
//
// Two 2048-bit moduli, uppercase hex: login?form=keys for the password,
// login?form=auth for the signature. Padding depends on the caller, not the key:
//
//	RSA.encrypt(pw, n, e)  -> jsbn pkcs1pad2, PKCS#1 v1.5   (password)
//	rsa.encrypt(chunk)     -> node-rsa default, OAEP-SHA1   (signature)
//
// OAEP only when the device advertises 13_rsa_pad_with_pkcs1_oaep.
// ---------------------------------------------------------------------------

type PubKey struct {
	N *big.Int
	E *big.Int

	hexLen int // width of the modulus hex the router sent, for padStart parity
}

func ParsePubKey(nHex, eHex string) (*PubKey, error) {
	nHex, eHex = strings.TrimSpace(nHex), strings.TrimSpace(eHex)
	n, ok := new(big.Int).SetString(nHex, 16)
	if !ok || n.Sign() <= 0 {
		return nil, fmt.Errorf("bad modulus hex %q", nHex)
	}
	e, ok := new(big.Int).SetString(eHex, 16)
	if !ok || e.Sign() <= 0 || !e.IsInt64() || e.Int64() > math.MaxInt32 {
		return nil, fmt.Errorf("bad exponent hex %q", eHex)
	}
	return &PubKey{N: n, E: e, hexLen: len(nHex)}, nil
}

func (p *PubKey) byteLen() int { return (p.N.BitLen() + 7) / 8 }

func (p *PubKey) pub() *rsa.PublicKey {
	return &rsa.PublicKey{N: p.N, E: int(p.E.Int64())}
}

// padHex reproduces RSA.encrypt's padStart(max(len(nHex), len(out)), "0").
func (p *PubKey) padHex(s string) string {
	if len(s) < p.hexLen {
		return strings.Repeat("0", p.hexLen-len(s)) + s
	}
	return s
}

// EncryptPKCS1v15 is the jsbn path: login password always, login signature on
// devices without the OAEP feature.
func (p *PubKey) EncryptPKCS1v15(msg string) (string, error) {
	var (
		ct  []byte
		err error
	)
	if p.N.BitLen() >= 1024 {
		ct, err = rsa.EncryptPKCS1v15(rand.Reader, p.pub(), []byte(msg))
	} else {
		// crypto/rsa refuses moduli under 1024 bits; older Archers hand out 512.
		ct, err = p.encryptSmallPKCS1v15([]byte(msg))
	}
	if err != nil {
		return "", err
	}
	return p.padHex(hex.EncodeToString(ct)), nil
}

// EncryptOAEP is the node-rsa path for the login signature: OAEP with SHA-1 as
// both digest and MGF1 hash, empty label.
func (p *PubKey) EncryptOAEP(msg string) (string, error) {
	ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, p.pub(), []byte(msg), nil)
	if err != nil {
		return "", err
	}
	return p.padHex(hex.EncodeToString(ct)), nil
}

func (p *PubKey) encryptSmallPKCS1v15(msg []byte) ([]byte, error) {
	k := p.byteLen()
	if len(msg) > k-11 {
		return nil, fmt.Errorf("message of %d bytes too long for %d-byte key", len(msg), k)
	}
	em := make([]byte, k)
	em[0] = 0x00
	em[1] = 0x02
	ps := em[2 : k-len(msg)-1]
	for i := range ps { // PS must be non-zero random bytes
		for {
			var b [1]byte
			if _, err := rand.Read(b[:]); err != nil {
				return nil, err
			}
			if b[0] != 0 {
				ps[i] = b[0]
				break
			}
		}
	}
	em[k-len(msg)-1] = 0x00
	copy(em[k-len(msg):], msg)

	c := new(big.Int).Exp(new(big.Int).SetBytes(em), p.E, p.N)
	out := make([]byte, k)
	c.FillBytes(out)
	return out, nil
}

// ---------------------------------------------------------------------------
// Hashes and signatures
// ---------------------------------------------------------------------------

// CredHash is the h= field of the login signature. The UI hardcodes the user
// name "admin"; SHA-256 replaces MD5 when the device advertises 2_login_SHA256.
func CredHash(username, password string, sha256Hash bool) string {
	s := username + password
	if sha256Hash {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])
	}
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// DataHash is the replacement h= under 12_replace_hash: SHA-256 of the base64
// payload, which then sticks for later requests too.
func DataHash(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

// signatureChunk is Encryptor.SIGNATURE_OFFSET: the plaintext is cut into
// 53-character pieces, each sealed separately. A flat constant, not derived
// from the key size.
const signatureChunk = 53

// LoginSignature seals "k=<key>&i=<iv>&h=<hash>&s=<seq+len(data)>" with RSA.
// The only request carrying the AES key; the router remembers it afterwards.
func LoginSignature(key *PubKey, c *Cipher, hash string, s int64, oaep bool) (string, error) {
	plain := fmt.Sprintf("%s&h=%s&s=%d", c.FormattedKey(), hash, s)
	var sb strings.Builder
	for _, part := range chunk(plain, signatureChunk) {
		var (
			out string
			err error
		)
		if oaep {
			out, err = key.EncryptOAEP(part)
		} else {
			out, err = key.EncryptPKCS1v15(part)
		}
		if err != nil {
			return "", err
		}
		sb.WriteString(out)
	}
	return sb.String(), nil
}

// SessionSignature seals "h=<hash>&s=<seq+len(data)>" after login. No RSA:
// each chunk is an HMAC-SHA256 keyed with the "k=...&i=..." string.
func SessionSignature(c *Cipher, hash string, s int64) string {
	plain := fmt.Sprintf("h=%s&s=%d", hash, s)
	var sb strings.Builder
	for _, part := range chunk(plain, signatureChunk) {
		m := hmac.New(sha256.New, []byte(c.FormattedKey()))
		m.Write([]byte(part))
		sb.WriteString(hex.EncodeToString(m.Sum(nil)))
	}
	return sb.String()
}

func chunk(s string, n int) []string {
	out := make([]string, 0, (len(s)+n-1)/n)
	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return out
}
