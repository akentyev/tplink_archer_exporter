package tpapi

import "slices"

// The certification list also decides whether the router locks itself for two
// hours on what it reads as concurrent logins: FEATURE_MAP gates
// "4_multiple_login" on SG CLS L1 STAGE2 and EU CE RED. It changes no bytes on
// the wire, so it is not in Features, but it is why a poller caps its logins.

// CertificationService.isSupport(feature) looks a feature up in FEATURE_MAP and
// asks whether any of its certifications appears in device_config's
// "certification" array. Same table, same names, here.

const (
	CertCE     = "EU CE"
	CertNTRA   = "Egypt NTRA"
	CertFCC    = "US FCC"
	CertKC     = "South Korea KC"
	CertRG     = "IMDA TS RG-SEC"
	CertSGL1S2 = "SG CLS L1 STAGE2"
	CertCERED  = "EU CE RED"
)

// Features is the subset of FEATURE_MAP that changes bytes on the wire.
type Features struct {
	Certifications []string

	SHA256Hash  bool // 2_login_SHA256:  h= is SHA-256(user+pass), not MD5
	Encrypt     bool // 5_gdpr:          bodies and replies are AES-encrypted at all
	ReplaceHash bool // 12_replace_hash: after login h= becomes SHA-256 of the payload
	OAEP        bool // 13_rsa_..._oaep: the login signature uses OAEP, not PKCS#1 v1.5
}

// FeaturesFor resolves a certification list into wire behaviour. An empty list
// means nothing is encrypted and the hash is plain MD5 — the correct answer for
// firmware without the endpoint.
func FeaturesFor(certs []string) Features {
	has := func(want ...string) bool {
		for _, c := range certs {
			if slices.Contains(want, c) {
				return true
			}
		}
		return false
	}
	return Features{
		Certifications: certs,
		SHA256Hash:     has(CertRG, CertSGL1S2, CertCERED),
		Encrypt:        has(CertSGL1S2, CertCERED),
		ReplaceHash:    has(CertSGL1S2),
		OAEP:           has(CertSGL1S2),
	}
}
