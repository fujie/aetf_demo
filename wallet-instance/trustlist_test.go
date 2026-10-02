package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func signTestJAdES(t *testing.T, key *ecdsa.PrivateKey, header map[string]any, payload []byte) string {
	t.Helper()
	h, _ := json.Marshal(header)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func testSigner(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "operator"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

func TestVerifyJAdESCompact(t *testing.T) {
	key, der := testSigner(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	trusted := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey}}}
	sum := sha256.Sum256(der)
	header := map[string]any{
		"alg": "ES256", "x5c": []string{base64.StdEncoding.EncodeToString(der)},
		"x5t#S256": base64.RawURLEncoding.EncodeToString(sum[:]), "sigT": "2026-10-02T00:00:00Z", "crit": []string{"sigT"},
	}
	payload := []byte(`{"LoTE":{}}`)

	if _, _, err := verifyJAdESCompact(signTestJAdES(t, key, header, payload), trusted); err != nil {
		t.Fatalf("valid JAdES rejected: %v", err)
	}
	// signer key not published in the federation metadata
	if _, _, err := verifyJAdESCompact(signTestJAdES(t, key, header, payload), &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &other.PublicKey}}}); err == nil {
		t.Fatal("untrusted signer accepted")
	}
	// tampered payload
	jws := signTestJAdES(t, key, header, payload)
	parts := strings.Split(jws, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"LoTE":{"x":1}}`))
	if _, _, err := verifyJAdESCompact(strings.Join(parts, "."), trusted); err == nil {
		t.Fatal("tampered payload accepted")
	}
	// unknown critical header
	bad := map[string]any{}
	for k, v := range header {
		bad[k] = v
	}
	bad["crit"] = []string{"sigT", "unknown"}
	if _, _, err := verifyJAdESCompact(signTestJAdES(t, key, bad, payload), trusted); err == nil {
		t.Fatal("unknown crit accepted")
	}
	// missing sigT
	delete(bad, "sigT")
	bad["crit"] = []string{}
	if _, _, err := verifyJAdESCompact(signTestJAdES(t, key, bad, payload), trusted); err == nil {
		t.Fatal("missing sigT accepted")
	}
}
