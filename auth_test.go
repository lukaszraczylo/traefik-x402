package traefikx402

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func edSecret(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(priv), pub
}

//nolint:gosec // test keys are generated at run time
func ecPEM(t *testing.T, pkcs8 bool) (string, *ecdsa.PublicKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var der []byte
	typ := "EC PRIVATE KEY"
	if pkcs8 {
		der, err = x509.MarshalPKCS8PrivateKey(k)
		typ = "PRIVATE KEY"
	} else {
		der, err = x509.MarshalECPrivateKey(k)
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})), &k.PublicKey
}

type parsedJWT struct {
	header, claims map[string]any
	input          string
	sig            []byte
}

func parseJWT(t *testing.T, tok string) parsedJWT {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	var p parsedJWT
	dec := base64.RawURLEncoding
	for i, dst := range []*map[string]any{&p.header, &p.claims} {
		b, err := dec.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, dst); err != nil {
			t.Fatal(err)
		}
	}
	sig, err := dec.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	p.sig = sig
	p.input = parts[0] + "." + parts[1]
	return p
}

func signedRequest(t *testing.T, s *cdpSigner, method, url string) string {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.sign(req); err != nil {
		t.Fatal(err)
	}
	h := req.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		t.Fatalf("Authorization %q", h)
	}
	return strings.TrimPrefix(h, "Bearer ")
}

func TestCDPSignerEd25519(t *testing.T) {
	secret, pub := edSecret(t)
	now := time.Unix(1_800_000_000, 0)
	s, err := newCDPSigner("key-1", secret, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	j := parseJWT(t, signedRequest(t, s, "POST", "https://api.cdp.coinbase.com/platform/v2/x402/verify"))
	if j.header["alg"] != "EdDSA" || j.header["typ"] != "JWT" || j.header["kid"] != "key-1" || len(j.header["nonce"].(string)) != 32 {
		t.Fatalf("header %v", j.header)
	}
	if j.claims["sub"] != "key-1" || j.claims["iss"] != "cdp" || j.claims["uri"] != "POST api.cdp.coinbase.com/platform/v2/x402/verify" {
		t.Fatalf("claims %v", j.claims)
	}
	if aud := j.claims["aud"].([]any); len(aud) != 1 || aud[0] != "cdp_service" {
		t.Fatalf("aud %v", aud)
	}
	if j.claims["nbf"] != float64(now.Unix()) || j.claims["exp"] != float64(now.Add(120*time.Second).Unix()) {
		t.Fatalf("times %v %v", j.claims["nbf"], j.claims["exp"])
	}
	if !ed25519.Verify(pub, []byte(j.input), j.sig) {
		t.Fatal("signature does not verify")
	}
}

func TestCDPSignerAcceptsSeedOnly(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := newCDPSigner("k", base64.StdEncoding.EncodeToString(priv.Seed()), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	j := parseJWT(t, signedRequest(t, s, "GET", "https://h.example/p"))
	if !ed25519.Verify(pub, []byte(j.input), j.sig) {
		t.Fatal("seed-only key produced a bad signature")
	}
}

func TestCDPSignerES256(t *testing.T) {
	for _, pkcs8 := range []bool{false, true} {
		text, pub := ecPEM(t, pkcs8)
		// A secret pasted into one line keeps literal \n sequences.
		s, err := newCDPSigner("ec-key", strings.ReplaceAll(text, "\n", `\n`), time.Now)
		if err != nil {
			t.Fatalf("pkcs8=%v: %v", pkcs8, err)
		}
		j := parseJWT(t, signedRequest(t, s, "GET", "https://h.example/supported"))
		if j.header["alg"] != "ES256" || len(j.sig) != 64 {
			t.Fatalf("header %v sig %d", j.header, len(j.sig))
		}
		digest := sha256.Sum256([]byte(j.input))
		r, sv := new(big.Int).SetBytes(j.sig[:32]), new(big.Int).SetBytes(j.sig[32:])
		if !ecdsa.Verify(pub, digest[:], r, sv) {
			t.Fatalf("pkcs8=%v: signature does not verify", pkcs8)
		}
	}
}

func TestCDPSignerRejectsBadSecrets(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(p384)
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edDER, _ := x509.MarshalPKCS8PrivateKey(edPriv)
	tests := map[string]string{ // #nosec G101 -- test fixture, not a credential
		"not base64":   "***",
		"wrong length": base64.StdEncoding.EncodeToString([]byte("short")),
		"bad pem":      "-----BEGIN EC PRIVATE KEY-----\nnot-pem\n",
		"p384":         string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})),
		"non-ec pkcs8": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edDER})),
		"garbage der":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("xx")})),
	}
	for name, secret := range tests {
		if _, err := newCDPSigner("k", secret, time.Now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCDPTokenCache(t *testing.T) {
	secret, _ := edSecret(t)
	now := time.Unix(1_800_000_000, 0)
	s, _ := newCDPSigner("k", secret, func() time.Time { return now })
	a := signedRequest(t, s, "POST", "https://h.example/verify")
	if b := signedRequest(t, s, "POST", "https://h.example/verify"); a != b {
		t.Fatal("token not reused inside its lifetime")
	}
	if c := signedRequest(t, s, "POST", "https://h.example/settle"); a == c {
		t.Fatal("token shared across URIs")
	}
	now = now.Add(cdpLifetime - cdpReuseMargin + time.Second)
	if d := signedRequest(t, s, "POST", "https://h.example/verify"); a == d {
		t.Fatal("token reused after the refresh margin")
	}
}

func TestResolveSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s")
	if err := os.WriteFile(path, []byte("  from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("X402_TEST_SECRET", "from-env")
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{"literal", "literal", false},
		{"env:X402_TEST_SECRET", "from-env", false},
		{"env:X402_TEST_MISSING", "", true},
		{"file:" + path, "from-file", false},
		{"file:" + filepath.Join(dir, "nope"), "", true},
	}
	for _, tc := range tests {
		got, err := resolveSecret(tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("resolveSecret(%q) = %q, %v", tc.in, got, err)
		}
	}
}

func TestFacilitatorAuthValidate(t *testing.T) {
	tests := []struct {
		name    string
		auth    FacilitatorAuth
		wantErr bool
	}{
		{"none", FacilitatorAuth{}, false},
		{"cdp", FacilitatorAuth{Type: "cdp", KeyID: "id", KeySecret: "s"}, false},
		{"cdp without secret", FacilitatorAuth{Type: "cdp", KeyID: "id"}, true},
		{"cdp without id", FacilitatorAuth{Type: "cdp", KeySecret: "s"}, true},
		{"unknown", FacilitatorAuth{Type: "oauth"}, true},
	}
	for _, tc := range tests {
		if err := tc.auth.validate(); (err != nil) != tc.wantErr {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestNewSignerResolvesSecrets(t *testing.T) {
	secret, _ := edSecret(t)
	t.Setenv("X402_TEST_KEY_ID", "env-id")
	t.Setenv("X402_TEST_KEY_SECRET", secret)
	if s, err := newSigner(&FacilitatorAuth{}, time.Now); s != nil || err != nil {
		t.Fatalf("empty auth gave %v, %v", s, err)
	}
	s, err := newSigner(&FacilitatorAuth{Type: "cdp", KeyID: "env:X402_TEST_KEY_ID", KeySecret: "env:X402_TEST_KEY_SECRET"}, time.Now) // #nosec G101 -- test fixture, not a credential
	if err != nil || s == nil {
		t.Fatalf("signer: %v", err)
	}
	for _, bad := range []FacilitatorAuth{
		{Type: "cdp", KeyID: "env:X402_TEST_NOPE", KeySecret: "x"},
		{Type: "cdp", KeyID: "id", KeySecret: "env:X402_TEST_NOPE"}, // #nosec G101 -- test fixture, not a credential
		{Type: "cdp", KeyID: "id", KeySecret: "!!!"},
	} {
		if _, err := newSigner(&bad, time.Now); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestFacilitatorCallsAreSigned(t *testing.T) {
	f := newFakeFacilitator(t)
	secret, pub := edSecret(t)
	c := baseConfig(f)
	c.FacilitatorAuth = FacilitatorAuth{Type: "cdp", KeyID: "kid", KeySecret: secret}
	p := newTestPlugin(t, c, okUpstream("ok"))
	rec := do(p, "GET", "http://api.test/premium/x", map[string]string{headerSignature: payHeader(t, usdcAccept())})
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	f.mu.Lock()
	auth := f.lastAuth
	f.mu.Unlock()
	j := parseJWT(t, strings.TrimPrefix(auth, "Bearer "))
	if !ed25519.Verify(pub, []byte(j.input), j.sig) {
		t.Fatal("facilitator saw an invalid signature")
	}
	if uri, _ := j.claims["uri"].(string); !strings.HasPrefix(uri, "POST 127.0.0.1:") || !strings.HasSuffix(uri, "/verify") {
		t.Fatalf("uri %q", uri)
	}
}

func TestFacilitatorHeadersResolveSecrets(t *testing.T) {
	f := newFakeFacilitator(t)
	t.Setenv("X402_TEST_API_KEY", "Bearer from-env")
	c := baseConfig(f)
	c.FacilitatorHeaders = map[string]string{"Authorization": "env:X402_TEST_API_KEY"}
	p := newTestPlugin(t, c, okUpstream("ok"))
	do(p, "GET", "http://api.test/premium/x", map[string]string{headerSignature: payHeader(t, usdcAccept())})
	if f.lastAuth != "Bearer from-env" {
		t.Fatalf("facilitator auth %q", f.lastAuth)
	}
	c.FacilitatorHeaders = map[string]string{"Authorization": "env:X402_TEST_UNSET"}
	if _, err := newPlugin(t.Context(), okUpstream("x"), c, "n"); err == nil || !strings.Contains(err.Error(), "facilitatorHeaders") {
		t.Fatalf("err %v", err)
	}
}

func TestNewPluginRejectsBadAuth(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.FacilitatorAuth = FacilitatorAuth{Type: "cdp", KeyID: "id", KeySecret: "!!!"}
	if _, err := newPlugin(t.Context(), okUpstream("x"), c, "n"); err == nil {
		t.Fatal("bad secret accepted")
	}
}
