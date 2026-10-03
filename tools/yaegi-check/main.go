// Command x402-yaegi-check loads the plugin under Yaegi the way Traefik and the
// Plugin Catalog analyzer do, then drives real x402 flows through it.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
	"gopkg.in/yaml.v3"
)

const (
	keyFacilitator = "facilitatorURL"
	headerSig      = "PAYMENT-SIGNATURE"
	importPath     = "github.com/lukaszraczylo/traefik-x402"
	pkgName        = "traefikx402"
	usdc           = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
	eurc           = "0x60a3E35Cc302bFA44Cb288Bc5a4F316Fdb1adb42"
	payTo          = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
)

const (
	keyAmount   = "amount"
	keyAccepts  = "accepts"
	pathPremium = "/premium/"
	headerUp    = "Upgrade"
)

const solana = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

var failures int

func check(ok bool, format string, args ...interface{}) {
	if ok {
		fmt.Printf("PASS  %s\n", fmt.Sprintf(format, args...))
		return
	}
	failures++
	fmt.Printf("FAIL  %s\n", fmt.Sprintf(format, args...))
}

func main() { os.Exit(run()) }

func run() int {
	if len(os.Args) != 2 {
		fmt.Println("usage: x402-yaegi-check <plugin-dir>")
		return 2
	}
	src := os.Args[1]
	gopath, err := os.MkdirTemp("", "x402-yaegi")
	must(err)
	defer func() { _ = os.RemoveAll(gopath) }()
	dst := filepath.Join(gopath, "src", filepath.FromSlash(importPath))
	must(os.MkdirAll(dst, 0o750))
	copyPlugin(src, dst)

	i := interp.New(interp.Options{GoPath: gopath, Env: os.Environ()})
	must(i.Use(stdlib.Symbols))
	_, err = i.Eval(fmt.Sprintf("import %q", importPath))
	must(err)
	cfgFn, err := i.Eval(pkgName + ".CreateConfig")
	must(err)
	newFn, err := i.Eval(pkgName + ".New")
	must(err)

	testData := loadTestData(src)
	build := func(data map[string]interface{}) (http.Handler, error) {
		cfg := cfgFn.Call(nil)[0]
		dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{WeaklyTypedInput: true, Result: cfg.Interface()})
		must(err)
		must(dec.Decode(data))
		var upstream http.Handler = http.HandlerFunc(upstreamHandler)
		out := newFn.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(upstream), cfg, reflect.ValueOf("yaegi")})
		fmt.Printf("      New returned %T, %T\n", out[0].Interface(), out[1].Interface())
		if e, _ := out[1].Interface().(error); e != nil {
			return nil, e
		}
		h, ok := out[0].Interface().(http.Handler)
		if !ok {
			return nil, fmt.Errorf("invalid handler type: %T", out[0].Interface())
		}
		return h, nil
	}

	_, err = build(testData)
	check(err == nil, ".traefik.yml testData builds a handler (err=%v)", err)

	_, err = build(map[string]interface{}{keyFacilitator: "https://f.example"})
	check(err != nil, "invalid config returns a real error across the reflect boundary (%v)", err)

	auth := &authState{}
	fac := newFacilitator(auth)
	defer fac.Close()
	flowChecks(build, fac)
	authChecks(build, fac, auth)
	policyChecks(build, fac)

	if failures > 0 {
		fmt.Printf("\n%d check(s) failed\n", failures)
		return 1
	}
	fmt.Println("\nall checks passed")
	return 0
}

func flowChecks(build func(map[string]interface{}) (http.Handler, error), fac *httptest.Server) {
	accepts := []interface{}{
		map[string]interface{}{"network": "eip155:84532", keyAmount: "10000", "asset": usdc, "payTo": payTo, "extra": map[string]interface{}{"name": "USDC", "version": "2"}},
		map[string]interface{}{"network": "eip155:84532", keyAmount: "10000", "asset": eurc, "payTo": payTo, "extra": map[string]interface{}{"name": "EURC", "version": "2"}},
	}
	h, err := build(map[string]interface{}{
		keyFacilitator: fac.URL, "allowInsecureFacilitator": true, keyAccepts: accepts,
		"prefixes": []interface{}{pathPremium}, "suffixes": []interface{}{".pdf"}, "exact": []interface{}{"/exact"},
		"payerHeader": "X-Payer", "description": "Premium", "mimeType": "application/json",
	})
	must(err)

	rec := serve(h, "/premium/data", nil)
	check(rec.Code == 402 && rec.Header().Get("PAYMENT-REQUIRED") != "", "unpaid prefix -> 402 + PAYMENT-REQUIRED (got %d)", rec.Code)
	var pr struct {
		Accepts []map[string]interface{}
	}
	decode(rec.Header().Get("PAYMENT-REQUIRED"), &pr)
	check(len(pr.Accepts) == 2, "402 advertises both assets (%d)", len(pr.Accepts))

	for _, p := range []string{"/exact", "/docs/a.pdf"} {
		check(serve(h, p, nil).Code == 402, "unpaid %s -> 402", p)
	}
	check(serve(h, "/free", nil).Code == 200, "unprotected path passes through")
	check(serve(h, "/free/../premium/x", nil).Code == 402, "dot-dot traversal still protected")

	for _, asset := range []string{usdc, eurc} {
		rec = serve(h, "/premium/data", map[string]string{headerSig: signature(accepts, asset)})
		var sr struct {
			Success     bool
			Transaction string
		}
		decode(rec.Header().Get("PAYMENT-RESPONSE"), &sr)
		check(rec.Code == 200 && sr.Success && sr.Transaction == "0xabc" && strings.Contains(rec.Body.String(), "payer=0x857b"),
			"paid with %s -> 200 + settlement header + payer header upstream (code %d body %q)", asset[:8], rec.Code, rec.Body.String())
	}

	sig := signature(accepts, usdc)
	serve(h, "/premium/replay", map[string]string{headerSig: sig})
	check(serve(h, "/premium/replay", map[string]string{headerSig: sig}).Code == 402, "replayed authorization rejected")

	rec = serve(h, "/premium/data", map[string]string{headerSig: "%%%"})
	check(rec.Code == 400, "malformed payment -> 400 (got %d)", rec.Code)

	rec = serve(h, "/premium/fail", map[string]string{headerSig: signatureNonce(accepts, usdc, "fail")})
	check(rec.Code == 500, "upstream 500 is passed through, not charged (got %d)", rec.Code)

	rec = serve(h, "/premium/data", map[string]string{headerSig: signatureNonce(accepts, usdc, "settlefail")})
	check(rec.Code == 402 && !strings.Contains(rec.Body.String(), "payer="), "failed settlement replaces response with 402 (got %d)", rec.Code)

	hb, err := build(map[string]interface{}{
		keyFacilitator: fac.URL, "allowInsecureFacilitator": true, keyAccepts: accepts,
		"prefixes": []interface{}{pathPremium}, "settlement": "before",
	})
	must(err)
	rec = serve(h, "/premium/ws", map[string]string{headerUp: "websocket", "Connection": headerUp})
	check(rec.Code == 501, "websocket upgrade on a protected path -> 501 (got %d)", rec.Code)
	rec = serve(h, "/free/ws", map[string]string{headerUp: "websocket", "Connection": headerUp})
	check(rec.Code == 200, "websocket upgrade on an unprotected path passes through (got %d)", rec.Code)

	rec = serve(hb, "/premium/data", map[string]string{headerSig: signatureNonce(accepts, usdc, "before")})
	check(rec.Code == 200 && rec.Header().Get("PAYMENT-RESPONSE") != "", "settlement=before -> 200 + header (got %d)", rec.Code)
}

func upstreamHandler(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/keyed") && r.Header.Get("X-API-Key") == "" && r.Header.Get("X-Payment-Verified") != "secret" {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/fail") {
		http.Error(w, "boom", http.StatusInternalServerError)
		return
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	_, _ = fmt.Fprintf(w, "ok payer=%s sig=%q", r.Header.Get("X-Payer"), r.Header.Get(headerSig)) // #nosec G705 -- test upstream echoing into a recorder, not a browser
}

// authState records how the fake facilitator judged Authorization headers.
type authState struct {
	edPub   ed25519.PublicKey
	ecPub   *ecdsa.PublicKey
	good    int
	bad     int
	missing int
}

func (a *authState) check(h string) {
	tok := strings.TrimPrefix(h, "Bearer ")
	parts := strings.Split(tok, ".")
	if h == "" || len(parts) != 3 {
		a.missing++
		return
	}
	var hdr struct{ Alg string }
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(hb, &hdr)
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	msg := []byte(parts[0] + "." + parts[1])
	ok := false
	switch hdr.Alg {
	case "EdDSA":
		ok = ed25519.Verify(a.edPub, msg, sig)
	case "ES256":
		d := sha256.Sum256(msg)
		ok = len(sig) == 64 && ecdsa.Verify(a.ecPub, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	}
	if ok {
		a.good++
	} else {
		a.bad++
	}
}

// newFacilitator approves everything except nonces containing "settlefail".
func newFacilitator(auth *authState) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "" {
			auth.check(r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/supported":
			_, _ = io.WriteString(w, `{"kinds":[{"x402Version":2,"scheme":"exact","network":"eip155:84532"},{"x402Version":2,"scheme":"exact","network":"`+solana+`","extra":{"feePayer":"FEEPAYER"}}]}`)
		case "/verify":
			_, _ = io.WriteString(w, `{"isValid":true,"payer":"0x857b06519E91e3A54538791bDbb0E22373e36b66"}`)
		case "/settle":
			if strings.Contains(string(b), "settlefail") {
				_, _ = io.WriteString(w, `{"success":false,"errorReason":"insufficient_funds","transaction":"","network":"eip155:84532"}`)
				return
			}
			_, _ = io.WriteString(w, `{"success":true,"transaction":"0xabc","network":"eip155:84532","payer":"0x857b06519E91e3A54538791bDbb0E22373e36b66"}`)
		default:
			http.NotFound(w, r)
		}
	}))
}

func signature(accepts []interface{}, asset string) string {
	return signatureNonce(accepts, asset, "n"+asset)
}

func signatureNonce(accepts []interface{}, asset, nonce string) string {
	var chosen map[string]interface{}
	for _, a := range accepts {
		m := a.(map[string]interface{})
		if m["asset"] == asset {
			chosen = map[string]interface{}{"scheme": "exact", "maxTimeoutSeconds": 60}
			for k, v := range m {
				chosen[k] = v
			}
		}
	}
	b, err := json.Marshal(map[string]interface{}{
		"x402Version": 2,
		"accepted":    chosen,
		"payload":     map[string]interface{}{"signature": "0xsig", "authorization": map[string]string{"nonce": nonce}},
	})
	must(err)
	return base64.StdEncoding.EncodeToString(b)
}

func serve(h http.Handler, path string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), "GET", "http://api.test"+path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decode(h string, into interface{}) {
	b, err := base64.StdEncoding.DecodeString(h)
	if err == nil {
		err = json.Unmarshal(b, into)
	}
	if err != nil {
		fmt.Printf("      cannot decode header %q: %v\n", h, err)
	}
}

func loadTestData(dir string) map[string]interface{} {
	raw, err := os.ReadFile(filepath.Join(dir, ".traefik.yml")) // #nosec G304,G703 -- operator-supplied plugin directory
	must(err)
	var m struct {
		TestData map[string]interface{} `yaml:"testData"`
	}
	must(yaml.Unmarshal(raw, &m))
	return m.TestData
}

func copyPlugin(src, dst string) {
	entries, err := os.ReadDir(src)
	must(err)
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || strings.HasSuffix(n, "_test.go") || (!strings.HasSuffix(n, ".go") && n != "go.mod" && n != ".traefik.yml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, n)) // #nosec G304,G703 -- operator-supplied plugin directory
		must(err)
		must(os.WriteFile(filepath.Join(dst, n), b, 0o600)) // #nosec G703 -- file name comes from the plugin directory listing
	}
}

func must(err error) {
	if err != nil {
		fmt.Println("fatal:", err)
		os.Exit(1)
	}
}

// authChecks drives the signing and /supported paths, which use crypto,
// encoding/pem and encoding/asn1 inside the interpreter.
func authChecks(build func(map[string]interface{}) (http.Handler, error), fac *httptest.Server, auth *authState) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	der, err := x509.MarshalECPrivateKey(ecKey)
	must(err)
	auth.edPub, auth.ecPub = edPub, &ecKey.PublicKey
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))

	solanaAccept := map[string]interface{}{"network": solana, keyAmount: "10000", "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "payTo": "payee"}
	for name, secret := range map[string]string{
		"Ed25519": base64.StdEncoding.EncodeToString(edPriv),
		"ES256":   ecPEM,
	} {
		before := auth.good
		h, err := build(map[string]interface{}{
			keyFacilitator: fac.URL, "allowInsecureFacilitator": true, "supportedCheck": "strict",
			"facilitatorAuth": map[string]interface{}{"type": "cdp", "keyID": "kid", "keySecret": secret},
			keyAccepts:        []interface{}{solanaAccept}, "prefixes": []interface{}{pathPremium},
		})
		must(err)
		check(auth.good > before && auth.bad == 0, "strict /supported call carries a valid %s JWT (good=%d bad=%d)", name, auth.good, auth.bad)
		rec := serve(h, "/premium/data", nil)
		var pr struct {
			Accepts []struct{ Extra map[string]string }
		}
		decode(rec.Header().Get("PAYMENT-REQUIRED"), &pr)
		check(len(pr.Accepts) == 1 && pr.Accepts[0].Extra["feePayer"] == "FEEPAYER", "%s: feePayer from /supported appears in the 402 (%v)", name, pr.Accepts)
	}

	_, err = build(map[string]interface{}{
		keyFacilitator: fac.URL, "allowInsecureFacilitator": true, "supportedCheck": "strict",
		keyAccepts: []interface{}{map[string]interface{}{"network": "eip155:1", keyAmount: "1", "asset": usdc, "payTo": payTo}},
		"prefixes": []interface{}{pathPremium},
	})
	check(err != nil && strings.Contains(err.Error(), "eip155:1"), "strict mode rejects an unsupported network (%v)", err)
}

// policyChecks drives exemptions, challenge mode and paid headers.
func policyChecks(build func(map[string]interface{}) (http.Handler, error), fac *httptest.Server) {
	accepts := []interface{}{
		map[string]interface{}{"network": "eip155:84532", "amount": "10000", "asset": usdc, "payTo": payTo, "extra": map[string]interface{}{"name": "USDC", "version": "2"}},
	}
	h, err := build(map[string]interface{}{
		keyFacilitator: fac.URL, "allowInsecureFacilitator": true, "supportedCheck": "off", keyAccepts: accepts,
		"prefixes": []interface{}{pathPremium}, "exemptHeaders": []interface{}{"Sec-Fetch-Mode"},
		"exemptUserAgents": []interface{}{"Googlebot"}, "challengeStatuses": []interface{}{401},
		"paidHeaders": map[string]interface{}{"X-Payment-Verified": "secret"},
	})
	must(err)
	check(serve(h, "/premium/keyed", map[string]string{"X-API-Key": "k"}).Code == 200, "challenge: upstream accepts the caller, response passes through")
	rec := serve(h, "/premium/keyed", nil)
	check(rec.Code == 402 && rec.Header().Get("PAYMENT-REQUIRED") != "", "challenge: upstream 401 becomes 402 (got %d)", rec.Code)
	rec = serve(h, "/premium/keyed", map[string]string{"PAYMENT-SIGNATURE": signatureNonce(accepts, usdc, "challenge")})
	check(rec.Code == 200 && rec.Header().Get("PAYMENT-RESPONSE") != "", "challenge: paid request reaches the upstream with the verified header (got %d)", rec.Code)
	check(serve(h, "/premium/data", map[string]string{"Sec-Fetch-Mode": "navigate"}).Code == 200, "exempt header passes without payment")
	check(serve(h, "/premium/data", map[string]string{"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"}).Code == 200, "exempt user agent passes without payment")
}
