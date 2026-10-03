package traefikx402

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const (
	testPayTo = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
	testUSDC  = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
	testEURC  = "0x60a3E35Cc302bFA44Cb288Bc5a4F316Fdb1adb42"
	testPayer = "0x857b06519E91e3A54538791bDbb0E22373e36b66"
)

// fakeFacilitator is a scriptable x402 facilitator.
type fakeFacilitator struct {
	srv            *httptest.Server
	verifyResp     string
	settleResp     string
	lastAuth       string
	supportedResp  string
	verifyBody     []byte
	settleBody     []byte
	supportedCalls int
	supportedCode  int
	verifyCode     int
	settleCode     int
	verifyCalls    int
	settleCalls    int
	mu             sync.Mutex
}

func newFakeFacilitator(t *testing.T) *fakeFacilitator {
	t.Helper()
	f := &fakeFacilitator{
		verifyResp:    `{"isValid":true,"payer":"` + testPayer + `"}`,
		settleResp:    `{"success":true,"transaction":"0xabc","network":"eip155:84532","payer":"` + testPayer + `"}`,
		verifyCode:    200,
		settleCode:    200,
		supportedResp: `{"kinds":[{"x402Version":2,"scheme":"exact","network":"eip155:84532"}]}`,
		supportedCode: 200,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.verifyCalls++
		f.verifyBody = b
		f.lastAuth = r.Header.Get("Authorization")
		resp, code := f.verifyResp, f.verifyCode
		f.mu.Unlock()
		w.WriteHeader(code)
		_, _ = io.WriteString(w, resp)
	})
	mux.HandleFunc("/supported", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.supportedCalls++
		f.lastAuth = r.Header.Get("Authorization")
		resp, code := f.supportedResp, f.supportedCode
		f.mu.Unlock()
		w.WriteHeader(code)
		_, _ = io.WriteString(w, resp)
	})
	mux.HandleFunc("/settle", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.settleCalls++
		f.settleBody = b
		resp, code := f.settleResp, f.settleCode
		f.mu.Unlock()
		w.WriteHeader(code)
		_, _ = io.WriteString(w, resp)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeFacilitator) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.verifyCalls, f.settleCalls
}

func usdcAccept() Accept {
	return Accept{
		Network: "eip155:84532", Amount: "10000", Asset: testUSDC, PayTo: testPayTo,
		Extra: map[string]string{"name": "USDC", "version": "2"},
	}
}

func eurcAccept() Accept {
	return Accept{
		Network: "eip155:84532", Amount: "10000", Asset: testEURC, PayTo: testPayTo,
		Extra: map[string]string{"name": "EURC", "version": "2"},
	}
}

func baseConfig(f *fakeFacilitator) *Config {
	c := CreateConfig()
	c.FacilitatorURL = f.srv.URL
	c.AllowInsecureFacilitator = true
	c.SupportedCheck = supportCheckOff
	c.Accepts = []Accept{usdcAccept()}
	c.Prefixes = []string{"/premium/"}
	return c
}

func okUpstream(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, body)
	})
}

func newTestPlugin(t *testing.T, c *Config, next http.Handler) *Plugin {
	t.Helper()
	p, err := newPlugin(context.Background(), next, c, "test")
	if err != nil {
		t.Fatalf("newPlugin: %v", err)
	}
	return p
}

// payHeader builds a PAYMENT-SIGNATURE value echoing the given accept.
func payHeader(t testing.TB, a Accept) string {
	t.Helper()
	a.applyDefaults()
	extra := map[string]interface{}{}
	for k, v := range a.Extra {
		extra[k] = v
	}
	payload := map[string]interface{}{
		"x402Version": 2,
		"resource":    map[string]string{"url": "http://example.test/premium/x"},
		"accepted": map[string]interface{}{
			"scheme": a.Scheme, "network": a.Network, "amount": a.Amount, "asset": a.Asset,
			"payTo": a.PayTo, "maxTimeoutSeconds": a.MaxTimeoutSeconds, "extra": extra,
		},
		"payload": map[string]interface{}{
			"signature":     "0xsig",
			"authorization": map[string]string{"from": testPayer, "to": testPayTo, "value": a.Amount, "nonce": "0x01"},
		},
		"futureField": "kept",
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func do(h http.Handler, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeHeaderJSON(t *testing.T, v string, into interface{}) {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		t.Fatalf("header not base64: %v", err)
	}
	if err := json.Unmarshal(b, into); err != nil {
		t.Fatalf("header not JSON: %v", err)
	}
}

func contains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("%q does not contain %q", got, want)
	}
}
