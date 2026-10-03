package traefikx402

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUnpaidRequestGets402(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.Description = "Premium data"
	c.MimeType = "application/json"
	c.ExtensionsJSON = `{"bazaar":{"info":{},"schema":{}}}`
	p := newTestPlugin(t, c, okUpstream("secret"))

	rec := do(p, "GET", "http://api.test/premium/data?x=1", map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "pub.example.com"})
	if rec.Code != 402 {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "secret") {
		t.Fatal("upstream body leaked")
	}
	var pr struct {
		Resource   struct{ URL, Description, MimeType string }
		Extensions map[string]json.RawMessage
		Error      string
		Accepts    []Accept
		Version    int `json:"x402Version"`
	}
	decodeHeaderJSON(t, rec.Header().Get(headerRequired), &pr)
	if pr.Version != 2 || pr.Error != msgSignatureRequired {
		t.Fatalf("bad envelope %+v", pr)
	}
	if pr.Resource.URL != "https://pub.example.com/premium/data?x=1" || pr.Resource.Description != "Premium data" || pr.Resource.MimeType != "application/json" {
		t.Fatalf("bad resource %+v", pr.Resource)
	}
	if len(pr.Accepts) != 1 || pr.Accepts[0].Scheme != "exact" || pr.Accepts[0].MaxTimeoutSeconds != 60 || pr.Accepts[0].Asset != testUSDC {
		t.Fatalf("bad accepts %+v", pr.Accepts)
	}
	if _, ok := pr.Extensions["bazaar"]; !ok {
		t.Fatal("extensions missing")
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["x402Version"] != float64(2) {
		t.Fatalf("body not PaymentRequired JSON: %v", err)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatal("bad 402 headers")
	}
	contains(t, rec.Header().Get("Access-Control-Expose-Headers"), headerResponse)
}

func TestUnprotectedPassesThrough(t *testing.T) {
	f := newFakeFacilitator(t)
	p := newTestPlugin(t, baseConfig(f), okUpstream("free"))
	rec := do(p, "GET", "http://api.test/free/x", nil)
	if rec.Code != 200 || rec.Body.String() != "free" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if v, s := f.counts(); v+s != 0 {
		t.Fatal("facilitator called for unprotected path")
	}
}

func TestMultipleAssetsOnePath(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.Accepts = []Accept{usdcAccept(), daiAccept()}
	p := newTestPlugin(t, c, okUpstream("ok"))

	rec := do(p, "GET", "http://api.test/premium/a", nil)
	var pr struct{ Accepts []Accept }
	decodeHeaderJSON(t, rec.Header().Get(headerRequired), &pr)
	if len(pr.Accepts) != 2 || pr.Accepts[0].Asset != testUSDC || pr.Accepts[1].Asset != testDAI {
		t.Fatalf("accepts %+v", pr.Accepts)
	}

	for _, a := range []Accept{usdcAccept(), daiAccept()} {
		rec := do(p, "GET", "http://api.test/premium/a", map[string]string{headerSignature: payHeader(t, a)})
		if rec.Code != 200 {
			t.Fatalf("asset %s: status %d %s", a.Asset, rec.Code, rec.Body.String())
		}
		f.mu.Lock()
		var vr struct {
			PaymentRequirements Accept `json:"paymentRequirements"`
		}
		_ = json.Unmarshal(f.verifyBody, &vr)
		f.mu.Unlock()
		if vr.PaymentRequirements.Asset != a.Asset || vr.PaymentRequirements.Amount != a.Amount {
			t.Fatalf("facilitator saw %+v, want asset %s", vr.PaymentRequirements, a.Asset)
		}
	}
}

func TestPerRuleAccepts(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.Rules = []Rule{{Name: "dai", Exact: []string{"/dai"}, Accepts: []Accept{daiAccept()}}}
	p := newTestPlugin(t, c, okUpstream("ok"))
	rec := do(p, "GET", "http://api.test/dai", nil)
	var pr struct{ Accepts []Accept }
	decodeHeaderJSON(t, rec.Header().Get(headerRequired), &pr)
	if len(pr.Accepts) != 1 || pr.Accepts[0].Asset != testDAI {
		t.Fatalf("accepts %+v", pr.Accepts)
	}
	rec = do(p, "GET", "http://api.test/premium/x", nil)
	decodeHeaderJSON(t, rec.Header().Get(headerRequired), &pr)
	if pr.Accepts[0].Asset != testUSDC {
		t.Fatalf("default accepts %+v", pr.Accepts)
	}
}

func TestMalformedPaymentGets400(t *testing.T) {
	f := newFakeFacilitator(t)
	p := newTestPlugin(t, baseConfig(f), okUpstream("ok"))
	v1 := base64.StdEncoding.EncodeToString([]byte(`{"x402Version":1,"accepted":{}}`))
	noAcc := base64.StdEncoding.EncodeToString([]byte(`{"x402Version":2}`))
	badJSON := base64.StdEncoding.EncodeToString([]byte(`{nope`))
	tests := []struct {
		name, sig, reason string
	}{
		{"not base64", "!!!not-base64!!!", reasonInvalidPayload},
		{"not json", badJSON, reasonInvalidPayload},
		{"no accepted", noAcc, reasonInvalidPayload},
		{"wrong version", v1, reasonInvalidVersion},
		{"oversize", strings.Repeat("A", maxPayloadHeaderBytes+1), reasonInvalidPayload},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(p, "GET", "http://api.test/premium/x", map[string]string{headerSignature: tc.sig})
			if rec.Code != 400 {
				t.Fatalf("status %d", rec.Code)
			}
			contains(t, rec.Body.String(), tc.reason)
		})
	}
	if v, _ := f.counts(); v != 0 {
		t.Fatal("facilitator called for malformed payment")
	}
}

func TestMismatchedRequirementsGets402(t *testing.T) {
	f := newFakeFacilitator(t)
	p := newTestPlugin(t, baseConfig(f), okUpstream("ok"))
	cheap := usdcAccept()
	cheap.Amount = "1"
	wrongExtra := usdcAccept()
	wrongExtra.Extra = map[string]string{"name": "USDC", "version": "3"}
	extraKey := usdcAccept()
	extraKey.Extra = map[string]string{"name": "USDC", "version": "2", "x": "y"}
	for name, a := range map[string]Accept{"amount": cheap, "extra value": wrongExtra, "extra key": extraKey} {
		rec := do(p, "GET", "http://api.test/premium/x", map[string]string{headerSignature: payHeader(t, a)})
		if rec.Code != 402 {
			t.Fatalf("%s: status %d", name, rec.Code)
		}
		contains(t, rec.Body.String(), reasonInvalidRequirements)
	}
	if v, _ := f.counts(); v != 0 {
		t.Fatal("facilitator called for mismatched requirements")
	}
}

func TestVerifyFailures(t *testing.T) {
	tests := []struct {
		name     string
		resp     string
		wantBody string
		code     int
		wantCode int
	}{
		{"invalid", `{"isValid":false,"invalidReason":"insufficient_funds"}`, "insufficient_funds", 200, 402},
		{"invalid no reason", `{"isValid":false}`, "invalid_payment", 200, 402},
		{"invalid on 4xx", `{"isValid":false,"invalidReason":"invalid_network"}`, "invalid_network", 400, 402},
		{"facilitator 500 text", `boom`, reasonUnexpectedVerify, 500, 500},
		{"garbage 200", `<<<`, reasonUnexpectedVerify, 200, 500},
		{"json of wrong type", `[1]`, reasonUnexpectedVerify, 200, 500},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeFacilitator(t)
			f.verifyResp, f.verifyCode = tc.resp, tc.code
			p := newTestPlugin(t, baseConfig(f), okUpstream("ok"))
			rec := do(p, "GET", "http://api.test/premium/x", map[string]string{headerSignature: payHeader(t, usdcAccept())})
			if rec.Code != tc.wantCode {
				t.Fatalf("status %d, want %d (%s)", rec.Code, tc.wantCode, rec.Body.String())
			}
			contains(t, rec.Body.String(), tc.wantBody)
			if _, s := f.counts(); s != 0 {
				t.Fatal("settled after failed verify")
			}
		})
	}
}

func TestFacilitatorUnreachable(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	f.srv.Close()
	p := newTestPlugin(t, c, okUpstream("ok"))
	rec := do(p, "GET", "http://api.test/premium/x", map[string]string{headerSignature: payHeader(t, usdcAccept())})
	if rec.Code != 500 {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestPaidRequestAfterSettlement(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.PayerHeader = "X-Payer"
	c.FacilitatorHeaders = map[string]string{"Authorization": "Bearer k"}
	var seen http.Header
	p := newTestPlugin(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("paid content"))
	}))
	sig := payHeader(t, usdcAccept())
	rec := do(p, "GET", "http://api.test/premium/x", map[string]string{headerSignature: sig, "X-Payer": "spoof"})
	if rec.Code != 201 || rec.Body.String() != "paid content" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	var sr struct {
		Transaction string
		Network     string
		Payer       string
		Success     bool
	}
	decodeHeaderJSON(t, rec.Header().Get(headerResponse), &sr)
	if !sr.Success || sr.Transaction != "0xabc" || sr.Network != "eip155:84532" || sr.Payer != testPayer {
		t.Fatalf("settlement header %+v", sr)
	}
	if seen.Get(headerSignature) != "" {
		t.Fatal("PAYMENT-SIGNATURE reached upstream")
	}
	if seen.Get("X-Payer") != testPayer {
		t.Fatalf("payer header %q", seen.Get("X-Payer"))
	}
	if f.lastAuth != "Bearer k" {
		t.Fatalf("facilitator auth %q", f.lastAuth)
	}
	// The facilitator receives the client payload verbatim, unknown fields included.
	contains(t, string(f.verifyBody), `"futureField":"kept"`)
	contains(t, string(f.settleBody), `"paymentRequirements":{"scheme":"exact"`)
	if v, s := f.counts(); v != 1 || s != 1 {
		t.Fatalf("calls verify=%d settle=%d", v, s)
	}
}

func TestForwardPaymentHeader(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.ForwardPaymentHeader = true
	var got string
	p := newTestPlugin(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(headerSignature)
	}))
	sig := payHeader(t, usdcAccept())
	do(p, "GET", "http://api.test/premium/x", map[string]string{headerSignature: sig})
	if got != sig {
		t.Fatal("header not forwarded")
	}
}

func TestUpstreamErrorIsNotCharged(t *testing.T) {
	for _, code := range []int{400, 404, 500, 503} {
		f := newFakeFacilitator(t)
		p := newTestPlugin(t, baseConfig(f), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", code)
		}))
		sig := payHeader(t, usdcAccept())
		rec := do(p, "GET", "http://api.test/premium/x", map[string]string{headerSignature: sig})
		if rec.Code != code || rec.Header().Get(headerResponse) != "" {
			t.Fatalf("code %d: got %d resp-header %q", code, rec.Code, rec.Header().Get(headerResponse))
		}
		if _, s := f.counts(); s != 0 {
			t.Fatalf("code %d settled", code)
		}
		// The released authorization can be retried once the upstream recovers.
		rec = do(p, "GET", "http://api.test/premium/x", map[string]string{headerSignature: sig})
		if rec.Code != code {
			t.Fatalf("retry blocked: %d", rec.Code)
		}
	}
}

func TestSettlementFailureReplacesResponse(t *testing.T) {
	f := newFakeFacilitator(t)
	f.settleResp = `{"success":false,"errorReason":"insufficient_funds","transaction":"","network":"eip155:84532","payer":"` + testPayer + `"}`
	p := newTestPlugin(t, baseConfig(f), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Length", "5")
		w.Header().Set("X-Keep", "yes")
		_, _ = w.Write([]byte("hello"))
	}))
	rec := do(p, "GET", "http://api.test/premium/x", map[string]string{headerSignature: payHeader(t, usdcAccept())})
	if rec.Code != 402 {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "hello") {
		t.Fatal("upstream body leaked on failed settlement")
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("content-type %q", rec.Header().Get("Content-Type"))
	}
	var sr struct {
		ErrorReason string
		Success     bool
	}
	decodeHeaderJSON(t, rec.Header().Get(headerResponse), &sr)
	if sr.Success || sr.ErrorReason != "insufficient_funds" {
		t.Fatalf("settlement header %+v", sr)
	}
	contains(t, rec.Body.String(), "insufficient_funds")
	if rec.Header().Get(headerRequired) == "" {
		t.Fatal("PAYMENT-REQUIRED missing on settlement failure")
	}
}

func TestSettlementTransportError(t *testing.T) {
	f := newFakeFacilitator(t)
	f.settleResp, f.settleCode = `oops`, 502
	p := newTestPlugin(t, baseConfig(f), okUpstream("x"))
	rec := do(p, "GET", "http://api.test/premium/x", map[string]string{headerSignature: payHeader(t, usdcAccept())})
	if rec.Code != 500 {
		t.Fatalf("status %d", rec.Code)
	}
	contains(t, rec.Body.String(), reasonUnexpectedSettle)
}

func TestSettleBeforeMode(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.Settlement = settleBefore
	var calls int32
	p := newTestPlugin(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "upstream failed", 500)
	}))
	rec := do(p, "GET", "http://api.test/premium/x", map[string]string{headerSignature: payHeader(t, usdcAccept())})
	if rec.Code != 500 || rec.Header().Get(headerResponse) == "" {
		t.Fatalf("got %d resp-header %q", rec.Code, rec.Header().Get(headerResponse))
	}
	if _, s := f.counts(); s != 1 {
		t.Fatalf("settle calls %d", s)
	}

	f2 := newFakeFacilitator(t)
	f2.settleResp = `{"success":false,"errorReason":"x","transaction":"","network":"n"}`
	c2 := baseConfig(f2)
	c2.Settlement = settleBefore
	atomic.StoreInt32(&calls, 0)
	p2 := newTestPlugin(t, c2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&calls, 1) }))
	sig := payHeader(t, usdcAccept())
	rec = do(p2, "GET", "http://api.test/premium/x", map[string]string{headerSignature: sig})
	if rec.Code != 402 || atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("settle failure: status %d upstream calls %d", rec.Code, atomic.LoadInt32(&calls))
	}
	// A failed settlement releases the replay guard.
	f2.mu.Lock()
	f2.settleResp = `{"success":true,"transaction":"0x1","network":"n"}`
	f2.mu.Unlock()
	if rec = do(p2, "GET", "http://api.test/premium/x", map[string]string{headerSignature: sig}); rec.Code != 200 {
		t.Fatalf("retry status %d", rec.Code)
	}
}

func TestReplayGuard(t *testing.T) {
	f := newFakeFacilitator(t)
	p := newTestPlugin(t, baseConfig(f), okUpstream("ok"))
	sig := payHeader(t, usdcAccept())
	hdr := map[string]string{headerSignature: sig}
	if rec := do(p, "GET", "http://api.test/premium/x", hdr); rec.Code != 200 {
		t.Fatalf("first: %d", rec.Code)
	}
	rec := do(p, "GET", "http://api.test/premium/x", hdr)
	if rec.Code != 402 {
		t.Fatalf("replay: %d", rec.Code)
	}
	contains(t, rec.Body.String(), reasonReplay)
}

func TestReplayGuardDisabled(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.ReplayGuard = false
	p := newTestPlugin(t, c, okUpstream("ok"))
	hdr := map[string]string{headerSignature: payHeader(t, usdcAccept())}
	for i := 0; i < 2; i++ {
		if rec := do(p, "GET", "http://api.test/premium/x", hdr); rec.Code != 200 {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
}

func TestConcurrentSamePaymentServedOnce(t *testing.T) {
	f := newFakeFacilitator(t)
	var served int32
	gate := make(chan struct{})
	p := newTestPlugin(t, baseConfig(f), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&served, 1)
		<-gate
		_, _ = w.Write([]byte("ok"))
	}))
	hdr := map[string]string{headerSignature: payHeader(t, usdcAccept())}
	var wg sync.WaitGroup
	codes := make(chan int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- do(p, "GET", "http://api.test/premium/x", hdr).Code
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(codes) < 7 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(gate)
	wg.Wait()
	close(codes)
	ok, rejected := 0, 0
	for c := range codes {
		switch c {
		case 200:
			ok++
		case 402:
			rejected++
		}
	}
	if ok != 1 || rejected != 7 || atomic.LoadInt32(&served) != 1 {
		t.Fatalf("ok=%d rejected=%d served=%d", ok, rejected, atomic.LoadInt32(&served))
	}
}

func TestPayerHeaderStrippedOnUnprotectedRoutes(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.PayerHeader = "X-Payer"
	var got string
	p := newTestPlugin(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Get("X-Payer") }))
	do(p, "GET", "http://api.test/free", map[string]string{"X-Payer": "0xevil"})
	if got != "" {
		t.Fatalf("spoofed payer header reached upstream: %q", got)
	}
}

func TestResourceBaseURLOverride(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.ResourceBaseURL = "https://canonical.example/"
	p := newTestPlugin(t, c, okUpstream("x"))
	rec := do(p, "GET", "http://api.test/premium/a%20b", map[string]string{"X-Forwarded-Host": "evil"})
	var pr struct{ Resource struct{ URL string } }
	decodeHeaderJSON(t, rec.Header().Get(headerRequired), &pr)
	if pr.Resource.URL != "https://canonical.example/premium/a%20b" {
		t.Fatalf("url %q", pr.Resource.URL)
	}
}

func TestResourceURLFromTLS(t *testing.T) {
	f := newFakeFacilitator(t)
	p := newTestPlugin(t, baseConfig(f), okUpstream("x"))
	req := httptest.NewRequest("GET", "https://api.test/premium/a", nil)
	if got := p.resourceURL(req); got != "https://api.test/premium/a" {
		t.Fatalf("url %q", got)
	}
	req.Header.Set("X-Forwarded-Proto", "javascript")
	if got := p.resourceURL(req); !strings.HasPrefix(got, "https://") {
		t.Fatalf("bad forwarded proto accepted: %q", got)
	}
}

func TestStreamingNotBuffered(t *testing.T) {
	f := newFakeFacilitator(t)
	var flushedBeforeEnd bool
	release := make(chan struct{})
	p := newTestPlugin(t, baseConfig(f), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("chunk1"))
		w.(http.Flusher).Flush()
		<-release
		_, _ = w.Write([]byte("chunk2"))
	}))
	srv := httptest.NewServer(p)
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/premium/s", nil)
	req.Header.Set(headerSignature, payHeader(t, usdcAccept()))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 6)
	if _, err := resp.Body.Read(buf); err == nil && string(buf) == "chunk1" {
		flushedBeforeEnd = true
	}
	close(release)
	if !flushedBeforeEnd {
		t.Fatal("first chunk not delivered before upstream finished")
	}
	if resp.Header.Get(headerResponse) == "" {
		t.Fatal("settlement header missing on streamed response")
	}
}

func TestEmptyUpstreamBodyStillSettles(t *testing.T) {
	f := newFakeFacilitator(t)
	p := newTestPlugin(t, baseConfig(f), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := do(p, "GET", "http://api.test/premium/x", map[string]string{headerSignature: payHeader(t, usdcAccept())})
	if rec.Code != 200 || rec.Header().Get(headerResponse) == "" {
		t.Fatalf("got %d header %q", rec.Code, rec.Header().Get(headerResponse))
	}
	if _, s := f.counts(); s != 1 {
		t.Fatalf("settle calls %d", s)
	}
}

func TestInformationalStatusPassesThrough(t *testing.T) {
	f := newFakeFacilitator(t)
	p := newTestPlugin(t, baseConfig(f), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusEarlyHints)
		if _, s := f.counts(); s != 0 {
			t.Error("settled on 1xx")
		}
		_, _ = w.Write([]byte("body"))
	}))
	rec := do(p, "GET", "http://api.test/premium/x", map[string]string{headerSignature: payHeader(t, usdcAccept())})
	if rec.Code != 103 && rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if _, s := f.counts(); s != 1 {
		t.Fatalf("settle calls %d", s)
	}
}

func TestWriterHijackFlushUnwrap(t *testing.T) {
	f := newFakeFacilitator(t)
	var hijacked, unwrapped bool
	p := newTestPlugin(t, baseConfig(f), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		unwrapped = rc.Flush() == nil
		conn, _, err := rc.Hijack()
		if err == nil {
			hijacked = true
			_ = conn.Close()
		}
	}))
	rec := &hijackRecorder{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest("GET", "http://api.test/premium/ws", nil)
	req.Header.Set(headerSignature, payHeader(t, usdcAccept()))
	p.ServeHTTP(rec, req)
	if !unwrapped || !rec.hijacked || !hijacked {
		t.Fatalf("flush=%v hijack=%v/%v", unwrapped, rec.hijacked, hijacked)
	}
	if _, s := f.counts(); s != 1 {
		t.Fatalf("settle calls %d", s)
	}
}

func TestHijackUnsupportedAndFailedSettle(t *testing.T) {
	f := newFakeFacilitator(t)
	var err error
	p := newTestPlugin(t, baseConfig(f), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, err = w.(http.Hijacker).Hijack()
	}))
	do(p, "GET", "http://api.test/premium/x", map[string]string{headerSignature: payHeader(t, usdcAccept())})
	if err == nil {
		t.Fatal("hijack on a non-hijackable writer succeeded")
	}

	f2 := newFakeFacilitator(t)
	f2.settleResp = `{"success":false,"errorReason":"x","transaction":"","network":"n"}`
	p2 := newTestPlugin(t, baseConfig(f2), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, err = w.(http.Hijacker).Hijack()
	}))
	rec := &hijackRecorder{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest("GET", "http://api.test/premium/x", nil)
	req.Header.Set(headerSignature, payHeader(t, usdcAccept()))
	p2.ServeHTTP(rec, req)
	if err == nil || rec.hijacked || rec.Code != 402 {
		t.Fatalf("err=%v hijacked=%v code=%d", err, rec.hijacked, rec.Code)
	}
}

func TestFlushAfterFailedSettleIsNoop(t *testing.T) {
	f := newFakeFacilitator(t)
	f.settleResp = `{"success":false,"errorReason":"x","transaction":"","network":"n"}`
	p := newTestPlugin(t, baseConfig(f), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush()
		n, err := w.Write([]byte("abc"))
		if n != 3 || err != nil {
			t.Errorf("discarded write returned %d, %v", n, err)
		}
		w.WriteHeader(200)
	}))
	rec := do(p, "GET", "http://api.test/premium/x", map[string]string{headerSignature: payHeader(t, usdcAccept())})
	if rec.Code != 402 {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	if _, err := New(context.Background(), okUpstream("x"), nil, "n"); err == nil {
		t.Fatal("nil config accepted")
	}
	if _, err := New(context.Background(), okUpstream("x"), CreateConfig(), "n"); err == nil {
		t.Fatal("empty config accepted")
	}
	f := newFakeFacilitator(t)
	h, err := New(context.Background(), okUpstream("x"), baseConfig(f), "n")
	if err != nil || h == nil {
		t.Fatalf("valid config: %v", err)
	}
}

func TestRequestBodyShape(t *testing.T) {
	b := requestBody([]byte(`{"a":1}`), []byte(`{"b":2}`))
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if string(m["x402Version"]) != "2" || !bytes.Equal(m["paymentPayload"], []byte(`{"a":1}`)) || !bytes.Equal(m["paymentRequirements"], []byte(`{"b":2}`)) {
		t.Fatalf("body %s", b)
	}
}

func TestBase64Variants(t *testing.T) {
	raw := []byte(`{"x402Version":2,"accepted":{"scheme":"exact"},"n":"???>>>"}`)
	for name, enc := range map[string]*base64.Encoding{
		"std": base64.StdEncoding, "rawstd": base64.RawStdEncoding,
		"url": base64.URLEncoding, "rawurl": base64.RawURLEncoding,
	} {
		p, got, err := decodePayload(" " + enc.EncodeToString(raw) + "\n")
		if err != nil || p.X402Version != 2 || !bytes.Equal(got, raw) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := decodeBase64("***"); err != errBadBase64 {
		t.Fatalf("err %v", err)
	}
}

func TestAppendJSONString(t *testing.T) {
	tests := map[string]string{
		"plain":       `"plain"`,
		`q"b\`:        `"q\"b\\"`,
		"tab\tnl\n":   `"tab\u0009nl\u000a"`,
		"ünï":         `"ünï"`,
		"bad\xffbyte": `"bad�byte"`,
	}
	for in, want := range tests {
		got := string(appendJSONString(nil, in))
		if got != want {
			t.Errorf("%q => %s, want %s", in, got, want)
		}
		if !json.Valid([]byte(got)) {
			t.Errorf("%q produced invalid JSON %s", in, got)
		}
	}
}

func TestSettlementModeSelection(t *testing.T) {
	tests := []struct {
		hdr        map[string]string
		name       string
		global     string
		rule       string
		wantBefore bool
	}{
		{nil, "default after", "", "", false},
		{nil, "global before", settleBefore, "", true},
		{nil, "rule overrides global before", settleBefore, settleAfter, false},
		{nil, "rule before over global after", settleAfter, settleBefore, true},
		{map[string]string{"Accept": "text/event-stream"}, "sse forces before", settleAfter, settleAfter, true},
		{map[string]string{"Upgrade": "websocket"}, "upgrade forces before", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeFacilitator(t)
			c := baseConfig(f)
			c.Settlement = tc.global
			c.Prefixes = nil
			c.Rules = []Rule{{Prefixes: []string{"/premium/"}, Settlement: tc.rule}}
			var settledAtUpstream int
			p := newTestPlugin(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, settledAtUpstream = f.counts()
			}))
			hdr := map[string]string{headerSignature: payHeader(t, usdcAccept())}
			for k, v := range tc.hdr {
				hdr[k] = v
			}
			do(p, "GET", "http://api.test/premium/x", hdr)
			if got := settledAtUpstream == 1; got != tc.wantBefore {
				t.Fatalf("settled before upstream = %v, want %v", got, tc.wantBefore)
			}
		})
	}
}

func TestInvalidRuleSettlement(t *testing.T) {
	c := validConfig()
	c.Rules = []Rule{{Exact: []string{"/x"}, Settlement: "later"}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "settlement") {
		t.Fatalf("err %v", err)
	}
}
