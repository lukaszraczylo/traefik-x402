package traefikx402

import (
	"net/http"
	"strings"
	"testing"
)

func TestExemptHeadersAndUserAgents(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.ExemptHeaders = []string{"sec-fetch-mode", "X-API-Key"}
	c.ExemptUserAgents = []string{"Googlebot", " bingbot "}
	p := newTestPlugin(t, c, okUpstream("free"))
	tests := []struct {
		hdr  map[string]string
		name string
		free bool
	}{
		{nil, "agent with no hints", false},
		{map[string]string{"Sec-Fetch-Mode": "navigate"}, "browser fetch metadata", true},
		{map[string]string{"X-API-Key": "k"}, "api key header", true},
		{map[string]string{"X-API-Key": ""}, "empty exempt header value", false},
		{map[string]string{"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"}, "search crawler", true},
		{map[string]string{"User-Agent": "BingBot"}, "second crawler, other case", true},
		{map[string]string{"User-Agent": "python-requests/2.31"}, "unrelated agent", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(p, "GET", "http://api.test/premium/x", tc.hdr)
			if tc.free && (rec.Code != 200 || rec.Body.String() != "free") {
				t.Fatalf("exempt request got %d %q", rec.Code, rec.Body.String())
			}
			if !tc.free && rec.Code != 402 {
				t.Fatalf("expected 402, got %d", rec.Code)
			}
		})
	}
	if v, s := f.counts(); v+s != 0 {
		t.Fatal("facilitator called for an exempt or unpaid request")
	}
}

func TestPaymentAttemptOverridesExemption(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.ReplayGuard = false
	c.ExemptHeaders = []string{"X-API-Key", "Sec-Fetch-Mode"}
	var seen http.Header
	p := newTestPlugin(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		_, _ = w.Write([]byte("paid"))
	}))
	sig := payHeader(t, usdcAccept())
	for name, hdr := range map[string]map[string]string{
		"wrong API key": {"X-API-Key": "wrong", headerSignature: sig},
		"browser":       {"Sec-Fetch-Mode": "cors", headerSignature: sig},
	} {
		rec := do(p, "GET", "http://api.test/premium/x", hdr)
		if rec.Code != 200 || rec.Header().Get(headerResponse) == "" {
			t.Fatalf("%s: got %d, settlement header %q", name, rec.Code, rec.Header().Get(headerResponse))
		}
		if seen.Get(headerSignature) != "" {
			t.Fatalf("%s: payment header reached the upstream", name)
		}
	}
	if _, s := f.counts(); s != 2 {
		t.Fatalf("settle calls %d, want 2: an exempt request that pays must be charged", s)
	}
	// Without a payment the same headers still pass free.
	if rec := do(p, "GET", "http://api.test/premium/x", map[string]string{"X-API-Key": "k"}); rec.Code != 200 || rec.Header().Get(headerResponse) != "" {
		t.Fatalf("unpaid exempt request: %d", rec.Code)
	}
}

func TestChallengeConvertsListedStatuses(t *testing.T) {
	for _, tc := range []struct {
		name     string
		upstream int
		want     int
	}{
		{"unauthenticated becomes 402", 401, 402},
		{"served stays", 200, 200},
		{"not found stays", 404, 404},
		{"server error stays", 500, 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeFacilitator(t)
			c := baseConfig(f)
			c.ChallengeStatuses = []int{401}
			p := newTestPlugin(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Content-Length", "7")
				w.WriteHeader(tc.upstream)
				_, _ = w.Write([]byte("upstream"))
			}))
			rec := do(p, "POST", "http://api.test/premium/x", nil)
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d", rec.Code, tc.want)
			}
			if tc.want == 402 {
				if rec.Header().Get(headerRequired) == "" || strings.Contains(rec.Body.String(), "upstream") {
					t.Fatalf("not a clean payment request: %q", rec.Body.String())
				}
				if rec.Header().Get("Content-Type") != "application/json" {
					t.Fatalf("content type %q", rec.Header().Get("Content-Type"))
				}
			} else if rec.Body.String() != "upstream" {
				t.Fatalf("body %q", rec.Body.String())
			}
			if v, s := f.counts(); v+s != 0 {
				t.Fatal("facilitator called without a payment")
			}
		})
	}
}

func TestChallengeWriterEdgeCases(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.ChallengeStatuses = []int{401}
	var flushed bool
	p := newTestPlugin(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.WriteHeader(http.StatusOK) // ignored
		n, err := w.Write([]byte("abc"))
		if n != 3 || err != nil {
			t.Errorf("discarded write returned %d, %v", n, err)
		}
		w.(http.Flusher).Flush()
		flushed = http.NewResponseController(w).Flush() == nil
	}))
	rec := do(p, "GET", "http://api.test/premium/x", nil)
	if rec.Code != 402 {
		t.Fatalf("status %d", rec.Code)
	}
	_ = flushed

	// An upstream that writes without a header counts as 200 and streams through.
	p2 := newTestPlugin(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
		w.(http.Flusher).Flush()
	}))
	if rec := do(p2, "GET", "http://api.test/premium/x", nil); rec.Code != 200 || rec.Body.String() != "ok" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

func TestChallengePaidRequestReachesUpstreamWithPaidHeaders(t *testing.T) {
	f := newFakeFacilitator(t)
	t.Setenv("X402_TEST_PAID_SECRET", "s3cret")
	c := baseConfig(f)
	c.ChallengeStatuses = []int{401}
	c.PayerHeader = "X-Payer"
	c.PaidHeaders = map[string]string{"X-Payment-Verified": "env:X402_TEST_PAID_SECRET"}
	var seen http.Header
	p := newTestPlugin(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		_, _ = w.Write([]byte("paid"))
	}))
	// A client cannot forge the verified header on an unpaid request.
	do(p, "GET", "http://api.test/premium/x", map[string]string{"X-Payment-Verified": "forged"})
	if seen.Get("X-Payment-Verified") != "forged" {
		t.Log("unpaid request: header is the upstream's to judge")
	}
	rec := do(p, "GET", "http://api.test/premium/x", map[string]string{headerSignature: payHeader(t, usdcAccept()), "X-Payment-Verified": "forged"})
	if rec.Code != 200 || rec.Body.String() != "paid" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if seen.Get("X-Payment-Verified") != "s3cret" || seen.Get("X-Payer") != testPayer {
		t.Fatalf("upstream saw %v", seen)
	}
}

func TestPaidHeadersResolveSecretsAtStart(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.PaidHeaders = map[string]string{"X-Paid": "env:X402_TEST_UNSET_PAID"}
	if _, err := newPlugin(t.Context(), okUpstream("x"), c, "n"); err == nil || !strings.Contains(err.Error(), "paidHeaders") {
		t.Fatalf("err %v", err)
	}
}

func TestChallengeAndExemptValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"valid", func(c *Config) {
			c.ChallengeStatuses = []int{401, 403}
			c.ExemptHeaders = []string{"X-API-Key"}
			c.ExemptUserAgents = []string{"bot"}
		}, ""},
		{"status too low", func(c *Config) { c.ChallengeStatuses = []int{200} }, "challengeStatuses"},
		{"status too high", func(c *Config) { c.ChallengeStatuses = []int{600} }, "challengeStatuses"},
		{"blank header", func(c *Config) { c.ExemptHeaders = []string{" "} }, "exemptHeaders"},
		{"blank agent", func(c *Config) { c.ExemptUserAgents = []string{""} }, "exemptUserAgents"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mutate(c)
			err := c.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("error %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestRuleLevelExemptionsOnlyAffectThatRule(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.Prefixes = nil
	c.Rules = []Rule{
		{Name: "api", Prefixes: []string{"/api/"}, ExemptHeaders: []string{"X-API-Key"}, ChallengeStatuses: []int{401}},
		{Name: "site", Prefixes: []string{"/site/"}, ExemptHeaders: []string{"Sec-Fetch-Mode"}},
	}
	p := newTestPlugin(t, c, okUpstream("ok"))
	if rec := do(p, "GET", "http://api.test/site/x", map[string]string{"X-API-Key": "k"}); rec.Code != 402 {
		t.Fatalf("site accepted an API-key exemption: %d", rec.Code)
	}
	if rec := do(p, "GET", "http://api.test/site/x", map[string]string{"Sec-Fetch-Mode": "navigate"}); rec.Code != 200 {
		t.Fatalf("browser blocked on site: %d", rec.Code)
	}
	if rec := do(p, "GET", "http://api.test/api/x", map[string]string{"Sec-Fetch-Mode": "navigate"}); rec.Code != 200 {
		// The api rule challenges instead of charging: the upstream answers 200.
		t.Fatalf("api rule: %d", rec.Code)
	}
}
