package traefikx402

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

const solanaMainnet = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

func solanaAccept() Accept {
	return Accept{Network: solanaMainnet, Amount: "10000", Asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", PayTo: "payee"}
}

func TestSupportedCheckValidation(t *testing.T) {
	for in, wantErr := range map[string]bool{"": false, "off": false, "warn": false, "strict": false, "always": true} {
		if err := validSupportCheck(in); (err != nil) != wantErr {
			t.Errorf("%q: %v", in, err)
		}
	}
	c := validConfig()
	c.SupportedCheck = "sometimes"
	if err := c.Validate(); err == nil {
		t.Fatal("bad supportedCheck validated")
	}
	c = validConfig()
	c.FacilitatorAuth.Type = "oauth"
	if err := c.Validate(); err == nil {
		t.Fatal("bad auth validated")
	}
}

func TestStrictAcceptsSupportedOptions(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.SupportedCheck = supportCheckStrict
	if _, err := newPlugin(t.Context(), okUpstream("x"), c, "n"); err != nil {
		t.Fatal(err)
	}
	if f.supportedCalls != 1 {
		t.Fatalf("supported calls %d", f.supportedCalls)
	}
}

func TestStrictFailures(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*fakeFacilitator, *Config)
		wantErr string
	}{
		{"unsupported network", func(f *fakeFacilitator, c *Config) { c.Accepts[0].Network = "eip155:1" }, "eip155:1"},
		{"unsupported in rule", func(f *fakeFacilitator, c *Config) {
			c.Rules = []Rule{{Exact: []string{"/s"}, Accepts: []Accept{solanaAccept()}}}
		}, "solana"},
		{"http error", func(f *fakeFacilitator, c *Config) { f.supportedResp, f.supportedCode = "down", 503 }, "/supported"},
		{"bad json", func(f *fakeFacilitator, c *Config) { f.supportedResp = "{" }, "/supported"},
		{"wrong version", func(f *fakeFacilitator, c *Config) {
			f.supportedResp = `{"kinds":[{"x402Version":1,"scheme":"exact","network":"eip155:84532"}]}`
		}, "eip155:84532"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeFacilitator(t)
			c := baseConfig(f)
			c.SupportedCheck = supportCheckStrict
			tc.mutate(f, c)
			_, err := newPlugin(t.Context(), okUpstream("x"), c, "n")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestStrictFacilitatorUnreachable(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.SupportedCheck = supportCheckStrict
	f.srv.Close()
	if _, err := newPlugin(t.Context(), okUpstream("x"), c, "n"); err == nil {
		t.Fatal("unreachable facilitator accepted in strict mode")
	}
}

func TestStrictFillsFeePayer(t *testing.T) {
	f := newFakeFacilitator(t)
	f.supportedResp = `{"kinds":[
		{"x402Version":2,"scheme":"exact","network":"eip155:84532","extra":{"name":"WRONG","feePayer":"ignored-on-evm-when-set"}},
		{"x402Version":2,"scheme":"exact","network":"` + solanaMainnet + `","extra":{"feePayer":"FEEPAYER","memo":"not-merged"}}]}`
	c := baseConfig(f)
	c.SupportedCheck = supportCheckStrict
	own := solanaAccept()
	own.PayTo = "own-payee"
	pinned := solanaAccept()
	pinned.Extra = map[string]string{"feePayer": "OPERATOR"}
	c.Accepts = []Accept{usdcAccept(), solanaAccept()}
	c.Rules = []Rule{{Exact: []string{"/pinned"}, Accepts: []Accept{pinned}}, {Exact: []string{"/own"}, Accepts: []Accept{own}}}
	p := newTestPlugin(t, c, okUpstream("ok"))

	extras := func(path string) []map[string]string {
		rec := do(p, "GET", "http://api.test"+path, nil)
		var pr struct{ Accepts []Accept }
		decodeHeaderJSON(t, rec.Header().Get(headerRequired), &pr)
		out := make([]map[string]string, 0, len(pr.Accepts))
		for _, a := range pr.Accepts {
			out = append(out, a.Extra)
		}
		return out
	}
	got := extras("/premium/x")
	if got[0]["name"] != "USDC" || got[0]["feePayer"] != "ignored-on-evm-when-set" {
		t.Fatalf("evm extra %v", got[0])
	}
	if got[1]["feePayer"] != "FEEPAYER" || got[1]["memo"] != "" {
		t.Fatalf("solana extra %v", got[1])
	}
	if got := extras("/pinned")[0]["feePayer"]; got != "OPERATOR" {
		t.Fatalf("operator value overridden: %q", got)
	}
	if got := extras("/own")[0]["feePayer"]; got != "FEEPAYER" {
		t.Fatalf("rule accept not enriched: %q", got)
	}
	// The caller's configuration stays untouched.
	if c.Accepts[1].Extra != nil {
		t.Fatal("config mutated")
	}
}

func TestWarnModeChecksInBackground(t *testing.T) {
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.SupportedCheck = supportCheckWarn
	c.Accepts = []Accept{usdcAccept(), solanaAccept()}
	p := newTestPlugin(t, c, okUpstream("x"))
	select {
	case <-p.supportedDone:
	case <-time.After(5 * time.Second):
		t.Fatal("background check never finished")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.supportedCalls != 1 {
		t.Fatalf("supported calls %d", f.supportedCalls)
	}
}

func TestWarnModeToleratesFailures(t *testing.T) {
	f := newFakeFacilitator(t)
	f.supportedCode, f.supportedResp = 500, "boom"
	c := baseConfig(f)
	c.SupportedCheck = supportCheckWarn
	p, err := newPlugin(t.Context(), okUpstream("x"), c, "n")
	if err != nil {
		t.Fatalf("warn mode failed start-up: %v", err)
	}
	<-p.supportedDone
	if rec := do(p, "GET", "http://api.test/premium/x", nil); rec.Code != 402 {
		t.Fatalf("plugin unusable after failed check: %d", rec.Code)
	}
}

func TestOffModeSkipsCheck(t *testing.T) {
	f := newFakeFacilitator(t)
	p := newTestPlugin(t, baseConfig(f), okUpstream("x"))
	if p.supportedDone != nil || f.supportedCalls != 0 {
		t.Fatal("check ran in off mode")
	}
}

func TestUpgradeRequestsRejectedOnProtectedPaths(t *testing.T) {
	f := newFakeFacilitator(t)
	var reached bool
	p := newTestPlugin(t, baseConfig(f), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	hdr := map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"}
	rec := do(p, "GET", "http://api.test/premium/ws", hdr)
	if rec.Code != http.StatusNotImplemented || !strings.Contains(rec.Body.String(), reasonUpgrade) {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	hdr[headerSignature] = payHeader(t, usdcAccept())
	if rec := do(p, "GET", "http://api.test/premium/ws", hdr); rec.Code != http.StatusNotImplemented {
		t.Fatalf("paid upgrade: %d", rec.Code)
	}
	if v, s := f.counts(); v+s != 0 || reached {
		t.Fatalf("upgrade request reached the facilitator (%d,%d) or upstream (%v)", v, s, reached)
	}
	if rec := do(p, "GET", "http://api.test/free/ws", map[string]string{"Upgrade": "websocket"}); rec.Code != 200 {
		t.Fatalf("unprotected upgrade blocked: %d", rec.Code)
	}
}

func TestWithFacilitatorExtraWithoutKind(t *testing.T) {
	got := withFacilitatorExtra([]Accept{usdcAccept()}, nil)
	if len(got) != 1 || got[0].Extra["name"] != "USDC" {
		t.Fatalf("%+v", got)
	}
	if describeProblems([]string{"a", "b"}) != "a, b" {
		t.Fatal("describeProblems")
	}
}
