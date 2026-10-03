package traefikx402

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func validConfig() *Config {
	c := CreateConfig()
	c.FacilitatorURL = "https://x402.org/facilitator"
	c.Accepts = []Accept{usdcAccept()}
	c.Exact = []string{"/a"}
	return c
}

func TestCreateConfigDefaults(t *testing.T) {
	c := CreateConfig()
	if c.Settlement != settleAfter || !c.ReplayGuard || c.FacilitatorTimeout != "10s" {
		t.Fatalf("defaults %+v", c)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"valid", func(c *Config) {}, ""},
		{"valid http insecure", func(c *Config) { c.FacilitatorURL = "http://f:1"; c.AllowInsecureFacilitator = true }, ""},
		{"empty url", func(c *Config) { c.FacilitatorURL = "" }, "facilitatorURL"},
		{"relative url", func(c *Config) { c.FacilitatorURL = "/x" }, "facilitatorURL"},
		{"ftp url", func(c *Config) { c.FacilitatorURL = "ftp://x" }, "facilitatorURL"},
		{"http without opt-in", func(c *Config) { c.FacilitatorURL = "http://f" }, "allowInsecureFacilitator"},
		{"bad timeout", func(c *Config) { c.FacilitatorTimeout = "soon" }, "facilitatorTimeout"},
		{"negative timeout", func(c *Config) { c.FacilitatorTimeout = "-1s" }, "facilitatorTimeout"},
		{"empty timeout uses default", func(c *Config) { c.FacilitatorTimeout = "" }, ""},
		{"bad settlement", func(c *Config) { c.Settlement = "never" }, "settlement"},
		{"settlement before", func(c *Config) { c.Settlement = "before" }, ""},
		{"bad base url", func(c *Config) { c.ResourceBaseURL = "nope" }, "resourceBaseURL"},
		{"bad extensions", func(c *Config) { c.ExtensionsJSON = "[1]" }, "extensionsJSON"},
		{"no rules", func(c *Config) { c.Exact = nil }, "no rules"},
		{"exact without slash", func(c *Config) { c.Exact = []string{"a"} }, "must start with /"},
		{"prefix without slash", func(c *Config) { c.Prefixes = []string{"a"} }, "must start with /"},
		{"empty suffix", func(c *Config) { c.Suffixes = []string{""} }, "suffix"},
		{"suffix only", func(c *Config) { c.Exact = nil; c.Suffixes = []string{".pdf"} }, ""},
		{"no accepts", func(c *Config) { c.Accepts = nil }, "no accepts"},
		{"bad network", func(c *Config) { c.Accepts[0].Network = "base" }, "CAIP-2"},
		{"bad network chars", func(c *Config) { c.Accepts[0].Network = "eip155:bad ref" }, "CAIP-2"},
		{"solana network", func(c *Config) { c.Accepts[0].Network = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" }, ""},
		{"bad amount", func(c *Config) { c.Accepts[0].Amount = "1.5" }, "amount"},
		{"empty amount", func(c *Config) { c.Accepts[0].Amount = "" }, "amount"},
		{"no asset", func(c *Config) { c.Accepts[0].Asset = "" }, "asset"},
		{"no payTo", func(c *Config) { c.Accepts[0].PayTo = "" }, "payTo"},
		{"negative timeout seconds", func(c *Config) { c.Accepts[0].MaxTimeoutSeconds = -1 }, "maxTimeoutSeconds"},
		{"rule without selector", func(c *Config) { c.Rules = []Rule{{Name: "r"}} }, "needs at least one"},
		{"rule own accepts invalid", func(c *Config) {
			c.Rules = []Rule{{Exact: []string{"/b"}, Accepts: []Accept{{Network: "x"}}}}
		}, "CAIP-2"},
		{"rule own accepts without defaults", func(c *Config) {
			c.Accepts = nil
			c.Exact = nil
			c.Rules = []Rule{{Exact: []string{"/b"}, Accepts: []Accept{usdcAccept()}}}
		}, ""},
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
				t.Fatalf("error %v, want substring %q", err, tc.wantErr)
			}
		})
	}
	var nilCfg *Config
	if nilCfg.Validate() == nil {
		t.Fatal("nil config validated")
	}
}

func TestValidateDoesNotMutate(t *testing.T) {
	c := validConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Accepts[0].Scheme != "" || c.Accepts[0].MaxTimeoutSeconds != 0 {
		t.Fatal("Validate applied defaults to the caller's config")
	}
}

func TestFacilitatorTimeoutParse(t *testing.T) {
	c := CreateConfig()
	d, err := c.facilitatorTimeout()
	if err != nil || d != 10*time.Second {
		t.Fatalf("%v %v", d, err)
	}
}

func matchPlugin(t *testing.T, mutate func(*Config)) *Plugin {
	t.Helper()
	f := newFakeFacilitator(t)
	c := baseConfig(f)
	c.Prefixes = nil
	mutate(c)
	return newTestPlugin(t, c, okUpstream("x"))
}

func TestPathMatching(t *testing.T) {
	p := matchPlugin(t, func(c *Config) {
		c.Exact = []string{"/report", "/exact/"}
		c.Prefixes = []string{"/premium/", "/v1/paid"}
		c.Suffixes = []string{".pdf", "/download"}
	})
	tests := []struct {
		path  string
		match bool
	}{
		{"/report", true},
		{"/report/", true}, // cleaned form equals an exact entry
		{"/reports", false},
		{"/exact/", true},
		{"/exact", false},
		{"/premium/a/b", true},
		{"/premium", false},
		{"/v1/paid", true},
		{"/v1/paidx", true},
		{"/docs/manual.pdf", true},
		{"/docs/manual.PDF", false},
		{"/files/x/download", true},
		{"/free/../premium/x", true},
		{"//premium/x", true},
		{"/free/./../premium/y", true},
		{"/free", false},
		{"/", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://h"+tc.path, nil)
			req.URL.Path = tc.path
			if got := p.findRule(req) != nil; got != tc.match {
				t.Fatalf("match=%v, want %v", got, tc.match)
			}
		})
	}
}

func TestIgnoreCase(t *testing.T) {
	p := matchPlugin(t, func(c *Config) {
		c.IgnoreCase = true
		c.Prefixes = []string{"/Premium/"}
		c.Exact = []string{"/Report"}
		c.Suffixes = []string{".PDF"}
	})
	for _, path := range []string{"/premium/x", "/PREMIUM/x", "/report", "/REPORT", "/a.pdf"} {
		req := httptest.NewRequest("GET", "http://h/", nil)
		req.URL.Path = path
		if p.findRule(req) == nil {
			t.Fatalf("%s not matched", path)
		}
	}
}

func TestMethodFiltering(t *testing.T) {
	p := matchPlugin(t, func(c *Config) { c.Prefixes = []string{"/premium/"}; c.Methods = []string{"post", "GET"} })
	for method, want := range map[string]bool{"GET": true, "POST": true, "DELETE": false, "OPTIONS": false} {
		req := httptest.NewRequest(method, "http://h/premium/x", nil)
		if got := p.findRule(req) != nil; got != want {
			t.Fatalf("%s: %v", method, got)
		}
	}
}

func TestOptionsPreflightNotCharged(t *testing.T) {
	p := matchPlugin(t, func(c *Config) { c.Prefixes = []string{"/premium/"} })
	req := httptest.NewRequest(http.MethodOptions, "http://h/premium/x", nil)
	if p.findRule(req) != nil {
		t.Fatal("CORS preflight is treated as protected")
	}
}

func TestFirstMatchingRuleWins(t *testing.T) {
	p := matchPlugin(t, func(c *Config) {
		c.Prefixes = []string{"/api/"}
		c.Rules = []Rule{
			{Name: "special", Exact: []string{"/api/special"}, Accepts: []Accept{eurcAccept()}, Description: "special"},
		}
	})
	req := httptest.NewRequest("GET", "http://h/api/special", nil)
	if cr := p.findRule(req); cr == nil || cr.name != "special" {
		t.Fatalf("rule %+v", cr)
	}
	req = httptest.NewRequest("GET", "http://h/api/other", nil)
	if cr := p.findRule(req); cr == nil || cr.name != "default" {
		t.Fatalf("rule %+v", cr)
	}
}

func TestCleanPath(t *testing.T) {
	tests := map[string]string{
		"/a/b":       "/a/b",
		"/a//b":      "/a/b",
		"/a/../b":    "/b",
		"/a/":        "/a",
		"/":          "/",
		"/a/./b/..":  "/a",
		"/../../etc": "/etc",
	}
	for in, want := range tests {
		if got := cleanPath(in); got != want {
			t.Errorf("cleanPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReplayGuardExpiryAndCapacity(t *testing.T) {
	now := time.Unix(1000, 0)
	g := newReplayGuard(func() time.Time { return now })
	if !g.claim("a-key", time.Second) {
		t.Fatal("first claim failed")
	}
	if g.claim("a-key", time.Second) {
		t.Fatal("duplicate claim allowed")
	}
	now = now.Add(time.Second + replayTTLMargin + time.Millisecond)
	if !g.claim("a-key", time.Second) {
		t.Fatal("expired claim not reusable")
	}
	g.release("a-key")
	if !g.claim("a-key", time.Second) {
		t.Fatal("released claim not reusable")
	}

	// A full shard fails open instead of rejecting paying clients.
	s := g.shards[int('z')%replayShards]
	s.mu.Lock()
	for i := 0; i < replayShardMax; i++ {
		s.seen[string(rune(i+1000))+"x"] = now.Add(time.Hour).UnixNano()
	}
	s.mu.Unlock()
	if !g.claim("zzz", time.Second) {
		t.Fatal("full shard rejected a claim")
	}
	if !g.claim("zzz", time.Second) {
		t.Fatal("untracked key unexpectedly deduplicated")
	}
}

func TestGuardKeyDeterministic(t *testing.T) {
	first, again := guardKey("a"), guardKey("a")
	if first != again || first == guardKey("b") || len(first) != 32 {
		t.Fatal("guardKey misbehaves")
	}
}

func TestSameAcceptNilExtra(t *testing.T) {
	a := &Accept{Scheme: "exact", Network: "n:1", Amount: "1", Asset: "a", PayTo: "p", MaxTimeoutSeconds: 5}
	g := &acceptedReq{Scheme: "exact", Network: "n:1", Amount: "1", Asset: "a", PayTo: "p", MaxTimeoutSeconds: 5}
	if !sameAccept(g, a) {
		t.Fatal("equal requirements differ")
	}
	g.Extra = map[string]interface{}{"k": 1.0}
	if sameAccept(g, a) {
		t.Fatal("unexpected extra accepted")
	}
}

func TestVerdictReason(t *testing.T) {
	v := &facilitatorVerdict{}
	if v.reason("fb") != "fb" {
		t.Fatal("fallback")
	}
	v.ErrorReason = "e"
	if v.reason("fb") != "e" {
		t.Fatal("error reason")
	}
	v.InvalidReason = "i"
	if v.reason("fb") != "i" {
		t.Fatal("invalid reason")
	}
}

func TestMarshalAcceptSpecOrderAndValidity(t *testing.T) {
	a := Accept{Network: "eip155:8453", Amount: "1", Asset: `a"b`, PayTo: "p", Extra: map[string]string{"z": "1", "a": "2"}}
	a.applyDefaults()
	got := string(marshalAccept(&a))
	want := `{"scheme":"exact","network":"eip155:8453","amount":"1","asset":"a\"b","payTo":"p","maxTimeoutSeconds":60,"extra":{"a":"2","z":"1"}}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	a.Extra = nil
	if got := string(marshalAccept(&a)); strings.Contains(got, "extra") {
		t.Fatalf("empty extra emitted: %s", got)
	}
}
