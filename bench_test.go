package traefikx402

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

type discardWriter struct{ h http.Header }

func (d *discardWriter) Header() http.Header         { return d.h }
func (d *discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func (d *discardWriter) WriteHeader(int)             {}

func benchPlugin(b *testing.B) *Plugin {
	b.Helper()
	c := CreateConfig()
	c.FacilitatorURL = "https://facilitator.invalid"
	c.SupportedCheck = supportCheckOff
	c.Accepts = []Accept{usdcAccept(), eurcAccept()}
	c.Exact = []string{"/a", "/b", "/c", "/d"}
	c.Prefixes = []string{"/premium/", "/paid/", "/v1/pro/"}
	c.Suffixes = []string{".pdf", ".zip"}
	p, err := newPlugin(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), c, "bench")
	if err != nil {
		b.Fatal(err)
	}
	return p
}

// BenchmarkUnprotectedPath measures the overhead on traffic the plugin ignores.
func BenchmarkUnprotectedPath(b *testing.B) {
	p := benchPlugin(b)
	req := httptest.NewRequest("GET", "http://h/static/app.js", nil)
	w := &discardWriter{h: http.Header{}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.ServeHTTP(w, req)
	}
}

// BenchmarkPaymentRequired measures building a 402 response.
func BenchmarkPaymentRequired(b *testing.B) {
	p := benchPlugin(b)
	req := httptest.NewRequest("GET", "http://h/premium/data", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := &discardWriter{h: http.Header{}}
		p.ServeHTTP(w, req)
	}
}

func BenchmarkFindRule(b *testing.B) {
	p := benchPlugin(b)
	req := httptest.NewRequest("GET", "http://h/v1/pro/x/y", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.findRule(req)
	}
}

func BenchmarkDecodePayload(b *testing.B) {
	sig := payHeader(b, usdcAccept())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := decodePayload(sig); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReplayGuardClaim(b *testing.B) {
	g := newReplayGuard(time.Now)
	keys := make([]string, 1024)
	for i := range keys {
		keys[i] = guardKey(strconv.Itoa(i))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k := keys[i&1023]
		g.claim(k, time.Second)
		g.release(k)
	}
}

// BenchmarkPaidRequest measures a full paid request against a facilitator on
// loopback: one /verify and one /settle call, replay guard off so the same
// payment repeats.
func BenchmarkPaidRequest(b *testing.B) {
	fac := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/verify" {
			_, _ = io.WriteString(w, `{"isValid":true,"payer":"0xp"}`)
			return
		}
		_, _ = io.WriteString(w, `{"success":true,"transaction":"0x1","network":"eip155:84532"}`)
	}))
	defer fac.Close()
	c := CreateConfig()
	c.FacilitatorURL = fac.URL
	c.AllowInsecureFacilitator = true
	c.SupportedCheck = supportCheckOff
	c.ReplayGuard = false
	c.Accepts = []Accept{usdcAccept()}
	c.Prefixes = []string{"/premium/"}
	p, err := newPlugin(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}), c, "bench")
	if err != nil {
		b.Fatal(err)
	}
	sig := payHeader(b, usdcAccept())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "http://h/premium/data", nil)
		req.Header.Set(headerSignature, sig)
		w := &discardWriter{h: http.Header{}}
		p.ServeHTTP(w, req)
	}
}
