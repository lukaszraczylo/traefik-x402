//go:build e2e

// Package integration runs the plugin inside a real Traefik container against
// a mock facilitator and upstream, using only the docker CLI.
package integration

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	traefikImage = "traefik:v3.7"
	usdc         = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
	eurc         = "0x60a3E35Cc302bFA44Cb288Bc5a4F316Fdb1adb42"
	payTo        = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
	payer        = "0x857b06519E91e3A54538791bDbb0E22373e36b66"
)

type mockFacilitator struct {
	pub      ed25519.PublicKey
	failFor  string
	verify   int
	settle   int
	supports int
	authGood int
	authBad  int
	mu       sync.Mutex
}

// checkAuth verifies the EdDSA bearer JWT the plugin signs for each call.
func (m *mockFacilitator) checkAuth(h string) {
	parts := strings.Split(strings.TrimPrefix(h, "Bearer "), ".")
	if len(parts) != 3 {
		m.authBad++
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err == nil && ed25519.Verify(m.pub, []byte(parts[0]+"."+parts[1]), sig) {
		m.authGood++
		return
	}
	m.authBad++
}

func (m *mockFacilitator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkAuth(r.Header.Get("Authorization"))
	switch r.URL.Path {
	case "/supported":
		m.supports++
		_, _ = io.WriteString(w, `{"kinds":[{"x402Version":2,"scheme":"exact","network":"eip155:84532"}]}`)
	case "/verify":
		m.verify++
		_, _ = fmt.Fprintf(w, `{"isValid":true,"payer":%q}`, payer)
	case "/settle":
		m.settle++
		if m.failFor != "" && strings.Contains(string(b), m.failFor) {
			_, _ = io.WriteString(w, `{"success":false,"errorReason":"insufficient_funds","transaction":"","network":"eip155:84532"}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"success":true,"transaction":"0xdeadbeef","network":"eip155:84532","payer":%q}`, payer)
	default:
		http.NotFound(w, r)
	}
}

func (m *mockFacilitator) counts() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.verify, m.settle
}

func listenAll(t *testing.T, h http.Handler) (*httptest.Server, int) {
	t.Helper()
	// The Traefik container reaches the mocks through the host gateway.
	l, err := net.Listen("tcp", "0.0.0.0:0") // #nosec G102 -- test mocks must be reachable from the container
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(h)
	s.Listener = l
	s.Start()
	t.Cleanup(s.Close)
	return s, l.Addr().(*net.TCPAddr).Port
}

func upstream() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/keyed/"):
			if r.Header.Get("X-API-Key") == "" && r.Header.Get("X-Payment-Verified") != "secret" {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			_, _ = fmt.Fprintf(w, "keyed ok payer=%s", r.Header.Get("X-Payer"))
		case strings.HasSuffix(r.URL.Path, "/ws"):
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			defer func() { _ = conn.Close() }()
			_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			_ = buf.Flush()
		case strings.HasSuffix(r.URL.Path, "/broken"):
			http.Error(w, "upstream exploded", http.StatusInternalServerError)
		case strings.HasSuffix(r.URL.Path, "/stream"):
			w.Header().Set("Content-Type", "text/event-stream")
			f := w.(http.Flusher)
			for i := 0; i < 3; i++ {
				fmt.Fprintf(w, "data: %d\n\n", i)
				f.Flush()
				time.Sleep(300 * time.Millisecond)
			}
		default:
			_, _ = fmt.Fprintf(w, "content for %s payer=%s sig=%q", r.URL.Path, r.Header.Get("X-Payer"), r.Header.Get("PAYMENT-SIGNATURE")) // #nosec G705 -- mock upstream response read by the test client, not a browser
		}
	})
}

func settlementMode() string {
	if m := os.Getenv("X402_E2E_SETTLEMENT"); m != "" {
		return m
	}
	return "after"
}

func dynamicConfig(facPort, upPort int) string {
	return fmt.Sprintf(`http:
  routers:
    all:
      rule: PathPrefix(`+"`/`"+`)
      entryPoints: [web]
      service: up
      middlewares: [pay]
  services:
    up:
      loadBalancer:
        servers:
          - url: http://host.docker.internal:%d
  middlewares:
    pay:
      plugin:
        x402:
          facilitatorURL: http://host.docker.internal:%d
          allowInsecureFacilitator: true
          payerHeader: X-Payer
          supportedCheck: strict
          facilitatorAuth:
            type: cdp
            keyID: e2e-key
            keySecret: env:X402_E2E_KEY_SECRET
          settlement: %s
          description: Premium content
          mimeType: text/plain
          accepts:
            - network: eip155:84532
              amount: "10000"
              asset: "%s"
              payTo: "%s"
              extra:
                name: USDC
                version: "2"
            - network: eip155:84532
              amount: "10000"
              asset: "%s"
              payTo: "%s"
              extra:
                name: EURC
                version: "2"
          exact:
            - /report
          prefixes:
            - /premium/
          suffixes:
            - .pdf
          paidHeaders:
            X-Payment-Verified: secret
          rules:
            - name: keyed
              prefixes:
                - /keyed/
              challengeStatuses:
                - 401
              exemptUserAgents:
                - Googlebot
              exemptHeaders:
                - X-Exempt
`, upPort, facPort, settlementMode(), usdc, payTo, eurc, payTo)
}

const staticConfig = `entryPoints:
  web:
    address: ":80"
experimental:
  localPlugins:
    x402:
      moduleName: github.com/lukaszraczylo/traefik-x402
providers:
  file:
    directory: /etc/traefik/dynamic
log:
  level: DEBUG
`

func startTraefik(t *testing.T, facPort, upPort int, keySecret string) string {
	t.Helper()
	repo, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(dir, "dynamic"), 0o750))
	must(t, os.WriteFile(filepath.Join(dir, "traefik.yml"), []byte(staticConfig), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "dynamic", "x402.yml"), []byte(dynamicConfig(facPort, upPort)), 0o600))
	name := fmt.Sprintf("x402-e2e-%d", time.Now().UnixNano())
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name, // #nosec G204 -- fixed docker binary; arguments are test-controlled
		"-e", "X402_E2E_KEY_SECRET="+keySecret,
		"--add-host", "host.docker.internal:host-gateway", "-p", "127.0.0.1::80",
		"-v", repo+":/plugins-local/src/github.com/lukaszraczylo/traefik-x402:ro",
		"-v", filepath.Join(dir, "traefik.yml")+":/etc/traefik/traefik.yml:ro",
		"-v", filepath.Join(dir, "dynamic")+":/etc/traefik/dynamic:ro",
		traefikImage, "--configfile=/etc/traefik/traefik.yml").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", name).CombinedOutput() // #nosec G204 -- fixed docker binary; arguments are test-controlled
			t.Logf("traefik logs:\n%s", logs)
		}
		_ = exec.Command("docker", "rm", "-f", name).Run() // #nosec G204 -- fixed docker binary; arguments are test-controlled
	})
	portOut, err := exec.Command("docker", "port", name, "80/tcp").Output() // #nosec G204 -- fixed docker binary; arguments are test-controlled
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	sc := bufio.NewScanner(strings.NewReader(string(portOut)))
	sc.Scan()
	addr := sc.Text()
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		addr = "http://127.0.0.1:" + addr[i+1:]
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(addr + "/free")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return addr
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("traefik never served /free (plugin failed to load?)")
	return ""
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func sign(asset, amount, name, version, nonce string) string {
	b, _ := json.Marshal(map[string]any{
		"x402Version": 2,
		"accepted": map[string]any{
			"scheme": "exact", "network": "eip155:84532", "amount": amount, "asset": asset, "payTo": payTo,
			"maxTimeoutSeconds": 60, "extra": map[string]string{"name": name, "version": version},
		},
		"payload": map[string]any{"signature": "0xsig", "authorization": map[string]string{"from": payer, "to": payTo, "value": amount, "nonce": nonce}},
	})
	return base64.StdEncoding.EncodeToString(b)
}

// result keeps the parts of a response the tests assert on, so no body stays open.
type result struct {
	Header     http.Header
	StatusCode int
}

func get(t *testing.T, url string, hdr map[string]string) (result, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return result{StatusCode: resp.StatusCode, Header: resp.Header}, string(b)
}

func decodeHdr(t *testing.T, v string, into any) {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		t.Fatalf("header %q: %v", v, err)
	}
	if err := json.Unmarshal(b, into); err != nil {
		t.Fatal(err)
	}
}

func TestE2E(t *testing.T) {
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker unavailable: %v %s", err, out)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	fac := &mockFacilitator{pub: pub}
	_, facPort := listenAll(t, fac)
	_, upPort := listenAll(t, upstream())
	base := startTraefik(t, facPort, upPort, base64.StdEncoding.EncodeToString(priv))

	t.Run("unprotected passes through", func(t *testing.T) {
		resp, body := get(t, base+"/free/page", nil)
		if resp.StatusCode != 200 || !strings.Contains(body, "content for /free/page") {
			t.Fatalf("%d %q", resp.StatusCode, body)
		}
	})

	t.Run("unpaid requests get 402 on exact, prefix and suffix", func(t *testing.T) {
		for _, p := range []string{"/report", "/premium/a/b", "/docs/manual.pdf"} {
			resp, body := get(t, base+p, nil)
			if resp.StatusCode != 402 {
				t.Fatalf("%s: %d", p, resp.StatusCode)
			}
			var pr struct {
				X402Version int `json:"x402Version"`
				Error       string
				Resource    struct{ URL, Description, MimeType string }
				Accepts     []struct{ Asset, Amount, Network, PayTo string }
			}
			decodeHdr(t, resp.Header.Get("PAYMENT-REQUIRED"), &pr)
			if pr.X402Version != 2 || len(pr.Accepts) != 2 || pr.Accepts[0].Asset != usdc || pr.Accepts[1].Asset != eurc {
				t.Fatalf("%s: %+v", p, pr)
			}
			if !strings.HasSuffix(pr.Resource.URL, p) || pr.Resource.Description != "Premium content" {
				t.Fatalf("resource %+v", pr.Resource)
			}
			if !strings.Contains(body, `"x402Version":2`) {
				t.Fatalf("body %q", body)
			}
		}
	})

	t.Run("traversal does not bypass", func(t *testing.T) {
		resp, _ := get(t, base+"/premium/../premium/x", nil)
		if resp.StatusCode != 402 {
			t.Fatalf("%d", resp.StatusCode)
		}
	})

	t.Run("paid with each asset", func(t *testing.T) {
		for i, a := range []struct{ asset, amount, name, version string }{
			{usdc, "10000", "USDC", "2"},
			{eurc, "10000", "EURC", "2"},
		} {
			resp, body := get(t, base+"/premium/data", map[string]string{"PAYMENT-SIGNATURE": sign(a.asset, a.amount, a.name, a.version, fmt.Sprintf("0x%02d", i))})
			if resp.StatusCode != 200 {
				t.Fatalf("%s: %d %s", a.name, resp.StatusCode, body)
			}
			var sr struct {
				Success     bool
				Transaction string
				Payer       string
			}
			decodeHdr(t, resp.Header.Get("PAYMENT-RESPONSE"), &sr)
			if !sr.Success || sr.Transaction != "0xdeadbeef" || sr.Payer != payer {
				t.Fatalf("%+v", sr)
			}
			if !strings.Contains(body, "payer="+payer) || !strings.Contains(body, `sig=""`) {
				t.Fatalf("upstream saw %q", body)
			}
		}
	})

	t.Run("replayed payment is rejected", func(t *testing.T) {
		h := map[string]string{"PAYMENT-SIGNATURE": sign(usdc, "10000", "USDC", "2", "0xreplay")}
		if resp, _ := get(t, base+"/premium/r", h); resp.StatusCode != 200 {
			t.Fatalf("first %d", resp.StatusCode)
		}
		if resp, _ := get(t, base+"/premium/r", h); resp.StatusCode != 402 {
			t.Fatalf("replay %d", resp.StatusCode)
		}
	})

	t.Run("upstream error is not charged", func(t *testing.T) {
		_, before := fac.counts()
		resp, body := get(t, base+"/premium/broken", map[string]string{"PAYMENT-SIGNATURE": sign(usdc, "10000", "USDC", "2", "0xbroken")})
		if resp.StatusCode != 500 || !strings.Contains(body, "upstream exploded") {
			t.Fatalf("%d %q", resp.StatusCode, body)
		}
		if _, after := fac.counts(); after != before {
			t.Fatalf("settled on upstream error (%d -> %d)", before, after)
		}
	})

	t.Run("failed settlement returns 402", func(t *testing.T) {
		fac.mu.Lock()
		fac.failFor = "0xnofunds"
		fac.mu.Unlock()
		resp, body := get(t, base+"/premium/data", map[string]string{"PAYMENT-SIGNATURE": sign(usdc, "10000", "USDC", "2", "0xnofunds")})
		if resp.StatusCode != 402 || strings.Contains(body, "content for") {
			t.Fatalf("%d %q", resp.StatusCode, body)
		}
		var sr struct {
			Success     bool
			ErrorReason string
		}
		decodeHdr(t, resp.Header.Get("PAYMENT-RESPONSE"), &sr)
		if sr.Success || sr.ErrorReason != "insufficient_funds" {
			t.Fatalf("%+v", sr)
		}
	})

	t.Run("malformed payment is 400", func(t *testing.T) {
		resp, _ := get(t, base+"/premium/x", map[string]string{"PAYMENT-SIGNATURE": "garbage!!"})
		if resp.StatusCode != 400 {
			t.Fatalf("%d", resp.StatusCode)
		}
	})

	t.Run("paid streaming response is not buffered", func(t *testing.T) {
		req, _ := http.NewRequest("GET", base+"/premium/stream", nil)
		req.Header.Set("Accept", "text/event-stream")
		req.Header.Set("PAYMENT-SIGNATURE", sign(usdc, "10000", "USDC", "2", "0xstream"))
		start := time.Now()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		r := bufio.NewReader(resp.Body)
		line, err := r.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "data: 0") {
			t.Fatalf("first event %q: %v", line, err)
		}
		if time.Since(start) > 700*time.Millisecond {
			t.Fatalf("first event arrived after %v: response was buffered", time.Since(start))
		}
		if resp.Header.Get("PAYMENT-RESPONSE") == "" {
			t.Fatal("settlement header missing")
		}
	})

	t.Run("challenge mode separates API callers from agents", func(t *testing.T) {
		if resp, body := get(t, base+"/keyed/data", map[string]string{"X-API-Key": "k"}); resp.StatusCode != 200 || !strings.Contains(body, "keyed ok") {
			t.Fatalf("API caller: %d %q", resp.StatusCode, body)
		}
		resp, _ := get(t, base+"/keyed/data", nil)
		if resp.StatusCode != 402 || resp.Header.Get("PAYMENT-REQUIRED") == "" {
			t.Fatalf("agent without payment: %d", resp.StatusCode)
		}
		resp, body := get(t, base+"/keyed/data", map[string]string{"PAYMENT-SIGNATURE": sign(usdc, "10000", "USDC", "2", "0xkeyed")})
		if resp.StatusCode != 200 || !strings.Contains(body, "payer="+payer) || resp.Header.Get("PAYMENT-RESPONSE") == "" {
			t.Fatalf("paid agent: %d %q", resp.StatusCode, body)
		}
		if resp, _ := get(t, base+"/keyed/data", map[string]string{"X-Exempt": "1"}); resp.StatusCode != 401 {
			t.Fatalf("exempt request must reach the upstream untouched, got %d", resp.StatusCode)
		}
		if resp, _ := get(t, base+"/keyed/data", map[string]string{"User-Agent": "Googlebot/2.1"}); resp.StatusCode != 401 {
			t.Fatalf("exempt user agent must reach the upstream untouched, got %d", resp.StatusCode)
		}
	})

	t.Run("websocket upgrade is rejected on protected paths only", func(t *testing.T) {
		if got := upgradeStatus(t, base, "/premium/ws"); got != 501 {
			t.Fatalf("protected: %d", got)
		}
		if got := upgradeStatus(t, base, "/free/ws"); got != 101 {
			t.Fatalf("unprotected: %d", got)
		}
	})

	t.Run("facilitator saw expected traffic", func(t *testing.T) {
		v, s := fac.counts()
		if v < 6 || s < 5 {
			t.Fatalf("verify=%d settle=%d", v, s)
		}
		fac.mu.Lock()
		defer fac.mu.Unlock()
		if fac.supports != 1 {
			t.Fatalf("/supported calls: %d", fac.supports)
		}
		if fac.authGood < 7 || fac.authBad != 0 {
			t.Fatalf("signed calls good=%d bad=%d", fac.authGood, fac.authBad)
		}
	})
}

// upgradeStatus sends a WebSocket handshake over a raw connection and returns the status code.
func upgradeStatus(t *testing.T, base, path string) int {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", path)
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var code int
	if _, err := fmt.Sscanf(line, "HTTP/1.1 %d", &code); err != nil {
		t.Fatalf("status line %q", line)
	}
	return code
}
