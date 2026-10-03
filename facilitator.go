package traefikx402

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	facilitatorMaxIdleConns = 128
	facilitatorIdleTimeout  = 90 * time.Second
)

// facilitator is a pooled HTTP client for a remote x402 facilitator.
type facilitator struct {
	client       *http.Client
	signer       requestSigner
	headers      map[string]string
	verifyURL    string
	settleURL    string
	supportedURL string
}

func newFacilitator(base string, timeout time.Duration, headers map[string]string) *facilitator {
	base = strings.TrimRight(base, "/")
	return &facilitator{
		verifyURL:    base + "/verify",
		settleURL:    base + "/settle",
		supportedURL: base + "/supported",
		headers:      headers,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				MaxIdleConns:        facilitatorMaxIdleConns,
				MaxIdleConnsPerHost: facilitatorMaxIdleConns,
				IdleConnTimeout:     facilitatorIdleTimeout,
				ForceAttemptHTTP2:   true,
			},
		},
	}
}

// requestBody builds the shared /verify and /settle request without re-encoding the payload.
func requestBody(payload, requirement []byte) []byte {
	const head = `{"x402Version":2,"paymentPayload":`
	const mid = `,"paymentRequirements":`
	b := make([]byte, 0, len(head)+len(payload)+len(mid)+len(requirement)+1)
	b = append(b, head...)
	b = append(b, payload...)
	b = append(b, mid...)
	b = append(b, requirement...)
	return append(b, '}')
}

// post sends a POST and returns the response bytes.
func (f *facilitator) post(ctx context.Context, url string, body []byte) ([]byte, error) {
	return f.do(ctx, http.MethodPost, url, body, true)
}

// do sends one request. A non-2xx status is an error, except that a JSON body
// is returned to the caller when judgeErrorBody is set: verify and settle
// report invalid payments with 4xx statuses.
func (f *facilitator) do(ctx context.Context, method, url string, body []byte, judgeErrorBody bool) ([]byte, error) {
	// #nosec G704 -- the facilitator URL is operator configuration, never request input
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range f.headers {
		req.Header.Set(k, v)
	}
	if f.signer != nil {
		if err := f.signer.sign(req); err != nil {
			return nil, fmt.Errorf("sign facilitator request: %w", err)
		}
	}
	resp, err := f.client.Do(req) // #nosec G704 -- URL comes from operator configuration
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFacilitatorBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 && (!judgeErrorBody || !json.Valid(data)) {
		return nil, fmt.Errorf("facilitator returned HTTP %d", resp.StatusCode)
	}
	return data, nil
}

// verify returns the facilitator verdict for a payment.
func (f *facilitator) verify(ctx context.Context, body []byte) (*facilitatorVerdict, error) {
	data, err := f.post(ctx, f.verifyURL, body)
	if err != nil {
		return nil, err
	}
	var v facilitatorVerdict
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("facilitator /verify response: %w", err)
	}
	return &v, nil
}

// settle returns the facilitator verdict and the raw (compacted) response,
// which is relayed to the client as the PAYMENT-RESPONSE header.
func (f *facilitator) settle(ctx context.Context, body []byte) (*facilitatorVerdict, []byte, error) {
	data, err := f.post(ctx, f.settleURL, body)
	if err != nil {
		return nil, nil, err
	}
	var v facilitatorVerdict
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, nil, fmt.Errorf("facilitator /settle response: %w", err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		return nil, nil, err
	}
	return &v, compact.Bytes(), nil
}
