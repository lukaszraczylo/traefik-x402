// Package traefikx402 is a Traefik middleware that enforces x402 v2 payments
// on selected URLs, delegating verification and settlement to a facilitator.
package traefikx402

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Plugin is the x402 resource-server middleware.
type Plugin struct {
	next           http.Handler
	fac            *facilitator
	guard          *replayGuard
	log            *slog.Logger
	supportedDone  chan struct{}
	paidHeaders    map[string]string
	baseURL        string
	payerHeader    string
	extensions     []byte
	rules          []*rule
	ignoreCase     bool
	settleBefore   bool
	forwardPayment bool
}

// New builds the middleware.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	p, err := newPlugin(ctx, next, config, name)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func newPlugin(ctx context.Context, next http.Handler, c *Config, name string) (*Plugin, error) {
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("x402: %w", err)
	}
	timeout, err := c.facilitatorTimeout()
	if err != nil {
		return nil, err
	}
	headers, err := resolveHeaders(c.FacilitatorHeaders)
	if err != nil {
		return nil, fmt.Errorf("x402: %w", err)
	}
	paid, err := resolveHeaders(c.PaidHeaders)
	if err != nil {
		return nil, fmt.Errorf("x402: paidHeaders: %w", err)
	}
	signer, err := newSigner(&c.FacilitatorAuth, time.Now)
	if err != nil {
		return nil, fmt.Errorf("x402: %w", err)
	}
	p := &Plugin{
		next:           next,
		log:            slog.New(slog.NewTextHandler(os.Stderr, nil)).With("plugin", "x402", "name", name),
		fac:            newFacilitator(c.FacilitatorURL, timeout, headers),
		baseURL:        strings.TrimRight(c.ResourceBaseURL, "/"),
		payerHeader:    c.PayerHeader,
		ignoreCase:     c.IgnoreCase,
		settleBefore:   c.Settlement == settleBefore,
		forwardPayment: c.ForwardPaymentHeader,
		paidHeaders:    paid,
	}
	p.fac.signer = signer
	if c.ExtensionsJSON != "" {
		var ext bytes.Buffer
		if err := json.Compact(&ext, []byte(c.ExtensionsJSON)); err != nil {
			return nil, err
		}
		p.extensions = ext.Bytes()
	}
	if c.ReplayGuard {
		p.guard = newReplayGuard(time.Now)
	}

	rules, defaults := c.allRules(), c.Accepts
	switch c.SupportedCheck {
	case supportCheckStrict:
		rules, defaults, err = p.applySupported(ctx, timeout, rules, defaults)
		if err != nil {
			return nil, fmt.Errorf("x402: %w", err)
		}
	case supportCheckOff:
	default:
		p.supportedDone = make(chan struct{})
		go p.warnUnsupported(timeout, rules, defaults) // #nosec G118 -- the check must outlive the context New receives
	}
	for i := range rules {
		p.rules = append(p.rules, compileRule(&rules[i], defaults, c.IgnoreCase))
	}
	return p, nil
}

// resolveHeaders expands env: and file: secret references in header values.
func resolveHeaders(in map[string]string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		r, err := resolveSecret(v)
		if err != nil {
			return nil, fmt.Errorf("facilitatorHeaders %q: %w", k, err)
		}
		out[k] = r
	}
	return out, nil
}

// marshalAccept encodes a requirement in the field order the x402 spec shows.
func marshalAccept(a *Accept) []byte {
	b := append([]byte(nil), `{"scheme":`...)
	b = appendJSONString(b, a.Scheme)
	b = append(b, `,"network":`...)
	b = appendJSONString(b, a.Network)
	b = append(b, `,"amount":`...)
	b = appendJSONString(b, a.Amount)
	b = append(b, `,"asset":`...)
	b = appendJSONString(b, a.Asset)
	b = append(b, `,"payTo":`...)
	b = appendJSONString(b, a.PayTo)
	b = append(b, `,"maxTimeoutSeconds":`...)
	b = strconv.AppendInt(b, int64(a.MaxTimeoutSeconds), 10)
	if len(a.Extra) > 0 {
		keys := make([]string, 0, len(a.Extra))
		for k := range a.Extra {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b = append(b, `,"extra":{`...)
		for i, k := range keys {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendJSONString(b, k)
			b = append(b, ':')
			b = appendJSONString(b, a.Extra[k])
		}
		b = append(b, '}')
	}
	return append(b, '}')
}

// find returns the configured requirement equal to the client's choice.
func (cr *rule) find(got *acceptedReq) *requirement {
	for i := range cr.reqs {
		if sameAccept(got, &cr.reqs[i].Accept) {
			return &cr.reqs[i]
		}
	}
	return nil
}

func (p *Plugin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.payerHeader != "" {
		r.Header.Del(p.payerHeader)
	}
	cr := p.findRule(r)
	if cr == nil {
		p.next.ServeHTTP(w, r)
		return
	}
	if r.Header.Get("Upgrade") != "" {
		p.notImplemented(w, reasonUpgrade)
		return
	}
	if cr.exempt(r) {
		p.next.ServeHTTP(w, r)
		return
	}
	sig := r.Header.Get(headerSignature)
	if sig == "" {
		if cr.challenge != nil {
			// The upstream decides who needs to pay: it answers first, and a
			// listed status turns into a payment request.
			p.next.ServeHTTP(&challengeWriter{ResponseWriter: w, p: p, r: r, cr: cr}, r)
			return
		}
		p.paymentRequired(w, r, cr, msgSignatureRequired)
		return
	}
	if len(sig) > maxPayloadHeaderBytes {
		p.clientError(w, reasonInvalidPayload)
		return
	}
	payload, raw, err := decodePayload(sig)
	if err != nil || payload.Accepted == nil {
		p.clientError(w, reasonInvalidPayload)
		return
	}
	if payload.X402Version != x402Version {
		p.clientError(w, reasonInvalidVersion)
		return
	}
	req := cr.find(payload.Accepted)
	if req == nil {
		p.paymentRequired(w, r, cr, reasonInvalidRequirements)
		return
	}

	body := requestBody(raw, req.json)
	verdict, err := p.fac.verify(r.Context(), body)
	if err != nil {
		p.log.Error("facilitator verify failed", "error", err)
		p.serverError(w, reasonUnexpectedVerify)
		return
	}
	if !verdict.IsValid {
		p.paymentRequired(w, r, cr, verdict.reason("invalid_payment"))
		return
	}

	key := ""
	if p.guard != nil {
		key = guardKey(sig)
		if !p.guard.claim(key, time.Duration(cr.maxTimeout)*time.Second) {
			p.paymentRequired(w, r, cr, reasonReplay)
			return
		}
	}

	if !p.forwardPayment {
		r.Header.Del(headerSignature)
	}
	if p.payerHeader != "" && verdict.Payer != "" {
		r.Header.Set(p.payerHeader, verdict.Payer)
	}
	for k, v := range p.paidHeaders {
		r.Header.Set(k, v)
	}

	sc := &settleCtx{p: p, r: r, cr: cr, body: body}
	if p.settlesBefore(cr, r) {
		if raw, ok := sc.settleOrRespond(w, false); ok {
			w.Header().Set(headerResponse, encodeBase64(raw))
			p.exposeHeaders(w)
			p.next.ServeHTTP(w, r)
			return
		}
		p.release(key)
		return
	}

	sw := &settleWriter{ResponseWriter: w, sc: sc}
	defer func() {
		if !sw.settled {
			p.release(key)
		}
	}()
	p.next.ServeHTTP(sw, r)
	sw.finish()
}

// settlesBefore decides whether to settle before forwarding. Event streams
// always do: Yaegi hides Flusher behind its ResponseWriter wrapper, so the
// post-upstream settlement writer would hold events back.
func (p *Plugin) settlesBefore(cr *rule, r *http.Request) bool {
	if isEventStream(r) {
		return true
	}
	if cr.settlement != "" {
		return cr.settlement == settleBefore
	}
	return p.settleBefore
}

func isEventStream(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/event-stream")
}

func (p *Plugin) release(key string) {
	if p.guard != nil && key != "" {
		p.guard.release(key)
	}
}

// settleCtx carries what settlement needs once the upstream outcome is known.
type settleCtx struct {
	p    *Plugin
	r    *http.Request
	cr   *rule
	body []byte
}

// settleOrRespond settles and, on failure, writes the error response itself,
// first dropping upstream entity headers when discard is set. On success it
// returns the raw PAYMENT-RESPONSE JSON.
func (sc *settleCtx) settleOrRespond(w http.ResponseWriter, discard bool) ([]byte, bool) {
	p := sc.p
	// The upstream work is done, so settlement must outlive a client disconnect.
	verdict, raw, err := p.fac.settle(context.Background(), sc.body)
	if err != nil || !verdict.Success {
		if discard {
			dropEntityHeaders(w.Header())
		}
	}
	if err != nil {
		p.log.Error("facilitator settle failed", "error", err)
		p.serverError(w, reasonUnexpectedSettle)
		return nil, false
	}
	if !verdict.Success {
		w.Header().Set(headerResponse, encodeBase64(raw))
		p.paymentRequired(w, sc.r, sc.cr, verdict.reason("settlement_failed"))
		return nil, false
	}
	return raw, true
}
