package traefikx402

import (
	"net/http"
	"strconv"
	"strings"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

const exposedHeaders = headerRequired + ", " + headerResponse

// resourceURL builds the ResourceInfo url for a request.
func (p *Plugin) resourceURL(r *http.Request) string {
	base := p.baseURL
	if base == "" {
		scheme := schemeHTTP
		if r.TLS != nil {
			scheme = schemeHTTPS
		}
		if f := firstValue(r.Header.Get("X-Forwarded-Proto")); f == schemeHTTP || f == schemeHTTPS {
			scheme = f
		}
		host := firstValue(r.Header.Get("X-Forwarded-Host"))
		if host == "" {
			host = r.Host
		}
		base = scheme + "://" + host
	}
	u := base + r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		u += "?" + r.URL.RawQuery
	}
	return u
}

func firstValue(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// requiredJSON encodes a PaymentRequired object for the request.
func (p *Plugin) requiredJSON(r *http.Request, cr *rule, msg string) []byte {
	b := make([]byte, 0, 192+len(cr.acceptsJSON)+len(p.extensions))
	b = append(b, `{"x402Version":2,"error":`...)
	b = appendJSONString(b, msg)
	b = append(b, `,"resource":{"url":`...)
	b = appendJSONString(b, p.resourceURL(r))
	if cr.description != "" {
		b = append(b, `,"description":`...)
		b = appendJSONString(b, cr.description)
	}
	if cr.mimeType != "" {
		b = append(b, `,"mimeType":`...)
		b = appendJSONString(b, cr.mimeType)
	}
	b = append(b, `},"accepts":`...)
	b = append(b, cr.acceptsJSON...)
	if p.extensions != nil {
		b = append(b, `,"extensions":`...)
		b = append(b, p.extensions...)
	}
	return append(b, '}')
}

func (p *Plugin) exposeHeaders(w http.ResponseWriter) {
	w.Header().Add("Access-Control-Expose-Headers", exposedHeaders)
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body) // #nosec G705 -- body is JSON built by this plugin; a failed write means the client left
}

// paymentRequired answers 402 with the PAYMENT-REQUIRED header and body.
func (p *Plugin) paymentRequired(w http.ResponseWriter, r *http.Request, cr *rule, msg string) {
	body := p.requiredJSON(r, cr, msg)
	w.Header().Set(headerRequired, encodeBase64(body))
	p.exposeHeaders(w)
	writeJSON(w, http.StatusPaymentRequired, body)
}

func errorBody(reason string) []byte {
	b := append([]byte(`{"error":`), appendJSONString(nil, reason)...)
	return append(b, '}')
}

// clientError answers 400 for a malformed payment.
func (p *Plugin) clientError(w http.ResponseWriter, reason string) {
	writeJSON(w, http.StatusBadRequest, errorBody(reason))
}

// serverError answers 500 for a facilitator or internal failure.
func (p *Plugin) serverError(w http.ResponseWriter, reason string) {
	writeJSON(w, http.StatusInternalServerError, errorBody(reason))
}
