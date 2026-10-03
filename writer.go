package traefikx402

import "net/http"

// staleEntityHeaders describe an upstream body that a failed settlement discards.
var staleEntityHeaders = []string{
	"Content-Length", "Content-Type", "Content-Encoding", "Content-Range",
	"Etag", "Last-Modified", "Transfer-Encoding", "Set-Cookie", "Accept-Ranges",
}

func dropEntityHeaders(h http.Header) {
	for _, k := range staleEntityHeaders {
		h.Del(k)
	}
}

// settleWriter settles the payment when the upstream commits to a success
// status, before any byte reaches the client. Error statuses are never charged
// and the body streams through without buffering.
type settleWriter struct {
	http.ResponseWriter
	sc          *settleCtx
	wroteHeader bool
	settled     bool
	failed      bool
}

func (sw *settleWriter) WriteHeader(code int) {
	if sw.wroteHeader {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		sw.ResponseWriter.WriteHeader(code)
		return
	}
	sw.wroteHeader = true
	if code >= 400 {
		sw.ResponseWriter.WriteHeader(code)
		return
	}
	if !sw.settle() {
		return
	}
	sw.ResponseWriter.WriteHeader(code)
}

// settle runs settlement once; it reports whether the upstream response may proceed.
func (sw *settleWriter) settle() bool {
	raw, ok := sw.sc.settleOrRespond(sw.ResponseWriter, true)
	if !ok {
		sw.failed = true
		return false
	}
	sw.settled = true
	sw.ResponseWriter.Header().Set(headerResponse, encodeBase64(raw))
	sw.sc.p.exposeHeaders(sw.ResponseWriter)
	return true
}

func (sw *settleWriter) Write(b []byte) (int, error) {
	if !sw.wroteHeader {
		sw.WriteHeader(http.StatusOK)
	}
	if sw.failed {
		return len(b), nil
	}
	return sw.ResponseWriter.Write(b)
}

func (sw *settleWriter) Flush() {
	if !sw.wroteHeader {
		sw.WriteHeader(http.StatusOK)
	}
	if sw.failed {
		return
	}
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the real writer.
func (sw *settleWriter) Unwrap() http.ResponseWriter { return sw.ResponseWriter }

// finish commits an implicit 200 when the upstream wrote nothing.
func (sw *settleWriter) finish() {
	if !sw.wroteHeader {
		sw.WriteHeader(http.StatusOK)
	}
}

// challengeWriter answers a request that carries no payment. It passes the
// upstream response through, except for the challenge statuses, which become a
// 402 payment request. The upstream never sees a payment here.
type challengeWriter struct {
	http.ResponseWriter
	p           *Plugin
	r           *http.Request
	cr          *rule
	wroteHeader bool
	converted   bool
}

func (cw *challengeWriter) WriteHeader(code int) {
	if cw.wroteHeader {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		cw.ResponseWriter.WriteHeader(code)
		return
	}
	cw.wroteHeader = true
	if !cw.cr.challenge[code] {
		cw.ResponseWriter.WriteHeader(code)
		return
	}
	cw.converted = true
	dropEntityHeaders(cw.Header())
	cw.p.paymentRequired(cw.ResponseWriter, cw.r, cw.cr, msgSignatureRequired)
}

func (cw *challengeWriter) Write(b []byte) (int, error) {
	if !cw.wroteHeader {
		cw.WriteHeader(http.StatusOK)
	}
	if cw.converted {
		return len(b), nil
	}
	return cw.ResponseWriter.Write(b)
}

func (cw *challengeWriter) Flush() {
	if cw.converted {
		return
	}
	if f, ok := cw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the real writer.
func (cw *challengeWriter) Unwrap() http.ResponseWriter { return cw.ResponseWriter }
