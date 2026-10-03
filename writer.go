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
