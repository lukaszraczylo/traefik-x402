package traefikx402

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"
)

// x402 v2 HTTP transport constants.
const (
	x402Version = 2

	headerRequired  = "PAYMENT-REQUIRED"
	headerSignature = "PAYMENT-SIGNATURE"
	headerResponse  = "PAYMENT-RESPONSE"

	maxPayloadHeaderBytes = 64 << 10
	maxFacilitatorBody    = 1 << 20

	msgSignatureRequired = "PAYMENT-SIGNATURE header is required"
)

// Error reasons surfaced to clients; the first group mirrors the x402 spec codes.
const (
	reasonInvalidPayload      = "invalid_payload"
	reasonInvalidVersion      = "invalid_x402_version"
	reasonInvalidRequirements = "invalid_payment_requirements"
	reasonUnexpectedVerify    = "unexpected_verify_error"
	reasonUnexpectedSettle    = "unexpected_settle_error"
	reasonReplay              = "payment_already_used"
)

var errBadBase64 = errors.New("payment header is not valid base64")

// acceptedReq is the PaymentRequirements object echoed in a PaymentPayload.
type acceptedReq struct {
	Extra             map[string]interface{} `json:"extra"`
	Scheme            string                 `json:"scheme"`
	Network           string                 `json:"network"`
	Amount            string                 `json:"amount"`
	Asset             string                 `json:"asset"`
	PayTo             string                 `json:"payTo"`
	MaxTimeoutSeconds int                    `json:"maxTimeoutSeconds"`
}

// paymentPayload is the subset of PaymentPayload the middleware inspects. The
// full decoded bytes are forwarded to the facilitator untouched.
type paymentPayload struct {
	Accepted    *acceptedReq `json:"accepted"`
	X402Version int          `json:"x402Version"`
}

// facilitatorVerdict decodes both /verify and /settle responses.
type facilitatorVerdict struct {
	InvalidReason string `json:"invalidReason"`
	ErrorReason   string `json:"errorReason"`
	Message       string `json:"invalidMessage"`
	ErrorMessage  string `json:"errorMessage"`
	Payer         string `json:"payer"`
	IsValid       bool   `json:"isValid"`
	Success       bool   `json:"success"`
}

func (v *facilitatorVerdict) reason(fallback string) string {
	for _, s := range []string{v.InvalidReason, v.ErrorReason} {
		if s != "" {
			return s
		}
	}
	return fallback
}

// decodePayload base64-decodes a PAYMENT-SIGNATURE value and parses it.
func decodePayload(sig string) (*paymentPayload, []byte, error) {
	raw, err := decodeBase64(sig)
	if err != nil {
		return nil, nil, err
	}
	var p paymentPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, nil, err
	}
	return &p, raw, nil
}

// decodeBase64 accepts standard and URL-safe alphabets, padded or not.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errBadBase64
}

func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// appendJSONString appends s as a JSON string literal, replacing invalid UTF-8.
func appendJSONString(dst []byte, s string) []byte {
	const hex = "0123456789abcdef"
	dst = append(dst, '"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch {
			case c == '"' || c == '\\':
				dst = append(dst, '\\', c)
			case c < 0x20:
				dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
			default:
				dst = append(dst, c)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			dst = append(dst, `�`...)
		} else {
			dst = append(dst, s[i:i+size]...)
		}
		i += size
	}
	return append(dst, '"')
}

// sameAccept reports whether the client-echoed requirements equal a configured one.
func sameAccept(got *acceptedReq, want *Accept) bool {
	if got.Scheme != want.Scheme || got.Network != want.Network || got.Amount != want.Amount ||
		got.Asset != want.Asset || got.PayTo != want.PayTo || got.MaxTimeoutSeconds != want.MaxTimeoutSeconds {
		return false
	}
	if len(got.Extra) != len(want.Extra) {
		return false
	}
	for k, wv := range want.Extra {
		gv, ok := got.Extra[k].(string)
		if !ok || gv != wv {
			return false
		}
	}
	return true
}
