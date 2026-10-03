package traefikx402

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	authCDP = "cdp"

	prefixEnv  = "env:"
	prefixFile = "file:"

	cdpIssuer      = "cdp"
	cdpAudience    = "cdp_service"
	cdpLifetime    = 120 * time.Second
	cdpReuseMargin = 30 * time.Second
	cdpNonceBytes  = 16
	ecCoordBytes   = 32
	pemMarker      = "-----BEGIN"
)

// FacilitatorAuth configures per-request facilitator credentials.
type FacilitatorAuth struct {
	Type      string `json:"type,omitempty"`
	KeyID     string `json:"keyID,omitempty"`
	KeySecret string `json:"keySecret,omitempty"`
}

// requestSigner adds credentials to an outgoing facilitator request.
type requestSigner interface {
	sign(req *http.Request) error
}

// resolveSecret expands "env:NAME" and "file:/path" references so secrets
// stay out of the Traefik dynamic configuration. Other values pass through.
func resolveSecret(v string) (string, error) {
	switch {
	case strings.HasPrefix(v, prefixEnv):
		name := strings.TrimPrefix(v, prefixEnv)
		val := os.Getenv(name)
		if val == "" {
			return "", fmt.Errorf("environment variable %q is empty", name)
		}
		return val, nil
	case strings.HasPrefix(v, prefixFile):
		path := strings.TrimPrefix(v, prefixFile)
		b, err := os.ReadFile(path) // #nosec G304 -- the operator names the secret file in configuration
		if err != nil {
			return "", fmt.Errorf("read secret file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return v, nil
}

func (a *FacilitatorAuth) validate() error {
	switch a.Type {
	case "":
		return nil
	case authCDP:
		if a.KeyID == "" || a.KeySecret == "" {
			return errors.New("facilitatorAuth type cdp needs keyID and keySecret")
		}
		return nil
	}
	return fmt.Errorf("facilitatorAuth type %q must be empty or %q", a.Type, authCDP)
}

// newSigner builds the signer for the configured auth type; nil means none.
func newSigner(a *FacilitatorAuth, now func() time.Time) (requestSigner, error) {
	if a.Type == "" {
		return nil, nil
	}
	id, err := resolveSecret(a.KeyID)
	if err != nil {
		return nil, fmt.Errorf("facilitatorAuth keyID: %w", err)
	}
	secret, err := resolveSecret(a.KeySecret)
	if err != nil {
		return nil, fmt.Errorf("facilitatorAuth keySecret: %w", err)
	}
	s, err := newCDPSigner(id, secret, now)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// cdpSigner signs Coinbase Developer Platform API-key JWTs. A token is bound
// to one "METHOD host/path", so a handful are cached and reused until close to expiry.
type cdpSigner struct {
	now   func() time.Time
	ec    *ecdsa.PrivateKey
	cache map[string]cdpToken
	keyID string
	ed    ed25519.PrivateKey
	mu    sync.Mutex
}

type cdpToken struct {
	expires time.Time
	value   string
}

type cdpClaims struct {
	Sub string   `json:"sub"`
	Iss string   `json:"iss"`
	URI string   `json:"uri"`
	Aud []string `json:"aud"`
	Nbf int64    `json:"nbf"`
	Exp int64    `json:"exp"`
}

type cdpHeader struct {
	Alg   string `json:"alg"`
	Typ   string `json:"typ"`
	Kid   string `json:"kid"`
	Nonce string `json:"nonce"`
}

func newCDPSigner(keyID, secret string, now func() time.Time) (*cdpSigner, error) {
	s := &cdpSigner{keyID: keyID, now: now, cache: make(map[string]cdpToken)}
	secret = strings.TrimSpace(strings.ReplaceAll(secret, `\n`, "\n"))
	if strings.HasPrefix(secret, pemMarker) {
		key, err := parseECKey(secret)
		if err != nil {
			return nil, err
		}
		s.ec = key
		return s, nil
	}
	raw, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("facilitatorAuth keySecret is neither PEM nor base64: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize, ed25519.PrivateKeySize:
		s.ed = ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
	default:
		return nil, fmt.Errorf("facilitatorAuth keySecret decodes to %d bytes, want 32 or 64", len(raw))
	}
	return s, nil
}

func parseECKey(pemText string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("facilitatorAuth keySecret holds invalid PEM")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return requireP256(k)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("facilitatorAuth keySecret is not an EC private key: %w", err)
	}
	k, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("facilitatorAuth keySecret is not an EC private key")
	}
	return requireP256(k)
}

func requireP256(k *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	if k.Curve != elliptic.P256() {
		return nil, errors.New("facilitatorAuth EC key must use curve P-256 for ES256")
	}
	return k, nil
}

func (s *cdpSigner) sign(req *http.Request) error {
	tok, err := s.token(req.Method + " " + req.URL.Host + req.URL.Path)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return nil
}

func (s *cdpSigner) token(uri string) (string, error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.cache[uri]; ok && now.Add(cdpReuseMargin).Before(t.expires) {
		return t.value, nil
	}
	v, err := s.build(uri, now)
	if err != nil {
		return "", err
	}
	s.cache[uri] = cdpToken{value: v, expires: now.Add(cdpLifetime)}
	return v, nil
}

func (s *cdpSigner) build(uri string, now time.Time) (string, error) {
	nonce := make([]byte, cdpNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	alg := "EdDSA"
	if s.ec != nil {
		alg = "ES256"
	}
	h, err := json.Marshal(cdpHeader{Alg: alg, Typ: "JWT", Kid: s.keyID, Nonce: hex.EncodeToString(nonce)})
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(cdpClaims{
		Sub: s.keyID, Iss: cdpIssuer, Aud: []string{cdpAudience},
		Nbf: now.Unix(), Exp: now.Add(cdpLifetime).Unix(), URI: uri,
	})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	sig, err := s.signBytes([]byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + enc.EncodeToString(sig), nil
}

func (s *cdpSigner) signBytes(msg []byte) ([]byte, error) {
	if s.ec == nil {
		return ed25519.Sign(s.ed, msg), nil
	}
	digest := sha256.Sum256(msg)
	der, err := ecdsa.SignASN1(rand.Reader, s.ec, digest[:])
	if err != nil {
		return nil, err
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &rs); err != nil {
		return nil, err
	}
	out := make([]byte, 2*ecCoordBytes)
	rs.R.FillBytes(out[:ecCoordBytes])
	rs.S.FillBytes(out[ecCoordBytes:])
	return out, nil
}
