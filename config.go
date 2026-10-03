package traefikx402

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	schemeExact       = "exact"
	settleAfter       = "after"
	settleBefore      = "before"
	defaultTimeoutSec = 60
	defaultFacTimeout = "10s"
)

// Accept is one acceptable payment method (x402 PaymentRequirements).
// A rule lists several to accept multiple assets or networks for one path.
type Accept struct {
	Extra             map[string]string `json:"extra,omitempty"`
	Scheme            string            `json:"scheme,omitempty"`
	Network           string            `json:"network"`
	Amount            string            `json:"amount"`
	Asset             string            `json:"asset"`
	PayTo             string            `json:"payTo"`
	MaxTimeoutSeconds int               `json:"maxTimeoutSeconds,omitempty"`
}

// Rule selects the paths a payment is enforced on. A request matches when
// its path equals any Exact entry, starts with any Prefix, or ends with any Suffix.
type Rule struct {
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	MimeType    string   `json:"mimeType,omitempty"`
	Settlement  string   `json:"settlement,omitempty"`
	Exact       []string `json:"exact,omitempty"`
	Prefixes    []string `json:"prefixes,omitempty"`
	Suffixes    []string `json:"suffixes,omitempty"`
	Methods     []string `json:"methods,omitempty"`
	Accepts     []Accept `json:"accepts,omitempty"`
}

// Config is the plugin configuration.
type Config struct {
	// Accepts is the default payment list for rules that declare none.
	// Exact, Prefixes, Suffixes, Methods, Description and MimeType form an
	// implicit rule appended after Rules, using the default Accepts.
	FacilitatorHeaders       map[string]string `json:"facilitatorHeaders,omitempty"`
	PayerHeader              string            `json:"payerHeader,omitempty"`
	FacilitatorTimeout       string            `json:"facilitatorTimeout,omitempty"`
	MimeType                 string            `json:"mimeType,omitempty"`
	Settlement               string            `json:"settlement,omitempty"`
	Description              string            `json:"description,omitempty"`
	ResourceBaseURL          string            `json:"resourceBaseURL,omitempty"`
	ExtensionsJSON           string            `json:"extensionsJSON,omitempty"`
	FacilitatorURL           string            `json:"facilitatorURL,omitempty"`
	Suffixes                 []string          `json:"suffixes,omitempty"`
	Accepts                  []Accept          `json:"accepts,omitempty"`
	Exact                    []string          `json:"exact,omitempty"`
	Prefixes                 []string          `json:"prefixes,omitempty"`
	Methods                  []string          `json:"methods,omitempty"`
	Rules                    []Rule            `json:"rules,omitempty"`
	ForwardPaymentHeader     bool              `json:"forwardPaymentHeader,omitempty"`
	IgnoreCase               bool              `json:"ignoreCase,omitempty"`
	ReplayGuard              bool              `json:"replayGuard"`
	AllowInsecureFacilitator bool              `json:"allowInsecureFacilitator,omitempty"`
}

// CreateConfig returns the default configuration.
func CreateConfig() *Config {
	return &Config{
		FacilitatorTimeout: defaultFacTimeout,
		Settlement:         settleAfter,
		ReplayGuard:        true,
	}
}

func (a *Accept) applyDefaults() {
	if a.Scheme == "" {
		a.Scheme = schemeExact
	}
	if a.MaxTimeoutSeconds == 0 {
		a.MaxTimeoutSeconds = defaultTimeoutSec
	}
}

func (a *Accept) validate() error {
	if !validCAIP2(a.Network) {
		return fmt.Errorf("network %q is not a CAIP-2 identifier (namespace:reference)", a.Network)
	}
	if a.Amount == "" || !allDigits(a.Amount) {
		return fmt.Errorf("amount %q must be a decimal string in atomic units", a.Amount)
	}
	if a.Asset == "" {
		return errors.New("asset is required")
	}
	if a.PayTo == "" {
		return errors.New("payTo is required")
	}
	if a.MaxTimeoutSeconds < 0 {
		return errors.New("maxTimeoutSeconds must be positive")
	}
	return nil
}

func validCAIP2(s string) bool {
	i := strings.IndexByte(s, ':')
	if i < 3 || i > 8 || len(s)-i-1 < 1 || len(s)-i-1 > 32 {
		return false
	}
	for j := 0; j < len(s); j++ {
		c := s[j]
		if j == i {
			continue
		}
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
		if j > i {
			ok = ok || c >= 'A' && c <= 'Z' || c == '_'
		}
		if !ok {
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

func (c *Config) facilitatorTimeout() (time.Duration, error) {
	s := c.FacilitatorTimeout
	if s == "" {
		s = defaultFacTimeout
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("facilitatorTimeout %q must be a positive duration like 10s", s)
	}
	return d, nil
}

// Validate checks the configuration without mutating it.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	u, err := url.Parse(c.FacilitatorURL)
	if err != nil || u.Host == "" || (u.Scheme != schemeHTTPS && u.Scheme != schemeHTTP) {
		return fmt.Errorf("facilitatorURL %q must be an absolute http(s) URL", c.FacilitatorURL)
	}
	if u.Scheme == schemeHTTP && !c.AllowInsecureFacilitator {
		return errors.New("facilitatorURL uses http; set allowInsecureFacilitator to permit it")
	}
	if _, err := c.facilitatorTimeout(); err != nil {
		return err
	}
	if err := validSettlement(c.Settlement); err != nil {
		return err
	}
	if c.ResourceBaseURL != "" {
		b, err := url.Parse(c.ResourceBaseURL)
		if err != nil || b.Host == "" || b.Scheme == "" {
			return fmt.Errorf("resourceBaseURL %q must be an absolute URL", c.ResourceBaseURL)
		}
	}
	if c.ExtensionsJSON != "" {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(c.ExtensionsJSON), &m); err != nil {
			return fmt.Errorf("extensionsJSON must be a JSON object: %v", err)
		}
	}
	for _, a := range c.Accepts {
		if err := a.validateWithDefaults(); err != nil {
			return fmt.Errorf("accepts: %v", err)
		}
	}
	rules := c.allRules()
	if len(rules) == 0 {
		return errors.New("no rules: set exact, prefixes, suffixes or rules")
	}
	for i := range rules {
		if err := rules[i].validate(len(c.Accepts) > 0); err != nil {
			return fmt.Errorf("rule %d (%s): %v", i, rules[i].Name, err)
		}
	}
	return nil
}

func (a Accept) validateWithDefaults() error {
	a.applyDefaults()
	return a.validate()
}

func validSettlement(s string) error {
	if s != "" && s != settleAfter && s != settleBefore {
		return fmt.Errorf("settlement %q must be %q or %q", s, settleAfter, settleBefore)
	}
	return nil
}

func (r *Rule) validate(haveDefaultAccepts bool) error {
	if err := validSettlement(r.Settlement); err != nil {
		return err
	}
	if len(r.Exact)+len(r.Prefixes)+len(r.Suffixes) == 0 {
		return errors.New("needs at least one of exact, prefixes, suffixes")
	}
	for _, p := range r.Exact {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("exact %q must start with /", p)
		}
	}
	for _, p := range r.Prefixes {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("prefix %q must start with /", p)
		}
	}
	for _, s := range r.Suffixes {
		if s == "" {
			return errors.New("suffix must not be empty")
		}
	}
	if len(r.Accepts) == 0 && !haveDefaultAccepts {
		return errors.New("no accepts: set accepts on the rule or at top level")
	}
	for _, a := range r.Accepts {
		if err := a.validateWithDefaults(); err != nil {
			return err
		}
	}
	return nil
}

// allRules returns Rules plus the implicit top-level rule when it selects paths.
func (c *Config) allRules() []Rule {
	rules := append([]Rule(nil), c.Rules...)
	if len(c.Exact)+len(c.Prefixes)+len(c.Suffixes) > 0 {
		rules = append(rules, Rule{
			Name:        "default",
			Exact:       c.Exact,
			Prefixes:    c.Prefixes,
			Suffixes:    c.Suffixes,
			Methods:     c.Methods,
			Description: c.Description,
			MimeType:    c.MimeType,
		})
	}
	return rules
}
