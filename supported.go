package traefikx402

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	supportCheckOff    = "off"
	supportCheckWarn   = "warn"
	supportCheckStrict = "strict"

	// extraFeePayer is the one scheme parameter a facilitator supplies for
	// Solana: the exact scheme requires it in PaymentRequirements.extra.
	extraFeePayer = "feePayer"
)

// supportedKind is one entry of the facilitator's GET /supported response.
type supportedKind struct {
	Extra       map[string]interface{} `json:"extra"`
	Scheme      string                 `json:"scheme"`
	Network     string                 `json:"network"`
	X402Version int                    `json:"x402Version"`
}

type supportedResponse struct {
	Kinds []supportedKind `json:"kinds"`
}

func validSupportCheck(s string) error {
	if s != "" && s != supportCheckOff && s != supportCheckWarn && s != supportCheckStrict {
		return fmt.Errorf("supportedCheck %q must be %q, %q or %q", s, supportCheckOff, supportCheckWarn, supportCheckStrict)
	}
	return nil
}

// supported fetches the facilitator's advertised payment kinds.
func (f *facilitator) supported(ctx context.Context) ([]supportedKind, error) {
	data, err := f.do(ctx, http.MethodGet, f.supportedURL, nil, false)
	if err != nil {
		return nil, err
	}
	var r supportedResponse
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("facilitator /supported response: %w", err)
	}
	return r.Kinds, nil
}

func findKind(kinds []supportedKind, scheme, network string) *supportedKind {
	for i := range kinds {
		k := &kinds[i]
		if k.X402Version == x402Version && k.Scheme == scheme && k.Network == network {
			return k
		}
	}
	return nil
}

// unsupportedAccepts lists the options the facilitator does not advertise.
func unsupportedAccepts(rules []Rule, defaults []Accept, kinds []supportedKind) []string {
	seen := map[string]bool{}
	var out []string
	check := func(accs []Accept) {
		for _, a := range accs {
			a.applyDefaults()
			id := a.Scheme + " on " + a.Network
			if !seen[id] && findKind(kinds, a.Scheme, a.Network) == nil {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	check(defaults)
	for i := range rules {
		check(rules[i].Accepts)
	}
	sort.Strings(out)
	return out
}

// withFacilitatorExtra returns a copy of accs with the facilitator's feePayer
// added where the operator set none. Configured values always win.
func withFacilitatorExtra(accs []Accept, kinds []supportedKind) []Accept {
	out := make([]Accept, len(accs))
	for i, a := range accs {
		out[i] = a
		a.applyDefaults()
		k := findKind(kinds, a.Scheme, a.Network)
		if k == nil {
			continue
		}
		fp, ok := k.Extra[extraFeePayer].(string)
		if _, set := a.Extra[extraFeePayer]; !ok || fp == "" || set {
			continue
		}
		extra := make(map[string]string, len(a.Extra)+1)
		for ek, ev := range a.Extra {
			extra[ek] = ev
		}
		extra[extraFeePayer] = fp
		out[i].Extra = extra
	}
	return out
}

// describeProblems formats unsupported options for logs and errors.
func describeProblems(p []string) string {
	return strings.Join(p, ", ")
}

// applySupported fetches /supported and fails fast when it cannot or when the
// facilitator lacks a configured option. It returns rules and defaults with
// the facilitator's feePayer filled in.
func (p *Plugin) applySupported(ctx context.Context, timeout time.Duration, rules []Rule, defaults []Accept) ([]Rule, []Accept, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	kinds, err := p.fac.supported(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("facilitator /supported: %w", err)
	}
	if bad := unsupportedAccepts(rules, defaults, kinds); len(bad) > 0 {
		return nil, nil, fmt.Errorf("facilitator does not support: %s", describeProblems(bad))
	}
	out := make([]Rule, len(rules))
	for i := range rules {
		out[i] = rules[i]
		out[i].Accepts = withFacilitatorExtra(rules[i].Accepts, kinds)
	}
	return out, withFacilitatorExtra(defaults, kinds), nil
}

// warnUnsupported logs options the facilitator does not advertise. It runs in
// the background so a slow facilitator never delays Traefik's start.
func (p *Plugin) warnUnsupported(timeout time.Duration, rules []Rule, defaults []Accept) {
	defer close(p.supportedDone)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	kinds, err := p.fac.supported(ctx)
	if err != nil {
		p.log.Warn("facilitator /supported check failed", "error", err)
		return
	}
	if bad := unsupportedAccepts(rules, defaults, kinds); len(bad) > 0 {
		p.log.Warn("facilitator does not advertise configured payment options", "options", describeProblems(bad))
	}
}
