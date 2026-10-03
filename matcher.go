package traefikx402

import (
	"net/http"
	"path"
	"strings"
)

// rule is a compiled Rule: lookups are map or prefix scans, nothing allocates per request.
type rule struct {
	exact       map[string]bool
	methods     map[string]bool
	name        string
	description string
	mimeType    string
	settlement  string
	prefixes    []string
	suffixes    []string
	reqs        []requirement
	acceptsJSON []byte
	maxTimeout  int
}

// requirement is a configured Accept with its pre-encoded JSON.
type requirement struct {
	Accept
	json []byte
}

func compileRule(r *Rule, defaults []Accept, ignoreCase bool) *rule {
	cr := &rule{
		name:        r.Name,
		description: r.Description,
		mimeType:    r.MimeType,
		settlement:  r.Settlement,
		exact:       make(map[string]bool, len(r.Exact)),
	}
	for _, e := range r.Exact {
		cr.exact[foldCase(e, ignoreCase)] = true
	}
	for _, p := range r.Prefixes {
		cr.prefixes = append(cr.prefixes, foldCase(p, ignoreCase))
	}
	for _, s := range r.Suffixes {
		cr.suffixes = append(cr.suffixes, foldCase(s, ignoreCase))
	}
	if len(r.Methods) > 0 {
		cr.methods = make(map[string]bool, len(r.Methods))
		for _, m := range r.Methods {
			cr.methods[strings.ToUpper(m)] = true
		}
	}
	accepts := r.Accepts
	if len(accepts) == 0 {
		accepts = defaults
	}
	cr.acceptsJSON = append(cr.acceptsJSON, '[')
	for i, a := range accepts {
		a.applyDefaults()
		b := marshalAccept(&a)
		if i > 0 {
			cr.acceptsJSON = append(cr.acceptsJSON, ',')
		}
		cr.acceptsJSON = append(cr.acceptsJSON, b...)
		cr.reqs = append(cr.reqs, requirement{Accept: a, json: b})
		if a.MaxTimeoutSeconds > cr.maxTimeout {
			cr.maxTimeout = a.MaxTimeoutSeconds
		}
	}
	cr.acceptsJSON = append(cr.acceptsJSON, ']')
	return cr
}

func foldCase(s string, fold bool) string {
	if fold {
		return strings.ToLower(s)
	}
	return s
}

// matches reports whether the rule selects the request. Both the decoded path
// and its cleaned form are tested so "/free/../paid" cannot dodge a prefix.
func (cr *rule) matches(method, p, cleaned string) bool {
	if cr.methods != nil {
		if !cr.methods[method] {
			return false
		}
	} else if method == http.MethodOptions {
		return false
	}
	return cr.matchPath(p) || (cleaned != p && cr.matchPath(cleaned))
}

func (cr *rule) matchPath(p string) bool {
	if cr.exact[p] {
		return true
	}
	for _, pre := range cr.prefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	for _, suf := range cr.suffixes {
		if strings.HasSuffix(p, suf) {
			return true
		}
	}
	return false
}

func needsClean(p string) bool {
	return strings.Contains(p, "//") || strings.Contains(p, "/.") || (len(p) > 1 && p[len(p)-1] == '/')
}

// cleanPath normalises a request path the way a backend router might.
func cleanPath(p string) string {
	if !needsClean(p) {
		return p
	}
	c := path.Clean(p)
	if c == "." {
		return "/"
	}
	return c
}

// findRule returns the first rule selecting the request, or nil.
func (p *Plugin) findRule(r *http.Request) *rule {
	pth := r.URL.Path
	if p.ignoreCase {
		pth = strings.ToLower(pth)
	}
	cleaned := cleanPath(pth)
	for _, cr := range p.rules {
		if cr.matches(r.Method, pth, cleaned) {
			return cr
		}
	}
	return nil
}
