//go:build live

package traefikx402

import (
	"strings"
	"testing"
)

// TestLiveXFacilitator runs strict start-up against the public x402.org
// facilitator. It needs network access: go test -tags live -run Live .
func TestLiveXFacilitator(t *testing.T) {
	c := CreateConfig()
	c.FacilitatorURL = "https://x402.org/facilitator"
	c.SupportedCheck = supportCheckStrict
	c.Accepts = []Accept{
		{Network: "eip155:84532", Amount: "10000", Asset: testUSDC, PayTo: testPayTo, Extra: map[string]string{"name": "USDC", "version": "2"}},
		{Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", Amount: "10000", Asset: "devnet-usdc-mint", PayTo: "payee"},
	}
	c.Prefixes = []string{"/premium/"}
	p := newTestPlugin(t, c, okUpstream("x"))
	rec := do(p, "GET", "http://api.test/premium/x", nil)
	var pr struct{ Accepts []Accept }
	decodeHeaderJSON(t, rec.Header().Get(headerRequired), &pr)
	t.Logf("accepts advertised: %+v", pr.Accepts)
	if pr.Accepts[1].Extra["feePayer"] == "" {
		t.Fatal("feePayer not filled from /supported")
	}

	c.Accepts = []Accept{{Network: "eip155:8453", Amount: "1", Asset: "a", PayTo: "p"}}
	if _, err := newPlugin(t.Context(), okUpstream("x"), c, "n"); err == nil || !strings.Contains(err.Error(), "eip155:8453") {
		t.Fatalf("Base mainnet should be rejected by the testnet facilitator: %v", err)
	}
}
