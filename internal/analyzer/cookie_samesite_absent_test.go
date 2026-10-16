package analyzer

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// ParseSetCookie leaves SameSite at the zero value when the attribute is
// absent. That is distinct from the nonzero SameSiteDefaultMode constant.
func TestCookieSameSitePresenceAndValidControls(t *testing.T) {
	cases := []struct {
		name, raw        string
		missing, invalid bool
	}{
		{"absent", "session=synthetic-secret; Path=/", true, false},
		{"absent_hardened_other_attributes", "session=synthetic-secret; Secure; HttpOnly; Path=/", true, false},
		{"strict", "session=synthetic-secret; Secure; SameSite=Strict", false, false},
		{"lax", "session=synthetic-secret; Secure; SameSite=Lax", false, false},
		{"none", "session=synthetic-secret; Secure; SameSite=None", false, false},
		{"case_insensitive", "session=synthetic-secret; Secure; sAmEsItE=sTrIcT", false, false},
		{"invalid", "session=synthetic-secret; SameSite=bogus", false, true},
		{"empty", "session=synthetic-secret; SameSite=", false, true},
		{"bare", "session=synthetic-secret; SameSite", false, true},
		{"duplicate_last_valid", "session=synthetic-secret; SameSite=bogus; SameSite=Strict", false, false},
		{"duplicate_last_invalid", "session=synthetic-secret; SameSite=Strict; SameSite=bogus", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse("https://example.test/")
			if err != nil {
				t.Fatal(err)
			}
			response := &http.Response{StatusCode: 200, Header: http.Header{
				"Content-Type": {"text/html"}, "Set-Cookie": {tc.raw},
			}, Request: &http.Request{URL: u}}
			findings := analyzeHeaders(response)
			missing, invalid := false, false
			for _, f := range findings {
				if f.ID == "HL-COOKIE-SAMESITE-SESSION" {
					missing = true
					if f.Severity != Info {
						t.Fatalf("missing SameSite must be contextual INFO, got %s", f.Severity)
					}
				}
				if f.ID == "HL-COOKIE-SAMESITE-INVALID-SESSION" {
					invalid = true
				}
				if strings.Contains(f.Evidence, "synthetic-secret") {
					t.Fatal("cookie secret leaked in finding")
				}
			}
			if missing != tc.missing || invalid != tc.invalid {
				t.Fatalf("missing=%v invalid=%v; want missing=%v invalid=%v", missing, invalid, tc.missing, tc.invalid)
			}
		})
	}
}
