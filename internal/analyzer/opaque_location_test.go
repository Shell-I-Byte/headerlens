package analyzer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression BUG-HL-070: data/mailto/javascript URI payloads live in URL.Opaque
// OR URL.Path and bypassed URL userinfo/query/fragment redaction. The same
// normalization applies to final response, blocked redirect, and 1xx evidence.
func TestOpaqueLocationPrivacyAtNetworkBoundary(t *testing.T) {
	const secret = "run17-private-content-in-opaque-uri"
	cases := []struct{ name, location, redacted string }{
		{"mailto", "mailto:" + secret + "@example.invalid", "mailto:REDACTED"},
		{"data", "data:text/plain," + secret, "data:REDACTED"},
		{"javascript-path", "javascript:/*" + secret + "*/void(0)", "javascript:REDACTED"},
		{"ftp", "ftp://other.example/" + secret, "ftp:REDACTED"},
		{"https-no-authority", "https:/*" + secret + "*/", "https:REDACTED"},
		{"malformed-data", "data:text/plain,%ZZ" + secret, "data:REDACTED"},
		{"malformed-javascript-path", "javascript:/%ZZ" + secret, "javascript:REDACTED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", tc.location)
				if tc.name == "malformed-javascript-path" {
					w.WriteHeader(http.StatusCreated)
				} else {
					w.WriteHeader(http.StatusFound)
				}
			}))
			defer server.Close()
			got, err := Analyze(context.Background(), server.URL, Options{ToolVersion: "test", MaxRedirects: 3})
			if err != nil {
				t.Fatal(err)
			}
			if got.SchemaVersion != ResultSchemaVersion {
				t.Fatalf("schema=%q", got.SchemaVersion)
			}
			if len(got.Headers["Location"]) != 1 || got.Headers["Location"][0] != tc.redacted {
				t.Fatalf("Location=%q want %q", got.Headers["Location"], tc.redacted)
			}
			blob, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(blob), secret) {
				t.Fatalf("secret survived default machine result: %s", blob)
			}
			// Raw evidence requires explicit sensitive opt-in (positive control).
			raw, err := Analyze(context.Background(), server.URL, Options{ToolVersion: "test", MaxRedirects: 3, IncludeSensitiveHeaders: true})
			if err != nil {
				t.Fatal(err)
			}
			if raw.Headers["Location"][0] != tc.location {
				t.Fatalf("opt-in changed raw location: %q", raw.Headers["Location"])
			}
			if !strings.Contains(raw.Headers["Location"][0], secret) {
				t.Fatal("positive control unexpectedly removed raw payload")
			}
		})
	}
}

func TestOpaqueLocationIsRedactedInInformationalResponse(t *testing.T) {
	const secret = "secret-in-103-opaque-location"
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "data:text/plain,"+secret)
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Location")
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()
	got, err := Analyze(context.Background(), s.URL, Options{ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.InterimResponses) != 1 {
		t.Fatalf("interim=%#v", got.InterimResponses)
	}
	h := got.InterimResponses[0].Headers["Location"]
	if len(h) != 1 || h[0] != "data:REDACTED" {
		t.Fatalf("1xx location %q", h)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatal("secret leaked through 1xx result")
	}
}

func TestEvidenceHashV13OpaqueURLGoldenVector(t *testing.T) {
	r := Result{
		SchemaVersion: "headerlens.result/v13",
		Tool:          "HeaderLens", ToolVersion: "ignored-version", Target: "https://example.test/start",
		FinalURL: "https://example.test/start", StatusCode: 302, HTTPVersion: "HTTP/1.1",
		Headers:         map[string][]string{"Location": {"data:REDACTED"}, "Server": {"local-fixture"}},
		HeadersRedacted: true,
		HTTPFraming:     &HTTPFramingInfo{ContentLength: 0},
		RedirectChain:   []string{"https://example.test/start"},
		RedirectBlocked: &RedirectBlock{URL: "data:REDACTED", Reason: "derived policy"},
		Findings:        []Finding{{ID: "derived-A", Severity: Warn}},
	}
	const expected = "2fc44acd0d6be533f7dfaf0dff9492a66dc5a42b297e39ef7055516396cf80ec"
	if got := evidenceHash(r); got != expected {
		t.Fatalf("v13 digest got %s want %s", got, expected)
	}
	r.ToolVersion = "new-build"
	r.RedirectBlocked.Reason = "different local decision"
	r.Findings[0].ID = "derived-B"
	if got := evidenceHash(r); got != expected {
		t.Fatalf("runtime/derived variation changed v13 digest: %s", got)
	}
	r.Headers["Location"] = []string{"mailto:REDACTED"}
	if got := evidenceHash(r); got == expected {
		t.Fatal("different normalized observation must change v13 digest")
	}
}

// Fuzz the privacy invariant for scheme-qualified non-HTTP(S) references:
// everything after the scheme delimiter is a response-controlled payload.
func FuzzOpaqueLocationRedactionSchemeOnly(f *testing.F) {
	for _, seed := range []string{
		"data:text/plain,credential", "mailto:user@internal.invalid",
		"javascript:/some/path%ZZ", "ftp://user:pass@example.invalid/private",
		"foo://a/b?q=x#fragment", "TeSt-Scheme:/suffix",
		"javascript:/*payload*/void(0)", "custom:/payload;param",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		colon := strings.IndexByte(raw, ':')
		if colon < 1 || !validSchemeName(raw[:colon]) {
			return
		}
		scheme := raw[:colon]
		if strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "https") {
			return
		}
		got := redactLocationValue(raw)
		want := strings.ToLower(scheme) + ":REDACTED"
		if got != want {
			t.Fatalf("non-HTTP URI leaked or mutated payload: input=%q got=%q want=%q", raw, got, want)
		}
	})
}
