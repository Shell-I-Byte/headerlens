package analyzer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

func responseFor(t *testing.T, target string, headers http.Header) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()
	for k, values := range headers {
		for _, v := range values {
			rr.Header().Add(k, v)
		}
	}
	resp := rr.Result()
	resp.Request = req
	return resp
}

func responseForStatus(t *testing.T, target string, status int, headers http.Header) *http.Response {
	t.Helper()
	resp := responseFor(t, target, headers)
	resp.StatusCode = status
	resp.Status = fmt.Sprintf("%d synthetic", status)
	return resp
}

func TestSecureHeaders(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Strict-Transport-Security": {"max-age=31536000; includeSubDomains"},
		"Content-Security-Policy":   {"default-src 'self'; frame-ancestors 'none'"},
		"X-Content-Type-Options":    {"nosniff"},
		"Referrer-Policy":           {"same-origin"},
		"Permissions-Policy":        {"camera=()"},
	})
	fs := analyzeHeaders(resp)
	for _, id := range []string{"HL-HSTS-002", "HL-CSP-002", "HL-XCTO-001", "HL-REF-003", "HL-PERM-002", "HL-FRAME-001"} {
		if !hasID(fs, id) {
			t.Fatalf("missing %s in %#v", id, fs)
		}
	}
}

func TestMissingHeadersWarn(t *testing.T) {
	fs := analyzeHeaders(responseFor(t, "https://example.test", nil))
	for _, id := range []string{"HL-HSTS-001", "HL-CSP-001", "HL-XCTO-002", "HL-REF-001", "HL-FRAME-002"} {
		if !hasID(fs, id) {
			t.Fatalf("expected %s", id)
		}
	}
}

func TestRejectInvalidURLAndUserinfo(t *testing.T) {
	for _, target := range []string{
		"file:///etc/passwd",
		"http://",
		"http://user:secret@example.test/",
	} {
		if _, err := Analyze(context.Background(), target, Options{Timeout: time.Second}); err == nil {
			t.Fatalf("expected invalid URL error for %q", target)
		}
	}
}

func TestCSPUnsafeDirectiveWarns(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Security-Policy": {"default-src 'self'; script-src 'unsafe-inline'"},
	})
	fs := analyzeHeaders(resp)
	if f, ok := findingByID(fs, "HL-CSP-002"); !ok || f.Severity != Warn || !strings.Contains(f.Evidence, "unsafe-inline") {
		t.Fatalf("expected risky CSP warning, got %#v", fs)
	}
}

func TestCSPFrameAncestorsRequiresDirectiveNotSubstring(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Security-Policy": {"default-src 'self'; report-uri https://reports.test/frame-ancestors"},
	})
	fs := analyzeHeaders(resp)
	if hasID(fs, "HL-FRAME-001") {
		t.Fatalf("frame-ancestors substring in report URI must not create a PASS: %#v", fs)
	}
	if !hasID(fs, "HL-FRAME-002") {
		t.Fatalf("expected missing anti-framing warning: %#v", fs)
	}
}

func TestReportOnlyFrameAncestorsDoesNotCountAsEnforcement(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Security-Policy-Report-Only": {"frame-ancestors 'none'"},
	})
	fs := analyzeHeaders(resp)
	if hasID(fs, "HL-FRAME-001") {
		t.Fatalf("report-only frame-ancestors must not count as enforced")
	}
	if !hasID(fs, "HL-CSP-003") {
		t.Fatalf("expected report-only informational finding")
	}
}

func TestHSTSQuotedMaxAgeAndDuplicateDirective(t *testing.T) {
	if max, ok, reason := parseHSTS(`max-age="31536000"; includeSubDomains`); !ok || max != 31536000 || reason != "" {
		t.Fatalf("quoted max-age should be valid: max=%d ok=%t reason=%q", max, ok, reason)
	}
	if _, ok, _ := parseHSTS("max-age=31536000; max-age=0"); ok {
		t.Fatal("duplicate HSTS directive must be invalid")
	}
	resp := responseFor(t, "https://example.test", http.Header{
		"Strict-Transport-Security": {"max-age=31536000; max-age=0"},
	})
	fs := analyzeHeaders(resp)
	if hasID(fs, "HL-HSTS-002") || !hasID(fs, "HL-HSTS-003") {
		t.Fatalf("invalid HSTS must not pass: %#v", fs)
	}
}

func TestHSTSMultipleFieldsWarnAndFirstFieldIsEvaluated(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Strict-Transport-Security": {"max-age=31536000", "max-age=0"},
	})
	fs := analyzeHeaders(resp)
	if !hasID(fs, "HL-HSTS-004") || !hasID(fs, "HL-HSTS-002") {
		t.Fatalf("expected duplicate-field warning and first-field evaluation: %#v", fs)
	}
}

func TestHSTSOverHTTPIsIgnored(t *testing.T) {
	resp := responseFor(t, "http://example.test", http.Header{
		"Strict-Transport-Security": {"max-age=31536000"},
	})
	if !hasID(analyzeHeaders(resp), "HL-HSTS-005") {
		t.Fatal("expected warning for HSTS over HTTP")
	}
}

func TestDuplicateXContentTypeOptionsDoesNotPass(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"X-Content-Type-Options": {"nosniff", "invalid"},
	})
	fs := analyzeHeaders(resp)
	if hasID(fs, "HL-XCTO-001") {
		t.Fatalf("duplicate singleton XCTO must not produce PASS: %#v", fs)
	}
	if !hasID(fs, "HL-XCTO-003") {
		t.Fatalf("expected duplicate XCTO warning: %#v", fs)
	}
}

func TestRedirectPolicyIPv4IPv6IDNAndUserinfoBoundaries(t *testing.T) {
	mustURL := func(raw string) *url.URL {
		t.Helper()
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	baseOpts := Options{MaxRedirects: 3}
	via := []*http.Request{{URL: mustURL("https://example.test/start")}}
	cases := []struct {
		name        string
		initial     string
		next        string
		wantBlocked bool
	}{
		{"ipv4 same host different port", "https://127.0.0.1:443", "https://127.0.0.1:8443", true},
		{"ipv4 different host", "https://127.0.0.1", "https://127.0.0.2", true},
		{"ipv6 same host different port", "https://[::1]:443", "https://[::1]:8443", true},
		{"ipv6 different host", "https://[::1]", "https://[::2]", true},
		{"trailing dot equivalent", "https://EXAMPLE.test.", "https://example.test", false},
		{"unicode and punycode treated conservatively distinct", "https://bücher.example", "https://xn--bcher-kva.example", true},
		{"redirect userinfo blocked", "https://example.test", "https://user:secret@example.test/next", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason := redirectBlockReason(mustURL(tc.initial), mustURL(tc.next), via, baseOpts)
			if (reason != "") != tc.wantBlocked {
				t.Fatalf("reason=%q blocked=%v want=%v", reason, reason != "", tc.wantBlocked)
			}
		})
	}
}

func TestReferrerPolicyFallbackUsesLastRecognizedPolicy(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Referrer-Policy": {"no-referrer, unsafe-url"},
	})
	fs := analyzeHeaders(resp)
	if !hasID(fs, "HL-REF-002") || hasID(fs, "HL-REF-003") {
		t.Fatalf("effective unsafe-url must warn: %#v", fs)
	}

	resp = responseFor(t, "https://example.test", http.Header{
		"Referrer-Policy": {"legacy-unknown, strict-origin-when-cross-origin"},
	})
	if !hasID(analyzeHeaders(resp), "HL-REF-003") {
		t.Fatal("last recognized referrer policy should be accepted")
	}
}

func TestInvalidReferrerPolicyWarns(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{"Referrer-Policy": {"totally-made-up"}})
	if !hasID(analyzeHeaders(resp), "HL-REF-004") {
		t.Fatal("expected invalid referrer policy warning")
	}
}

func TestDuplicateXFrameOptionsDoesNotCreatePass(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"X-Frame-Options": {"DENY", "SAMEORIGIN"},
	})
	fs := analyzeHeaders(resp)
	if !hasID(fs, "HL-FRAME-003") || hasID(fs, "HL-FRAME-001") {
		t.Fatalf("duplicate XFO must be flagged rather than passed: %#v", fs)
	}
}

func TestCookiePrefixAndSameSiteNoneRules(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Set-Cookie": {
			"__Host-session=secret; Secure; HttpOnly; Path=/wrong",
			"cross=secret; SameSite=None; HttpOnly",
		},
	})
	fs := analyzeHeaders(resp)
	if !hasID(fs, "HL-COOKIE-PREFIX-__HOST_SESSION") {
		t.Fatalf("expected __Host- prefix warning: %#v", fs)
	}
	if !hasID(fs, "HL-COOKIE-NONE-SECURE-CROSS") {
		t.Fatalf("expected SameSite=None without Secure warning: %#v", fs)
	}
}

func TestSetCookieValuesRedactedByDefault(t *testing.T) {
	h := http.Header{"Set-Cookie": {"session=supersecret; Path=/; Secure; HttpOnly"}, "Server": {"test"}}
	redacted, redactedBytes := cloneHeader(h, false)
	if redactedBytes != nil {
		t.Fatalf("valid UTF-8 headers should not require byte fallback: %#v", redactedBytes)
	}
	if strings.Contains(strings.Join(redacted["Set-Cookie"], ""), "supersecret") {
		t.Fatalf("secret leaked from redacted headers: %#v", redacted)
	}
	if !strings.Contains(redacted["Set-Cookie"][0], "session=<redacted>") || !strings.Contains(redacted["Set-Cookie"][0], "HttpOnly") {
		t.Fatalf("expected attributes to remain after value redaction: %#v", redacted)
	}
	raw, rawBytes := cloneHeader(h, true)
	if rawBytes != nil {
		t.Fatalf("valid UTF-8 headers should not require byte fallback: %#v", rawBytes)
	}
	if !strings.Contains(raw["Set-Cookie"][0], "supersecret") {
		t.Fatalf("explicit sensitive-header mode should retain value: %#v", raw)
	}
}

func TestCrossHostRedirectBlockedWithoutSendingNextRequest(t *testing.T) {
	var dstHits atomic.Int32
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dstHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer dst.Close()
	dstURL, _ := url.Parse(dst.URL)
	location := "http://localhost:" + dstURL.Port() + "/dst"

	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, location, http.StatusFound)
	}))
	defer src.Close()

	res, err := Analyze(context.Background(), src.URL, Options{Timeout: 2 * time.Second, MaxRedirects: 3})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if dstHits.Load() != 0 {
		t.Fatalf("cross-host destination received %d requests", dstHits.Load())
	}
	if res.RedirectBlocked == nil || !strings.Contains(res.RedirectBlocked.Reason, "cross-host") || !hasID(res.Findings, "HL-REDIRECT-001") {
		t.Fatalf("expected explicit blocked redirect evidence: %#v", res)
	}
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected last safe response, got %d", res.StatusCode)
	}
}

func TestAllowCrossHostRedirectExplicitly(t *testing.T) {
	var dstHits atomic.Int32
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dstHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer dst.Close()
	dstURL, _ := url.Parse(dst.URL)
	location := "http://localhost:" + dstURL.Port() + "/dst"

	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, location, http.StatusFound)
	}))
	defer src.Close()

	res, err := Analyze(context.Background(), src.URL, Options{Timeout: 2 * time.Second, MaxRedirects: 3, AllowCrossHostRedirects: true, AllowCrossPortRedirects: true})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if dstHits.Load() != 1 || res.StatusCode != http.StatusNoContent || res.RedirectBlocked != nil {
		t.Fatalf("explicitly authorized cross-host redirect did not behave as expected: hits=%d result=%#v", dstHits.Load(), res)
	}
}

func TestMaxRedirectsZeroDisablesFollowing(t *testing.T) {
	var secondHits atomic.Int32
	s := httptest.NewServer(nil)
	defer s.Close()
	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			secondHits.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/next", http.StatusFound)
	})
	res, err := Analyze(context.Background(), s.URL, Options{Timeout: 2 * time.Second, MaxRedirects: 0})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if secondHits.Load() != 0 || res.RedirectBlocked == nil {
		t.Fatalf("redirect following should be disabled: hits=%d result=%#v", secondHits.Load(), res)
	}
}

func TestSameHostRedirectAllowedByDefault(t *testing.T) {
	s := httptest.NewServer(nil)
	defer s.Close()
	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Redirect(w, r, "/next", http.StatusFound)
	})
	res, err := Analyze(context.Background(), s.URL, Options{Timeout: 2 * time.Second, MaxRedirects: 2})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.StatusCode != http.StatusNoContent || res.RedirectBlocked != nil || len(res.RedirectChain) != 2 {
		t.Fatalf("same-host redirect should be followed: %#v", res)
	}
}

func TestRedirectDowngradePolicyHelper(t *testing.T) {
	initial, _ := url.Parse("https://example.test/start")
	prevReq := &http.Request{URL: initial}
	next, _ := url.Parse("http://example.test/next")
	reason := redirectBlockReason(initial, next, []*http.Request{prevReq}, Options{MaxRedirects: 3})
	if !strings.Contains(reason, "downgrade") {
		t.Fatalf("expected downgrade block, got %q", reason)
	}
	if reason = redirectBlockReason(initial, next, []*http.Request{prevReq}, Options{MaxRedirects: 3, AllowDowngradeRedirects: true, AllowCrossPortRedirects: true}); reason != "" {
		t.Fatalf("explicitly allowed downgrade should pass helper, got %q", reason)
	}
}

func TestTimeoutIsEnforced(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()
	start := time.Now()
	_, err := Analyze(context.Background(), s.URL, Options{Timeout: 25 * time.Millisecond, MaxRedirects: 1})
	if err == nil {
		t.Fatal("expected timeout")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("timeout was not bounded; elapsed=%s", elapsed)
	}
}

func TestResponseHeaderLimitIsEnforced(t *testing.T) {
	large := strings.Repeat("x", 16*1024)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Large", large)
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()
	_, err := Analyze(context.Background(), s.URL, Options{Timeout: time.Second, MaxRedirects: 1, MaxResponseHeaderBytes: 1024})
	if err == nil {
		t.Fatal("expected oversized response headers to be rejected")
	}
}

func TestCompressionIsNotTransparentlyInjectedOrRewritten(t *testing.T) {
	var acceptEncoding string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acceptEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()
	res, err := Analyze(context.Background(), s.URL, Options{Timeout: time.Second, MaxRedirects: 1})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if acceptEncoding != "" {
		t.Fatalf("transport unexpectedly injected Accept-Encoding=%q", acceptEncoding)
	}
	if got := res.Headers["Content-Encoding"]; len(got) != 1 || got[0] != "gzip" {
		t.Fatalf("wire response header was not preserved: %#v", res.Headers)
	}
}

func TestEvidenceHashExcludesTimingMetadata(t *testing.T) {
	r1 := Result{
		SchemaVersion: ResultSchemaVersion,
		Tool:          "HeaderLens",
		ToolVersion:   "test",
		Target:        "https://example.test",
		FinalURL:      "https://example.test",
		StatusCode:    200,
		HTTPVersion:   "HTTP/2.0",
		Headers:       map[string][]string{"Server": {"unit"}},
		Findings:      []Finding{{ID: "x", Severity: Info, Category: "test", Title: "same"}},
		ScannedAt:     time.Unix(1, 0),
		DurationMS:    1,
	}
	r2 := r1
	r2.ScannedAt = time.Unix(999, 0)
	r2.DurationMS = 999
	r2.ToolVersion = "another-version"
	r2.Findings = []Finding{{ID: "changed", Severity: Fail, Category: "derived", Title: "derived finding changed"}}
	if h1, h2 := evidenceHash(r1), evidenceHash(r2); h1 == "" || h1 != h2 {
		t.Fatalf("evidence digest should ignore timing/tool-version/derived-finding metadata: %q vs %q", h1, h2)
	}
}

func TestCertificateVerificationFailureReturnsStructuredEvidence(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()
	res, err := Analyze(context.Background(), s.URL, Options{Timeout: time.Second, MaxRedirects: 1, ToolVersion: "test"})
	if err != nil {
		t.Fatalf("certificate verification failure should be a structured result, got error: %v", err)
	}
	if !hasID(res.Findings, "HL-CERT-005") || res.TLS == nil || res.TLS.CertSHA256 == "" || res.StatusCode != 0 {
		t.Fatalf("missing structured certificate verification evidence: %#v", res)
	}
}

func TestCertificateFailureAfterAllowedRedirectPreservesRedirectChain(t *testing.T) {
	tlsDst := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsDst.Close()

	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, tlsDst.URL, http.StatusFound)
	}))
	defer src.Close()

	res, err := Analyze(context.Background(), src.URL, Options{Timeout: time.Second, MaxRedirects: 2, ToolVersion: "test", AllowCrossPortRedirects: true})
	if err != nil {
		t.Fatalf("certificate verification failure after redirect should be structured, got: %v", err)
	}
	if !hasID(res.Findings, "HL-CERT-005") {
		t.Fatalf("missing certificate verification finding: %#v", res.Findings)
	}
	if res.FinalURL != tlsDst.URL {
		t.Fatalf("final URL lost failing redirect destination: got %q want %q", res.FinalURL, tlsDst.URL)
	}
	if len(res.RedirectChain) != 2 || res.RedirectChain[0] != src.URL || res.RedirectChain[1] != tlsDst.URL {
		t.Fatalf("redirect chain lost on certificate failure: %#v", res.RedirectChain)
	}
}

func TestExpiredCertificateReturnsExpiredFindingWithoutDisablingVerification(t *testing.T) {
	cert := makeServerCertificate(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	s.StartTLS()
	defer s.Close()

	res, err := Analyze(context.Background(), s.URL, Options{Timeout: time.Second, MaxRedirects: 1, ToolVersion: "test"})
	if err != nil {
		t.Fatalf("expired certificate should be represented as findings, got error: %v", err)
	}
	if !hasID(res.Findings, "HL-CERT-001") || !hasID(res.Findings, "HL-CERT-005") {
		t.Fatalf("expected expiry and verification findings: %#v", res.Findings)
	}
	if res.TLS == nil || !res.TLS.CertNotAfter.Before(time.Now()) {
		t.Fatalf("expired leaf certificate metadata missing: %#v", res.TLS)
	}
}

func makeServerCertificate(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestNormalizeHostname(t *testing.T) {
	if got := normalizeHostname("EXAMPLE.TEST."); got != "example.test" {
		t.Fatalf("got %q", got)
	}
}

func TestAnalyzePopulatesVersionedEvidenceMetadata(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=secret; HttpOnly")
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()
	res, err := Analyze(context.Background(), s.URL, Options{Timeout: time.Second, MaxRedirects: 1, ToolVersion: "0.1.2-test"})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.SchemaVersion != ResultSchemaVersion || res.Tool != "HeaderLens" || res.ToolVersion != "0.1.2-test" || len(res.EvidenceSHA256) != 64 {
		t.Fatalf("missing evidence metadata: %#v", res)
	}
	blob := fmt.Sprint(res.Headers["Set-Cookie"])
	if strings.Contains(blob, "secret") || !res.HeadersRedacted {
		t.Fatalf("default result leaked Set-Cookie secret: %s", blob)
	}
}

func hasID(fs []Finding, id string) bool {
	_, ok := findingByID(fs, id)
	return ok
}

func findingByID(fs []Finding, id string) (Finding, bool) {
	for _, f := range fs {
		if f.ID == id {
			return f, true
		}
	}
	return Finding{}, false
}

func FuzzParseHSTSNoPanic(f *testing.F) {
	for _, seed := range []string{
		"max-age=31536000",
		"max-age=\"31536000\"; includeSubDomains",
		"max-age=0",
		"max-age=1; max-age=2",
		"includeSubDomains",
		"max-age=999999999999999999999999",
		"max-age=abc",
		"; ; ;",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		maxAge, valid, _ := parseHSTS(in)
		if valid && maxAge < 0 {
			t.Fatalf("valid HSTS must not produce negative max-age: %q -> %d", in, maxAge)
		}
	})
}

func FuzzEffectiveReferrerPolicyKnownOrEmpty(f *testing.F) {
	for _, seed := range []string{
		"no-referrer",
		"no-referrer, unsafe-url",
		"bogus, strict-origin-when-cross-origin",
		"",
	} {
		f.Add(seed)
	}
	valid := map[string]bool{
		"":            true,
		"no-referrer": true, "no-referrer-when-downgrade": true, "same-origin": true,
		"origin": true, "strict-origin": true, "origin-when-cross-origin": true,
		"strict-origin-when-cross-origin": true, "unsafe-url": true,
	}
	f.Fuzz(func(t *testing.T, in string) {
		got := effectiveReferrerPolicy(in)
		if !valid[got] {
			t.Fatalf("unexpected effective policy %q for input %q", got, in)
		}
	})
}

func TestFrameAncestorsWildcardOverridesXFOAndWarns(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Security-Policy": {"frame-ancestors *"},
		"X-Frame-Options":         {"DENY"},
	})
	fs := analyzeHeaders(resp)
	if hasID(fs, "HL-FRAME-001") || !hasID(fs, "HL-FRAME-004") {
		t.Fatalf("wildcard frame-ancestors must not be treated as protected even with XFO: %#v", fs)
	}
}

func TestFrameAncestorsWildcardWithAdditionalSourcesStillBroad(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Security-Policy": {"frame-ancestors 'self' * https://trusted.example"},
	})
	fs := analyzeHeaders(resp)
	if hasID(fs, "HL-FRAME-001") || !hasID(fs, "HL-FRAME-004") {
		t.Fatalf("wildcard in a source list is a union and must remain broad: %#v", fs)
	}
}

func TestFrameAncestorsDuplicateUsesFirstDirective(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Security-Policy": {"frame-ancestors *; frame-ancestors 'none'"},
	})
	fs := analyzeHeaders(resp)
	if hasID(fs, "HL-FRAME-001") || !hasID(fs, "HL-FRAME-004") || !hasID(fs, "HL-FRAME-005") {
		t.Fatalf("first duplicate CSP directive must control the policy and duplicate must be visible: %#v", fs)
	}
}

func TestSeparateCSPPoliciesComposeRestrictively(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Security-Policy": {"frame-ancestors *", "frame-ancestors 'self'"},
	})
	fs := analyzeHeaders(resp)
	if !hasID(fs, "HL-FRAME-001") || hasID(fs, "HL-FRAME-004") {
		t.Fatalf("a separate restrictive CSP policy constrains the broad policy: %#v", fs)
	}
}

func TestPrefixedCookieRequiresSecureOrigin(t *testing.T) {
	resp := responseFor(t, "http://example.test", http.Header{
		"Set-Cookie": {"__Host-session=secret; Secure; HttpOnly; Path=/"},
	})
	fs := analyzeHeaders(resp)
	if !hasID(fs, "HL-COOKIE-PREFIX-__HOST_SESSION") || !hasID(fs, "HL-COOKIE-ORIGIN-__HOST_SESSION") {
		t.Fatalf("secure prefixes set from HTTP must be flagged: %#v", fs)
	}
}

func TestMalformedSetCookieIsReportedWithoutValueLeak(t *testing.T) {
	secret := "very-secret-cookie-value"
	resp := responseFor(t, "https://example.test", http.Header{
		"Set-Cookie": {"bad cookie=" + secret + "; Secure; HttpOnly"},
	})
	fs := analyzeHeaders(resp)
	f, ok := findingByID(fs, "HL-COOKIE-PARSE-001")
	if !ok {
		t.Fatalf("malformed Set-Cookie line must be visible: %#v", fs)
	}
	if strings.Contains(f.Evidence, secret) {
		t.Fatalf("malformed cookie finding leaked value: %q", f.Evidence)
	}
}

func TestUnparsedCookieAttributesAreReportedWithoutAttributeContents(t *testing.T) {
	secretAttribute := "internal-secret-marker"
	resp := responseFor(t, "https://example.test", http.Header{
		"Set-Cookie": {"session=secret; Secure; HttpOnly; Weird=" + secretAttribute},
	})
	fs := analyzeHeaders(resp)
	f, ok := findingByID(fs, "HL-COOKIE-UNPARSED-SESSION")
	if !ok {
		t.Fatalf("unknown cookie attributes must be surfaced: %#v", fs)
	}
	if strings.Contains(f.Evidence, secretAttribute) {
		t.Fatalf("unparsed attribute content leaked into finding: %q", f.Evidence)
	}
}

func TestHSTSRejectsMalformedExtensionDirectiveValues(t *testing.T) {
	for _, input := range []string{
		`max-age=31536000; ext="unterminated`,
		`max-age=31536000; ext=`,
		`max-age=31536000; ext="bad\\`,
	} {
		if _, ok, _ := parseHSTS(input); ok {
			t.Fatalf("malformed HSTS extension directive must invalidate field: %q", input)
		}
	}
}

func TestHSTSQuotedExtensionMayContainSemicolon(t *testing.T) {
	input := `max-age=31536000; ext="alpha;beta"; includeSubDomains`
	max, ok, reason := parseHSTS(input)
	if !ok || max != 31536000 || reason != "" {
		t.Fatalf("valid quoted-string extension was split incorrectly: max=%d ok=%t reason=%q", max, ok, reason)
	}
}

func TestHSTSQuotedMaxAgeEscapesStillRequireDigits(t *testing.T) {
	if max, ok, reason := parseHSTS(`max-age="3153\6000"`); !ok || max != 31536000 || reason != "" {
		t.Fatalf("valid quoted-pair digits should decode before digit validation: max=%d ok=%t reason=%q", max, ok, reason)
	}
	if _, ok, _ := parseHSTS(`max-age="3153\;6000"`); ok {
		t.Fatal("decoded non-digit in max-age must be rejected")
	}
}

func TestAnalyzeRejectsURLFragmentBeforeNetwork(t *testing.T) {
	if _, err := Analyze(context.Background(), "https://example.test/path#client-secret", Options{Timeout: time.Second}); err == nil || !strings.Contains(err.Error(), "fragment") {
		t.Fatalf("expected fragment rejection before any network request, got %v", err)
	}
}

func TestTLSInfoAndAnalyzerSyntheticState(t *testing.T) {
	certPair := makeServerCertificate(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	cert, err := x509.ParseCertificate(certPair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	state := &tls.ConnectionState{
		Version:            tls.VersionTLS13,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		ServerName:         "example.test",
		NegotiatedProtocol: "h2",
		PeerCertificates:   []*x509.Certificate{cert},
		VerifiedChains:     [][]*x509.Certificate{{cert}},
	}
	info := tlsInfo(state)
	if info.Version != "TLS 1.3" || info.CipherSuite == "" || info.ServerName != "example.test" || info.NegotiatedProtocol != "h2" || info.VerifiedChains != 1 || len(info.CertSHA256) != 64 {
		t.Fatalf("unexpected TLS evidence: %#v", info)
	}
	fs := analyzeTLS(state)
	if !hasID(fs, "HL-TLS-001") || !hasID(fs, "HL-CERT-003") {
		t.Fatalf("expected TLS 1.3 and certificate validity findings: %#v", fs)
	}
}

func TestAnalyzeTLSCertificateTemporalStates(t *testing.T) {
	makeState := func(notBefore, notAfter time.Time) *tls.ConnectionState {
		pair := makeServerCertificate(t, notBefore, notAfter)
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return &tls.ConnectionState{Version: tls.VersionTLS12, PeerCertificates: []*x509.Certificate{cert}}
	}
	now := time.Now()
	if fs := analyzeTLS(makeState(now.Add(time.Hour), now.Add(90*24*time.Hour))); !hasID(fs, "HL-CERT-004") {
		t.Fatalf("future certificate must be not-yet-valid: %#v", fs)
	}
	if fs := analyzeTLS(makeState(now.Add(-90*24*time.Hour), now.Add(-time.Hour))); !hasID(fs, "HL-CERT-001") {
		t.Fatalf("expired certificate must fail: %#v", fs)
	}
	if fs := analyzeTLS(makeState(now.Add(-time.Hour), now.Add(7*24*time.Hour))); !hasID(fs, "HL-CERT-002") {
		t.Fatalf("soon-expiring certificate must warn: %#v", fs)
	}
}

func FuzzSplitHSTSDirectivesNoPanic(f *testing.F) {
	for _, seed := range []string{
		`max-age=31536000; ext="alpha;beta"`,
		`max-age=31536000; ext="unterminated`,
		`max-age="31536000"; includeSubDomains`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		parts, ok := splitHSTSDirectives(in)
		if ok && len(parts) == 0 {
			t.Fatalf("successful split returned no parts for %q", in)
		}
	})
}

func TestEvidenceHashBindsBlockedRedirectObservation(t *testing.T) {
	base := Result{
		SchemaVersion:   ResultSchemaVersion,
		Tool:            "HeaderLens",
		Target:          "https://example.test",
		FinalURL:        "https://example.test",
		StatusCode:      302,
		HTTPVersion:     "HTTP/1.1",
		Headers:         map[string][]string{"Location": {"https://other.example/a"}},
		HeadersRedacted: true,
		RedirectChain:   []string{"https://example.test"},
	}
	r1 := base
	r1.RedirectBlocked = &RedirectBlock{URL: "https://other.example/a", Reason: "cross-host redirect blocked by default"}
	r2 := base
	r2.RedirectBlocked = &RedirectBlock{URL: "https://other.example/b", Reason: "cross-host redirect blocked by default"}
	if h1, h2 := evidenceHash(r1), evidenceHash(r2); h1 == h2 {
		t.Fatalf("blocked redirect is direct evidence and must affect digest: %s", h1)
	}
}

func TestDeprecatedSecurityHeadersAreSurfacedConservatively(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"X-XSS-Protection":            {"1; mode=block"},
		"Public-Key-Pins":             {`pin-sha256="abc"; max-age=1000`},
		"Public-Key-Pins-Report-Only": {`pin-sha256="def"; max-age=1000`},
		"Expect-CT":                   {"max-age=86400, enforce"},
	})
	fs := analyzeHeaders(resp)
	for _, id := range []string{"HL-LEGACY-XSS-002", "HL-LEGACY-HPKP-001", "HL-LEGACY-EXPECTCT-001"} {
		if !hasID(fs, id) {
			t.Fatalf("expected %s: %#v", id, fs)
		}
	}
}

func TestXSSProtectionZeroIsInformational(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{"X-XSS-Protection": {"0"}})
	f, ok := findingByID(analyzeHeaders(resp), "HL-LEGACY-XSS-001")
	if !ok || f.Severity != Info {
		t.Fatalf("disabled legacy header should be informational: %#v", f)
	}
}

func TestInvalidXFrameOptionsEvidenceIsPreserved(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{"X-Frame-Options": {"ALLOW-FROM https://old.example"}})
	f, ok := findingByID(analyzeHeaders(resp), "HL-FRAME-002")
	if !ok || !strings.Contains(f.Evidence, "ALLOW-FROM") {
		t.Fatalf("invalid XFO value should be visible in warning evidence: %#v", f)
	}
}

func TestHSTSIsNotReportedAsProtectionForIPLiteralHosts(t *testing.T) {
	for _, target := range []string{"https://127.0.0.1/", "https://[2001:db8::1]/"} {
		resp := responseFor(t, target, http.Header{
			"Strict-Transport-Security": {"max-age=31536000"},
		})
		fs := analyzeHeaders(resp)
		if hasID(fs, "HL-HSTS-002") || hasID(fs, "HL-HSTS-001") || !hasID(fs, "HL-HSTS-006") {
			t.Fatalf("HSTS on an IP literal must not be reported as durable HSTS protection for %s: %#v", target, fs)
		}
	}

	fs := analyzeHeaders(responseFor(t, "https://127.0.0.1/", nil))
	if hasID(fs, "HL-HSTS-001") {
		t.Fatalf("missing HSTS on an IP literal is not a meaningful HSTS-host warning: %#v", fs)
	}
}

func TestHSTSMaxAgeZeroIsExplicitDisable(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Strict-Transport-Security": {"max-age=0"},
	})
	fs := analyzeHeaders(resp)
	if hasID(fs, "HL-HSTS-002") || !hasID(fs, "HL-HSTS-007") {
		t.Fatalf("max-age=0 removes HSTS state and must not pass: %#v", fs)
	}
}

func TestCommaDelimitedCSPPoliciesComposeRestrictively(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Security-Policy": {"frame-ancestors *, frame-ancestors 'none'"},
	})
	fs := analyzeHeaders(resp)
	if !hasID(fs, "HL-FRAME-001") || hasID(fs, "HL-FRAME-004") || hasID(fs, "HL-FRAME-006") {
		t.Fatalf("comma-delimited CSP policies must be evaluated as separate jointly-enforced policies: %#v", fs)
	}
}

func TestMalformedFrameAncestorsDoesNotFallBackToXFO(t *testing.T) {
	for _, policy := range []string{
		"frame-ancestors",
		"frame-ancestors 'unsafe-inline'",
		"frame-ancestors 'none' https://trusted.example",
		"frame-ancestors https://bad^host.example",
	} {
		resp := responseFor(t, "https://example.test", http.Header{
			"Content-Security-Policy": {policy},
			"X-Frame-Options":         {"DENY"},
		})
		fs := analyzeHeaders(resp)
		if hasID(fs, "HL-FRAME-001") || !hasID(fs, "HL-FRAME-006") {
			t.Fatalf("malformed enforced frame-ancestors must not create a PASS via XFO (%q): %#v", policy, fs)
		}
	}
}

func TestSchemeOnlyFrameAncestorsIsBroad(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Security-Policy": {"frame-ancestors https:"},
		"X-Frame-Options":         {"DENY"},
	})
	fs := analyzeHeaders(resp)
	if hasID(fs, "HL-FRAME-001") || !hasID(fs, "HL-FRAME-004") {
		t.Fatalf("scheme-source permits every matching-scheme ancestor and is too broad to count as anti-framing protection: %#v", fs)
	}
}

func TestFrameAncestorsOnlySelfOrNoneGetsUnconditionalPass(t *testing.T) {
	for _, policy := range []string{"frame-ancestors 'self'", "frame-ancestors 'none'"} {
		state, _, _ := cspFrameAncestorsState([]string{policy})
		if state != frameAncestorsRestrictive {
			t.Fatalf("expected restrictive classification for %q, got %v", policy, state)
		}
	}
	for _, policy := range []string{"frame-ancestors https://trusted.example", "frame-ancestors https://trusted.example/path"} {
		state, _, _ := cspFrameAncestorsState([]string{policy})
		if state != frameAncestorsContextual {
			t.Fatalf("explicit host trust requires engagement context for %q, got %v", policy, state)
		}
	}
}

func TestRiskyCSPKeywordDetectedAcrossCommaDelimitedPolicies(t *testing.T) {
	values := []string{"default-src 'self', script-src 'unsafe-eval'"}
	if !cspContainsRiskyKeywords(values) {
		t.Fatal("risky keyword in second serialized policy must be detected")
	}
}

func FuzzCSPFrameAncestorsClassifierNoPanic(f *testing.F) {
	for _, seed := range []string{
		"frame-ancestors 'none'",
		"frame-ancestors *",
		"frame-ancestors https:",
		"frame-ancestors https://example.test",
		"frame-ancestors, frame-ancestors 'self'",
		"frame-ancestors 'unsafe-inline'",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		state, _, _ := cspFrameAncestorsState([]string{in})
		if state < frameAncestorsAbsent || state > frameAncestorsInvalid {
			t.Fatalf("unexpected frame state %d for %q", state, in)
		}
	})
}

func TestAntiFramingChecksSkipRedirectButKeepContextualJSONSignal(t *testing.T) {
	redirect := responseFor(t, "https://example.test", nil)
	redirect.StatusCode = http.StatusFound
	if fs := analyzeHeaders(redirect); hasID(fs, "HL-FRAME-001") || hasID(fs, "HL-FRAME-002") || hasID(fs, "HL-FRAME-004") || hasID(fs, "HL-FRAME-006") || hasID(fs, "HL-FRAME-007") {
		t.Fatalf("anti-framing findings should not be emitted for redirect responses: %#v", fs)
	}

	for _, contentType := range []string{"application/json", "application/problem+json; charset=utf-8"} {
		resp := responseFor(t, "https://example.test", http.Header{"Content-Type": {contentType}})
		fs := analyzeHeaders(resp)
		f, ok := findingByID(fs, "HL-FRAME-007")
		if !ok || f.Severity != Info || hasID(fs, "HL-FRAME-002") {
			t.Fatalf("JSON API response %q should retain a contextual INFO signal without a blanket warning: %#v", contentType, fs)
		}
	}
}

func TestJSONAPIAntiFramingControlCanStillBeObserved(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Type":            {"application/json"},
		"Content-Security-Policy": {"frame-ancestors 'none'"},
	})
	fs := analyzeHeaders(resp)
	if !hasID(fs, "HL-FRAME-001") || hasID(fs, "HL-FRAME-007") {
		t.Fatalf("explicit frame-ancestors on a JSON/API response should remain observable: %#v", fs)
	}
}

func TestDuplicateCookieAttributesAreSurfacedWithoutSecrets(t *testing.T) {
	secret := "do-not-leak"
	resp := responseFor(t, "https://example.test", http.Header{
		"Set-Cookie": {"session=" + secret + "; Secure; SameSite=None; SameSite=Strict; Path=/; Path=/app; HttpOnly"},
	})
	fs := analyzeHeaders(resp)
	f, ok := findingByID(fs, "HL-COOKIE-DUPATTR-001")
	if !ok {
		t.Fatalf("duplicate cookie attributes must be surfaced: %#v", fs)
	}
	if strings.Contains(f.Evidence, secret) || !strings.Contains(f.Evidence, "samesite") || !strings.Contains(f.Evidence, "path") {
		t.Fatalf("duplicate-attribute evidence should list names but never values: %q", f.Evidence)
	}
}

func TestDuplicateCookieAttributeDetectionIsCaseInsensitive(t *testing.T) {
	dups := duplicateCookieAttributes("sid=x; SameSite=Lax; samesite=None; Secure; secure")
	if got := strings.Join(dups, ","); got != "samesite,secure" {
		t.Fatalf("unexpected duplicate list: %q", got)
	}
}

func TestFrameProtectionRelevanceNoContentResponses(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusResetContent} {
		resp := responseFor(t, "https://example.test", nil)
		resp.StatusCode = status
		if frameProtectionRelevant(resp) {
			t.Fatalf("status %d has no renderable document and should skip anti-framing analysis", status)
		}
	}
}

func TestCSPHostSourceClassifierBoundaries(t *testing.T) {
	for _, source := range []string{"example.test", "*.example.test:*", "https://*.example.test:443/path"} {
		if !isCSPHostSource(source) {
			t.Fatalf("expected valid conservative host-source: %q", source)
		}
	}
	for _, source := range []string{"", "*", "-bad.example", "bad-.example", "bad..example", "bad^host.example", "https://", "user@example.test", "[2001:db8::1]:443"} {
		if isCSPHostSource(source) {
			t.Fatalf("expected invalid/non-specific host-source: %q", source)
		}
	}
	for _, source := range []string{"*", "*:443", "https://*", "https://*:443/path"} {
		if !isCSPAnyHostSource(source) {
			t.Fatalf("expected any-host source: %q", source)
		}
	}
	if isCSPAnyHostSource("https://*.example.test") {
		t.Fatal("wildcard subdomain is constrained to a domain and must not be classified as any-host")
	}
}

func TestPermissionsPolicyPresenceIsNotAProtectionPass(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Permissions-Policy": {"geolocation=*"},
	})
	fs := analyzeHeaders(resp)
	f, ok := findingByID(fs, "HL-PERM-002")
	if !ok {
		t.Fatalf("expected permissions-policy observation: %#v", fs)
	}
	if f.Severity == Pass {
		t.Fatalf("presence-only Permissions-Policy analysis must not produce PASS: %#v", f)
	}
}

func TestGenericCSPPresenceIsNotAProtectionPass(t *testing.T) {
	for _, policy := range []string{"default-src *", "report-uri /csp-report", "script-src https:"} {
		t.Run(policy, func(t *testing.T) {
			resp := responseFor(t, "https://example.test", http.Header{"Content-Security-Policy": {policy}})
			fs := analyzeHeaders(resp)
			f, ok := findingByID(fs, "HL-CSP-002")
			if !ok {
				t.Fatalf("expected CSP observation: %#v", fs)
			}
			if f.Severity == Pass {
				t.Fatalf("partial CSP analysis must not claim PASS for %q: %#v", policy, f)
			}
		})
	}
}

func TestCookieWithoutSecureWarnsEvenWhenObservedOverHTTP(t *testing.T) {
	resp := responseFor(t, "http://example.test", http.Header{
		"Set-Cookie": {"session=abc; HttpOnly; SameSite=Lax"},
	})
	fs := analyzeHeaders(resp)
	if !hasID(fs, "HL-COOKIE-SECURE-SESSION") {
		t.Fatalf("cookie lacking Secure over HTTP must be visible as a transport-risk finding: %#v", fs)
	}
}

func TestNonstandardFinalStatusCodeIsPreservedAndFlagged(t *testing.T) {
	resp := responseFor(t, "https://example.test", nil)
	resp.StatusCode = 799
	fs := analyzeHeaders(resp)
	if !hasID(fs, "HL-HTTP-STATUS-001") {
		t.Fatalf("nonstandard three-digit status should be flagged: %#v", fs)
	}
}

func TestCSPFrameAncestorsAllowsGrammarValidTrailingDotHost(t *testing.T) {
	state, _, _ := cspFrameAncestorsState([]string{"frame-ancestors https://example.com."})
	if state != frameAncestorsContextual {
		t.Fatalf("CSP host-part grammar permits an optional trailing dot, but explicit host trust remains contextual; got state %v", state)
	}
}

func TestCSPUnicodeWhitespaceDoesNotCreateFrameAncestorsPass(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Security-Policy": {"frame-ancestors\u00a0'self'"},
	})
	fs := analyzeHeaders(resp)
	if hasID(fs, "HL-FRAME-001") {
		t.Fatalf("non-ASCII whitespace is not CSP ASCII whitespace and must not create PASS: %#v", fs)
	}
}

func TestHSTSUnicodeWhitespaceIsNotAcceptedAsOWS(t *testing.T) {
	if _, ok, _ := parseHSTS("\u00a0max-age=31536000\u00a0"); ok {
		t.Fatal("non-ASCII whitespace must not be accepted as HSTS grammar whitespace")
	}
}

func TestReferrerPolicyUnicodeWhitespaceIsNotAccepted(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Referrer-Policy": {"\u00a0no-referrer\u00a0"},
	})
	fs := analyzeHeaders(resp)
	if hasID(fs, "HL-REF-003") {
		t.Fatalf("non-ASCII whitespace must not normalize into a valid referrer-policy token: %#v", fs)
	}
	if !hasID(fs, "HL-REF-004") {
		t.Fatalf("expected unrecognized referrer policy warning: %#v", fs)
	}
}

func TestXContentTypeOptionsUnicodeWhitespaceDoesNotPass(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"X-Content-Type-Options": {"\u00a0nosniff\u00a0"},
	})
	fs := analyzeHeaders(resp)
	if hasID(fs, "HL-XCTO-001") {
		t.Fatalf("non-ASCII whitespace must not normalize into nosniff PASS: %#v", fs)
	}
}

func TestXFrameOptionsUnicodeWhitespaceDoesNotPass(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"X-Frame-Options": {"\u00a0DENY\u00a0"},
	})
	fs := analyzeHeaders(resp)
	if hasID(fs, "HL-FRAME-001") {
		t.Fatalf("non-ASCII whitespace must not normalize into an XFO PASS: %#v", fs)
	}
}

func TestInvalidUnicodePaddedJSONContentTypeDoesNotSuppressFrameCheck(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Type": {"\u00a0application/json\u00a0"},
	})
	fs := analyzeHeaders(resp)
	if !hasID(fs, "HL-FRAME-002") {
		t.Fatalf("invalid non-ASCII-padded media type must not suppress anti-framing analysis: %#v", fs)
	}
}

func TestCSPASCIITabWhitespaceStillParsesFrameAncestors(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Security-Policy": {"frame-ancestors\t'self'"},
	})
	if !hasID(analyzeHeaders(resp), "HL-FRAME-001") {
		t.Fatal("CSP ASCII tab whitespace should remain valid")
	}
}

func TestNoContentAndSwitchingResponsesSuppressRepresentationHeaderNoise(t *testing.T) {
	noiseIDs := []string{"HL-CSP-001", "HL-XCTO-002", "HL-REF-001", "HL-FRAME-002", "HL-PERM-001"}
	for _, status := range []int{http.StatusSwitchingProtocols, http.StatusNoContent, http.StatusResetContent} {
		resp := responseForStatus(t, "http://example.test", status, nil)
		fs := analyzeHeaders(resp)
		for _, id := range noiseIDs {
			if hasID(fs, id) {
				t.Fatalf("status %d must not emit representation-only missing control %s: %#v", status, id, fs)
			}
		}
	}
}

func Test304AnalyzesPresentRepresentationMetadataButDoesNotReportMissing(t *testing.T) {
	empty := analyzeHeaders(responseForStatus(t, "http://example.test", http.StatusNotModified, nil))
	for _, id := range []string{"HL-CSP-001", "HL-XCTO-002", "HL-REF-001", "HL-FRAME-002", "HL-PERM-001"} {
		if hasID(empty, id) {
			t.Fatalf("304 absence must not imply cached representation lacked %s: %#v", id, empty)
		}
	}

	resp := responseForStatus(t, "http://example.test", http.StatusNotModified, http.Header{
		"Content-Security-Policy": {"script-src 'unsafe-inline'"},
		"Referrer-Policy":         {"unsafe-url"},
		"X-Content-Type-Options":  {"invalid"},
		"Permissions-Policy":      {"camera=()"},
	})
	fs := analyzeHeaders(resp)
	for _, id := range []string{"HL-CSP-002", "HL-REF-002", "HL-XCTO-002", "HL-PERM-002"} {
		if !hasID(fs, id) {
			t.Fatalf("304 should still analyze present metadata %s: %#v", id, fs)
		}
	}
}

func TestSwitchingProtocolsValidation(t *testing.T) {
	missing := analyzeHeaders(responseForStatus(t, "http://example.test", http.StatusSwitchingProtocols, nil))
	for _, id := range []string{"HL-UPGRADE-001", "HL-UPGRADE-002", "HL-UPGRADE-003"} {
		if !hasID(missing, id) {
			t.Fatalf("expected %s for malformed unsolicited 101: %#v", id, missing)
		}
	}

	properFields := analyzeHeaders(responseForStatus(t, "http://example.test", http.StatusSwitchingProtocols, http.Header{
		"Upgrade":    {"websocket"},
		"Connection": {"keep-alive, Upgrade"},
	}))
	if !hasID(properFields, "HL-UPGRADE-001") {
		t.Fatalf("101 remains unsolicited because HeaderLens did not request Upgrade: %#v", properFields)
	}
	for _, id := range []string{"HL-UPGRADE-002", "HL-UPGRADE-003"} {
		if hasID(properFields, id) {
			t.Fatalf("syntactically complete 101 must not emit %s: %#v", id, properFields)
		}
	}
}

func Test426RequiresUpgrade(t *testing.T) {
	missing := analyzeHeaders(responseForStatus(t, "http://example.test", http.StatusUpgradeRequired, nil))
	if !hasID(missing, "HL-UPGRADE-004") {
		t.Fatalf("426 without Upgrade must be flagged: %#v", missing)
	}
	present := analyzeHeaders(responseForStatus(t, "http://example.test", http.StatusUpgradeRequired, http.Header{"Upgrade": {"HTTP/2.0"}}))
	if hasID(present, "HL-UPGRADE-004") {
		t.Fatalf("426 with Upgrade must not be flagged as missing it: %#v", present)
	}
}

func TestFramingHeadersForbiddenOn1xxAnd204(t *testing.T) {
	for _, status := range []int{http.StatusSwitchingProtocols, http.StatusNoContent} {
		resp := responseForStatus(t, "http://example.test", status, http.Header{
			"Content-Length":    {"5"},
			"Transfer-Encoding": {"chunked"},
		})
		resp.TransferEncoding = []string{"chunked"}
		fs := analyzeHeaders(resp)
		for _, id := range []string{"HL-FRAMING-001", "HL-FRAMING-002"} {
			if !hasID(fs, id) {
				t.Fatalf("status %d must flag %s: %#v", status, id, fs)
			}
		}
	}
}

func Test205ResetContentNonZeroLengthWarns(t *testing.T) {
	bad := responseForStatus(t, "http://example.test", http.StatusResetContent, http.Header{"Content-Length": {"3"}})
	bad.ContentLength = 3
	if !hasID(analyzeHeaders(bad), "HL-FRAMING-003") {
		t.Fatalf("205 with positive parsed Content-Length must be flagged: %#v", analyzeHeaders(bad))
	}
	zero := responseForStatus(t, "http://example.test", http.StatusResetContent, http.Header{"Content-Length": {"0"}})
	zero.ContentLength = 0
	if hasID(analyzeHeaders(zero), "HL-FRAMING-003") {
		t.Fatalf("205 with Content-Length: 0 must not be flagged as positive content: %#v", analyzeHeaders(zero))
	}
}

func TestAnalyzePreservesInterim103AsHashBoundObservation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				serverDone <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, err = fmt.Fprint(conn, "HTTP/1.1 103 Early Hints\r\nLink: </early.js>; rel=preload\r\nSet-Cookie: sid=early-secret; Secure; HttpOnly\r\nLocation: /hint?token=early-secret\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n")
		serverDone <- err
	}()

	target := "http://" + ln.Addr().String() + "/"
	res, err := Analyze(context.Background(), target, Options{Timeout: time.Second, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if res.SchemaVersion != ResultSchemaVersion {
		t.Fatalf("schema=%q want %s", res.SchemaVersion, ResultSchemaVersion)
	}
	if len(res.InterimResponses) != 1 || res.InterimResponses[0].StatusCode != http.StatusEarlyHints {
		t.Fatalf("103 observation lost: %#v", res.InterimResponses)
	}
	hop := res.InterimResponses[0]
	if hop.RequestIndex != 0 {
		t.Fatalf("initial 1xx request_index=%d want 0", hop.RequestIndex)
	}
	if hop.URL != target {
		t.Fatalf("initial 1xx URL=%q want operator target %q", hop.URL, target)
	}
	if got := strings.Join(hop.Headers["Set-Cookie"], " | "); strings.Contains(got, "early-secret") || !strings.Contains(got, "<redacted>") {
		t.Fatalf("interim Set-Cookie not privacy-normalized: %q", got)
	}
	if got := strings.Join(hop.Headers["Location"], " | "); strings.Contains(got, "early-secret") || !strings.Contains(got, "REDACTED") {
		t.Fatalf("interim Location not privacy-normalized: %q", got)
	}
	encoded, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("early-secret")) {
		t.Fatalf("interim secret leaked into default result: %s", encoded)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("raw 103 server: %v", err)
	}
}

func TestInterimResponseOnFollowedRedirectUsesPrivacyNormalizedRequestURL(t *testing.T) {
	const secret = "redirect-query-secret"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				serverDone <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, err = conn.Write([]byte("HTTP/1.1 103 Early Hints\r\nLink: </x>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Type: text/html\r\n\r\n"))
		serverDone <- err
	}()

	destination := "http://" + ln.Addr().String() + "/final?token=" + secret
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", destination)
		w.WriteHeader(http.StatusFound)
	}))
	defer source.Close()

	res, err := Analyze(context.Background(), source.URL, Options{ToolVersion: "test", MaxRedirects: 3, AllowCrossPortRedirects: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("raw redirect destination: %v", err)
	}
	if len(res.InterimResponses) != 1 {
		t.Fatalf("redirect-destination 103 lost: %#v", res.InterimResponses)
	}
	if strings.Contains(res.InterimResponses[0].URL, secret) || !strings.Contains(res.InterimResponses[0].URL, "REDACTED") {
		t.Fatalf("server-derived request URL was not privacy-normalized: %q", res.InterimResponses[0].URL)
	}
	blob, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte(secret)) {
		t.Fatalf("redirect query secret leaked through interim provenance: %s", blob)
	}
}

func TestInterimResponseChangesEvidenceDigest(t *testing.T) {
	base := Result{
		SchemaVersion: ResultSchemaVersion, Tool: "HeaderLens", Target: "http://example.test", FinalURL: "http://example.test",
		StatusCode: 200, HTTPVersion: "HTTP/1.1", Headers: map[string][]string{}, HeadersRedacted: true,
		HTTPFraming:      &HTTPFramingInfo{ContentLength: 0},
		InterimResponses: []InterimResponse{{URL: "http://example.test", StatusCode: 103, Headers: map[string][]string{"Link": {"</a>; rel=preload"}}, HeadersRedacted: true}},
	}
	changed := base
	changed.InterimResponses = []InterimResponse{{URL: "http://example.test", StatusCode: 103, Headers: map[string][]string{"Link": {"</b>; rel=preload"}}, HeadersRedacted: true}}
	if evidenceHash(base) == evidenceHash(changed) {
		t.Fatal("interim response observation must affect evidence digest")
	}
}

func TestInterimDerivedFindingsDoNotAffectEvidenceDigest(t *testing.T) {
	base := Result{
		SchemaVersion: ResultSchemaVersion, Tool: "HeaderLens", Target: "http://example.test", FinalURL: "http://example.test",
		StatusCode: 200, HTTPVersion: "HTTP/1.1", Headers: map[string][]string{}, HeadersRedacted: true,
		HTTPFraming: &HTTPFramingInfo{ContentLength: 0},
		InterimResponses: []InterimResponse{{
			URL: "http://example.test", StatusCode: http.StatusEarlyHints,
			Headers: map[string][]string{"Link": {"</a>; rel=preload"}}, HeadersRedacted: true,
			Findings: []Finding{{ID: "DERIVED-A", Severity: Info, Category: "test", Title: "derived"}},
		}},
	}
	changed := base
	changed.InterimResponses = append([]InterimResponse(nil), base.InterimResponses...)
	changed.InterimResponses[0].Findings = []Finding{{ID: "DERIVED-B", Severity: Warn, Category: "test", Title: "different derived interpretation"}}
	if evidenceHash(base) != evidenceHash(changed) {
		t.Fatal("derived interim findings must not affect evidence digest")
	}
}

func TestAnalyzeInterimHeadersProtocolAndEarlyHintsSemantics(t *testing.T) {
	h := http.Header{
		"Content-Length":          {"1"},
		"Transfer-Encoding":       {"chunked"},
		"Trailer":                 {"Strict-Transport-Security"},
		"Set-Cookie":              {"sid=secret"},
		"Content-Security-Policy": {"default-src 'none'"},
	}
	fs := analyzeInterimHeaders(http.StatusEarlyHints, h)
	for _, id := range []string{"HL-FRAMING-001", "HL-FRAMING-002", "HL-FRAMING-004", "HL-COOKIE-1XX-001", "HL-EARLYHINTS-001"} {
		if !hasID(fs, id) {
			t.Fatalf("expected %s in informational findings: %#v", id, fs)
		}
	}
	for _, f := range fs {
		if f.ID == "HL-CSP-001" || f.ID == "HL-HSTS-001" {
			t.Fatalf("103 security-control fields must not be promoted to final-response policy findings: %#v", fs)
		}
	}
}

func TestInformationalSetCookieIsContextualNotPersistentCookieAnalysis(t *testing.T) {
	resp := responseForStatus(t, "http://example.test", http.StatusSwitchingProtocols, http.Header{
		"Set-Cookie": {"session=secret"},
	})
	fs := analyzeHeaders(resp)
	if !hasID(fs, "HL-COOKIE-1XX-001") {
		t.Fatalf("100-level Set-Cookie should be contextualized: %#v", fs)
	}
	for _, id := range []string{"HL-COOKIE-SECURE-SESSION", "HL-COOKIE-HTTPONLY-SESSION", "HL-COOKIE-SAMESITE-SESSION"} {
		if hasID(fs, id) {
			t.Fatalf("100-level Set-Cookie must not be assumed persistent (%s): %#v", id, fs)
		}
	}
}

func TestAnalyzeBindsTransportConsumedTransferEncodingIntoV10Evidence(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				serverDone <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, err = fmt.Fprint(conn, "HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n")
		serverDone <- err
	}()

	res, err := Analyze(context.Background(), "http://"+ln.Addr().String(), Options{Timeout: time.Second, MaxRedirects: 1, ToolVersion: "test"})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.SchemaVersion != ResultSchemaVersion {
		t.Fatalf("expected %s evidence, got %q", ResultSchemaVersion, res.SchemaVersion)
	}
	if res.HTTPFraming == nil || len(res.HTTPFraming.TransferEncoding) != 1 || res.HTTPFraming.TransferEncoding[0] != "chunked" {
		t.Fatalf("Go-consumed Transfer-Encoding must be direct evidence: %#v", res.HTTPFraming)
	}
	if len(res.Headers["Transfer-Encoding"]) != 0 {
		t.Fatalf("test requires proving net/http consumed Transfer-Encoding from Header: %#v", res.Headers)
	}
	if !hasID(res.Findings, "HL-FRAMING-002") {
		t.Fatalf("forbidden transfer coding must be flagged from structured framing state: %#v", res.Findings)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("raw server: %v", err)
	}
}

func TestHTTPFramingStateChangesEvidenceDigest(t *testing.T) {
	r1 := Result{SchemaVersion: ResultSchemaVersion, Tool: "HeaderLens", Target: "http://example.test", FinalURL: "http://example.test", StatusCode: 200, HTTPVersion: "HTTP/1.1", Headers: map[string][]string{}, HeadersRedacted: true, HTTPFraming: &HTTPFramingInfo{ContentLength: -1}}
	r2 := r1
	r2.HTTPFraming = &HTTPFramingInfo{ContentLength: -1, TransferEncoding: []string{"chunked"}}
	if evidenceHash(r1) == evidenceHash(r2) {
		t.Fatal("framing state must be cryptographically bound into v11 evidence")
	}
}

func TestAnalyzePreservesAndFlagsNonstandardThreeDigitStatus(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				serverDone <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, err = fmt.Fprint(conn, "HTTP/1.1 799 Weird\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		serverDone <- err
	}()

	res, err := Analyze(context.Background(), "http://"+ln.Addr().String(), Options{Timeout: time.Second, MaxRedirects: 1, ToolVersion: "test"})
	if err != nil {
		t.Fatalf("Analyze should preserve a parseable three-digit status: %v", err)
	}
	if res.StatusCode != 799 || !hasID(res.Findings, "HL-HTTP-STATUS-001") {
		t.Fatalf("unexpected result: %#v", res)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("raw server: %v", err)
	}
}

func TestReferrerPolicyWeakRecognizedValuesDoNotPass(t *testing.T) {
	cases := []struct {
		policy string
		want   Severity
	}{
		{"no-referrer-when-downgrade", Warn},
		{"origin", Info},
		{"origin-when-cross-origin", Info},
	}
	for _, tc := range cases {
		t.Run(tc.policy, func(t *testing.T) {
			resp := responseFor(t, "https://example.test", http.Header{"Referrer-Policy": {tc.policy}})
			f, ok := findingByID(analyzeHeaders(resp), "HL-REF-003")
			if !ok {
				t.Fatalf("expected referrer-policy finding")
			}
			if f.Severity != tc.want {
				t.Fatalf("policy %q: got %s, want %s: %#v", tc.policy, f.Severity, tc.want, f)
			}
		})
	}
}

func TestReferrerPolicyStrongValuesRemainPass(t *testing.T) {
	for _, policy := range []string{"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"} {
		t.Run(policy, func(t *testing.T) {
			resp := responseFor(t, "https://example.test", http.Header{"Referrer-Policy": {policy}})
			f, ok := findingByID(analyzeHeaders(resp), "HL-REF-003")
			if !ok || f.Severity != Pass {
				t.Fatalf("policy %q should remain a strong PASS: %#v", policy, f)
			}
		})
	}
}

func TestAnalyzeStoresSchemaSafeNormalizedTargetURI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	raw := srv.URL + "/café"
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Analyze(context.Background(), raw, Options{Timeout: time.Second, MaxRedirects: 1, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Target != u.String() {
		t.Fatalf("target should use URI-safe URL serialization: got %q want %q", res.Target, u.String())
	}
}

func TestDeprecatedFeaturePolicyIsSurfaced(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{"Feature-Policy": {"camera 'none'"}})
	if !hasID(analyzeHeaders(resp), "HL-LEGACY-FEATUREPOLICY-001") {
		t.Fatal("deprecated Feature-Policy should be surfaced")
	}
}

func TestObsoleteCSPHeadersAreSurfaced(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"X-Content-Security-Policy": {"default-src 'self'"},
		"X-WebKit-Csp":              {"default-src 'self'"},
	})
	if !hasID(analyzeHeaders(resp), "HL-LEGACY-CSP-001") {
		t.Fatal("obsolete CSP header names should be surfaced")
	}
}

func TestHSTSHugeMaxAgeRemainsSyntacticallyValid(t *testing.T) {
	huge := strings.Repeat("9", 200)
	max, ok, reason := parseHSTS("max-age=" + huge)
	if !ok || reason != "" {
		t.Fatalf("1*DIGIT max-age must remain valid even beyond int64: max=%d ok=%t reason=%q", max, ok, reason)
	}
	if max < 31536000 {
		t.Fatalf("overflow value should saturate as a long lifetime, got %d", max)
	}
}

func TestWildcardFrameAncestorsDoesNotClaimRestrictivePass(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Security-Policy": {"frame-ancestors https://*.example.com"},
	})
	fs := analyzeHeaders(resp)
	if hasID(fs, "HL-FRAME-001") {
		t.Fatalf("wildcard host trust requires context and must not claim restrictive PASS: %#v", fs)
	}
	if !hasID(fs, "HL-FRAME-008") {
		t.Fatalf("expected contextual wildcard finding: %#v", fs)
	}
}

func TestIPv6LiteralFrameAncestorIsNotValidCSP3HostSource(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Security-Policy": {"frame-ancestors [::1]"},
	})
	fs := analyzeHeaders(resp)
	if hasID(fs, "HL-FRAME-001") || !hasID(fs, "HL-FRAME-006") {
		t.Fatalf("literal IPv6 source is outside current CSP3 host-part grammar: %#v", fs)
	}
}

func TestAnalyzePreservesInvalidUTF8HeaderBytesInV5Evidence(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				serverDone <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, err = conn.Write([]byte("HTTP/1.1 200 OK\r\nX-Obs: abc\xffdef\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		serverDone <- err
	}()

	res, err := Analyze(context.Background(), "http://"+ln.Addr().String(), Options{Timeout: time.Second, MaxRedirects: 1, ToolVersion: "test"})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.SchemaVersion != ResultSchemaVersion {
		t.Fatalf("unexpected schema: %s", res.SchemaVersion)
	}
	if got := res.Headers["X-Obs"]; len(got) != 1 || got[0] != "abc\uFFFDdef" {
		t.Fatalf("unexpected display-normalized header: %#v", got)
	}
	b64 := res.HeaderBytesB64["X-Obs"]
	if len(b64) != 1 {
		t.Fatalf("missing byte-preserving fallback: %#v", res.HeaderBytesB64)
	}
	raw, err := base64.StdEncoding.DecodeString(b64[0])
	if err != nil || string(raw) != "abc\xffdef" {
		t.Fatalf("header bytes not preserved: raw=%v err=%v", raw, err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("raw server: %v", err)
	}
}

func TestDistinctInvalidUTF8HeadersProduceDistinctEvidenceHashes(t *testing.T) {
	base := Result{
		SchemaVersion: ResultSchemaVersion, Tool: "HeaderLens", ToolVersion: "test",
		Target: "http://example.test", FinalURL: "http://example.test", StatusCode: 200,
		HTTPVersion: "HTTP/1.1", HeadersRedacted: true,
	}
	r1 := base
	r1.Headers = map[string][]string{"X-Obs": {"abc\uFFFD"}}
	r1.HeaderBytesB64 = map[string][]string{"X-Obs": {base64.StdEncoding.EncodeToString([]byte("abc\xfe"))}}
	r2 := base
	r2.Headers = map[string][]string{"X-Obs": {"abc\uFFFD"}}
	r2.HeaderBytesB64 = map[string][]string{"X-Obs": {base64.StdEncoding.EncodeToString([]byte("abc\xff"))}}
	if evidenceHash(r1) == evidenceHash(r2) {
		t.Fatal("distinct opaque header octets must not collide after JSON normalization")
	}
}

func TestAnalyzeTLSNotYetValidDoesNotAlsoPassValidity(t *testing.T) {
	pair := makeServerCertificate(t, time.Now().Add(time.Hour), time.Now().Add(90*24*time.Hour))
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	fs := analyzeTLS(&tls.ConnectionState{Version: tls.VersionTLS12, PeerCertificates: []*x509.Certificate{cert}})
	if !hasID(fs, "HL-CERT-004") || hasID(fs, "HL-CERT-003") {
		t.Fatalf("future certificate must fail without contradictory PASS: %#v", fs)
	}
}

func TestFrameAncestorsClassificationIsOrderIndependentForBroadAndWildcard(t *testing.T) {
	for _, value := range []string{
		"frame-ancestors *.trusted.example https:",
		"frame-ancestors https: *.trusted.example",
	} {
		findings := analyzeHeaders(responseFor(t, "https://example.test", http.Header{"Content-Security-Policy": []string{value}}))
		if !hasID(findings, "HL-FRAME-004") {
			t.Fatalf("expected broad frame-ancestors finding for %q; got %#v", value, findings)
		}
		if hasID(findings, "HL-FRAME-008") || hasID(findings, "HL-FRAME-005") {
			t.Fatalf("broad source must dominate wildcard/restrictive classification for %q; got %#v", value, findings)
		}
	}
}

func TestFrameAncestorsMalformedPolicyDoesNotGetContextualPassUnlessSeparateRestrictivePolicyExists(t *testing.T) {
	findings := analyzeHeaders(responseFor(t, "https://example.test", http.Header{"Content-Security-Policy": []string{"frame-ancestors *.trusted.example ???"}}))
	if !hasID(findings, "HL-FRAME-006") {
		t.Fatalf("expected malformed frame-ancestors warning; got %#v", findings)
	}
	if hasID(findings, "HL-FRAME-008") || hasID(findings, "HL-FRAME-005") {
		t.Fatalf("malformed policy must not be presented as contextual/restrictive protection; got %#v", findings)
	}

	findings = analyzeHeaders(responseFor(t, "https://example.test", http.Header{"Content-Security-Policy": []string{
		"frame-ancestors *.trusted.example ???",
		"frame-ancestors 'self'",
	}}))
	if !hasID(findings, "HL-FRAME-001") {
		t.Fatalf("separate restrictive policy should dominate because CSP policies compose restrictively; got %#v", findings)
	}
}

func TestHeaderByteMirrorCoversEveryCapturedHeaderWhenNeeded(t *testing.T) {
	h := http.Header{
		"X-Valid":    {"plain"},
		"X-Opaque":   {"a\xffb"},
		"Set-Cookie": {"session=supersecret; Path=/; HttpOnly"},
	}
	display, mirror := cloneHeader(h, false)
	if mirror == nil {
		t.Fatal("expected byte mirror when any value is invalid UTF-8")
	}
	if len(mirror) != len(display) {
		t.Fatalf("byte mirror must cover every stored header: display=%#v mirror=%#v", display, mirror)
	}
	for key, vals := range display {
		encoded, ok := mirror[key]
		if !ok || len(encoded) != len(vals) {
			t.Fatalf("byte mirror mismatch for %q: display=%#v mirror=%#v", key, vals, encoded)
		}
	}
	cookieRaw, err := base64.StdEncoding.DecodeString(mirror["Set-Cookie"][0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cookieRaw), "supersecret") || !strings.Contains(string(cookieRaw), "<redacted>") {
		t.Fatalf("byte mirror must not bypass Set-Cookie redaction: %q", cookieRaw)
	}
}

func TestCookiePrefixesAreMatchedCaseInsensitivelyPerRFC10025(t *testing.T) {
	for _, raw := range []string{
		"__secure-SID=x",
		"__SECURE-SID=x",
		"__host-SID=x; Secure; Path=/app",
		"__HOST-SID=x; Secure",
	} {
		resp := responseFor(t, "https://example.test", http.Header{"Set-Cookie": {raw}})
		fs := analyzeHeaders(resp)
		matched := false
		for _, f := range fs {
			if strings.HasPrefix(f.ID, "HL-COOKIE-PREFIX-") {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("case-insensitive prefix requirements were missed for %q: %#v", raw, fs)
		}
	}
}

func TestExplicitInvalidSameSiteIsNotReportedAsAbsent(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Set-Cookie": {"sid=x; Secure; HttpOnly; SameSite=DefinitelyNotValid"},
	})
	fs := analyzeHeaders(resp)
	if !hasID(fs, "HL-COOKIE-SAMESITE-INVALID-SID") {
		t.Fatalf("explicit invalid SameSite should be surfaced: %#v", fs)
	}
	if hasID(fs, "HL-COOKIE-SAMESITE-SID") {
		t.Fatalf("explicit invalid SameSite must not be described as absent: %#v", fs)
	}
}

func TestMalformedSetCookieRedactionDoesNotLeakSemicolonSecretFragments(t *testing.T) {
	secret := "top-secret-fragment"
	raw := "session=\"prefix;" + secret + "\"; Secure; HttpOnly"
	redacted := redactSetCookieValue(raw)
	if strings.Contains(redacted, secret) || strings.Contains(redacted, "prefix") {
		t.Fatalf("malformed Set-Cookie redaction leaked secret material: %q", redacted)
	}
	if !strings.Contains(redacted, "redacted malformed") {
		t.Fatalf("malformed Set-Cookie should use conservative marker: %q", redacted)
	}
	resp := responseFor(t, "https://example.test", http.Header{"Set-Cookie": {raw}})
	f, ok := findingByID(analyzeHeaders(resp), "HL-COOKIE-PARSE-001")
	if !ok || strings.Contains(f.Evidence, secret) || strings.Contains(f.Evidence, "prefix") {
		t.Fatalf("malformed cookie finding leaked secret: %#v", f)
	}
}

func TestSetCookieRedactionKeepsSecurityStateWithoutCookieOrExtensionValues(t *testing.T) {
	raw := "sid=supersecret; Secure; HttpOnly; SameSite=None; Path=/account/token; Domain=example.test; Weird=extension-secret"
	redacted := redactSetCookieValue(raw)
	for _, secret := range []string{"supersecret", "/account/token", "example.test", "extension-secret"} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("redacted Set-Cookie leaked %q in %q", secret, redacted)
		}
	}
	for _, marker := range []string{"Secure", "HttpOnly", "SameSite=None", "Path=<redacted>", "Domain=<redacted>", "Unknown-Attributes=1"} {
		if !strings.Contains(redacted, marker) {
			t.Fatalf("security-relevant state %q missing from %q", marker, redacted)
		}
	}
}

func TestCSPFrameAncestorsRejectsInvalidPathGrammar(t *testing.T) {
	invalid := []string{
		"frame-ancestors https://example.test//double-leading-segment",
		"frame-ancestors https://example.test/bad|path",
		"frame-ancestors https://example.test/bad%ZZescape",
	}
	for _, policy := range invalid {
		resp := responseFor(t, "https://target.test", http.Header{"Content-Security-Policy": {policy}})
		fs := analyzeHeaders(resp)
		if hasID(fs, "HL-FRAME-001") || !hasID(fs, "HL-FRAME-006") {
			t.Fatalf("invalid CSP host-source path must not create PASS for %q: %#v", policy, fs)
		}
	}
	valid := []string{
		"frame-ancestors https://example.test/path/to/page",
		"frame-ancestors https://example.test/a%2Fb",
		"frame-ancestors https://example.test/a%3Bb",
		"frame-ancestors https://example.test/a%2Cb",
	}
	for _, policy := range valid {
		resp := responseFor(t, "https://target.test", http.Header{"Content-Security-Policy": {policy}})
		fs := analyzeHeaders(resp)
		if hasID(fs, "HL-FRAME-001") || !hasID(fs, "HL-FRAME-008") {
			t.Fatalf("valid CSP host-source path should be syntactically valid but trust-contextual for %q: %#v", policy, fs)
		}
	}
}

func TestHSTSZonedIPv6LiteralIsNotReportedAsDurableHostProtection(t *testing.T) {
	resp := responseFor(t, "https://[fe80::1%25eth0]/", http.Header{
		"Strict-Transport-Security": {"max-age=31536000"},
	})
	fs := analyzeHeaders(resp)
	if hasID(fs, "HL-HSTS-002") || !hasID(fs, "HL-HSTS-006") {
		t.Fatalf("zoned IPv6 literal must be treated as an IP-literal for HSTS: %#v", fs)
	}
}

func TestBlockedRedirectUserinfoIsRedactedFromDefaultEvidence(t *testing.T) {
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer dst.Close()
	dstURL, err := url.Parse(dst.URL)
	if err != nil {
		t.Fatal(err)
	}
	secret := "redirect-password"
	location := "http://operator:" + secret + "@localhost:" + dstURL.Port() + "/next"
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusFound)
	}))
	defer src.Close()

	res, err := Analyze(context.Background(), src.URL, Options{Timeout: time.Second, MaxRedirects: 2, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), secret) || strings.Contains(string(blob), "operator") {
		t.Fatalf("default evidence leaked redirect userinfo: %s", blob)
	}
	if res.RedirectBlocked == nil || !strings.Contains(res.RedirectBlocked.URL, "REDACTED@") {
		t.Fatalf("blocked redirect should retain a redaction marker: %#v", res.RedirectBlocked)
	}
	if got := strings.Join(res.Headers["Location"], " "); !strings.Contains(got, "REDACTED@") {
		t.Fatalf("Location header should be normalized with redacted userinfo: %q", got)
	}
}

func TestSensitiveHeaderOptInCanPreserveRedirectUserinfo(t *testing.T) {
	h := http.Header{"Location": {"https://user:secret@example.test/next"}}
	stored, _ := cloneHeader(h, true)
	if !strings.Contains(stored["Location"][0], "user:secret@") {
		t.Fatalf("explicit sensitive-header opt-in should preserve raw Location userinfo: %#v", stored)
	}
}

func TestDuplicateSetCookieNamesAreSurfaced(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Set-Cookie": {
			"sid=one; Secure; HttpOnly; SameSite=Lax",
			"sid=two; Secure; HttpOnly; SameSite=Lax",
		},
	})
	if !hasID(analyzeHeaders(resp), "HL-COOKIE-DUPNAME-SID") {
		t.Fatal("RFC 10025 duplicate cookie-name requirement should be surfaced")
	}
}

func TestCookieFindingEvidenceDoesNotLeakPathDomainOrInvalidSameSitePayload(t *testing.T) {
	r := responseFor(t, "https://example.test/", http.Header{
		"Set-Cookie": {
			"session=TOP-SECRET-VALUE; Secure; SameSite=Lax; Path=/private-secret; Domain=private.example.test",
			"prefs=x; Secure; SameSite=TOP-SECRET-SAMESITE",
		},
	})
	findings := analyzeHeaders(r)
	b, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, secret := range []string{"TOP-SECRET-VALUE", "/private-secret", "private.example.test", "TOP-SECRET-SAMESITE"} {
		if strings.Contains(got, secret) {
			t.Fatalf("cookie finding evidence leaked %q: %s", secret, got)
		}
	}
	evidence := ""
	for _, f := range findings {
		evidence += f.Evidence + "\n"
	}
	if !strings.Contains(evidence, "PathPresent=true") || !strings.Contains(evidence, "PathIsRoot=false") || !strings.Contains(evidence, "DomainPresent=true") || !strings.Contains(evidence, "SameSite=<invalid>") {
		t.Fatalf("expected privacy-safe cookie security state in findings, got %s", evidence)
	}
}

func TestMalformedLocationUserinfoIsRedactedWithoutSuccessfulURLParse(t *testing.T) {
	h := http.Header{"Location": {"http://alice:super-secret%ZZ@example.test/path"}}
	out, _ := cloneHeader(h, false)
	got := out["Location"][0]
	if strings.Contains(got, "alice") || strings.Contains(got, "super-secret") {
		t.Fatalf("malformed Location leaked userinfo: %q", got)
	}
	if got != "http://REDACTED@example.test/path" {
		t.Fatalf("unexpected malformed Location redaction: %q", got)
	}
}

func TestNetworkPathLocationUserinfoIsRedacted(t *testing.T) {
	h := http.Header{"Location": {"//alice:secret@example.test/path"}}
	out, _ := cloneHeader(h, false)
	if got := out["Location"][0]; got != "//REDACTED@example.test/path" {
		t.Fatalf("unexpected network-path Location redaction: %q", got)
	}
}

func TestEvidenceHashBindsTLSVerificationState(t *testing.T) {
	base := Result{SchemaVersion: ResultSchemaVersion, Tool: "HeaderLens", ToolVersion: "test", Target: "https://example.test", FinalURL: "https://example.test", Headers: map[string][]string{}, HeadersRedacted: true, TLS: &TLSInfo{CertSHA256: strings.Repeat("a", 64)}}
	verified := base
	verified.TLSVerification = &TLSVerificationInfo{Verified: true}
	failed := base
	failed.TLSVerification = &TLSVerificationInfo{Verified: false, ErrorKind: "unknown_authority"}
	if evidenceHash(verified) == evidenceHash(failed) {
		t.Fatal("TLS verification state is direct evidence and must be bound into the digest")
	}
}

func TestCookieHostPrefixRejectsExplicitEmptyDomain(t *testing.T) {
	raw := "__Host-x=1; Secure; Path=/; Domain="
	c, err := http.ParseSetCookie(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !cookiePrefixInvalid(c, raw, true) {
		t.Fatal("__Host- must reject any explicit Domain attribute, including an empty one")
	}
}

func TestDuplicateCookieAttributeDoesNotTreatNBSPAsOWS(t *testing.T) {
	if got := duplicateCookieAttributes("sid=1; Secure;\u00a0Secure"); len(got) != 0 {
		t.Fatalf("NBSP is not HTTP OWS and must not manufacture a duplicate attribute: %v", got)
	}
}

func TestCSPRiskKeywordContextAndOverrides(t *testing.T) {
	if cspContainsRiskyKeywords([]string{"img-src 'unsafe-inline'"}) {
		t.Fatal("unsafe-inline is inert in unrelated fetch directives and must not create a generic warning")
	}
	if cspContainsRiskyKeywords([]string{"script-src 'unsafe-inline' https: 'nonce-abc' 'strict-dynamic'"}) {
		t.Fatal("CSP3 nonce/strict-dynamic overrides unsafe-inline for script execution")
	}
	if !cspContainsRiskyKeywords([]string{"script-src 'unsafe-eval' 'nonce-abc' 'strict-dynamic'"}) {
		t.Fatal("unsafe-eval remains risky despite nonce/strict-dynamic")
	}
	if !cspContainsRiskyKeywords([]string{"style-src 'unsafe-inline'"}) {
		t.Fatal("active unsafe-inline in style-src should still be surfaced")
	}
}

func TestMalformedNonceDoesNotSuppressUnsafeInlineWarning(t *testing.T) {
	if !cspContainsRiskyKeywords([]string{"script-src 'unsafe-inline' 'nonce-bad!value'"}) {
		t.Fatal("malformed nonce syntax must not suppress an active unsafe-inline warning")
	}
}

func TestCertificateInvalidReasonKindUsesStableNames(t *testing.T) {
	cases := map[x509.InvalidReason]string{
		x509.NotAuthorizedToSign:           "not_authorized_to_sign",
		x509.Expired:                       "expired_or_not_yet_valid",
		x509.CANotAuthorizedForThisName:    "ca_not_authorized_for_name",
		x509.TooManyIntermediates:          "too_many_intermediates",
		x509.IncompatibleUsage:             "incompatible_usage",
		x509.NameMismatch:                  "issuer_subject_name_mismatch",
		x509.NameConstraintsWithoutSANs:    "name_constraints_without_sans",
		x509.UnconstrainedName:             "unconstrained_name",
		x509.TooManyConstraints:            "too_many_constraints",
		x509.CANotAuthorizedForExtKeyUsage: "ca_not_authorized_for_ext_key_usage",
	}
	for reason, want := range cases {
		if got := certificateInvalidReasonKind(reason); got != want {
			t.Fatalf("reason %d: got %q want %q", reason, got, want)
		}
	}
	if got := certificateInvalidReasonKind(x509.InvalidReason(9999)); got != "other" {
		t.Fatalf("unknown reason should stay stable, got %q", got)
	}
}

func TestFollowedRedirectQueryAndFragmentAreRedactedFromDefaultEvidence(t *testing.T) {
	const querySecret = "oauth-code-super-secret"
	const fragmentSecret = "fragment-super-secret"
	var base string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			w.Header().Set("Location", base+"/callback?code="+querySecret+"#token="+fragmentSecret)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()
	base = s.URL

	res, err := Analyze(context.Background(), s.URL+"/start", Options{Timeout: time.Second, MaxRedirects: 2, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{querySecret, fragmentSecret} {
		if strings.Contains(string(blob), secret) {
			t.Fatalf("default result leaked server-supplied redirect secret %q: %s", secret, blob)
		}
	}
	if len(res.RedirectChain) != 2 || !strings.Contains(res.RedirectChain[1], "?REDACTED") || !strings.Contains(res.RedirectChain[1], "#REDACTED") {
		t.Fatalf("redirect chain should preserve topology with redaction markers: %#v", res.RedirectChain)
	}
	if !strings.Contains(res.FinalURL, "?REDACTED") || !strings.Contains(res.FinalURL, "#REDACTED") {
		t.Fatalf("final redirect-derived URL should be privacy-normalized: %q", res.FinalURL)
	}
	if res.Target != s.URL+"/start" {
		t.Fatalf("operator-supplied target must remain verbatim: %q", res.Target)
	}
}

func TestBlockedRedirectQueryAndFragmentAreRedactedFromDefaultEvidence(t *testing.T) {
	const secret = "blocked-redirect-secret"
	location := "https://outside.example/callback?code=" + secret + "#state=" + secret
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusFound)
	}))
	defer s.Close()

	res, err := Analyze(context.Background(), s.URL, Options{Timeout: time.Second, MaxRedirects: 2, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), secret) {
		t.Fatalf("blocked redirect secret leaked into default result: %s", blob)
	}
	if res.RedirectBlocked == nil || res.RedirectBlocked.URL != "https://outside.example/callback?REDACTED#REDACTED" {
		t.Fatalf("unexpected blocked redirect evidence: %#v", res.RedirectBlocked)
	}
	if got := res.Headers["Location"]; len(got) != 1 || got[0] != "https://outside.example/callback?REDACTED#REDACTED" {
		t.Fatalf("Location evidence was not privacy-normalized: %#v", got)
	}
}

func TestSensitiveHeaderOptInPreservesServerRedirectQueryAndFragment(t *testing.T) {
	const secret = "explicit-sensitive-opt-in"
	var base string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			w.Header().Set("Location", base+"/done?code="+secret+"#token="+secret)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer s.Close()
	base = s.URL

	res, err := Analyze(context.Background(), s.URL+"/start", Options{Timeout: time.Second, MaxRedirects: 2, ToolVersion: "test", IncludeSensitiveHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RedirectChain) != 2 || !strings.Contains(res.RedirectChain[1], secret) || !strings.Contains(res.FinalURL, secret) {
		t.Fatalf("explicit sensitive opt-in should preserve raw redirect evidence: chain=%#v final=%q", res.RedirectChain, res.FinalURL)
	}
}

func TestMalformedLocationQueryAndFragmentAreConservativelyRedacted(t *testing.T) {
	raw := "http://alice:secret%ZZ@example.test/path?code=oauth-secret#token=fragment-secret"
	got := redactLocationValue(raw)
	for _, secret := range []string{"alice", "secret%ZZ", "oauth-secret", "fragment-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("malformed Location redaction leaked %q: %q", secret, got)
		}
	}
	if got != "http://REDACTED@example.test/path?REDACTED#REDACTED" {
		t.Fatalf("unexpected malformed Location normalization: %q", got)
	}
}

func TestInitialTargetQueryRemainsVerbatimWhileServerRedirectQueryIsRedacted(t *testing.T) {
	const targetValue = "operator-evidence-value"
	const redirectSecret = "server-secret-value"
	var base string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			w.Header().Set("Location", base+"/done?code="+redirectSecret)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer s.Close()
	base = s.URL
	target := s.URL + "/start?engagement=" + targetValue

	res, err := Analyze(context.Background(), target, Options{Timeout: time.Second, MaxRedirects: 2, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Target, targetValue) || !strings.Contains(res.RedirectChain[0], targetValue) {
		t.Fatalf("operator target evidence was unexpectedly mutated: target=%q chain=%#v", res.Target, res.RedirectChain)
	}
	blob, _ := json.Marshal(res)
	if !strings.Contains(string(blob), targetValue) {
		t.Fatal("operator-supplied query should remain available under documented OPEN-HL-005 behavior")
	}
	if strings.Contains(string(blob), redirectSecret) {
		t.Fatalf("server-supplied redirect secret leaked despite default redaction: %s", blob)
	}
}

func TestDuplicateContentTypeIsWarnedAndDoesNotDowngradeAntiFramingFinding(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Type": {"application/json", "text/html"},
	})
	fs := analyzeHeaders(resp)
	if !hasID(fs, "HL-CONTENTTYPE-001") {
		t.Fatalf("duplicate singleton Content-Type must be surfaced: %#v", fs)
	}
	if !hasID(fs, "HL-FRAME-002") || hasID(fs, "HL-FRAME-007") {
		t.Fatalf("ambiguous Content-Type must not downgrade missing anti-framing protection to JSON/API context: %#v", fs)
	}
}

func TestSingleJSONContentTypeKeepsContextualAntiFramingClassification(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Type": {"application/problem+json; charset=utf-8"},
	})
	fs := analyzeHeaders(resp)
	if !hasID(fs, "HL-FRAME-007") || hasID(fs, "HL-CONTENTTYPE-001") {
		t.Fatalf("single JSON media type should retain contextual API classification: %#v", fs)
	}
}

func TestCSPUnsafeEvalDirectiveContext(t *testing.T) {
	if !cspContainsRiskyKeywords([]string{"style-src 'unsafe-eval'"}) {
		t.Fatal("style-src unsafe-eval should remain visible because CSP3 gates CSSOM string-parsing algorithms on it")
	}
	if !cspContainsRiskyKeywords([]string{"script-src 'unsafe-eval'"}) {
		t.Fatal("script-src unsafe-eval should be reported")
	}
	if cspContainsRiskyKeywords([]string{"img-src 'unsafe-eval'"}) {
		t.Fatal("unsafe-eval in an unrelated directive must not create a generic CSP warning")
	}
}

func TestCSPDefaultSrcRiskRespectsSpecificDirectiveFallbacks(t *testing.T) {
	if cspContainsRiskyKeywords([]string{"default-src 'unsafe-eval'; script-src 'self'; style-src 'self'"}) {
		t.Fatal("default-src unsafe-eval is inert for eval-like sinks when both script-src and style-src override it")
	}
	if !cspContainsRiskyKeywords([]string{"default-src 'unsafe-eval'; script-src 'self'"}) {
		t.Fatal("default-src unsafe-eval should remain relevant to style/CSSOM when style-src is absent")
	}
	if !cspContainsRiskyKeywords([]string{"default-src 'unsafe-eval'; style-src 'self'"}) {
		t.Fatal("default-src unsafe-eval should remain relevant to script eval when script-src is absent")
	}
	if cspContainsRiskyKeywords([]string{"default-src 'unsafe-inline'; script-src 'self'; style-src 'self'"}) {
		t.Fatal("default-src unsafe-inline is inert for script/style inline checks when both specific directives override it")
	}
	if cspContainsRiskyKeywords([]string{"default-src 'unsafe-inline'; script-src-elem 'self'; script-src-attr 'self'; style-src-elem 'self'; style-src-attr 'self'"}) {
		t.Fatal("default-src unsafe-inline is inert when all script/style inline subdirective paths are explicitly overridden")
	}
	if !cspContainsRiskyKeywords([]string{"default-src 'unsafe-inline'; script-src-elem 'self'; style-src-elem 'self'"}) {
		t.Fatal("default-src unsafe-inline remains relevant when attribute fallback paths are not overridden")
	}
}

func TestCSPStrictDynamicSuppressesUnsafeInlineForScriptSubdirectives(t *testing.T) {
	for _, policy := range []string{
		"script-src 'unsafe-inline' 'strict-dynamic'",
		"script-src-elem 'unsafe-inline' 'strict-dynamic'",
		"script-src-attr 'unsafe-inline' 'strict-dynamic'",
	} {
		if cspContainsRiskyKeywords([]string{policy}) {
			t.Fatalf("strict-dynamic should disable unsafe-inline for script/script-attribute behavior in %q", policy)
		}
	}
	// default-src also falls back for style directives; strict-dynamic does not
	// disable unsafe-inline for styles, so the generic risk warning remains valid.
	if !cspContainsRiskyKeywords([]string{"default-src 'unsafe-inline' 'strict-dynamic'"}) {
		t.Fatal("default-src unsafe-inline remains risky through style fallback despite strict-dynamic")
	}
}

func TestCSPHostSourceRejectsEmptyPort(t *testing.T) {
	for _, source := range []string{"https://example.test:", "example.test:"} {
		if isCSPHostSource(source) {
			t.Fatalf("CSP port-part requires '*' or at least one digit; accepted %q", source)
		}
	}
	for _, source := range []string{"https://example.test:443", "example.test:*"} {
		if !isCSPHostSource(source) {
			t.Fatalf("valid CSP port-part unexpectedly rejected for %q", source)
		}
	}
}

func TestMalformedSingletonContentTypeIsWarned(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Type": {"application/json, text/html"},
	})
	fs := analyzeHeaders(resp)
	if !hasID(fs, "HL-CONTENTTYPE-002") {
		t.Fatalf("invalid/comma-combined singleton Content-Type must be surfaced: %#v", fs)
	}
	if hasID(fs, "HL-FRAME-007") {
		t.Fatalf("invalid Content-Type must not downgrade anti-framing to JSON/API context: %#v", fs)
	}
}

func TestContentTypeParserAcceptsQuotedCommaParameter(t *testing.T) {
	resp := responseFor(t, "https://example.test", http.Header{
		"Content-Type": {`application/problem+json; profile="a,b"`},
	})
	fs := analyzeHeaders(resp)
	if hasID(fs, "HL-CONTENTTYPE-002") {
		t.Fatalf("quoted comma inside a media-type parameter is syntactically valid: %#v", fs)
	}
	if !hasID(fs, "HL-FRAME-007") {
		t.Fatalf("valid +json media type should retain contextual API classification: %#v", fs)
	}
}

func TestSameHostCrossPortRedirectBlockedByDefault(t *testing.T) {
	var destinationHits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationHits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/dest", http.StatusFound)
	}))
	defer source.Close()

	res, err := Analyze(context.Background(), source.URL, Options{ToolVersion: "test", MaxRedirects: 3})
	if err != nil {
		t.Fatal(err)
	}
	if destinationHits.Load() != 0 {
		t.Fatalf("cross-port destination was requested %d times", destinationHits.Load())
	}
	if res.RedirectBlocked == nil || !strings.Contains(res.RedirectBlocked.Reason, "cross-port") {
		t.Fatalf("expected cross-port block, got %#v", res.RedirectBlocked)
	}
	if res.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want %d", res.StatusCode, http.StatusFound)
	}
}

func TestSameHostCrossPortRedirectRequiresExplicitOptIn(t *testing.T) {
	var destinationHits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationHits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/dest", http.StatusFound)
	}))
	defer source.Close()

	res, err := Analyze(context.Background(), source.URL, Options{ToolVersion: "test", MaxRedirects: 3, AllowCrossPortRedirects: true})
	if err != nil {
		t.Fatal(err)
	}
	if destinationHits.Load() != 1 {
		t.Fatalf("cross-port opt-in destination hits=%d want 1", destinationHits.Load())
	}
	if res.RedirectBlocked != nil {
		t.Fatalf("unexpected redirect block: %#v", res.RedirectBlocked)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", res.StatusCode)
	}
}

func TestRedirectPortBoundaryAllowsEquivalentPortsAndDefaultHTTPUpgrade(t *testing.T) {
	cases := []struct {
		initial string
		next    string
		want    bool
	}{
		{"http://example.test/", "http://example.test:80/a", true},
		{"https://example.test/", "https://example.test:443/a", true},
		{"http://example.test/", "https://example.test/a", true},
		{"http://example.test:8080/", "https://example.test:8443/a", false},
		{"https://example.test/", "https://example.test:8443/a", false},
		{"http://example.test/", "http://example.test:8080/a", false},
	}
	for _, tc := range cases {
		i, _ := url.Parse(tc.initial)
		n, _ := url.Parse(tc.next)
		if got := redirectPortWithinDefaultBoundary(i, n); got != tc.want {
			t.Errorf("initial=%s next=%s got=%t want=%t", tc.initial, tc.next, got, tc.want)
		}
	}
}

func TestRefreshHeaderURLIsPrivacyNormalizedByDefault(t *testing.T) {
	const secret = "refresh-super-secret-token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Refresh", "0; url=https://example.test/callback?token="+secret+"#frag")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := Analyze(context.Background(), srv.URL, Options{ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(secret)) {
		t.Fatalf("Refresh URL secret leaked in default result: %s", b)
	}
	got := ""
	if vals := res.Headers["Refresh"]; len(vals) > 0 {
		got = vals[0]
	}
	if got != "0; REDACTED" {
		t.Fatalf("Refresh=%q want redacted delay marker", got)
	}
}

func TestRefreshHeaderSensitiveOptInPreservesRawValue(t *testing.T) {
	const raw = "0; url=https://example.test/callback?token=keep-me#frag"
	h := http.Header{"Refresh": []string{raw}}
	got, b64 := cloneHeader(h, true)
	if b64 != nil {
		t.Fatalf("unexpected byte mirror: %#v", b64)
	}
	refresh := ""
	if vals := got["Refresh"]; len(vals) > 0 {
		refresh = vals[0]
	}
	if refresh != raw {
		t.Fatalf("Refresh=%q want raw %q", refresh, raw)
	}
}

func TestRefreshRedactionConservativeMalformedInputs(t *testing.T) {
	cases := map[string]string{
		"5":                          "5",
		"0.5":                        "0.5",
		"5, url=https://e/?secret=x": "5, REDACTED",
		"5;URL=https://e/?secret=x":  "5; REDACTED",
		"https://e/?secret=no-delay": "<redacted Refresh>",
		"nonsense; token=secret":     "<redacted Refresh>",
	}
	for in, want := range cases {
		if got := redactRefreshValue(in); got != want {
			t.Errorf("redactRefreshValue(%q)=%q want %q", in, got, want)
		}
	}
}

func FuzzRefreshRedactionNeverReturnsURLPayload(f *testing.F) {
	for _, seed := range []string{
		"0",
		"5; url=https://example.test/?token=secret#frag",
		"1,https://example.test/path?x=y",
		"nonsense; credential=secret",
		"0.5;URL=//user:pass@example.test/",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got := redactRefreshValue(raw)
		if !utf8.ValidString(got) {
			t.Fatalf("redacted output is not valid UTF-8: %q", got)
		}
		if strings.Contains(got, "://") || strings.ContainsAny(got, "?#@") {
			t.Fatalf("redirect-like payload survived Refresh redaction: input=%q output=%q", raw, got)
		}
	})
}

func TestRepresentationOnlyMissingHeadersSuppressedOnRedirect(t *testing.T) {
	resp := responseForStatus(t, "https://example.test/start", http.StatusFound, nil)
	fs := analyzeHeaders(resp)
	for _, id := range []string{"HL-CSP-001", "HL-XCTO-002", "HL-PERM-001"} {
		if hasID(fs, id) {
			t.Fatalf("redirect response should not claim missing representation-only control %s: %#v", id, fs)
		}
	}
	if !hasID(fs, "HL-REF-001") {
		t.Fatalf("Referrer-Policy remains navigation-relevant on redirects: %#v", fs)
	}
}

func TestAnalyzeCapturesFollowedRedirectResponseEvidence(t *testing.T) {
	const secret = "intermediate-cookie-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "/final")
			w.Header().Add("Set-Cookie", "sid="+secret+"; HttpOnly; SameSite=Lax")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := Analyze(context.Background(), srv.URL+"/start", Options{ToolVersion: "test", MaxRedirects: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RedirectResponses) != 1 {
		t.Fatalf("followed redirect response was lost: %#v", res.RedirectResponses)
	}
	hop := res.RedirectResponses[0]
	if hop.StatusCode != http.StatusFound || hop.URL != srv.URL+"/start" {
		t.Fatalf("unexpected hop identity: %#v", hop)
	}
	if !hasID(hop.Findings, "HL-COOKIE-SECURE-SID") || !hasID(hop.Findings, "HL-REF-002") && !hasID(hop.Findings, "HL-REF-003") {
		t.Fatalf("intermediate security findings were not preserved: %#v", hop.Findings)
	}
	blob, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte(secret)) {
		t.Fatalf("redirect-response evidence leaked Set-Cookie secret: %s", blob)
	}
	if vals := hop.Headers["Set-Cookie"]; len(vals) != 1 || !strings.Contains(vals[0], "<redacted>") {
		t.Fatalf("intermediate Set-Cookie not privacy-normalized: %#v", hop.Headers)
	}
}

func TestRedirectResponseObservationIsHashBoundButFindingsAreNot(t *testing.T) {
	base := Result{
		SchemaVersion:   ResultSchemaVersion,
		Tool:            "HeaderLens",
		Target:          "https://example.test/start",
		FinalURL:        "https://example.test/final",
		StatusCode:      200,
		HTTPVersion:     "HTTP/1.1",
		Headers:         map[string][]string{},
		HeadersRedacted: true,
		HTTPFraming:     &HTTPFramingInfo{ContentLength: 0},
		RedirectChain:   []string{"https://example.test/start", "https://example.test/final"},
		RedirectResponses: []RedirectResponse{{
			URL: "https://example.test/start", StatusCode: 302, HTTPVersion: "HTTP/1.1",
			Headers: map[string][]string{"X-Hop": {"a"}}, HeadersRedacted: true,
			HTTPFraming: &HTTPFramingInfo{ContentLength: 0},
			Findings:    []Finding{{ID: "DERIVED-A", Severity: Info, Category: "test", Title: "derived"}},
		}},
	}
	changedObservation := base
	changedObservation.RedirectResponses = append([]RedirectResponse(nil), base.RedirectResponses...)
	changedObservation.RedirectResponses[0] = base.RedirectResponses[0]
	changedObservation.RedirectResponses[0].Headers = map[string][]string{"X-Hop": {"b"}}
	if evidenceHash(base) == evidenceHash(changedObservation) {
		t.Fatal("intermediate redirect response observation must affect evidence digest")
	}
	changedFinding := base
	changedFinding.RedirectResponses = append([]RedirectResponse(nil), base.RedirectResponses...)
	changedFinding.RedirectResponses[0] = base.RedirectResponses[0]
	changedFinding.RedirectResponses[0].Findings = []Finding{{ID: "DERIVED-B", Severity: Warn, Category: "test", Title: "changed"}}
	if evidenceHash(base) != evidenceHash(changedFinding) {
		t.Fatal("derived redirect findings must remain outside evidence identity")
	}
}

func TestAnalyzeBindsAnnouncedSecurityTrailerNames(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				serverDone <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, err = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: Strict-Transport-Security, X-Foo\r\nConnection: close\r\n\r\n2\r\nok\r\n0\r\nStrict-Transport-Security: max-age=31536000\r\nX-Foo: bar\r\n\r\n")
		serverDone <- err
	}()

	res, err := Analyze(context.Background(), "http://"+ln.Addr().String(), Options{Timeout: time.Second, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if res.HTTPFraming == nil || len(res.HTTPFraming.TrailerNames) != 2 {
		t.Fatalf("announced trailer names not preserved: %#v", res.HTTPFraming)
	}
	if !hasID(res.Findings, "HL-TRAILER-001") {
		t.Fatalf("security response-control trailer must be flagged: %#v", res.Findings)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("raw trailer server: %v", err)
	}
}

func TestRedirectPortBoundaryUsesCurrentHopAfterDefaultHTTPSUpgrade(t *testing.T) {
	initial, _ := url.Parse("http://example.test/")
	upgraded, _ := url.Parse("https://example.test/")
	next, _ := url.Parse("https://example.test:80/second")
	via := []*http.Request{{URL: initial}, {URL: upgraded}}
	reason := redirectBlockReason(initial, next, via, Options{MaxRedirects: 5})
	if !strings.Contains(reason, "cross-port") {
		t.Fatalf("expected current-hop cross-port block for https:443 -> https:80; got %q", reason)
	}
}

func TestRedirectBlockedPolicyReasonDoesNotChangeEvidenceIdentity(t *testing.T) {
	var destinationHits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Freeze the observed HTTP Date: the two valid separate requests may
		// otherwise straddle a one-second boundary. A changing observed Date
		// must change evidence SHA-256, independent of local policy reasons.
		w.Header().Set("Date", "Mon, 02 Jan 2006 15:04:05 GMT")
		http.Redirect(w, r, destination.URL+"/dest", http.StatusFound)
	}))
	defer source.Close()

	byCount, err := Analyze(context.Background(), source.URL, Options{ToolVersion: "test", MaxRedirects: 0})
	if err != nil {
		t.Fatal(err)
	}
	byPort, err := Analyze(context.Background(), source.URL, Options{ToolVersion: "test", MaxRedirects: 5})
	if err != nil {
		t.Fatal(err)
	}
	if destinationHits.Load() != 0 {
		t.Fatalf("blocked destination was contacted %d times", destinationHits.Load())
	}
	if byCount.RedirectBlocked == nil || byPort.RedirectBlocked == nil {
		t.Fatal("expected both scans to block the same destination")
	}
	if byCount.RedirectBlocked.URL != byPort.RedirectBlocked.URL {
		t.Fatalf("blocked URLs differ: %#v vs %#v", byCount.RedirectBlocked, byPort.RedirectBlocked)
	}
	if byCount.RedirectBlocked.Reason == byPort.RedirectBlocked.Reason {
		t.Fatalf("expected different local policy reasons, got %q", byCount.RedirectBlocked.Reason)
	}
	if byCount.EvidenceSHA256 != byPort.EvidenceSHA256 {
		t.Fatalf("policy reason text must not change direct evidence identity: %s vs %s", byCount.EvidenceSHA256, byPort.EvidenceSHA256)
	}
	// Positive control: Date is part of the *observed* response and must
	// remain evidence-bound. The fixture stabilization must never hide real
	// observations merely to make tests pass.
	changedDate := byCount
	changedDate.Headers = make(map[string][]string, len(byCount.Headers))
	for name, values := range byCount.Headers {
		changedDate.Headers[name] = append([]string(nil), values...)
	}
	changedDate.Headers["Date"] = []string{"Tue, 03 Jan 2006 15:04:05 GMT"}
	if got := evidenceHash(changedDate); got == byCount.EvidenceSHA256 {
		t.Fatal("changing an observed HTTP Date must change evidence identity")
	}
}

func TestInterimEvidenceBindsRequestOccurrence(t *testing.T) {
	var mode atomic.Int32
	var aVisits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeHint := func(label string) {
			w.Header().Set("X-Interim-Occurrence", label)
			w.WriteHeader(http.StatusEarlyHints)
			w.Header().Del("X-Interim-Occurrence")
		}
		switch r.URL.Path {
		case "/a":
			visit := aVisits.Add(1)
			if mode.Load() == 1 {
				if visit == 1 {
					writeHint("X")
					writeHint("Y")
				}
			} else {
				if visit == 1 {
					writeHint("X")
				}
				if visit == 2 {
					writeHint("Y")
				}
			}
			if visit == 1 {
				http.Redirect(w, r, "/b", http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		case "/b":
			http.Redirect(w, r, "/a", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	mode.Store(1)
	aVisits.Store(0)
	first, err := Analyze(context.Background(), srv.URL+"/a", Options{ToolVersion: "test", MaxRedirects: 4})
	if err != nil {
		t.Fatal(err)
	}
	mode.Store(2)
	aVisits.Store(0)
	second, err := Analyze(context.Background(), srv.URL+"/a", Options{ToolVersion: "test", MaxRedirects: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.InterimResponses) != 2 || len(second.InterimResponses) != 2 {
		t.Fatalf("unexpected interim counts: %d vs %d", len(first.InterimResponses), len(second.InterimResponses))
	}
	if first.InterimResponses[0].RequestIndex != 0 || first.InterimResponses[1].RequestIndex != 0 {
		t.Fatalf("first temporal grouping lost: %#v", first.InterimResponses)
	}
	if second.InterimResponses[0].RequestIndex != 0 || second.InterimResponses[1].RequestIndex != 2 {
		t.Fatalf("second temporal grouping lost: %#v", second.InterimResponses)
	}
	if first.EvidenceSHA256 == second.EvidenceSHA256 {
		t.Fatalf("different temporal attachment of 1xx observations must not collide: %s", first.EvidenceSHA256)
	}
}

// A server-derived Location must not become an unredacted URL merely because
// a later connection fails before HeaderLens can emit its normal JSON evidence.
func TestFailedFollowedRedirectRedactsServerURLInDefaultError(t *testing.T) {
	const secret = "secret-from-server-redirect-error"
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	destination := "http://" + closed.Addr().String() + "/callback?code=" + secret
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination, http.StatusFound)
	}))
	defer server.Close()
	_, err = Analyze(context.Background(), server.URL, Options{Timeout: 2 * time.Second, AllowCrossPortRedirects: true, MaxRedirects: 3})
	if err == nil {
		t.Fatal("expected connection failure")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("server-controlled redirect credential leaked to default error: %v", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "connection refused") {
		t.Fatalf("useful non-sensitive cause lost: %v", err)
	}
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		t.Fatalf("programmatic transport error chain should remain available: %T", err)
	}
}

func TestServerControlledMalformedResponseDoesNotLeakInDefaultError(t *testing.T) {
	const secret = "secret-from-malformed-wire-response"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				serverDone <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, err = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nInvalidHeader %s\r\n\r\n", secret)
		serverDone <- err
	}()
	_, err = Analyze(context.Background(), "http://"+ln.Addr().String()+"/", Options{Timeout: 2 * time.Second})
	if err == nil {
		t.Fatal("expected malformed response failure")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("server-controlled malformed header leaked to default error: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("synthetic raw HTTP fixture failed: %v", err)
	}
}

func TestSensitiveErrorOptInPreservesDetailedRedirectFailure(t *testing.T) {
	const secret = "secret-only-in-opted-in-error"
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	destination := "http://" + closed.Addr().String() + "/?state=" + secret
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination, http.StatusFound)
	}))
	defer server.Close()
	_, err = Analyze(context.Background(), server.URL, Options{Timeout: 2 * time.Second, AllowCrossPortRedirects: true, MaxRedirects: 3, IncludeSensitiveHeaders: true})
	if err == nil || !strings.Contains(err.Error(), secret) {
		t.Fatalf("explicit sensitive opt-in did not retain detailed error: %v", err)
	}
}

func TestSafeRequestErrorKindsAndUnwrap(t *testing.T) {
	cases := []struct {
		name  string
		cause error
		want  string
	}{
		{"refused", fmt.Errorf("attacker-marker: %w", syscall.ECONNREFUSED), "connection refused"},
		{"reset", fmt.Errorf("attacker-marker: %w", syscall.ECONNRESET), "connection reset"},
		{"timeout", fmt.Errorf("attacker-marker: %w", context.DeadlineExceeded), "request timed out"},
		{"canceled", fmt.Errorf("attacker-marker: %w", context.Canceled), "request canceled"},
		{"dns", &net.DNSError{Err: "attacker-marker", Name: "attacker-marker"}, "DNS lookup failed"},
		{"unknown", errors.New("attacker-marker"), "HTTP transport/protocol failure"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			safe := &safeRequestError{cause: tc.cause, kind: classifyRequestError(tc.cause)}
			if strings.Contains(safe.Error(), "attacker-marker") || !strings.Contains(safe.Error(), tc.want) {
				t.Fatalf("unexpected surfaced error: %s", safe.Error())
			}
			if !errors.Is(safe, tc.cause) {
				t.Fatalf("failed to preserve wrapped cause: %T", tc.cause)
			}
		})
	}
}

// A stable v12 digest vector catches accidental marshaling/digest changes when
// build CI moves between supported Go toolchains (including Go 1.27's JSON
// implementation update). This is a normalized evidence hash, not an HMAC.
func TestEvidenceHashV12GoldenVector(t *testing.T) {
	r := Result{
		SchemaVersion: "headerlens.result/v12", Tool: "HeaderLens",
		ToolVersion: "ignored-build-version", Target: "https://example.test/",
		FinalURL:   "https://example.test/next?REDACTED",
		StatusCode: 200, HTTPVersion: "HTTP/1.1", DurationMS: 42,
		Headers: map[string][]string{
			"X-Normalized": {"<tag>&"}, "Content-Type": {"text/html; charset=utf-8"},
		},
		HeadersRedacted: true,
		HTTPFraming:     &HTTPFramingInfo{ContentLength: -1, ConnectionClose: true},
		RedirectChain:   []string{"https://example.test/", "https://example.test/next?REDACTED"},
		RedirectResponses: []RedirectResponse{{
			URL: "https://example.test/", StatusCode: 302, HTTPVersion: "HTTP/1.1",
			Headers:         map[string][]string{"Location": {"https://example.test/next?REDACTED"}},
			HeadersRedacted: true, HTTPFraming: &HTTPFramingInfo{ContentLength: 0},
			Findings: []Finding{{ID: "excluded", Severity: Warn}},
		}},
		InterimResponses: []InterimResponse{{
			RequestIndex: 1, URL: "https://example.test/next?REDACTED", StatusCode: 103,
			Headers:         map[string][]string{"Link": {"</a.css>; rel=preload"}},
			HeadersRedacted: true,
			Findings:        []Finding{{ID: "also-excluded", Severity: Info}},
		}},
		Findings: []Finding{{ID: "excluded-top-level", Severity: Pass}},
	}
	const expected = "711bd9b58fb8b061be195e852cd3a6be2440b89e2d499cd74080f2d747fc4436"
	got := evidenceHash(r)
	if got != expected {
		t.Fatalf("v12 canonical evidence digest changed: got %s, want %s", got, expected)
	}
	r.ToolVersion = "totally-different-version"
	r.DurationMS = 999999
	r.Findings[0].ID = "changed-derived-interpretation"
	r.RedirectResponses[0].Findings[0].ID = "changed-hop-interpretation"
	if alternate := evidenceHash(r); alternate != expected {
		t.Fatalf("derived or runtime-only metadata changed v12 digest: %s", alternate)
	}
}
