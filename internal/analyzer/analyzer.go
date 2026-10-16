package analyzer

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

const ResultSchemaVersion = "headerlens.result/v15"

type Severity string

const (
	Info Severity = "INFO"
	Pass Severity = "PASS"
	Warn Severity = "WARN"
	Fail Severity = "FAIL"
)

type Finding struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

type TLSInfo struct {
	Version            string    `json:"version,omitempty"`
	CipherSuite        string    `json:"cipher_suite,omitempty"`
	ServerName         string    `json:"server_name,omitempty"`
	NegotiatedProtocol string    `json:"negotiated_protocol,omitempty"`
	CertSubject        string    `json:"cert_subject,omitempty"`
	CertIssuer         string    `json:"cert_issuer,omitempty"`
	CertNotBefore      time.Time `json:"cert_not_before,omitempty"`
	CertNotAfter       time.Time `json:"cert_not_after,omitempty"`
	CertDNSNames       []string  `json:"cert_dns_names,omitempty"`
	CertSHA256         string    `json:"cert_sha256,omitempty"`
	VerifiedChains     int       `json:"verified_chains,omitempty"`
}

type TLSVerificationInfo struct {
	Verified  bool   `json:"verified"`
	ErrorKind string `json:"error_kind,omitempty"`
}

// HTTPFramingInfo preserves net/http's parsed message-framing view. Some
// hop-by-hop fields such as Transfer-Encoding are consumed by the Go transport
// and therefore do not remain in Response.Header. Keeping this structured state
// in the evidence contract lets protocol findings remain provenance-backed.
type HTTPFramingInfo struct {
	ContentLength    int64    `json:"content_length"`
	TransferEncoding []string `json:"transfer_encoding,omitempty"`
	ConnectionClose  bool     `json:"connection_close"`
	TrailerNames     []string `json:"trailer_names,omitempty"`
}

// RedirectResponse preserves the response that caused a redirect which was
// actually followed. Security-relevant headers on intermediate 3xx responses
// (notably HSTS and Set-Cookie) are browser-observable and must not disappear
// merely because net/http subsequently returned the final response.
type RedirectResponse struct {
	URL             string               `json:"url"`
	StatusCode      int                  `json:"status_code"`
	HTTPVersion     string               `json:"http_version"`
	Headers         map[string][]string  `json:"headers"`
	HeaderBytesB64  map[string][]string  `json:"header_bytes_b64,omitempty"`
	HeadersRedacted bool                 `json:"headers_redacted"`
	TLS             *TLSInfo             `json:"tls,omitempty"`
	TLSVerification *TLSVerificationInfo `json:"tls_verification,omitempty"`
	HTTPFraming     *HTTPFramingInfo     `json:"http_framing"`
	Findings        []Finding            `json:"findings"`
}

// InterimResponse preserves non-terminal 1xx response headers surfaced by
// net/http/httptrace before the final response. 101 Switching Protocols is
// terminal in Go's transport and therefore remains the normal final Result.
// Early hints and other informational responses are direct observations; they
// are not treated as final-response security controls.
type InterimResponse struct {
	RequestIndex    int                 `json:"request_index"`
	URL             string              `json:"url"`
	StatusCode      int                 `json:"status_code"`
	Headers         map[string][]string `json:"headers"`
	HeaderBytesB64  map[string][]string `json:"header_bytes_b64,omitempty"`
	HeadersRedacted bool                `json:"headers_redacted"`
	Findings        []Finding           `json:"findings"`
}

type RedirectBlock struct {
	URL    string `json:"url"`
	Reason string `json:"reason"`
}

type Result struct {
	SchemaVersion     string               `json:"schema_version"`
	Tool              string               `json:"tool"`
	ToolVersion       string               `json:"tool_version"`
	Target            string               `json:"target"`
	FinalURL          string               `json:"final_url"`
	StatusCode        int                  `json:"status_code"`
	DurationMS        int64                `json:"duration_ms"`
	HTTPVersion       string               `json:"http_version"`
	Headers           map[string][]string  `json:"headers"`
	HeaderBytesB64    map[string][]string  `json:"header_bytes_b64,omitempty"`
	HeadersRedacted   bool                 `json:"headers_redacted"`
	TLS               *TLSInfo             `json:"tls,omitempty"`
	TLSVerification   *TLSVerificationInfo `json:"tls_verification,omitempty"`
	HTTPFraming       *HTTPFramingInfo     `json:"http_framing,omitempty"`
	Findings          []Finding            `json:"findings"`
	RedirectChain     []string             `json:"redirect_chain,omitempty"`
	RedirectResponses []RedirectResponse   `json:"redirect_responses,omitempty"`
	InterimResponses  []InterimResponse    `json:"interim_responses,omitempty"`
	RedirectBlocked   *RedirectBlock       `json:"redirect_blocked,omitempty"`
	EvidenceSHA256    string               `json:"evidence_sha256"`
	ScannedAt         time.Time            `json:"scanned_at"`
}

type Options struct {
	Timeout                 time.Duration
	MaxRedirects            int
	UserAgent               string
	ToolVersion             string
	AllowCrossHostRedirects bool
	AllowCrossPortRedirects bool
	AllowDowngradeRedirects bool
	UseEnvironmentProxy     bool
	IncludeSensitiveHeaders bool
	MaxResponseHeaderBytes  int64
}

type interimCollector struct {
	mu               sync.Mutex
	nextRequestIndex int
	items            []InterimResponse
}

func (c *interimCollector) beginRequest() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	index := c.nextRequestIndex
	c.nextRequestIndex++
	return index
}

func (c *interimCollector) add(v InterimResponse) {
	c.mu.Lock()
	c.items = append(c.items, v)
	c.mu.Unlock()
}

func (c *interimCollector) snapshot() []InterimResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]InterimResponse(nil), c.items...)
}

// interimTraceRoundTripper attaches a request-specific 1xx trace without
// mutating the Client's request context. That matters for redirects: net/http
// constructs each redirect from the original request context, so each RoundTrip
// gets exactly one observer bound to the URL actually requested.
type interimTraceRoundTripper struct {
	base             http.RoundTripper
	includeSensitive bool
	collector        *interimCollector
}

func (t *interimTraceRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	requestIndex := t.collector.beginRequest()
	evidenceURL := req.URL.String()
	if req.Response != nil && !t.includeSensitive {
		evidenceURL = redactServerURLForEvidence(req.URL)
	}
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			rawHeader := http.Header(header)
			headers, headerBytesB64 := cloneHeader(rawHeader, t.includeSensitive)
			findings := analyzeInterimHeaders(code, rawHeader)
			sort.SliceStable(findings, func(i, j int) bool {
				return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
			})
			t.collector.add(InterimResponse{
				RequestIndex:    requestIndex,
				URL:             evidenceURL,
				StatusCode:      code,
				Headers:         headers,
				HeaderBytesB64:  headerBytesB64,
				HeadersRedacted: !t.includeSensitive,
				Findings:        findings,
			})
			return nil
		},
	}
	traced := req.Clone(httptrace.WithClientTrace(req.Context(), trace))
	return t.base.RoundTrip(traced)
}

func Analyze(ctx context.Context, rawURL string, opts Options) (Result, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.MaxRedirects < 0 {
		return Result{}, fmt.Errorf("max redirects must be >= 0")
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "HeaderLens/0.1.21-rc11"
	}
	if opts.ToolVersion == "" {
		opts.ToolVersion = "unknown"
	}
	if opts.MaxResponseHeaderBytes <= 0 {
		opts.MaxResponseHeaderBytes = 1 << 20 // 1 MiB; enough for normal responses while bounding hostile headers.
	}

	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" {
		return Result{}, fmt.Errorf("invalid target URL: use http:// or https:// with a host")
	}
	if u.User != nil {
		return Result{}, fmt.Errorf("target URL must not contain username/password userinfo")
	}
	if u.Fragment != "" {
		return Result{}, fmt.Errorf("target URL must not contain a fragment; fragments are client-side and are not sent in the HTTP target URI")
	}

	redirects := []string{u.String()}
	redirectResponses := make([]RedirectResponse, 0, 4)
	interimResponses := &interimCollector{}
	var blocked *RedirectBlock
	transport := &http.Transport{
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: opts.MaxResponseHeaderBytes,
		ResponseHeaderTimeout:  opts.Timeout,
		TLSHandshakeTimeout:    opts.Timeout,
		ExpectContinueTimeout:  time.Second,
		IdleConnTimeout:        30 * time.Second,
		MaxIdleConns:           2,
		MaxIdleConnsPerHost:    2,
	}
	if opts.UseEnvironmentProxy {
		transport.Proxy = http.ProxyFromEnvironment
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &interimTraceRoundTripper{
			base: transport, includeSensitive: opts.IncludeSensitiveHeaders, collector: interimResponses,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			reason := redirectBlockReason(u, req.URL, via, opts)
			evidenceURL := req.URL.String()
			if !opts.IncludeSensitiveHeaders {
				evidenceURL = redactServerURLForEvidence(req.URL)
			}
			if reason != "" {
				blocked = &RedirectBlock{URL: evidenceURL, Reason: reason}
				return http.ErrUseLastResponse
			}

			// req.Response is the response that caused this upcoming redirect.
			// Capture it before net/http closes/discards the hop. The first hop URL
			// is operator-supplied; later hop URLs came from prior server redirects
			// and use the same privacy normalization as RedirectChain.
			if req.Response != nil {
				hopURL := req.Response.Request.URL.String()
				if len(via) > 1 && !opts.IncludeSensitiveHeaders {
					hopURL = redactServerURLForEvidence(req.Response.Request.URL)
				}
				redirectResponses = append(redirectResponses, captureRedirectResponse(req.Response, hopURL, opts.IncludeSensitiveHeaders))
			}
			redirects = append(redirects, evidenceURL)
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	req.Header.Set("Accept", "*/*")

	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)
	if err != nil {
		if partial, ok := certificateFailureResult(rawURL, u, opts, duration, redirects, redirectResponses, interimResponses.snapshot(), err); ok {
			return partial, nil
		}
		if opts.IncludeSensitiveHeaders {
			// Sensitive opt-in explicitly allows raw diagnostic material in errors.
			return Result{}, fmt.Errorf("request failed: %w", err)
		}
		return Result{}, &safeRequestError{cause: err, kind: classifyRequestError(err)}
	}
	defer resp.Body.Close()

	headers, headerBytesB64 := cloneHeader(resp.Header, opts.IncludeSensitiveHeaders)
	finalURL := resp.Request.URL.String()
	if len(redirects) > 1 && !opts.IncludeSensitiveHeaders {
		// The initial target is operator-supplied evidence and remains verbatim,
		// but any URL learned from a server redirect is privacy-normalized by
		// default. OAuth and similar flows legitimately place credentials in
		// redirect query components; retaining them in default evidence would
		// leak secrets unrelated to HeaderLens' header analysis.
		finalURL = redactServerURLForEvidence(resp.Request.URL)
	}
	result := Result{
		SchemaVersion:     ResultSchemaVersion,
		Tool:              "HeaderLens",
		ToolVersion:       opts.ToolVersion,
		Target:            u.String(),
		FinalURL:          finalURL,
		StatusCode:        resp.StatusCode,
		DurationMS:        duration.Milliseconds(),
		HTTPVersion:       resp.Proto,
		Headers:           headers,
		HeaderBytesB64:    headerBytesB64,
		HeadersRedacted:   !opts.IncludeSensitiveHeaders,
		HTTPFraming:       httpFramingInfo(resp),
		RedirectChain:     redirects,
		RedirectResponses: redirectResponses,
		InterimResponses:  interimResponses.snapshot(),
		RedirectBlocked:   blocked,
		ScannedAt:         time.Now().UTC(),
	}
	if resp.TLS != nil {
		result.TLS = tlsInfo(resp.TLS)
		result.TLSVerification = &TLSVerificationInfo{Verified: true}
	}
	result.Findings = analyzeHeaders(resp)
	if blocked != nil {
		result.Findings = append(result.Findings, Finding{
			ID:          "HL-REDIRECT-001",
			Severity:    Info,
			Category:    "scope",
			Title:       "Redirect not followed by safe redirect policy",
			Evidence:    blocked.URL + " (" + blocked.Reason + ")",
			Remediation: "Review the redirect manually. Only relax redirect safety when the destination is explicitly authorized.",
		})
	}
	if result.TLS != nil {
		result.Findings = append(result.Findings, analyzeTLS(resp.TLS)...)
	}
	sort.SliceStable(result.Findings, func(i, j int) bool {
		return severityRank(result.Findings[i].Severity) > severityRank(result.Findings[j].Severity)
	})
	result.EvidenceSHA256 = evidenceHash(result)
	return result, nil
}

// safeRequestError avoids rendering untrusted Go transport error strings in
// standard CLI/stderr output. A failure after a server-supplied redirect can
// contain the entire Location URL (including OAuth codes); malformed server
// headers can also be quoted in parser errors. Keep the original error only
// behind Unwrap for explicit programmatic diagnostics, never in Error().
type safeRequestError struct {
	cause error
	kind  string
}

func (e *safeRequestError) Error() string {
	return "request failed: " + e.kind
}

func (e *safeRequestError) Unwrap() error { return e.cause }

func classifyRequestError(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "request canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "request timed out"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "network/host unreachable"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "connection closed before a complete HTTP response"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "DNS lookup failed"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "network request timed out"
	}
	// Do not stringify err here: net/http embeds raw Location URLs, malformed
	// field lines and other attacker-controlled bytes in some error messages.
	return "HTTP transport/protocol failure (raw details suppressed in default mode)"
}

func certificateFailureResult(rawURL string, u *url.URL, opts Options, duration time.Duration, redirects []string, redirectResponses []RedirectResponse, interimResponses []InterimResponse, requestErr error) (Result, bool) {
	var verifyErr *tls.CertificateVerificationError
	if !errors.As(requestErr, &verifyErr) || len(verifyErr.UnverifiedCertificates) == 0 {
		return Result{}, false
	}

	cert := verifyErr.UnverifiedCertificates[0]
	finalURL := u.String()
	redirectChain := append([]string(nil), redirects...)
	if len(redirectChain) == 0 {
		redirectChain = []string{u.String()}
	}
	if len(redirectChain) > 0 {
		finalURL = redirectChain[len(redirectChain)-1]
	}
	result := Result{
		SchemaVersion:     ResultSchemaVersion,
		Tool:              "HeaderLens",
		ToolVersion:       opts.ToolVersion,
		Target:            u.String(),
		FinalURL:          finalURL,
		DurationMS:        duration.Milliseconds(),
		Headers:           map[string][]string{},
		HeadersRedacted:   !opts.IncludeSensitiveHeaders,
		TLS:               tlsInfoFromCertificate(cert),
		TLSVerification:   &TLSVerificationInfo{Verified: false, ErrorKind: verificationErrorKind(verifyErr.Err)},
		RedirectChain:     redirectChain,
		RedirectResponses: append([]RedirectResponse(nil), redirectResponses...),
		InterimResponses:  append([]InterimResponse(nil), interimResponses...),
		ScannedAt:         time.Now().UTC(),
	}
	result.Findings = append(result.Findings, Finding{
		ID:          "HL-CERT-005",
		Severity:    Fail,
		Category:    "tls",
		Title:       "TLS certificate verification failed",
		Evidence:    verifyErr.Err.Error(),
		Remediation: "Correct the certificate chain, validity period, and hostname coverage. HeaderLens does not bypass certificate verification.",
	})
	now := time.Now()
	if now.Before(cert.NotBefore) {
		result.Findings = append(result.Findings, Finding{
			ID: "HL-CERT-004", Severity: Fail, Category: "tls", Title: "Certificate is not yet valid",
			Evidence: cert.NotBefore.UTC().Format(time.RFC3339), Remediation: "Use a certificate whose validity period includes the current time.",
		})
	}
	if now.After(cert.NotAfter) {
		result.Findings = append(result.Findings, Finding{
			ID: "HL-CERT-001", Severity: Fail, Category: "tls", Title: "Certificate expired",
			Evidence: cert.NotAfter.UTC().Format(time.RFC3339), Remediation: "Replace the expired certificate.",
		})
	}
	sort.SliceStable(result.Findings, func(i, j int) bool {
		return severityRank(result.Findings[i].Severity) > severityRank(result.Findings[j].Severity)
	})
	result.EvidenceSHA256 = evidenceHash(result)
	return result, true
}

func verificationErrorKind(err error) string {
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return "unknown_authority"
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return "hostname_mismatch"
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return "certificate_invalid:" + certificateInvalidReasonKind(invalid.Reason)
	}
	return "verification_failed"
}

func certificateInvalidReasonKind(reason x509.InvalidReason) string {
	switch reason {
	case x509.NotAuthorizedToSign:
		return "not_authorized_to_sign"
	case x509.Expired:
		return "expired_or_not_yet_valid"
	case x509.CANotAuthorizedForThisName:
		return "ca_not_authorized_for_name"
	case x509.TooManyIntermediates:
		return "too_many_intermediates"
	case x509.IncompatibleUsage:
		return "incompatible_usage"
	case x509.NameMismatch:
		return "issuer_subject_name_mismatch"
	case x509.NameConstraintsWithoutSANs:
		return "name_constraints_without_sans"
	case x509.UnconstrainedName:
		return "unconstrained_name"
	case x509.TooManyConstraints:
		return "too_many_constraints"
	case x509.CANotAuthorizedForExtKeyUsage:
		return "ca_not_authorized_for_ext_key_usage"
	default:
		return "other"
	}
}

func tlsInfoFromCertificate(c *x509.Certificate) *TLSInfo {
	t := &TLSInfo{
		CertSubject:   c.Subject.String(),
		CertIssuer:    c.Issuer.String(),
		CertNotBefore: c.NotBefore,
		CertNotAfter:  c.NotAfter,
		CertDNSNames:  append([]string(nil), c.DNSNames...),
	}
	sum := sha256.Sum256(c.Raw)
	t.CertSHA256 = hex.EncodeToString(sum[:])
	return t
}

func redirectBlockReason(initial, next *url.URL, via []*http.Request, opts Options) string {
	if len(via) > opts.MaxRedirects {
		return fmt.Sprintf("maximum redirect count reached (%d)", opts.MaxRedirects)
	}
	if next.User != nil {
		return "redirect URL contains username/password userinfo"
	}
	if next.Scheme != "http" && next.Scheme != "https" {
		return "redirect uses a non-HTTP(S) scheme"
	}
	if !opts.AllowCrossHostRedirects && normalizeHostname(next.Hostname()) != normalizeHostname(initial.Hostname()) {
		return "cross-host redirect blocked by default"
	}
	current := initial
	if len(via) > 0 {
		current = via[len(via)-1].URL
	}
	if !opts.AllowDowngradeRedirects && current.Scheme == "https" && next.Scheme == "http" {
		return "HTTPS-to-HTTP downgrade redirect blocked by default"
	}
	if !opts.AllowCrossPortRedirects && !redirectPortWithinDefaultBoundary(current, next) {
		return "cross-port redirect blocked by default"
	}
	return ""
}

// redirectPortWithinDefaultBoundary keeps each redirect hop on the current
// effective port by default. The one intentional exception is the conventional
// http-default (80) -> https-default (443) upgrade on the same hostname,
// which is the normal secure transition for a web endpoint. Any other port
// change is a separate service boundary and requires explicit operator opt-in.
func redirectPortWithinDefaultBoundary(current, next *url.URL) bool {
	currentPort, ok := effectiveURLPort(current)
	if !ok {
		return false
	}
	nextPort, ok := effectiveURLPort(next)
	if !ok {
		return false
	}
	if currentPort == nextPort {
		return true
	}
	return strings.EqualFold(current.Scheme, "http") && currentPort == "80" && strings.EqualFold(next.Scheme, "https") && nextPort == "443"
}

func effectiveURLPort(u *url.URL) (string, bool) {
	if u == nil {
		return "", false
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", false
		}
		return strconv.Itoa(n), true
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80", true
	case "https":
		return "443", true
	default:
		return "", false
	}
}

func normalizeHostname(s string) string {
	return strings.TrimSuffix(strings.ToLower(s), ".")
}

func cloneHeader(h http.Header, includeSensitive bool) (map[string][]string, map[string][]string) {
	out := make(map[string][]string, len(h))
	bytesOut := make(map[string][]string, len(h))
	hasInvalidUTF8 := false
	for k, v := range h {
		key := http.CanonicalHeaderKey(k)
		vals := append([]string(nil), v...)
		if !includeSensitive {
			if strings.EqualFold(key, "Set-Cookie") {
				for i := range vals {
					vals[i] = redactSetCookieValue(vals[i])
				}
			}
			if strings.EqualFold(key, "Location") {
				for i := range vals {
					vals[i] = redactLocationValue(vals[i])
				}
			}
			if strings.EqualFold(key, "Refresh") {
				for i := range vals {
					vals[i] = redactRefreshValue(vals[i])
				}
			}
			// Auth response fields can contain reusable challenges/nonces,
			// server-authentication material, or credentials accidentally echoed
			// by a gateway. RFC 7615 and RFC 7616 expressly allow nextnonce
			// and rspauth in Authentication-Info. Keep field presence/count and
			// require explicit sensitive opt-in for the raw field value. Do
			// not rely on parsing scheme-specific values: a malformed auth field
			// must never become an accidental redaction bypass.
			switch strings.ToLower(key) {
			case "authentication-info", "proxy-authentication-info",
				"authorization", "proxy-authorization",
				"www-authenticate", "proxy-authenticate":
				for i := range vals {
					vals[i] = "<redacted authentication field>"
				}
			}
		}
		display := make([]string, len(vals))
		b64 := make([]string, len(vals))
		for i, value := range vals {
			if !utf8.ValidString(value) {
				hasInvalidUTF8 = true
			}
			display[i] = strings.ToValidUTF8(value, "\uFFFD")
			b64[i] = base64.StdEncoding.EncodeToString([]byte(value))
		}
		out[key] = display
		bytesOut[key] = b64
	}
	if !hasInvalidUTF8 {
		return out, nil
	}
	return out, bytesOut
}

// redactSetCookieValue intentionally keeps only a privacy-safe summary. A
// malformed Set-Cookie field can contain semicolon-delimited fragments that
// look like attributes but are actually attacker-controlled secret text. We
// therefore do not preserve the raw tail unless the field parses successfully,
// and even for valid fields we retain only security-relevant attribute state.
func redactSetCookieValue(v string) string {
	c, err := http.ParseSetCookie(v)
	if err != nil {
		return "<redacted malformed Set-Cookie>"
	}
	parts := []string{c.Name + "=<redacted>"}
	if c.Secure {
		parts = append(parts, "Secure")
	}
	if c.HttpOnly {
		parts = append(parts, "HttpOnly")
	}
	if present, value := lastCookieAttribute(v, "SameSite"); present {
		value = trimHTTPOWS(value)
		switch {
		case strings.EqualFold(value, "Strict"):
			parts = append(parts, "SameSite=Strict")
		case strings.EqualFold(value, "Lax"):
			parts = append(parts, "SameSite=Lax")
		case strings.EqualFold(value, "None"):
			parts = append(parts, "SameSite=None")
		default:
			parts = append(parts, "SameSite=<invalid>")
		}
	}
	if hasCookieAttribute(v, "Path") {
		parts = append(parts, "Path=<redacted>")
	}
	if hasCookieAttribute(v, "Domain") {
		parts = append(parts, "Domain=<redacted>")
	}
	if hasCookieAttribute(v, "Max-Age") {
		parts = append(parts, "Max-Age=<redacted>")
	}
	if hasCookieAttribute(v, "Expires") {
		parts = append(parts, "Expires=<redacted>")
	}
	if c.Partitioned {
		parts = append(parts, "Partitioned")
	}
	if unknown := unknownCookieAttributeCount(v); unknown > 0 {
		parts = append(parts, fmt.Sprintf("Unknown-Attributes=%d", unknown))
	}
	return strings.Join(parts, "; ")
}

func redactRefreshValue(raw string) string {
	// Refresh can carry a browser navigation URL. That URL has the same durable
	// evidence privacy problem as Location (OAuth codes, signed URLs, reset
	// tokens, fragments), but HeaderLens does not need its payload to prove the
	// presence of a Refresh directive. Preserve a simple delay-only value and
	// collapse any redirect-like or malformed payload to a deterministic marker.
	value := trimHTTPOWS(raw)
	if value == "" {
		return value
	}
	if i := strings.IndexAny(value, ";,"); i >= 0 {
		prefix := trimHTTPOWS(value[:i])
		sep := value[i : i+1]
		if isNonNegativeRefreshDelay(prefix) {
			return prefix + sep + " REDACTED"
		}
		return "<redacted Refresh>"
	}
	if isNonNegativeRefreshDelay(value) {
		return value
	}
	return "<redacted Refresh>"
}

func isNonNegativeRefreshDelay(v string) bool {
	if v == "" {
		return false
	}
	dotSeen := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c >= '0' && c <= '9' {
			continue
		}
		if c == '.' && !dotSeen {
			dotSeen = true
			continue
		}
		return false
	}
	return v != "."
}

func redactLocationValue(raw string) string {
	u, err := url.Parse(raw)
	if err == nil {
		return redactServerURLForEvidence(u)
	}

	// A malformed Location can still contain scheme-specific secret material.
	// If it has an unsupported scheme (or a malformed HTTP(S) authority), do
	// not preserve the entire unparsed payload merely because net/url failed.
	if colon := strings.IndexByte(raw, ':'); colon > 0 && validSchemeName(raw[:colon]) {
		scheme := raw[:colon]
		if (!strings.EqualFold(scheme, "http") && !strings.EqualFold(scheme, "https")) || !strings.HasPrefix(raw[colon+1:], "//") {
			return strings.ToLower(scheme) + ":REDACTED"
		}
	}
	// For malformed hierarchical HTTP(S) locations, conservatively redact
	// authority userinfo and query/fragment material. Paths remain observable.
	redacted := redactMalformedLocationUserinfo(raw)
	if i := strings.IndexByte(redacted, '?'); i >= 0 {
		end := len(redacted)
		if j := strings.IndexByte(redacted[i+1:], '#'); j >= 0 {
			end = i + 1 + j
		}
		redacted = redacted[:i+1] + "REDACTED" + redacted[end:]
	}
	if i := strings.IndexByte(redacted, '#'); i >= 0 {
		redacted = redacted[:i+1] + "REDACTED"
	}
	return redacted
}

func redactMalformedLocationUserinfo(raw string) string {
	authorityStart := -1
	if strings.HasPrefix(raw, "//") {
		authorityStart = 2
	} else if i := strings.Index(raw, "://"); i > 0 {
		authorityStart = i + 3
	}
	if authorityStart < 0 || authorityStart >= len(raw) {
		return raw
	}
	authorityEnd := len(raw)
	if i := strings.IndexAny(raw[authorityStart:], "/?#"); i >= 0 {
		authorityEnd = authorityStart + i
	}
	authority := raw[authorityStart:authorityEnd]
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		return raw[:authorityStart] + "REDACTED@" + authority[at+1:] + raw[authorityEnd:]
	}
	return raw
}

// redactServerURLForEvidence is intentionally used only for URL material
// learned from a server (Location/redirects). The initial operator-supplied
// target remains verbatim so HeaderLens does not silently mutate engagement
// input. Query and fragment values are not needed to prove redirect topology
// and frequently contain OAuth codes, state, signed URLs, or other secrets.
func redactServerURLForEvidence(u *url.URL) string {
	if u == nil {
		return ""
	}
	// Non-HTTP(S) redirect schemes (data:, javascript:, mailto:, etc.)
	// are outside our active redirect scope. Their payload can live in
	// URL.Opaque *or* Path (e.g. javascript:/...); omit the whole payload,
	// preserving only the scheme as topology/classification evidence.
	// The same applies to malformed HTTP(S) scheme URLs without an authority.
	if u.Scheme != "" && (!strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") || u.Host == "") {
		return (&url.URL{Scheme: u.Scheme, Opaque: "REDACTED"}).String()
	}
	copyURL := *u
	// Some scheme-specific URL forms store secrets in Opaque, not RawQuery.
	if copyURL.Opaque != "" {
		copyURL.Opaque = "REDACTED"
	}
	if copyURL.User != nil {
		copyURL.User = url.User("REDACTED")
	}
	if copyURL.RawQuery != "" || copyURL.ForceQuery {
		copyURL.RawQuery = "REDACTED"
		copyURL.ForceQuery = false
	}
	if copyURL.Fragment != "" || copyURL.RawFragment != "" {
		copyURL.Fragment = "REDACTED"
		copyURL.RawFragment = ""
	}
	return copyURL.String()
}

func tlsInfo(s *tls.ConnectionState) *TLSInfo {
	t := &TLSInfo{
		Version:            tlsVersion(s.Version),
		CipherSuite:        tls.CipherSuiteName(s.CipherSuite),
		ServerName:         s.ServerName,
		NegotiatedProtocol: s.NegotiatedProtocol,
		VerifiedChains:     len(s.VerifiedChains),
	}
	if len(s.PeerCertificates) > 0 {
		c := s.PeerCertificates[0]
		t.CertSubject = c.Subject.String()
		t.CertIssuer = c.Issuer.String()
		t.CertNotBefore = c.NotBefore
		t.CertNotAfter = c.NotAfter
		t.CertDNSNames = append([]string(nil), c.DNSNames...)
		sum := sha256.Sum256(c.Raw)
		t.CertSHA256 = hex.EncodeToString(sum[:])
	}
	return t
}

func httpFramingInfo(resp *http.Response) *HTTPFramingInfo {
	if resp == nil {
		return nil
	}
	trailerNames := make([]string, 0, len(resp.Trailer))
	for name := range resp.Trailer {
		trailerNames = append(trailerNames, http.CanonicalHeaderKey(name))
	}
	sort.Strings(trailerNames)
	return &HTTPFramingInfo{
		ContentLength:    resp.ContentLength,
		TransferEncoding: append([]string(nil), resp.TransferEncoding...),
		ConnectionClose:  resp.Close,
		TrailerNames:     trailerNames,
	}
}

func captureRedirectResponse(resp *http.Response, evidenceURL string, includeSensitive bool) RedirectResponse {
	headers, headerBytesB64 := cloneHeader(resp.Header, includeSensitive)
	hop := RedirectResponse{
		URL:             evidenceURL,
		StatusCode:      resp.StatusCode,
		HTTPVersion:     resp.Proto,
		Headers:         headers,
		HeaderBytesB64:  headerBytesB64,
		HeadersRedacted: !includeSensitive,
		HTTPFraming:     httpFramingInfo(resp),
		Findings:        analyzeHeaders(resp),
	}
	if resp.TLS != nil {
		hop.TLS = tlsInfo(resp.TLS)
		hop.TLSVerification = &TLSVerificationInfo{Verified: true}
		hop.Findings = append(hop.Findings, analyzeTLS(resp.TLS)...)
	}
	sort.SliceStable(hop.Findings, func(i, j int) bool {
		return severityRank(hop.Findings[i].Severity) > severityRank(hop.Findings[j].Severity)
	})
	return hop
}

func securityTrailerNames(resp *http.Response) []string {
	if resp == nil || len(resp.Trailer) == 0 {
		return nil
	}
	securityOrControl := map[string]struct{}{
		"strict-transport-security":           {},
		"content-security-policy":             {},
		"content-security-policy-report-only": {},
		"x-content-type-options":              {},
		"x-frame-options":                     {},
		"referrer-policy":                     {},
		"permissions-policy":                  {},
		"set-cookie":                          {},
		"location":                            {},
		"refresh":                             {},
		"clear-site-data":                     {},
		"cross-origin-opener-policy":          {},
		"cross-origin-embedder-policy":        {},
		"cross-origin-resource-policy":        {},
	}
	out := make([]string, 0, len(resp.Trailer))
	for name := range resp.Trailer {
		if _, ok := securityOrControl[strings.ToLower(name)]; ok {
			out = append(out, http.CanonicalHeaderKey(name))
		}
	}
	sort.Strings(out)
	return out
}

func analyzeInterimHeaders(status int, h http.Header) []Finding {
	findings := make([]Finding, 0, 4)
	add := func(id string, sev Severity, cat, title, ev, rem string) {
		findings = append(findings, Finding{ID: id, Severity: sev, Category: cat, Title: title, Evidence: ev, Remediation: rem})
	}
	if values := h.Values("Content-Length"); len(values) > 0 {
		add("HL-FRAMING-001", Warn, "protocol", "Content-Length is forbidden on this informational response", strings.Join(values, " | "), "Do not send Content-Length on 1xx responses; they terminate at the end of the header section.")
	}
	if values := h.Values("Transfer-Encoding"); len(values) > 0 {
		add("HL-FRAMING-002", Warn, "protocol", "Transfer-Encoding is forbidden on this informational response", strings.Join(values, " | "), "Do not send Transfer-Encoding on 1xx responses.")
	}
	if values := h.Values("Trailer"); len(values) > 0 {
		add("HL-FRAMING-004", Warn, "protocol", "Trailer field announced on an informational response", strings.Join(values, " | "), "1xx responses cannot contain a trailer section; remove Trailer announcements from informational responses.")
	}
	if values := h.Values("Set-Cookie"); len(values) > 0 {
		add("HL-COOKIE-1XX-001", Info, "cookies", "Set-Cookie observed on an informational response", fmt.Sprintf("%d Set-Cookie field(s)", len(values)), "Do not assume persistence from a 100-level response. RFC 10025 permits user agents to ignore Set-Cookie fields on 100-level responses; assess any application impact in the actual client context.")
	}
	if status == http.StatusEarlyHints {
		for _, name := range []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"} {
			if len(h.Values(name)) > 0 {
				add("HL-EARLYHINTS-001", Info, "protocol", "Security-control header observed in 103 Early Hints", name, "RFC 8297 treats 103 fields as hints and says they must not affect processing of the final response except for speculative/performance behavior. Evaluate the corresponding control on the final response separately.")
				break
			}
		}
	}
	return findings
}

func analyzeHeaders(resp *http.Response) []Finding {
	h := resp.Header
	scheme := resp.Request.URL.Scheme
	findings := make([]Finding, 0, 24)

	add := func(id string, sev Severity, cat, title, ev, rem string) {
		findings = append(findings, Finding{ID: id, Severity: sev, Category: cat, Title: title, Evidence: ev, Remediation: rem})
	}

	if resp.StatusCode < 100 || resp.StatusCode > 599 {
		add("HL-HTTP-STATUS-001", Warn, "protocol", "Non-standard HTTP status code observed", strconv.Itoa(resp.StatusCode), "Review the upstream server/proxy response. HeaderLens preserves three-digit status codes accepted by Go even when they fall outside the standard 100-599 range.")
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		// HeaderLens never sends an Upgrade request field. A 101 is therefore an
		// unsolicited protocol switch relative to this probe, even when the
		// response also contains syntactically correct Upgrade/Connection fields.
		add("HL-UPGRADE-001", Warn, "protocol", "Unsolicited 101 Switching Protocols response", strings.Join(h.Values("Upgrade"), " | "), "HeaderLens did not request a protocol upgrade. Review the upstream server/proxy behavior and ensure 101 is sent only in response to an explicit compatible Upgrade request.")
		if len(h.Values("Upgrade")) == 0 {
			add("HL-UPGRADE-002", Warn, "protocol", "101 response is missing mandatory Upgrade field", "Upgrade not present", "A 101 response must identify the protocol(s) being selected in an Upgrade response field.")
		}
		if !headerListHasToken(h.Values("Connection"), "upgrade") {
			add("HL-UPGRADE-003", Warn, "protocol", "101 response is missing Connection: upgrade", strings.Join(h.Values("Connection"), " | "), "When Upgrade is sent in HTTP/1.1, the sender must also nominate Upgrade in the Connection field so intermediaries do not forward the hop-by-hop field incorrectly.")
		}
	}
	if resp.StatusCode == http.StatusUpgradeRequired && len(h.Values("Upgrade")) == 0 {
		add("HL-UPGRADE-004", Warn, "protocol", "426 Upgrade Required response is missing Upgrade field", "Upgrade not present", "A 426 response must include Upgrade to indicate acceptable protocols.")
	}
	if (resp.StatusCode >= 100 && resp.StatusCode < 200) || resp.StatusCode == http.StatusNoContent {
		if values := h.Values("Content-Length"); len(values) > 0 {
			add("HL-FRAMING-001", Warn, "protocol", "Content-Length is forbidden on this response status", strings.Join(values, " | "), "Do not send Content-Length on 1xx or 204 responses; their message framing terminates at the end of the header section.")
		}
		if values := observedTransferEncodings(resp); len(values) > 0 {
			add("HL-FRAMING-002", Warn, "protocol", "Transfer-Encoding is forbidden on this response status", strings.Join(values, " | "), "Do not send Transfer-Encoding on 1xx or 204 responses; their message framing terminates at the end of the header section.")
		}
	}
	if resp.StatusCode == http.StatusResetContent && resp.ContentLength > 0 {
		add("HL-FRAMING-003", Warn, "protocol", "205 Reset Content advertises a non-zero content length", strconv.FormatInt(resp.ContentLength, 10), "RFC 9110 forbids generating content in a 205 response. Use Content-Length: 0 or otherwise ensure the response carries no content.")
	}
	if names := securityTrailerNames(resp); len(names) > 0 {
		add("HL-TRAILER-001", Warn, "protocol", "Security/response-control field announced as an HTTP trailer", strings.Join(names, ", "), "Do not rely on security or response-control fields in trailers. RFC 9110 requires trailer use to be explicitly permitted by the field definition and notes that fields needed before content processing cannot be safely deferred.")
	}

	hstsValues := h.Values("Strict-Transport-Security")
	hostIsIP := isIPLiteralHost(resp.Request.URL.Hostname())
	if scheme == "https" && hostIsIP {
		if len(hstsValues) > 0 {
			add("HL-HSTS-006", Info, "headers", "HSTS cannot establish policy for an IP-literal host", hstsValues[0], "Use a DNS hostname when relying on HSTS. RFC 6797 user agents do not store IP-literal or IPv4 hosts as Known HSTS Hosts.")
		}
	} else if scheme == "https" {
		if len(hstsValues) == 0 {
			add("HL-HSTS-001", Warn, "headers", "HSTS header missing", "Strict-Transport-Security not present", "Consider HSTS after confirming all relevant subdomains support HTTPS.")
		} else {
			if len(hstsValues) > 1 {
				add("HL-HSTS-004", Warn, "headers", "Multiple HSTS header fields received", strings.Join(hstsValues, " | "), "Emit one Strict-Transport-Security field; user agents process only the first field.")
			}
			maxAge, valid, reason := parseHSTS(hstsValues[0])
			if !valid {
				add("HL-HSTS-003", Warn, "headers", "HSTS policy is invalid", hstsValues[0]+" ("+reason+")", "Emit one valid HSTS policy containing exactly one max-age directive.")
			} else if maxAge == 0 {
				add("HL-HSTS-007", Warn, "headers", "HSTS is explicitly disabled", hstsValues[0], "Use max-age=0 only when deliberately removing a previously stored HSTS policy; otherwise configure an intentional positive max-age.")
			} else if maxAge >= 31536000 {
				add("HL-HSTS-002", Pass, "headers", "HSTS enabled", hstsValues[0], "")
			} else {
				add("HL-HSTS-003", Warn, "headers", "HSTS max-age is short", hstsValues[0], "Use a deliberate max-age appropriate for your deployment; one year is a common hardened baseline.")
			}
		}
	} else if len(hstsValues) > 0 {
		add("HL-HSTS-005", Warn, "headers", "HSTS sent over insecure HTTP and will be ignored", hstsValues[0], "Serve HSTS only over HTTPS and redirect HTTP traffic to HTTPS according to deployment policy.")
	}

	cspValues := h.Values("Content-Security-Policy")
	cspEvidence := strings.Join(cspValues, " | ")
	repAnalyzePresent, repReportMissing := representationSecurityPolicyMode(resp)
	if repAnalyzePresent {
		if len(cspValues) == 0 {
			if repReportMissing {
				add("HL-CSP-001", Warn, "headers", "Content-Security-Policy missing", "", "Define a CSP suited to the application's actual resource requirements.")
			}
		} else {
			sev := Info
			title := "Content-Security-Policy present (partial analysis)"
			if cspContainsRiskyKeywords(cspValues) {
				sev = Warn
				title = "CSP contains potentially risky source keywords"
			}
			add("HL-CSP-002", sev, "headers", title, cspEvidence, "HeaderLens does not claim a generic CSP PASS from header presence alone. Review effective directives in browser context; avoid unsafe-inline/unsafe-eval where feasible and account for nonces/hashes/strict-dynamic.")
		}
		if len(h.Values("Content-Security-Policy-Report-Only")) > 0 && len(cspValues) == 0 {
			add("HL-CSP-003", Info, "headers", "Only report-only CSP observed", strings.Join(h.Values("Content-Security-Policy-Report-Only"), " | "), "Report-only CSP monitors violations but does not enforce restrictions.")
		}

		xctoValues := h.Values("X-Content-Type-Options")
		if len(xctoValues) == 1 && strings.EqualFold(trimHTTPOWS(xctoValues[0]), "nosniff") {
			add("HL-XCTO-001", Pass, "headers", "MIME sniffing protection enabled", "X-Content-Type-Options: nosniff", "")
		} else if len(xctoValues) > 1 {
			add("HL-XCTO-003", Warn, "headers", "Multiple X-Content-Type-Options fields are ambiguous", strings.Join(xctoValues, " | "), "Emit one X-Content-Type-Options: nosniff field.")
		} else if len(xctoValues) == 1 {
			add("HL-XCTO-002", Warn, "headers", "X-Content-Type-Options missing or unexpected", h.Get("X-Content-Type-Options"), "Set X-Content-Type-Options: nosniff.")
		} else if repReportMissing {
			add("HL-XCTO-002", Warn, "headers", "X-Content-Type-Options missing or unexpected", "", "Set X-Content-Type-Options: nosniff.")
		}

		if h.Get("Permissions-Policy") == "" {
			if repReportMissing {
				add("HL-PERM-001", Info, "headers", "Permissions-Policy not present", "", "Consider restricting browser features that the application does not use.")
			}
		} else {
			add("HL-PERM-002", Info, "headers", "Permissions-Policy present (semantics not evaluated)", h.Get("Permissions-Policy"), "HeaderLens records header presence but does not claim a protection PASS until the policy grammar and effective allowlists are evaluated.")
		}
	}

	refAnalyzePresent, refReportMissing := referrerPolicyMode(resp)
	if refAnalyzePresent {
		refRaw := strings.Join(h.Values("Referrer-Policy"), ",")
		if trimHTTPOWS(refRaw) == "" {
			if refReportMissing {
				add("HL-REF-001", Warn, "headers", "Referrer-Policy missing", "", "Set an explicit referrer policy appropriate for the application.")
			}
		} else {
			effective := effectiveReferrerPolicy(refRaw)
			switch effective {
			case "":
				add("HL-REF-004", Warn, "headers", "Referrer-Policy contains no recognized policy", refRaw, "Use a recognized Referrer-Policy token.")
			case "unsafe-url":
				add("HL-REF-002", Warn, "headers", "Referrer-Policy may disclose full URLs", refRaw+" (effective: unsafe-url)", "Prefer no-referrer, same-origin, strict-origin, or strict-origin-when-cross-origin where compatible.")
			case "no-referrer-when-downgrade":
				add("HL-REF-003", Warn, "headers", "Referrer-Policy permits full URL disclosure across secure origins", refRaw+" (effective: "+effective+")", "Prefer strict-origin-when-cross-origin, strict-origin, same-origin, or no-referrer where compatible. no-referrer-when-downgrade can send path/query data on same-security-level cross-origin requests.")
			case "origin", "origin-when-cross-origin":
				add("HL-REF-003", Info, "headers", "Referrer-Policy configured with moderate disclosure", refRaw+" (effective: "+effective+")", "Review whether origin disclosure is intended. Prefer a strict-* policy, same-origin, or no-referrer when a tighter policy fits the application.")
			default:
				add("HL-REF-003", Pass, "headers", "Referrer-Policy explicitly configured with a restrictive policy", refRaw+" (effective: "+effective+")", "")
			}
		}
	}

	if contentTypes := h.Values("Content-Type"); len(contentTypes) > 1 {
		add("HL-CONTENTTYPE-001", Warn, "protocol", "Multiple Content-Type fields are ambiguous", strings.Join(contentTypes, " | "), "Emit a single Content-Type field. RFC 9110 defines Content-Type as a singleton and notes security/interoperability risks when recipients resolve duplicates differently.")
	} else if len(contentTypes) == 1 {
		if _, err := parseContentTypeStrict(contentTypes[0]); err != nil {
			add("HL-CONTENTTYPE-002", Warn, "protocol", "Content-Type field is syntactically invalid", contentTypes[0], "Emit one syntactically valid media type. A comma-combined singleton such as 'application/json, text/html' is ambiguous and can be interpreted differently by recipients.")
		}
	}

	if frameProtectionRelevant(resp) {
		frameState, frameEvidence, duplicateFrameDirective := cspFrameAncestorsState(cspValues)
		xfoValues := h.Values("X-Frame-Options")
		xfoValid := false
		xfoEvidence := strings.Join(xfoValues, " | ")
		if len(xfoValues) == 1 {
			xfo := strings.ToUpper(trimHTTPOWS(xfoValues[0]))
			xfoValid = xfo == "DENY" || xfo == "SAMEORIGIN"
		} else if len(xfoValues) > 1 {
			add("HL-FRAME-003", Warn, "headers", "Multiple X-Frame-Options fields may be ambiguous", xfoEvidence, "Prefer one X-Frame-Options value, or use an enforced CSP frame-ancestors directive.")
		}
		if duplicateFrameDirective {
			add("HL-FRAME-005", Info, "headers", "Duplicate CSP frame-ancestors directive observed", frameEvidence, "Browsers ignore duplicate directives after the first occurrence within a policy; remove duplicates to avoid misleading reviews.")
		}
		switch frameState {
		case frameAncestorsRestrictive:
			add("HL-FRAME-001", Pass, "headers", "Restrictive frame embedding policy present", frameEvidence, "")
		case frameAncestorsBroad:
			add("HL-FRAME-004", Warn, "headers", "CSP frame-ancestors policy is effectively broad", frameEvidence, "Use a restrictive frame-ancestors source list such as 'none', 'self', or explicitly authorized ancestors. X-Frame-Options is ignored when an enforced frame-ancestors directive is present.")
		case frameAncestorsContextual:
			add("HL-FRAME-008", Info, "headers", "CSP frame-ancestors uses wildcard host trust", frameEvidence, "Review whether every hostname matched by the wildcard is actually trusted. HeaderLens does not claim a restrictive PASS for wildcard host sources without engagement-specific ownership context.")
		case frameAncestorsInvalid:
			add("HL-FRAME-006", Warn, "headers", "CSP frame-ancestors policy is invalid or not safely classifiable", frameEvidence, "Correct frame-ancestors syntax and use only valid ancestor sources. HeaderLens does not fall back to X-Frame-Options when an enforced frame-ancestors directive is present but malformed.")
		default:
			if xfoValid {
				add("HL-FRAME-001", Pass, "headers", "Frame embedding policy present", xfoEvidence, "")
			} else if jsonAPIResponse(resp) {
				add("HL-FRAME-007", Info, "headers", "No anti-framing policy observed on JSON/API response (context-dependent)", xfoEvidence, "Browser-consumed APIs can still benefit from frame-ancestors 'none' (and X-Frame-Options: DENY for legacy compatibility). For APIs never rendered or consumed by browsers, treat this as context rather than a defect.")
			} else {
				add("HL-FRAME-002", Warn, "headers", "No clear anti-framing policy found", xfoEvidence, "Use enforced CSP frame-ancestors; X-Frame-Options can be retained for legacy defense in depth. ALLOW-FROM is obsolete and unsupported by modern browsers.")
			}
		}
	}

	if v := h.Get("X-XSS-Protection"); v != "" {
		if trimHTTPOWS(v) == "0" {
			add("HL-LEGACY-XSS-001", Info, "headers", "Deprecated X-XSS-Protection header present but disabled", v, "Modern browsers do not rely on X-XSS-Protection. Prefer a well-designed CSP and remove legacy header dependencies.")
		} else {
			add("HL-LEGACY-XSS-002", Warn, "headers", "Deprecated X-XSS-Protection is enabled", v, "Disable/remove the legacy XSS auditor header and use a well-designed Content-Security-Policy instead.")
		}
	}
	if values := append(append([]string(nil), h.Values("Public-Key-Pins")...), h.Values("Public-Key-Pins-Report-Only")...); len(values) > 0 {
		add("HL-LEGACY-HPKP-001", Warn, "headers", "Deprecated HTTP Public Key Pinning header present", strings.Join(values, " | "), "Remove HPKP response headers; modern browsers no longer support HPKP and operational mistakes can cause outages.")
	}
	if values := h.Values("Expect-CT"); len(values) > 0 {
		add("HL-LEGACY-EXPECTCT-001", Info, "headers", "Deprecated Expect-CT header present", strings.Join(values, " | "), "Expect-CT is obsolete in modern Chromium-based browsers; remove it unless a documented legacy requirement exists.")
	}
	if values := h.Values("Feature-Policy"); len(values) > 0 {
		add("HL-LEGACY-FEATUREPOLICY-001", Info, "headers", "Deprecated Feature-Policy header present", strings.Join(values, " | "), "Feature-Policy was replaced by Permissions-Policy. Migrate intentionally and validate the current Permissions-Policy directives used by the application.")
	}
	legacyCSP := append(append([]string(nil), h.Values("X-Content-Security-Policy")...), h.Values("X-WebKit-CSP")...)
	if len(legacyCSP) > 0 {
		add("HL-LEGACY-CSP-001", Info, "headers", "Obsolete CSP header name present", strings.Join(legacyCSP, " | "), "Use the standard Content-Security-Policy header. Do not rely on obsolete X-Content-Security-Policy or X-WebKit-CSP headers for enforcement.")
	}

	for _, name := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"} {
		if v := h.Get(name); v != "" {
			add("HL-DISC-"+strings.ToUpper(strings.ReplaceAll(name, "-", "")), Info, "disclosure", name+" header discloses implementation detail", v, "Remove unnecessary version/product disclosure where practical.")
		}
	}

	setCookieValues := h.Values("Set-Cookie")
	if resp.StatusCode >= 100 && resp.StatusCode < 200 {
		if len(setCookieValues) > 0 {
			add("HL-COOKIE-1XX-001", Info, "cookies", "Set-Cookie observed on an informational response", fmt.Sprintf("%d Set-Cookie field(s)", len(setCookieValues)), "Do not assume persistence from a 100-level response. RFC 10025 permits user agents to ignore Set-Cookie fields on 100-level responses; assess any application impact in the actual client context.")
		}
		return findings
	}

	seenCookieNames := make(map[string]int)
	for i, rawCookie := range setCookieValues {
		c, err := http.ParseSetCookie(rawCookie)
		if err != nil {
			add(fmt.Sprintf("HL-COOKIE-PARSE-%03d", i+1), Warn, "cookies", "Malformed Set-Cookie header", redactSetCookieValue(rawCookie), "Correct the Set-Cookie syntax. Invalid cookie lines can be ignored by user agents and by high-level parsers.")
			continue
		}
		if duplicates := duplicateCookieAttributes(rawCookie); len(duplicates) > 0 {
			add(fmt.Sprintf("HL-COOKIE-DUPATTR-%03d", i+1), Warn, "cookies", "Cookie repeats one or more attributes", c.Name+": "+strings.Join(duplicates, ", "), "Emit each cookie attribute at most once. Duplicate attributes can be interpreted inconsistently and high-level parsers may silently select one value.")
		}
		seenCookieNames[c.Name]++
		if seenCookieNames[c.Name] == 2 {
			add("HL-COOKIE-DUPNAME-"+safeID(c.Name), Warn, "cookies", "Response sets the same cookie name more than once", c.Name, "Emit at most one Set-Cookie field per cookie-name in a response. RFC 10025 forbids servers from sending more than one Set-Cookie field with the same cookie-name.")
		}
		ev := cookieSecurityEvidence(c, rawCookie)
		if len(c.Unparsed) > 0 {
			add("HL-COOKIE-UNPARSED-"+safeID(c.Name), Warn, "cookies", "Cookie contains unparsed attributes", fmt.Sprintf("%s: %d attribute(s) not understood by Go's parser", c.Name, len(c.Unparsed)), "Review malformed or unsupported cookie attributes manually; HeaderLens does not assume they are enforced by browsers.")
		}
		if !c.Secure {
			add("HL-COOKIE-SECURE-"+safeID(c.Name), Warn, "cookies", "Cookie lacks Secure attribute", ev, "Set Secure on cookies that should only travel over HTTPS.")
		}
		if scheme != "https" && c.Secure {
			add("HL-COOKIE-ORIGIN-"+safeID(c.Name), Warn, "cookies", "Secure cookie set from an insecure HTTP origin", ev, "Set Secure cookies from HTTPS. Some user agents make localhost exceptions, but do not rely on insecure origins for production cookies.")
		}
		if !c.HttpOnly {
			add("HL-COOKIE-HTTPONLY-"+safeID(c.Name), Info, "cookies", "Cookie lacks HttpOnly attribute", ev, "Set HttpOnly for cookies not intentionally accessed by client-side script.")
		}
		// An absent SameSite attribute decodes to zero, not SameSiteDefaultMode.
		if c.SameSite == 0 || c.SameSite == http.SameSiteDefaultMode {
			if present, _ := lastCookieAttribute(rawCookie, "SameSite"); present {
				add("HL-COOKIE-SAMESITE-INVALID-"+safeID(c.Name), Warn, "cookies", "Cookie has an explicit but unrecognized SameSite value", fmt.Sprintf("%s: SameSite=<invalid> (effective enforcement: Default)", c.Name), "Use SameSite=Strict, SameSite=Lax, or SameSite=None intentionally. RFC 10025 maps unrecognized SameSite values to Default enforcement rather than treating the attribute as absent.")
			} else {
				add("HL-COOKIE-SAMESITE-"+safeID(c.Name), Info, "cookies", "Cookie has no explicit SameSite attribute", ev, "Set SameSite deliberately based on application flow.")
			}
		}
		if c.SameSite == http.SameSiteNoneMode && !c.Secure {
			add("HL-COOKIE-NONE-SECURE-"+safeID(c.Name), Warn, "cookies", "SameSite=None cookie lacks Secure", ev, "Modern browsers require Secure when SameSite=None is used.")
		}
		if c.Partitioned && !c.Secure {
			add("HL-COOKIE-PARTITIONED-"+safeID(c.Name), Warn, "cookies", "Partitioned cookie lacks Secure", ev, "Partitioned cookies require Secure.")
		}
		if cookiePrefixInvalid(c, rawCookie, scheme == "https") {
			add("HL-COOKIE-PREFIX-"+safeID(c.Name), Warn, "cookies", "Cookie prefix requirements are not satisfied", ev, "Ensure __Secure-, __Host-, __Http-, and __Host-Http- cookie prefix requirements are satisfied and set prefixed cookies from HTTPS.")
		}
	}

	return findings
}

func analyzeTLS(s *tls.ConnectionState) []Finding {
	findings := []Finding{}
	add := func(id string, sev Severity, title, ev, rem string) {
		findings = append(findings, Finding{ID: id, Severity: sev, Category: "tls", Title: title, Evidence: ev, Remediation: rem})
	}
	if s.Version == tls.VersionTLS13 {
		add("HL-TLS-001", Pass, "TLS 1.3 negotiated", tlsVersion(s.Version), "")
	} else if s.Version == tls.VersionTLS12 {
		add("HL-TLS-002", Pass, "TLS 1.2 negotiated", tlsVersion(s.Version), "TLS 1.3 is preferable when supported, but TLS 1.2 remains broadly acceptable with strong configuration.")
	}
	if len(s.PeerCertificates) > 0 {
		c := s.PeerCertificates[0]
		now := time.Now()
		notYetValid := now.Before(c.NotBefore)
		if notYetValid {
			add("HL-CERT-004", Fail, "Certificate is not yet valid", c.NotBefore.UTC().Format(time.RFC3339), "Use a certificate whose validity period includes the current time.")
		}
		left := c.NotAfter.Sub(now)
		if left < 0 {
			add("HL-CERT-001", Fail, "Certificate expired", c.NotAfter.UTC().Format(time.RFC3339), "Replace the expired certificate.")
		} else if !notYetValid && left < 30*24*time.Hour {
			add("HL-CERT-002", Warn, "Certificate expires soon", c.NotAfter.UTC().Format(time.RFC3339), "Renew the certificate before expiry.")
		} else if !notYetValid {
			add("HL-CERT-003", Pass, "Certificate validity window is currently valid", c.NotAfter.UTC().Format(time.RFC3339), "")
		}
	}
	return findings
}

func parseHSTS(v string) (int64, bool, string) {
	directives, ok := splitHSTSDirectives(v)
	if !ok {
		return 0, false, "unterminated quoted directive value"
	}
	seen := map[string]bool{}
	maxAgeSeen := false
	var maxAge int64
	for _, rawPart := range directives {
		part := trimHTTPOWS(rawPart)
		if part == "" {
			continue
		}
		name, rawValue, hasValue := strings.Cut(part, "=")
		name = strings.ToLower(trimHTTPOWS(name))
		if !isToken(name) {
			return 0, false, "invalid directive name"
		}
		if seen[name] {
			return 0, false, "duplicate directive: " + name
		}
		seen[name] = true

		value := ""
		if hasValue {
			var ok bool
			value, ok = parseHSTSDirectiveValue(rawValue)
			if !ok {
				return 0, false, "invalid directive value for " + name
			}
		}

		switch name {
		case "max-age":
			if !hasValue {
				return 0, false, "max-age has no value"
			}
			if value == "" || !allDigits(value) {
				return 0, false, "max-age must contain decimal digits only"
			}
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				if errors.Is(err, strconv.ErrRange) {
					// RFC 6797 defines max-age as 1*DIGIT without an upper
					// syntax bound. Saturate values beyond int64 because the
					// analyzer only needs to distinguish zero, short, and long
					// lifetimes; overflow must not turn a valid field invalid.
					n = int64(^uint64(0) >> 1)
				} else {
					return 0, false, "max-age could not be parsed"
				}
			}
			maxAge = n
			maxAgeSeen = true
		case "includesubdomains":
			if hasValue {
				return 0, false, "includeSubDomains must not have a value"
			}
		default:
			// Unknown extension directives are allowed, but their generic
			// token/quoted-string syntax is still validated above.
		}
	}
	if !maxAgeSeen {
		return 0, false, "required max-age directive missing"
	}
	return maxAge, true, ""
}

// splitHSTSDirectives separates semicolon-delimited directives without treating
// semicolons inside quoted-string directive values as delimiters. RFC 6797 uses
// HTTP quoted-string syntax for directive-value, so a simple strings.Split is
// not grammar-correct for extension directives.
func splitHSTSDirectives(v string) ([]string, bool) {
	parts := make([]string, 0, 4)
	start := 0
	quoted := false
	escaped := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if quoted {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				quoted = false
			}
			continue
		}
		switch c {
		case '"':
			quoted = true
		case ';':
			parts = append(parts, v[start:i])
			start = i + 1
		}
	}
	if quoted || escaped {
		return nil, false
	}
	parts = append(parts, v[start:])
	return parts, true
}

func parseHSTSDirectiveValue(raw string) (string, bool) {
	raw = trimHTTPOWS(raw)
	if isToken(raw) {
		return raw, true
	}
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return "", false
	}
	var b strings.Builder
	for i := 1; i < len(raw)-1; i++ {
		c := raw[i]
		if c == '\\' {
			i++
			if i >= len(raw)-1 || !validQuotedPairByte(raw[i]) {
				return "", false
			}
			b.WriteByte(raw[i])
			continue
		}
		if !validQuotedTextByte(c) || c == '"' {
			return "", false
		}
		b.WriteByte(c)
	}
	return b.String(), true
}

func validQuotedTextByte(c byte) bool {
	return c == '\t' || c == ' ' || c == '!' || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e) || c >= 0x80
}

func validQuotedPairByte(c byte) bool {
	return c == '\t' || c == ' ' || (c >= 0x21 && c <= 0x7e) || c >= 0x80
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func splitCSPPolicies(values []string) []string {
	policies := make([]string, 0, len(values))
	for _, fieldValue := range values {
		// CSP response-header grammar is a comma-delimited list of serialized
		// policies. Commas are not valid inside directive values, so splitting
		// the field here mirrors the top-level list grammar rather than treating
		// two policies as one policy.
		for _, policy := range strings.Split(fieldValue, ",") {
			if policy = trimCSPASCIIWhitespace(policy); policy != "" {
				policies = append(policies, policy)
			}
		}
	}
	return policies
}

func cspContainsRiskyKeywords(values []string) bool {
	for _, policy := range splitCSPPolicies(values) {
		// CSP fallback is policy-local. A default-src keyword is only effective for
		// a script/style capability when no more-specific directive handles that
		// capability. Record directive presence before evaluating the first
		// occurrence of each directive.
		present := make(map[string]bool)
		for _, directive := range strings.Split(policy, ";") {
			directive = trimCSPASCIIWhitespace(directive)
			if directive == "" || !isASCIIString(directive) {
				continue
			}
			fields := splitCSPASCIIWhitespace(strings.ToLower(directive))
			if len(fields) == 0 {
				continue
			}
			name := fields[0]
			if !present[name] {
				present[name] = true
			}
		}

		seen := make(map[string]bool)
		for _, directive := range strings.Split(policy, ";") {
			directive = trimCSPASCIIWhitespace(directive)
			if directive == "" || !isASCIIString(directive) {
				continue
			}
			fields := splitCSPASCIIWhitespace(strings.ToLower(directive))
			if len(fields) < 2 {
				continue
			}
			name := fields[0]
			if seen[name] {
				continue // CSP ignores later duplicate directives in the same policy.
			}
			seen[name] = true

			relevantInline := name == "default-src" || name == "script-src" || name == "script-src-elem" || name == "script-src-attr" || name == "style-src" || name == "style-src-elem" || name == "style-src-attr"
			// unsafe-eval governs JavaScript/WebAssembly through script-src (or
			// default-src fallback) and CSSOM string-parsing capabilities through
			// style-src (or fallback). The elem/attr subdirectives do not govern the
			// eval-style sinks.
			relevantEval := name == "default-src" || name == "script-src" || name == "style-src"
			if name == "default-src" {
				// default-src does not influence a capability once a more-specific
				// directive exists. For eval-like sinks, script-src and style-src are
				// the specific controls. For inline content, elem/attr directives can
				// independently replace the script/style fallback path.
				relevantEval = !present["script-src"] || !present["style-src"]
				scriptInlineFallsBack := !present["script-src"] && !(present["script-src-elem"] && present["script-src-attr"])
				styleInlineFallsBack := !present["style-src"] && !(present["style-src-elem"] && present["style-src-attr"])
				relevantInline = scriptInlineFallsBack || styleInlineFallsBack
			}

			hasNonceOrHash := false
			hasStrictDynamic := false
			for _, token := range fields[1:] {
				if isCSPNonceOrHashSource(token) {
					hasNonceOrHash = true
				}
				if token == "'strict-dynamic'" {
					hasStrictDynamic = true
				}
			}
			for _, token := range fields[1:] {
				switch token {
				case "'unsafe-eval'":
					if relevantEval {
						return true
					}
				case "'unsafe-inline'":
					if !relevantInline {
						continue
					}
					// CSP3 source-list processing disables unsafe-inline when a nonce
					// or hash is present. strict-dynamic also disables it for script,
					// but not for style/default-src's style fallback.
					if hasNonceOrHash {
						continue
					}
					if (name == "script-src" || name == "script-src-elem" || name == "script-src-attr") && hasStrictDynamic {
						continue
					}
					return true
				}
			}
		}
	}
	return false
}

type frameAncestorsState int

const (
	frameAncestorsAbsent frameAncestorsState = iota
	frameAncestorsBroad
	frameAncestorsContextual
	frameAncestorsRestrictive
	frameAncestorsInvalid
)

func cspFrameAncestorsState(values []string) (frameAncestorsState, string, bool) {
	state := frameAncestorsAbsent
	duplicate := false
	evidence := make([]string, 0, len(values))
	for _, policy := range splitCSPPolicies(values) {
		seen := false
		for _, directive := range strings.Split(policy, ";") {
			directive = trimCSPASCIIWhitespace(directive)
			if directive == "" || !isASCIIString(directive) {
				continue // CSP parsing ignores non-ASCII serialized directives.
			}
			fields := splitCSPASCIIWhitespace(directive)
			if len(fields) == 0 || !strings.EqualFold(fields[0], "frame-ancestors") {
				continue
			}
			if seen {
				duplicate = true
				continue // CSP parsing ignores duplicate directives after the first in a policy.
			}
			seen = true
			evidence = append(evidence, directive)

			policyState := classifyFrameAncestors(fields[1:])
			switch policyState {
			case frameAncestorsRestrictive:
				// Multiple CSP policies compose restrictively. One independently
				// restrictive policy is sufficient to constrain framing even if a
				// separate policy is broad, contextual, or malformed.
				state = frameAncestorsRestrictive
			case frameAncestorsContextual:
				if state == frameAncestorsAbsent || state == frameAncestorsBroad {
					state = frameAncestorsContextual
				}
			case frameAncestorsBroad:
				if state == frameAncestorsAbsent {
					state = frameAncestorsBroad
				}
			case frameAncestorsInvalid:
				if state != frameAncestorsRestrictive {
					// Malformed evidence wins over broad/contextual evidence. We refuse
					// to claim a protection unless another separately enforced policy is
					// independently restrictive.
					state = frameAncestorsInvalid
				}
			}
		}
	}
	return state, strings.Join(evidence, " | "), duplicate
}

func classifyFrameAncestors(sources []string) frameAncestorsState {
	if len(sources) == 0 {
		return frameAncestorsInvalid
	}
	if len(sources) == 1 && strings.EqualFold(sources[0], "'none'") {
		return frameAncestorsRestrictive
	}

	seenValid := false
	seenHostTrust := false
	seenInvalid := false
	for _, raw := range sources {
		source := trimCSPASCIIWhitespace(raw)
		lower := strings.ToLower(source)
		if lower == "'none'" {
			// A lone 'none' is the special deny-all value. In a list with other
			// expressions it has no useful restrictive effect, and HeaderLens
			// conservatively exposes the malformed/ambiguous policy rather than
			// deriving a PASS from the other tokens.
			seenInvalid = true
			continue
		}
		if lower == "'self'" {
			seenValid = true
			continue
		}
		if source == "*" || isCSPSchemeSource(source) || isCSPAnyHostSource(source) {
			// Any broad source makes the union broad, regardless of token order.
			return frameAncestorsBroad
		}
		if !isCSPHostSource(source) {
			seenInvalid = true
			continue
		}
		seenValid = true
		// Any explicit host allowlist requires engagement context: a syntactically
		// narrow third-party host can still be attacker-controlled or outside the
		// intended trust boundary. Only 'none'/'self' can earn an unconditional PASS.
		seenHostTrust = true
	}

	if seenInvalid {
		return frameAncestorsInvalid
	}
	if seenHostTrust {
		return frameAncestorsContextual
	}
	if seenValid {
		return frameAncestorsRestrictive
	}
	return frameAncestorsInvalid
}

func isCSPSchemeSource(source string) bool {
	if !strings.HasSuffix(source, ":") || strings.Contains(source, "://") {
		return false
	}
	return validSchemeName(strings.TrimSuffix(source, ":"))
}

func isCSPNonceOrHashSource(token string) bool {
	if len(token) < 4 || token[0] != '\'' || token[len(token)-1] != '\'' {
		return false
	}
	inner := token[1 : len(token)-1]
	value := ""
	switch {
	case strings.HasPrefix(inner, "nonce-"):
		value = inner[len("nonce-"):]
	case strings.HasPrefix(inner, "sha256-"):
		value = inner[len("sha256-"):]
	case strings.HasPrefix(inner, "sha384-"):
		value = inner[len("sha384-"):]
	case strings.HasPrefix(inner, "sha512-"):
		value = inner[len("sha512-"):]
	default:
		return false
	}
	if value == "" {
		return false
	}
	padding := 0
	for i := len(value) - 1; i >= 0 && value[i] == '='; i-- {
		padding++
	}
	if padding > 2 || padding == len(value) {
		return false
	}
	for i := 0; i < len(value)-padding; i++ {
		c := value[i]
		if isASCIILetter(c) || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

func validSchemeName(s string) bool {
	if s == "" || !isASCIILetter(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if isASCIILetter(c) || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isCSPAnyHostSource(source string) bool {
	candidate := source
	if i := strings.Index(candidate, "://"); i >= 0 {
		candidate = candidate[i+3:]
	}
	candidate = strings.SplitN(candidate, "/", 2)[0]
	if strings.HasPrefix(candidate, "[") {
		return false
	}
	if host, _, err := net.SplitHostPort(candidate); err == nil {
		candidate = host
	} else if i := strings.LastIndex(candidate, ":"); i > -1 {
		port := candidate[i+1:]
		if port == "*" || allDigits(port) {
			candidate = candidate[:i]
		}
	}
	return candidate == "*"
}

func isCSPHostSource(source string) bool {
	if source == "" || strings.ContainsAny(source, "'\";,?#") {
		return false
	}
	candidate := source
	if i := strings.Index(candidate, "://"); i >= 0 {
		if !validSchemeName(candidate[:i]) {
			return false
		}
		candidate = candidate[i+3:]
	}
	if candidate == "" {
		return false
	}
	if slash := strings.IndexByte(candidate, '/'); slash >= 0 {
		if !validCSPPathPart(candidate[slash:]) {
			return false
		}
		candidate = candidate[:slash]
	}
	if candidate == "" {
		return false
	}

	host := candidate
	if strings.HasPrefix(candidate, "[") {
		// CSP3 host-part is currently DNS-label syntax only; literal IPv6
		// sources are intentionally not part of the host-source grammar.
		return false
	} else if i := strings.LastIndex(candidate, ":"); i >= 0 {
		port := candidate[i+1:]
		if port != "*" && !allDigits(port) {
			return false
		}
		host = candidate[:i]
	}
	if host == "" || host == "*" {
		return false
	}
	host = strings.TrimPrefix(host, "*.")
	if host == "" || strings.HasPrefix(host, ".") || strings.Contains(host, "..") {
		return false
	}
	// CSP3 host-part permits one optional trailing dot. Preserve the source
	// semantics while validating the underlying labels.
	if strings.HasSuffix(host, ".") {
		host = strings.TrimSuffix(host, ".")
		if host == "" || strings.HasSuffix(host, ".") {
			return false
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if isASCIILetter(c) || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func effectiveReferrerPolicy(v string) string {
	valid := map[string]bool{
		"no-referrer": true, "no-referrer-when-downgrade": true, "same-origin": true,
		"origin": true, "strict-origin": true, "origin-when-cross-origin": true,
		"strict-origin-when-cross-origin": true, "unsafe-url": true,
	}
	last := ""
	for _, token := range strings.Split(v, ",") {
		t := strings.ToLower(trimHTTPOWS(token))
		if valid[t] {
			last = t
		}
	}
	return last
}

func headerListHasToken(values []string, want string) bool {
	for _, field := range values {
		for _, token := range strings.Split(field, ",") {
			if strings.EqualFold(trimHTTPOWS(token), want) {
				return true
			}
		}
	}
	return false
}

func observedTransferEncodings(resp *http.Response) []string {
	values := make([]string, 0, len(resp.TransferEncoding)+len(resp.Header.Values("Transfer-Encoding")))
	seen := make(map[string]struct{})
	for _, raw := range append(append([]string(nil), resp.Header.Values("Transfer-Encoding")...), resp.TransferEncoding...) {
		for _, part := range strings.Split(raw, ",") {
			v := trimHTTPOWS(part)
			if v == "" {
				continue
			}
			key := strings.ToLower(v)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			values = append(values, v)
		}
	}
	return values
}

func representationSecurityPolicyMode(resp *http.Response) (analyzePresent, reportMissing bool) {
	if resp == nil {
		return false, false
	}
	switch resp.StatusCode {
	case http.StatusSwitchingProtocols, http.StatusNoContent, http.StatusResetContent:
		// These responses do not deliver a document/representation to which CSP,
		// XCTO, or Permissions-Policy can meaningfully attach. Reporting their
		// absence as a weakness is endpoint noise.
		return false, false
	case http.StatusNotModified:
		// 304 carries no representation. Existing cached header metadata can be
		// updated by fields that are present, but absence does not mean the cached
		// representation lacked the corresponding control. Analyze present fields
		// only and suppress missing-header claims.
		return true, false
	default:
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			// Other redirects can carry a small fallback representation, but their
			// primary semantics are navigation. Treat any explicit controls as
			// observable evidence without claiming that absent representation-only
			// controls are defects on an intermediate redirect response.
			return true, false
		}
		return true, true
	}
}

func referrerPolicyMode(resp *http.Response) (analyzePresent, reportMissing bool) {
	if resp == nil {
		return false, false
	}
	switch resp.StatusCode {
	case http.StatusSwitchingProtocols, http.StatusNoContent, http.StatusResetContent:
		return false, false
	case http.StatusNotModified:
		return true, false
	default:
		// Referrer-Policy on redirects remains relevant to subsequent navigation,
		// so unlike representation-only controls, 3xx responses are analyzed.
		return true, true
	}
}

func frameProtectionRelevant(resp *http.Response) bool {
	// Redirect and no-content responses do not carry a renderable response
	// representation. JSON/API responses are still analyzed, but absence of an
	// anti-framing control is contextual INFO rather than a generic WARN because
	// applicability depends on whether browser clients can consume/render them.
	return !(resp.StatusCode == http.StatusSwitchingProtocols || (resp.StatusCode >= 300 && resp.StatusCode < 400) || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusResetContent)
}

func jsonAPIResponse(resp *http.Response) bool {
	values := resp.Header.Values("Content-Type")
	// Content-Type is a singleton field. Duplicate lines can be resolved
	// differently by different recipients, so do not downgrade anti-framing
	// findings to contextual API noise when the representation type itself is
	// ambiguous.
	if len(values) != 1 {
		return false
	}
	contentType, err := parseContentTypeStrict(values[0])
	if err != nil {
		return false
	}
	contentType = strings.ToLower(contentType)
	return contentType == "application/json" || strings.HasSuffix(contentType, "+json")
}

func parseContentTypeStrict(raw string) (string, error) {
	value := trimHTTPOWS(raw)
	// mime.ParseMediaType is intentionally user-friendly and can accept some
	// Unicode whitespace that is not HTTP OWS. Content-Type grammar is ASCII
	// outside quoted-string parameter values, so reject non-ASCII bytes there
	// before delegating the remaining media-type grammar to the standard parser.
	quoted := false
	escaped := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if quoted {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				quoted = false
			}
			continue
		}
		if c == '"' {
			quoted = true
			continue
		}
		if c >= 0x80 {
			return "", fmt.Errorf("non-ASCII byte outside quoted-string")
		}
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return "", err
	}
	return mediaType, nil
}

func trimHTTPOWS(s string) string {
	return strings.Trim(s, " \t")
}

func trimCSPASCIIWhitespace(s string) string {
	return strings.Trim(s, " \t\n\f\r")
}

func splitCSPASCIIWhitespace(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\f', '\r':
			return true
		default:
			return false
		}
	})
}

func isASCIIString(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func isIPLiteralHost(host string) bool {
	candidate := host
	if i := strings.LastIndex(candidate, "%"); i > 0 && strings.Contains(candidate[:i], ":") {
		candidate = candidate[:i]
	}
	return net.ParseIP(candidate) != nil
}

func cookieAttributeParts(raw string) []string {
	parts := strings.Split(raw, ";")
	if len(parts) <= 1 {
		return nil
	}
	return parts[1:]
}

func lastCookieAttribute(raw, want string) (bool, string) {
	present := false
	value := ""
	for _, part := range cookieAttributeParts(raw) {
		part = trimHTTPOWS(part)
		name, val, hasValue := strings.Cut(part, "=")
		name = trimHTTPOWS(name)
		if !strings.EqualFold(name, want) {
			continue
		}
		present = true
		if hasValue {
			value = trimHTTPOWS(val)
		} else {
			value = ""
		}
	}
	return present, value
}

func hasCookieAttribute(raw, want string) bool {
	present, _ := lastCookieAttribute(raw, want)
	return present
}

func unknownCookieAttributeCount(raw string) int {
	known := map[string]bool{
		"expires": true, "max-age": true, "domain": true, "path": true,
		"secure": true, "httponly": true, "samesite": true, "partitioned": true,
	}
	count := 0
	for _, part := range cookieAttributeParts(raw) {
		part = trimHTTPOWS(part)
		if part == "" {
			continue
		}
		name, _, _ := strings.Cut(part, "=")
		name = strings.ToLower(trimHTTPOWS(name))
		if name != "" && !known[name] {
			count++
		}
	}
	return count
}

func validCSPPathPart(path string) bool {
	if path == "" || path[0] != '/' {
		return false
	}
	if len(path) == 1 {
		return true
	}
	// RFC 3986 path-absolute requires the first segment after '/' to be
	// non-empty. CSP3 additionally excludes literal ';' and ',' from path-part.
	if path[1] == '/' {
		return false
	}
	for i := 1; i < len(path); i++ {
		c := path[i]
		if c == '/' {
			continue
		}
		if c == ';' || c == ',' || c >= 0x80 {
			return false
		}
		if isUnreservedURIByte(c) || isSubDelimURIByte(c) || c == ':' || c == '@' {
			continue
		}
		if c == '%' {
			if i+2 >= len(path) || !isHexByte(path[i+1]) || !isHexByte(path[i+2]) {
				return false
			}
			i += 2
			continue
		}
		return false
	}
	return true
}

func isUnreservedURIByte(c byte) bool {
	return isASCIILetter(c) || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~'
}

func isSubDelimURIByte(c byte) bool {
	switch c {
	case '!', '$', '&', '\'', '(', ')', '*', '+', '=':
		return true
	default:
		return false
	}
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func duplicateCookieAttributes(raw string) []string {
	parts := strings.Split(raw, ";")
	if len(parts) < 3 {
		return nil
	}
	seen := make(map[string]bool, len(parts)-1)
	dups := map[string]bool{}
	for _, part := range parts[1:] {
		part = trimHTTPOWS(part)
		if part == "" {
			continue
		}
		name, _, _ := strings.Cut(part, "=")
		name = strings.ToLower(trimHTTPOWS(name))
		if name == "" {
			continue
		}
		if seen[name] {
			dups[name] = true
		}
		seen[name] = true
	}
	out := make([]string, 0, len(dups))
	for name := range dups {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func cookieSecurityEvidence(c *http.Cookie, raw string) string {
	pathPresent, _ := lastCookieAttribute(raw, "Path")
	domainPresent, _ := lastCookieAttribute(raw, "Domain")
	return fmt.Sprintf("%s: Secure=%t HttpOnly=%t SameSite=%s PathPresent=%t PathIsRoot=%t DomainPresent=%t Partitioned=%t",
		c.Name, c.Secure, c.HttpOnly, sameSite(c.SameSite), pathPresent, c.Path == "/", domainPresent, c.Partitioned)
}

func cookiePrefixInvalid(c *http.Cookie, raw string, secureOrigin bool) bool {
	name := strings.ToLower(c.Name)
	domainPresent := hasCookieAttribute(raw, "Domain")
	switch {
	case strings.HasPrefix(name, "__host-http-"):
		return !secureOrigin || !c.Secure || !c.HttpOnly || domainPresent || c.Path != "/"
	case strings.HasPrefix(name, "__host-"):
		return !secureOrigin || !c.Secure || domainPresent || c.Path != "/"
	case strings.HasPrefix(name, "__http-"):
		return !secureOrigin || !c.Secure || !c.HttpOnly
	case strings.HasPrefix(name, "__secure-"):
		return !secureOrigin || !c.Secure
	default:
		return false
	}
}

func evidenceHash(r Result) string {
	type redirectEvidence struct {
		URL             string               `json:"url"`
		StatusCode      int                  `json:"status_code"`
		HTTPVersion     string               `json:"http_version"`
		Headers         map[string][]string  `json:"headers"`
		HeaderBytesB64  map[string][]string  `json:"header_bytes_b64,omitempty"`
		HeadersRedacted bool                 `json:"headers_redacted"`
		TLS             *TLSInfo             `json:"tls,omitempty"`
		TLSVerification *TLSVerificationInfo `json:"tls_verification,omitempty"`
		HTTPFraming     *HTTPFramingInfo     `json:"http_framing"`
	}
	type interimEvidence struct {
		RequestIndex    int                 `json:"request_index"`
		URL             string              `json:"url"`
		StatusCode      int                 `json:"status_code"`
		Headers         map[string][]string `json:"headers"`
		HeaderBytesB64  map[string][]string `json:"header_bytes_b64,omitempty"`
		HeadersRedacted bool                `json:"headers_redacted"`
	}
	redirectEvidenceItems := make([]redirectEvidence, 0, len(r.RedirectResponses))
	for _, hop := range r.RedirectResponses {
		redirectEvidenceItems = append(redirectEvidenceItems, redirectEvidence{
			URL: hop.URL, StatusCode: hop.StatusCode, HTTPVersion: hop.HTTPVersion,
			Headers: hop.Headers, HeaderBytesB64: hop.HeaderBytesB64, HeadersRedacted: hop.HeadersRedacted,
			TLS: hop.TLS, TLSVerification: hop.TLSVerification, HTTPFraming: hop.HTTPFraming,
		})
	}
	interimEvidenceItems := make([]interimEvidence, 0, len(r.InterimResponses))
	for _, interim := range r.InterimResponses {
		interimEvidenceItems = append(interimEvidenceItems, interimEvidence{
			RequestIndex: interim.RequestIndex, URL: interim.URL, StatusCode: interim.StatusCode, Headers: interim.Headers,
			HeaderBytesB64: interim.HeaderBytesB64, HeadersRedacted: interim.HeadersRedacted,
		})
	}
	type redirectBlockEvidence struct {
		URL string `json:"url"`
	}
	var blockedEvidence *redirectBlockEvidence
	if r.RedirectBlocked != nil {
		blockedEvidence = &redirectBlockEvidence{URL: r.RedirectBlocked.URL}
	}
	payload := struct {
		SchemaVersion     string                 `json:"schema_version"`
		Tool              string                 `json:"tool"`
		Target            string                 `json:"target"`
		FinalURL          string                 `json:"final_url"`
		StatusCode        int                    `json:"status_code"`
		HTTPVersion       string                 `json:"http_version"`
		Headers           map[string][]string    `json:"headers"`
		HeaderBytesB64    map[string][]string    `json:"header_bytes_b64,omitempty"`
		HeadersRedacted   bool                   `json:"headers_redacted"`
		TLS               *TLSInfo               `json:"tls,omitempty"`
		TLSVerification   *TLSVerificationInfo   `json:"tls_verification,omitempty"`
		HTTPFraming       *HTTPFramingInfo       `json:"http_framing,omitempty"`
		RedirectChain     []string               `json:"redirect_chain,omitempty"`
		RedirectResponses []redirectEvidence     `json:"redirect_responses,omitempty"`
		InterimResponses  []interimEvidence      `json:"interim_responses,omitempty"`
		RedirectBlocked   *redirectBlockEvidence `json:"redirect_blocked,omitempty"`
	}{
		SchemaVersion: r.SchemaVersion, Tool: r.Tool, Target: r.Target, FinalURL: r.FinalURL,
		StatusCode: r.StatusCode, HTTPVersion: r.HTTPVersion, Headers: r.Headers,
		HeaderBytesB64: r.HeaderBytesB64, HeadersRedacted: r.HeadersRedacted, TLS: r.TLS, TLSVerification: r.TLSVerification, HTTPFraming: r.HTTPFraming, RedirectChain: r.RedirectChain,
		RedirectResponses: redirectEvidenceItems, InterimResponses: interimEvidenceItems, RedirectBlocked: blockedEvidence,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	// v14 hashes the same normalized UTF-8 representation consumers can
	// recover from the publicly serialized JSON. Go's first JSON marshal of
	// invalid UTF-8 string bytes emits the JSON U+FFFD escape, but a consumer later
	// sees valid U+FFFD codepoints. Without this normalization the two JSON
	// serializations produce different SHA-256 inputs (BUG-HL-071).
	// Keep v13's historical digest and schema frozen; never rewrite v13 IDs.
	// v14 and v15 share the same two-pass JSON UTF-8 normalization.
	// Retain v14's historical digest when computing legacy observations;
	// otherwise the current-version bump would silently regress replay.
	if r.SchemaVersion == "headerlens.result/v14" || r.SchemaVersion == ResultSchemaVersion {
		// Decode into a fresh instance to avoid mutating TLS/header slices or
		// maps shared with the caller while normalizing arbitrary UTF-8.
		normalized := reflect.New(reflect.TypeOf(payload)).Interface()
		if err := json.Unmarshal(b, normalized); err != nil {
			return ""
		}
		b, err = json.Marshal(normalized)
		if err != nil {
			return ""
		}
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func severityRank(s Severity) int {
	switch s {
	case Fail:
		return 4
	case Warn:
		return 3
	case Info:
		return 2
	case Pass:
		return 1
	default:
		return 0
	}
}

func sameSite(s http.SameSite) string {
	switch s {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "Default"
	}
}

func safeID(s string) string {
	s = strings.ToUpper(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
