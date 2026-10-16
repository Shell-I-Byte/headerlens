package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Shell-I-Byte/headerlens/internal/analyzer"
)

func sampleResult() analyzer.Result {
	return analyzer.Result{
		SchemaVersion:     analyzer.ResultSchemaVersion,
		Tool:              "HeaderLens",
		ToolVersion:       "test",
		Target:            "https://example.test",
		FinalURL:          "https://example.test",
		StatusCode:        200,
		DurationMS:        12,
		HTTPVersion:       "HTTP/2.0",
		Headers:           map[string][]string{"X-Test": {"yes"}},
		HeadersRedacted:   true,
		TLS:               &analyzer.TLSInfo{Version: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256"},
		TLSVerification:   &analyzer.TLSVerificationInfo{Verified: true},
		Findings:          []analyzer.Finding{{ID: "TEST-1", Severity: analyzer.Info, Category: "test", Title: "example", Evidence: "evidence"}},
		InterimResponses:  []analyzer.InterimResponse{{URL: "https://example.test", StatusCode: 103, Headers: map[string][]string{"Link": {"</x>; rel=preload"}}, HeadersRedacted: true}},
		RedirectResponses: []analyzer.RedirectResponse{{URL: "https://example.test/start", StatusCode: 302, HTTPVersion: "HTTP/1.1", Headers: map[string][]string{}, HeadersRedacted: true, HTTPFraming: &analyzer.HTTPFramingInfo{ContentLength: 0}, Findings: []analyzer.Finding{{ID: "HOP-1", Severity: analyzer.Warn, Category: "cookies", Title: "hop finding", Evidence: "redacted"}}}},
		RedirectBlocked:   &analyzer.RedirectBlock{URL: "https://other.test", Reason: "cross-host redirect blocked by default"},
		EvidenceSHA256:    strings.Repeat("a", 64),
		ScannedAt:         time.Unix(1, 0).UTC(),
	}
}

func TestJSONProducesDecodableResult(t *testing.T) {
	var buf bytes.Buffer
	in := sampleResult()
	if err := JSON(&buf, in); err != nil {
		t.Fatal(err)
	}
	var got analyzer.Result
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != analyzer.ResultSchemaVersion || got.EvidenceSHA256 != in.EvidenceSHA256 {
		t.Fatalf("unexpected JSON result: %#v", got)
	}
}

func TestTextIncludesSafetyAndEvidence(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, sampleResult())
	out := buf.String()
	for _, want := range []string{"HeaderLens", "TLS verification: verified", "Redirect safety: blocked", "Informational responses: 1 preserved", "Redirect responses: 1 followed hop(s) preserved", "hop finding", "Evidence SHA-256:", "[INFO]"} {
		if !strings.Contains(out, want) {
			t.Fatalf("text report missing %q: %s", want, out)
		}
	}
}

func TestTextEscapesTerminalControlAndBidiCharacters(t *testing.T) {
	in := sampleResult()
	in.Target = "https://example.test/a\u202Etxt.exe"
	in.FinalURL = "https://example.test/ok\nFAKE: injected"
	in.Findings[0].Evidence = "trusted\u001b[31mRED\u001b[0m\u2066isolate\u2028line"
	var buf bytes.Buffer
	Text(&buf, in)
	out := buf.String()
	for _, dangerous := range []string{"\u202E", "\u001b", "\u2066", "\u2028", "ok\nFAKE"} {
		if strings.Contains(out, dangerous) {
			t.Fatalf("text report retained terminal-dangerous sequence %q: %q", dangerous, out)
		}
	}
	for _, escaped := range []string{"\\u202E", "\\x1B", "\\u2066", "\\u2028", "\\x0A"} {
		if !strings.Contains(out, escaped) {
			t.Fatalf("text report missing visible escape %q: %q", escaped, out)
		}
	}
}

// Both immediate write failures and partial writes after a successful prefix
// must prevent a success exit from a text-report consumer.
type syntheticFailWriter struct {
	writes    int
	failAfter int
	short     bool
}

func (w *syntheticFailWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes <= w.failAfter {
		return len(p), nil
	}
	if w.short {
		return len(p) / 2, nil
	}
	return 0, errors.New("synthetic disk full")
}
func TestTextDetectsPartialAndFailedOutput(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after int
		short bool
	}{
		{"immediate_failure", 0, false},
		{"mid_report_failure", 3, false},
		{"mid_report_short_write", 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &syntheticFailWriter{failAfter: tc.after, short: tc.short}
			err := Text(sink, sampleResult())
			if err == nil {
				t.Fatalf("partial report was silently accepted")
			}
			if tc.short && !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("err=%v want io.ErrShortWrite", err)
			}
			if sink.writes != tc.after+1 {
				t.Fatalf("writer invoked %d times after failure; want %d", sink.writes, tc.after+1)
			}
		})
	}
}

func TestJSONRejectsShortWrite(t *testing.T) {
	sink := &syntheticFailWriter{short: true}
	if err := JSON(sink, sampleResult()); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("json partial output error=%v, want io.ErrShortWrite", err)
	}
}

// A locally supplied Result can contain hostile display strings, and a future
// analyzer may move raw response metadata into another text field. Text output
// must apply the same terminal-neutralization rule to EVERY displayed value.
func TestTextEscapesEveryDisplayedFindingAndTLSField(t *testing.T) {
	in := sampleResult()
	in.TLS.Version = "TLS\x1b[31m"
	in.TLS.CipherSuite = "cipher\u202Ereversed"
	in.Findings[0].Severity = analyzer.Severity("WARN\x1b[31m")
	in.Findings[0].Category = "category\x1b[31m"
	in.Findings[0].Title = "title\x1b[31m"
	in.Findings[0].Remediation = "remediation\u202Ereversed"
	in.RedirectResponses[0].Findings[0].Severity = analyzer.Severity("WARN\x1b[32m")
	in.RedirectResponses[0].Findings[0].Category = "hop\x1b[32m"
	in.InterimResponses[0].Findings = []analyzer.Finding{{Severity: analyzer.Severity("INFO\x1b[33m"), Category: "interim\x1b[33m", Title: "title\x1b[33m", Evidence: "safe"}}
	var b bytes.Buffer
	if err := Text(&b, in); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, bad := range []string{"\x1b", "\u202E"} {
		if strings.Contains(out, bad) {
			t.Fatalf("unescaped control %q in %q", bad, out)
		}
	}
	for _, want := range []string{`TLS\x1B[31m`, `cipher\u202Ereversed`, `WARN\x1B[31m`, `category\x1B[31m`, `title\x1B[31m`, `remediation\u202Ereversed`, `WARN\x1B[32m`, `INFO\x1B[33m`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing escaped %q in %q", want, out)
		}
	}
}
