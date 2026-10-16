package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/Shell-I-Byte/headerlens/internal/analyzer"
)

func JSON(w io.Writer, r analyzer.Result) error {
	checked := &checkedWriter{destination: w}
	enc := json.NewEncoder(checked)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return err
	}
	return checked.err
}

// checkedWriter remembers partial or failed writes, including a broken pipe
// after earlier lines already reached the destination. This prevents the CLI
// from returning success after delivering an incomplete text report.
type checkedWriter struct {
	destination io.Writer
	err         error
}

func (c *checkedWriter) Write(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	n, err := c.destination.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		c.err = err
	}
	return n, err
}

func Text(w io.Writer, r analyzer.Result) error {
	checked := &checkedWriter{destination: w}
	w = checked
	fmt.Fprintf(w, "HeaderLens\nTarget: %s\nFinal:  %s\nHTTP:   %d (%s)\nTime:   %d ms\n", terminalSafe(r.Target), terminalSafe(r.FinalURL), r.StatusCode, terminalSafe(r.HTTPVersion), r.DurationMS)
	if r.TLS != nil {
		fmt.Fprintf(w, "TLS:    %s / %s\n", terminalSafe(r.TLS.Version), terminalSafe(r.TLS.CipherSuite))
	}
	if r.TLSVerification != nil {
		if r.TLSVerification.Verified {
			fmt.Fprintln(w, "TLS verification: verified")
		} else {
			fmt.Fprintf(w, "TLS verification: failed (%s)\n", terminalSafe(r.TLSVerification.ErrorKind))
		}
	}
	if r.RedirectBlocked != nil {
		fmt.Fprintf(w, "Redirect safety: blocked %s (%s)\n", terminalSafe(r.RedirectBlocked.URL), terminalSafe(r.RedirectBlocked.Reason))
	}
	if len(r.InterimResponses) > 0 {
		fmt.Fprintf(w, "Informational responses: %d preserved\n", len(r.InterimResponses))
		for i, interim := range r.InterimResponses {
			fmt.Fprintf(w, "  1xx %d (request %d): %d %s\n", i+1, interim.RequestIndex, interim.StatusCode, terminalSafe(interim.URL))
			for _, f := range interim.Findings {
				fmt.Fprintf(w, "    [%s] %-10s %s\n", terminalSafe(string(f.Severity)), terminalSafe(f.Category), terminalSafe(f.Title))
				if f.Evidence != "" {
					fmt.Fprintf(w, "           evidence: %s\n", terminalSafe(f.Evidence))
				}
			}
		}
	}
	if len(r.RedirectResponses) > 0 {
		fmt.Fprintf(w, "Redirect responses: %d followed hop(s) preserved\n", len(r.RedirectResponses))
		for i, hop := range r.RedirectResponses {
			fmt.Fprintf(w, "  Hop %d: %d %s %s\n", i+1, hop.StatusCode, terminalSafe(hop.HTTPVersion), terminalSafe(hop.URL))
			for _, f := range hop.Findings {
				fmt.Fprintf(w, "    [%s] %-10s %s\n", terminalSafe(string(f.Severity)), terminalSafe(f.Category), terminalSafe(f.Title))
				if f.Evidence != "" {
					fmt.Fprintf(w, "           evidence: %s\n", terminalSafe(f.Evidence))
				}
			}
		}
	}
	if r.EvidenceSHA256 != "" {
		fmt.Fprintf(w, "Evidence SHA-256: %s\n", r.EvidenceSHA256)
	}
	fmt.Fprintln(w, "\nFindings:")
	for _, f := range r.Findings {
		fmt.Fprintf(w, "[%s] %-10s %s\n", terminalSafe(string(f.Severity)), terminalSafe(f.Category), terminalSafe(f.Title))
		if f.Evidence != "" {
			fmt.Fprintf(w, "       evidence: %s\n", terminalSafe(f.Evidence))
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "       note: %s\n", terminalSafe(f.Remediation))
		}
	}
	return checked.err
}

func terminalSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || isBidiControl(r) {
			if r <= 0xff {
				fmt.Fprintf(&b, "\\x%02X", r)
			} else if r <= 0xffff {
				fmt.Fprintf(&b, "\\u%04X", r)
			} else {
				fmt.Fprintf(&b, "\\U%08X", r)
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isBidiControl(r rune) bool {
	return r == '\u061c' || r == '\u200e' || r == '\u200f' || r == '\u2028' || r == '\u2029' ||
		(r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069')
}
