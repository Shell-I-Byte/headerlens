package main

import (
	"bytes"
	"strings"
	"testing"
)

// Regression for BUG-HL-075: flag.FlagSet's default error renderer echoes the
// user-supplied unknown option, including raw ANSI, line breaks and bidi.
// A terminal or CI log must never interpret those bytes as trusted output.
func TestInvalidFlagsCannotInjectTerminalOrCILogs(t *testing.T) {
	cases := []struct {
		name, arg, forbidden string
	}{
		{"newline_fake_status", "-bad\nCI-SUCCESS-FAKE", "CI-SUCCESS-FAKE"},
		{"ansi_escape", "-bad\x1b[31mUNSAFE\x1b[0m", "\x1b"},
		{"bidi_override", "-bad\u202eLOG-STATUS", "\u202e"},
		{"invalid_value_newline", "-timeout=invalid\nCI-SUCCESS-FAKE", "\nCI-SUCCESS-FAKE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run([]string{tc.arg}, &stdout, &stderr); code != 2 {
				t.Fatalf("exit=%d want 2", code)
			}
			if stdout.Len() != 0 {
				t.Fatalf("unexpected stdout: %q", stdout.String())
			}
			if strings.Contains(stderr.String(), tc.forbidden) {
				t.Fatalf("untrusted control/log marker escaped into stderr: %q", stderr.String())
			}
		})
	}
}

// Sanitizing parse errors must not silently suppress the static help text.
func TestInvalidFlagStillPrintsTrustedUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run([]string{"-fake\x1b[33m"}, &stdout, &stderr); got != 2 {
		t.Fatalf("exit=%d, want 2", got)
	}
	msg := stderr.String()
	for _, want := range []string{"Usage: headerlens", "-json", "-timeout", "-max-header-bytes"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing expected usage option %q from %q", want, msg)
		}
	}
	if strings.Contains(msg, "\x1b") {
		t.Fatalf("ANSI control rendered in usage: %q", msg)
	}
}
