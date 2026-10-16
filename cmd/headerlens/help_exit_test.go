package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelpFlagsReturnSuccessAndTrustedUsage(t *testing.T) {
	for _, flagArg := range []string{"-h", "--help", "-help"} {
		t.Run(flagArg, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run([]string{flagArg}, &stdout, &stderr); got != 0 {
				t.Errorf("help exit=%d, want 0", got)
			}
			if stdout.Len() != 0 {
				t.Errorf("help unexpectedly wrote stdout=%q", stdout.String())
			}
			if !strings.Contains(stderr.String(), "Usage: headerlens") {
				t.Errorf("missing trusted usage: %q", stderr.String())
			}
			if strings.Contains(stderr.String(), "invalid command-line option") {
				t.Errorf("incorrect invalid-option diagnostic: %q", stderr.String())
			}
		})
	}
}
