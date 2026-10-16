package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if rc := run([]string{"-version"}, &stdout, &stderr); rc != 0 {
		t.Fatalf("exit=%d stderr=%q", rc, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != version {
		t.Fatalf("stdout=%q want version %q", stdout.String(), version)
	}
}

func TestRunRequiresTarget(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if rc := run(nil, &stdout, &stderr); rc != 2 {
		t.Fatalf("exit=%d want 2", rc)
	}
	if !strings.Contains(stderr.String(), "Usage: headerlens") {
		t.Fatalf("usage missing: %q", stderr.String())
	}
}

func TestRunRejectsInvalidOptions(t *testing.T) {
	cases := [][]string{
		{"-timeout=0s", "http://example.test"},
		{"-max-redirects=-1", "http://example.test"},
		{"-max-header-bytes=0", "http://example.test"},
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		if rc := run(args, &stdout, &stderr); rc != 2 {
			t.Fatalf("args=%v exit=%d want 2", args, rc)
		}
	}
}

func TestRunRejectsUnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if rc := run([]string{"-does-not-exist"}, &stdout, &stderr); rc != 2 {
		t.Fatalf("exit=%d want 2", rc)
	}
}

// A CLI must never report success when its report cannot be delivered to its
// configured output sink. This regression uses only a loopback HTTP server.
type rejectedOutput struct{ writes int }

func (w *rejectedOutput) Write(p []byte) (int, error) {
	w.writes++
	return 0, errors.New("synthetic output sink unavailable")
}
func TestRunReportsTextOutputFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	for _, flags := range [][]string{{}, {"-json"}} {
		var stderr bytes.Buffer
		out := &rejectedOutput{}
		args := append(append([]string(nil), flags...), server.URL)
		if code := run(args, out, &stderr); code != 1 {
			t.Errorf("args=%q exit=%d, want 1 for output failure; stderr=%q", args, code, stderr.String())
		}
		if out.writes == 0 {
			t.Errorf("args=%q writer was not exercised", args)
		}
	}
}
func TestRunReportsVersionOutputFailure(t *testing.T) {
	var stderr bytes.Buffer
	if got := run([]string{"-version"}, &rejectedOutput{}, &stderr); got != 1 {
		t.Fatalf("version exit=%d want 1 for output failure", got)
	}
}

type shortOutput struct{}

func (shortOutput) Write(p []byte) (int, error) { return len(p) / 2, nil }
func TestRunRejectsShortVersionWrite(t *testing.T) {
	var stderr bytes.Buffer
	if rc := run([]string{"-version"}, shortOutput{}, &stderr); rc != 1 {
		t.Fatalf("exit=%d want=1 because version output was truncated", rc)
	}
}
