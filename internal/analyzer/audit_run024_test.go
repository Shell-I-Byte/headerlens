package analyzer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Regression coverage for fail-closed cancellation. No external targets are used.
func TestRun024AlreadyCancelledNeverSendsRequest(t *testing.T) {
	var served atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Analyze(ctx, server.URL, Options{Timeout: time.Second, ToolVersion: "run024"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if got := served.Load(); got != 0 {
		t.Fatalf("already-cancelled scan made %d network requests", got)
	}
}

// Every scan has its own transport, trace collector, and immutable deterministic
// evidence hash despite concurrent invocations and differing scan timestamps.
func TestRun024ConcurrentIndependentScansDeterministicEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The default net/http Date field is wall-clock dependent and can change
		// between parallel requests crossing a UTC-second boundary. Bind the
		// fixture to one observed response so this test measures concurrency,
		// not two legitimately different HTTP observations.
		w.Header().Set("Date", "Fri, 09 Oct 2026 12:00:00 GMT")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	const runs = 48
	digests := make([]string, runs)
	failures := make(chan error, runs)
	var wg sync.WaitGroup
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			result, err := Analyze(context.Background(), server.URL, Options{Timeout: 3 * time.Second, ToolVersion: "run024"})
			if err != nil {
				failures <- fmt.Errorf("scan %d: %w", i, err)
				return
			}
			if result.StatusCode != http.StatusNoContent || result.EvidenceSHA256 == "" || result.SchemaVersion != ResultSchemaVersion {
				failures <- fmt.Errorf("scan %d: unexpected result: code %d, hash %q, schema %q", i, result.StatusCode, result.EvidenceSHA256, result.SchemaVersion)
				return
			}
			digests[i] = result.EvidenceSHA256
		}(i)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	for i, digest := range digests {
		if digest != digests[0] {
			t.Fatalf("scan %d evidence differs from scan 0: %s vs %s", i, digest, digests[0])
		}
	}
}

func TestRun024IPv6LoopbackNoExternalTraffic(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable in this environment: %v", err)
	}
	var served atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
	}))
	_ = server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()

	result, err := Analyze(context.Background(), server.URL, Options{Timeout: 3 * time.Second, ToolVersion: "run024"})
	if err != nil {
		t.Fatalf("IPv6 local scan: %v", err)
	}
	if result.StatusCode != 200 || result.FinalURL != server.URL || served.Load() != 1 {
		t.Fatalf("unexpected IPv6 provenance: code=%d final=%q served=%d", result.StatusCode, result.FinalURL, served.Load())
	}
}
