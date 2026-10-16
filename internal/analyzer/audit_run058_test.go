package analyzer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A changed server Date is changed directly observed evidence. This positive
// control guards against "fixing" a timing-sensitive test by accidentally
// dropping Date (or other ordinary response headers) from evidence_sha256.
func TestRun058DifferentServerDateChangesEvidenceHash(t *testing.T) {
	var requestNo atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestNo.Add(1) == 1 {
			w.Header().Set("Date", "Fri, 09 Oct 2026 12:00:00 GMT")
		} else {
			w.Header().Set("Date", "Fri, 09 Oct 2026 12:00:01 GMT")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	opts := Options{Timeout: 3 * time.Second, ToolVersion: "audit058"}
	first, err := Analyze(context.Background(), server.URL, opts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Analyze(context.Background(), server.URL, opts)
	if err != nil {
		t.Fatal(err)
	}
	if first.EvidenceSHA256 == "" || second.EvidenceSHA256 == "" || first.EvidenceSHA256 == second.EvidenceSHA256 {
		t.Fatalf("different observed Date values must bind to different hashes: %q, %q", first.EvidenceSHA256, second.EvidenceSHA256)
	}
	if first.Headers["Date"][0] == second.Headers["Date"][0] {
		t.Fatalf("synthetic Date header was not changed: %#v, %#v", first.Headers, second.Headers)
	}
}
