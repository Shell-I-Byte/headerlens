package analyzer

import (
	"encoding/json"
	"testing"
	"time"
)

// A digest intended for independent ingestion must survive an actual producer
// JSON marshal + consumer unmarshal + digest recomputation. Go's encoding/json
// emits invalid UTF-8 as a literal \\ufffd JSON escape on the initial marshal,
// but emits an already-valid U+FFFD as UTF-8 on the next marshal. Computing a
// digest before normalization binds bytes the consumer cannot reconstruct.
func TestEvidenceDigestIsRecomputableFromSerializedJSONWithInvalidUTF8(t *testing.T) {
	t0 := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	r := Result{SchemaVersion: ResultSchemaVersion, Tool: "HeaderLens", ToolVersion: "test", Target: "https://localhost/", FinalURL: "https://localhost/", StatusCode: 0, HTTPVersion: "", Headers: map[string][]string{}, HeadersRedacted: true, TLS: &TLSInfo{CertSubject: "CN=invalid\xff", CertNotBefore: t0, CertNotAfter: t0.Add(time.Hour)}, TLSVerification: &TLSVerificationInfo{Verified: false, ErrorKind: "certificate_invalid"}, ScannedAt: t0}
	r.EvidenceSHA256 = evidenceHash(r)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var consumer Result
	if err := json.Unmarshal(b, &consumer); err != nil {
		t.Fatal(err)
	}
	if got := evidenceHash(consumer); got != r.EvidenceSHA256 {
		t.Fatalf("the producer emitted an unreproducible observation hash: producer=%s consumer=%s", r.EvidenceSHA256, got)
	}
}
