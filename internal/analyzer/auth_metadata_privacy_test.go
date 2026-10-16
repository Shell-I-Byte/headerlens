package analyzer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// These are deliberately synthetic authorization/authentication tokens.
// RFC 7615/7616 Authentication-Info can contain nextnonce and rspauth.
func TestDefaultAuthenticationMetadataIsRedactedOnEveryHTTPHop(t *testing.T) {
	const secret = "SYNTHETIC_AUTH_NEXTNONCE_72_NEVER_PUBLISH"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			w.Header().Set("Authentication-Info", `nextnonce="`+secret+`"`)
			w.Header().Set("Proxy-Authentication-Info", `rspauth="`+secret+`"`)
			w.Header().Set("WWW-Authenticate", `Digest realm="`+secret+`"`)
			w.Header().Set("Authorization", "Bearer "+secret)
			w.Header().Set("Proxy-Authorization", "Basic "+secret)
			w.Header().Set("Proxy-Authenticate", `Digest nonce="`+secret+`"`)
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			w.Header().Set("Authentication-Info", `nextnonce="`+secret+`"`)
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+secret+`"`)
			w.WriteHeader(http.StatusEarlyHints)
			w.Header().Del("Authentication-Info")
			w.Header().Del("WWW-Authenticate")
			w.Header().Set("Authentication-Info", `nextnonce="`+secret+`"`)
			w.Header().Set("Proxy-Authentication-Info", `nextnonce="`+secret+`"`)
			w.WriteHeader(http.StatusOK)
		}
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	opts := Options{Timeout: 3 * time.Second, MaxRedirects: 3, ToolVersion: "0.1.18"}

	result, err := Analyze(context.Background(), server.URL+"/redirect", opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.RedirectResponses) != 1 {
		t.Fatalf("redirect observations: %d", len(result.RedirectResponses))
	}
	if len(result.InterimResponses) != 1 {
		t.Fatalf("interim observations: %d", len(result.InterimResponses))
	}
	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serialized), secret) {
		t.Fatalf("default evidence disclosed synthetic auth secret: %s", serialized)
	}
	for _, header := range []string{"Authentication-Info", "Proxy-Authentication-Info"} {
		if strings.Contains(strings.Join(result.Headers[header], ""), secret) {
			t.Fatalf("final %s not redacted", header)
		}
	}
	// Explicitly opting in must not discard raw evidence needed by an authorized operator.
	opts.IncludeSensitiveHeaders = true
	raw, err := Analyze(context.Background(), server.URL+"/redirect", opts)
	if err != nil {
		t.Fatal(err)
	}
	rawBytes, _ := json.Marshal(raw)
	if !strings.Contains(string(rawBytes), secret) {
		t.Fatalf("raw opt-in removed authentication metadata")
	}
}

func TestAuthFieldRedactorCaseInsensitiveValueCountAndByteMirror(t *testing.T) {
	const secret = "TEST_ONLY_AUTH_FIELD_72"
	headers := http.Header{
		"aUtHeNtIcAtIoN-iNfO": []string{`nextnonce="` + secret + `"`, string([]byte{0xff, 0xfe}) + secret},
		"pRoXy-aUtHeNtIcAtE":  []string{`Digest nonce="` + secret + `"`},
		"X-Documentation":     []string{"safe-status"},
	}
	got, b64 := cloneHeader(headers, false)
	if len(got["Authentication-Info"]) != 2 || got["Authentication-Info"][0] != "<redacted authentication field>" || got["Authentication-Info"][1] != "<redacted authentication field>" {
		t.Fatalf("sensitive auth field values or cardinality not normalized: %#v", got)
	}
	if got["Proxy-Authenticate"][0] != "<redacted authentication field>" {
		t.Fatalf("case-insensitive proxy auth redaction failed: %#v", got)
	}
	if got["X-Documentation"][0] != "safe-status" {
		t.Fatalf("unrelated header unnecessarily redacted: %#v", got)
	}
	if b64 != nil {
		t.Fatalf("raw invalid UTF-8 bytes survived into b64 mirror: %#v", b64)
	}
	raw, rawB64 := cloneHeader(headers, true)
	if !strings.Contains(raw["Authentication-Info"][0], secret) || len(rawB64) == 0 {
		t.Fatal("sensitive opt-in must preserve raw values and opaque byte mirror")
	}
}

// Explicit historical v14 calls must retain their original two-stage UTF-8
// normalizer even after the producer's current schema is bumped to v15.
func TestHistoricalV14EvidenceHashNormalizationSurvivesV15Upgrade(t *testing.T) {
	orig := Result{
		SchemaVersion:   "headerlens.result/v14",
		Tool:            "HeaderLens",
		Target:          "http://127.0.0.1/",
		FinalURL:        "http://127.0.0.1/",
		Headers:         map[string][]string{"X-Custom": {string([]byte{0xff})}},
		HeadersRedacted: true,
	}
	marshaled, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var consumed Result
	if err := json.Unmarshal(marshaled, &consumed); err != nil {
		t.Fatal(err)
	}
	before, after := evidenceHash(orig), evidenceHash(consumed)
	if before != after {
		t.Fatalf("v14 hash must still use its frozen UTF-8 normalization after v15 bump: producer=%s consumer=%s", before, after)
	}
}
