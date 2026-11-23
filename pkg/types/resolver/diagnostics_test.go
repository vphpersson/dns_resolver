package resolver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
)

// GET /cache lists a bounded number of entries; it used to list the whole
// cache, built under its lock.
func TestDiagnostics_CacheGet(t *testing.T) {
	t.Parallel()

	upstream := startUpstream(t, answerWith("192.0.2.1"))
	resolver := newTestResolver(t, upstream)
	for i := range 5 {
		ask(resolver, "udp", newQuery(fmt.Sprintf("n%d.example.", i), dns.TypeA))
	}
	handler := resolver.DiagnosticsHandler()

	testCases := []struct {
		name       string
		target     string
		wantStatus int
		wantSize   int
	}{
		{name: "default", target: "/cache", wantStatus: http.StatusOK, wantSize: 5},
		{name: "limit", target: "/cache?limit=2", wantStatus: http.StatusOK, wantSize: 2},
		{name: "one name", target: "/cache?name=n1.example", wantStatus: http.StatusOK, wantSize: 1},
		{name: "zero limit", target: "/cache?limit=0", wantStatus: http.StatusBadRequest},
		{name: "limit too large", target: "/cache?limit=1000000", wantStatus: http.StatusBadRequest},
		{name: "malformed limit", target: "/cache?limit=all", wantStatus: http.StatusBadRequest},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, testCase.target, nil))
			if recorder.Code != testCase.wantStatus {
				t.Fatalf("status = %d; want %d (%s)", recorder.Code, testCase.wantStatus, recorder.Body.String())
			}
			if testCase.wantStatus != http.StatusOK {
				return
			}

			var body struct {
				Size    int               `json:"size"`
				Total   int               `json:"total"`
				Entries []json.RawMessage `json:"entries"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body.Size != testCase.wantSize || len(body.Entries) != testCase.wantSize || body.Total != 5 {
				t.Fatalf("size=%d entries=%d total=%d; want %d, %d and 5", body.Size, len(body.Entries), body.Total, testCase.wantSize, testCase.wantSize)
			}
		})
	}
}
