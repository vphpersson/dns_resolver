package resolver

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux"
	muxEndpoint "github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	muxResponseError "github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
)

// DiagnosticsHandler returns an HTTP handler exposing the resolver's diagnostic
// endpoints:
//
//   - GET    /metrics       — resolver and cache counters (JSON).
//   - GET    /cache         — a summary of every live cache entry.
//   - DELETE /cache         — flush the whole cache.
//   - DELETE /cache?name=x  — evict every entry for one name (the targeted
//     "unpoison" control, so a single bad name no longer needs a full restart).
//
// The endpoints are unauthenticated and meant to be reached by machine clients
// (the quadlet, a curl, Prometheus-style scrapers), so the fetch-metadata check
// is disabled and they are marked public. The mutating /cache DELETE is why the
// server must be bound to loopback or the LAN — never the WAN.
func (r *Resolver) DiagnosticsHandler() http.Handler {
	return mux.New(
		&muxEndpoint.Endpoint{
			Path:               "/metrics",
			Method:             http.MethodGet,
			Public:             true,
			DisableFetchMedata: true,
			Handler:            r.handleMetrics,
		},
		&muxEndpoint.Endpoint{
			Path:               "/cache",
			Method:             http.MethodGet,
			Public:             true,
			DisableFetchMedata: true,
			Handler:            r.handleCacheGet,
		},
		&muxEndpoint.Endpoint{
			Path:               "/cache",
			Method:             http.MethodDelete,
			Public:             true,
			DisableFetchMedata: true,
			Handler:            r.handleCacheDelete,
		},
	)
}

func jsonResponse(status int, payload any) (*muxResponse.Response, *muxResponseError.ResponseError) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, &muxResponseError.ResponseError{
			ServerError: motmedelErrors.New(fmt.Errorf("json marshal: %w", err), payload),
		}
	}

	return &muxResponse.Response{
		StatusCode: status,
		Headers:    []*muxResponse.HeaderEntry{{Name: "Content-Type", Value: "application/json"}},
		Body:       append(body, '\n'),
	}, nil
}

func (r *Resolver) handleMetrics(*http.Request, []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
	return jsonResponse(http.StatusOK, r.Metrics())
}

func (r *Resolver) handleCacheGet(*http.Request, []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
	if r.Cache == nil {
		return jsonResponse(http.StatusOK, map[string]any{"size": 0, "entries": []any{}})
	}

	entries := r.Cache.Snapshot()
	return jsonResponse(http.StatusOK, map[string]any{
		"size":    len(entries),
		"entries": entries,
	})
}

func (r *Resolver) handleCacheDelete(request *http.Request, _ []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
	if r.Cache == nil {
		return jsonResponse(http.StatusOK, map[string]int{"flushed": 0})
	}

	name := request.URL.Query().Get("name")
	if name == "" {
		removed := r.Cache.Flush()
		r.logCacheControl("flush", "", removed)
		return jsonResponse(http.StatusOK, map[string]int{"flushed": removed})
	}

	removed := r.Cache.DeleteName(name)
	r.logCacheControl("delete", name, removed)
	return jsonResponse(http.StatusOK, map[string]int{"deleted": removed})
}

// logCacheControl records a mutating cache action so it is auditable in the same
// log stream as everything else (a flush/eviction is operationally significant).
func (r *Resolver) logCacheControl(action string, name string, removed int) {
	attrs := []any{slog.String("action", action), slog.Int("removed", removed)}
	if name != "" {
		attrs = append(attrs, slog.String("name", name))
	}
	slog.WarnContext(
		r.ParentContext,
		"",
		makeEventGroup(
			"cache_control",
			"The cache was modified via the diagnostic endpoint.",
			"success",
			"configuration",
		),
		slog.Group("cache", attrs...),
	)
}
