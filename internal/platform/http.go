// Package platform provides the M0 health and build information surface.
package platform

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	forgev1 "github.com/cavula/forge/gen/go/forge/v1"
	"github.com/cavula/forge/gen/go/forge/v1/forgev1connect"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type infoServer struct{}

func (infoServer) GetInfo(context.Context, *connect.Request[forgev1.GetInfoRequest]) (*connect.Response[forgev1.GetInfoResponse], error) {
	return connect.NewResponse(&forgev1.GetInfoResponse{Version: "0.0.0-dev"}), nil
}

// Handler's readiness check must verify dependencies without returning secrets.
func Handler(ready func(context.Context) error) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := ready(r.Context()); err != nil {
			http.Error(w, "dependencies unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	path, handler := forgev1connect.NewFoundationServiceHandler(infoServer{})
	mux.Handle(path, handler)
	return otelhttp.NewHandler(mux, "forge.http")
}
