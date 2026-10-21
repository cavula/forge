package platform

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	forgev1 "github.com/cavula/forge/gen/go/forge/v1"
	"github.com/cavula/forge/gen/go/forge/v1/forgev1connect"
	"github.com/cavula/forge/internal/testutil"
)

func TestHealthAndReadiness(t *testing.T) {
	for _, tc := range []struct {
		path    string
		failure bool
		want    int
	}{
		{"/healthz", false, 200}, {"/healthz", true, 200}, {"/readyz", false, 200}, {"/readyz", true, 503}, {"/missing", false, 404},
	} {
		secret := "forge-test-sensitive-credential"
		h := Handler(func(context.Context) error {
			if tc.failure {
				return errors.New(secret)
			}
			return nil
		})
		response := httptest.NewRecorder()
		h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if response.Code != tc.want {
			t.Fatalf("%s: got %d want %d", tc.path, response.Code, tc.want)
		}
		testutil.NoSecrets(t, response.Body.String(), secret)
	}
}

func TestConnectInfo(t *testing.T) {
	server := httptest.NewServer(Handler(func(context.Context) error { return nil }))
	defer server.Close()
	client := forgev1connect.NewFoundationServiceClient(server.Client(), server.URL)
	response, err := client.GetInfo(context.Background(), connect.NewRequest(&forgev1.GetInfoRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if response.Msg.Version != "0.0.0-dev" {
		t.Fatal("unexpected build version")
	}
	// Verify the public JSON Connect protocol too.
	request, _ := http.NewRequest(http.MethodPost, server.URL+forgev1connect.FoundationServiceGetInfoProcedure, strings.NewReader("{}"))
	request.Header.Set("Content-Type", "application/json")
	res, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || !strings.Contains(string(body), "0.0.0-dev") {
		t.Fatalf("JSON protocol failed: %s", body)
	}
}
