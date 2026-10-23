package stacks_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	forgev1 "github.com/cavula/forge/gen/go/forge/v1"
	"github.com/cavula/forge/gen/go/forge/v1/forgev1connect"
	"google.golang.org/protobuf/proto"
)

func TestStackServiceGetContract(t *testing.T) {
	file := forgev1.File_forge_v1_stack_service_proto
	if file.Messages().Len() != 0 || file.Services().Len() != 1 {
		t.Fatal("service file must declare only StackService")
	}
	service := file.Services().Get(0)
	if service.FullName() != "forge.v1.StackService" || service.Methods().Len() != 1 {
		t.Fatal("unexpected service or method count")
	}
	method := service.Methods().Get(0)
	if method.Name() != "GetStack" || method.IsStreamingClient() || method.IsStreamingServer() ||
		method.Input().FullName() != "forge.v1.GetStackRequest" || method.Output().FullName() != "forge.v1.GetStackResponse" {
		t.Fatal("GetStack must use the existing unary lookup messages")
	}
	if forgev1connect.StackServiceName != string(service.FullName()) ||
		forgev1connect.StackServiceGetStackProcedure != "/forge.v1.StackService/GetStack" {
		t.Fatal("Connect names differ from the approved procedure")
	}
	request := &forgev1.GetStackRequest{Id: "20000000-0000-0000-0000-000000000001"}
	wire, err := proto.Marshal(request)
	if err != nil || !bytes.Equal(wire, append([]byte{10, 36}, []byte(request.Id)...)) {
		t.Fatalf("request must retain the existing field-one wire encoding: %v", err)
	}
	var decoded forgev1.GetStackRequest
	if err := proto.Unmarshal(wire, &decoded); err != nil || !proto.Equal(request, &decoded) {
		t.Fatalf("request wire roundtrip: %v", err)
	}
}

type contractHTTPClient struct{ handler http.Handler }

func (client contractHTTPClient) Do(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	client.handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

func TestGeneratedStackServiceRemainsUnimplemented(t *testing.T) {
	path, handler := forgev1connect.NewStackServiceHandler(forgev1connect.UnimplementedStackServiceHandler{})
	if path != "/forge.v1.StackService/" {
		t.Fatalf("unexpected generated mount path %q", path)
	}
	// Exercise generated HTTP encoding and dispatch entirely within this test.
	client := forgev1connect.NewStackServiceClient(contractHTTPClient{handler}, "http://contract.test")
	response, err := client.GetStack(context.Background(), connect.NewRequest(&forgev1.GetStackRequest{
		Id: "20000000-0000-0000-0000-000000000001",
	}))
	if response != nil || connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("generated default must return Unimplemented, got response=%v error=%v", response, err)
	}
	connectError, ok := err.(*connect.Error)
	if !ok || connectError.Message() != "forge.v1.StackService.GetStack is not implemented" {
		t.Fatalf("unexpected default error %v", err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path+"CreateStack", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("undeclared method must be absent, got status %d", recorder.Code)
	}
}
