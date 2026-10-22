package proto_test

import (
	"fmt"
	"strings"
	"testing"

	_ "github.com/cavula/forge/gen/go/forge/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
)

// Fields are ordered by their permanent wire number. Metadata contracts omit
// secret values and state bytes, including their encrypted representations.
var fields = map[protoreflect.Name]string{
	"Org":             "id:string,name:string,created_at:google.protobuf.Timestamp",
	"User":            "id:string,org_id:string,oidc_issuer:string,oidc_subject:string,display_name:string,role:forge.v1.Role,created_at:google.protobuf.Timestamp",
	"Team":            "id:string,org_id:string,name:string,created_at:google.protobuf.Timestamp",
	"Stack":           "id:string,org_id:string,name:string,repository_url:string,branch:string,working_directory:string,engine:forge.v1.Engine,engine_version:string,created_at:google.protobuf.Timestamp",
	"Run":             "id:string,org_id:string,stack_id:string,status:forge.v1.RunStatus,kind:forge.v1.RunKind,commit_sha:string,created_at:google.protobuf.Timestamp,started_at:google.protobuf.Timestamp,finished_at:google.protobuf.Timestamp",
	"StateVersion":    "id:string,org_id:string,stack_id:string,serial:int64,lineage:string,sha256:string,size_bytes:int64,created_at:google.protobuf.Timestamp",
	"Policy":          "id:string,org_id:string,name:string,rego:string,enabled:bool,created_at:google.protobuf.Timestamp",
	"Secret":          "id:string,org_id:string,stack_id:string,name:string,created_at:google.protobuf.Timestamp,updated_at:google.protobuf.Timestamp",
	"AuditEvent":      "id:string,org_id:string,actor_id:string,action:string,resource_type:string,resource_id:string,stack_id:string,occurred_at:google.protobuf.Timestamp,request_id:string",
	"GetInfoRequest":  "",
	"GetInfoResponse": "version:string",
}

func TestRegisteredContracts(t *testing.T) {
	count := 0
	protoregistry.GlobalFiles.RangeFilesByPackage("forge.v1", func(file protoreflect.FileDescriptor) bool {
		for i := 0; i < file.Messages().Len(); i++ {
			count++
			d := file.Messages().Get(i)
			t.Run(string(d.Name()), func(t *testing.T) { checkContract(t, d) })
		}
		return true
	})
	if count == 0 {
		t.Fatal("no Forge messages registered")
	}
}

func TestRegisteredEnums(t *testing.T) {
	want := map[protoreflect.Name]string{
		"Role":      "UNSPECIFIED,ADMIN,WRITER,READER",
		"Engine":    "UNSPECIFIED,OPENTOFU,TERRAFORM,ANSIBLE",
		"RunKind":   "UNSPECIFIED,IAC,ANSIBLE,DRIFT",
		"RunStatus": "UNSPECIFIED,QUEUED,PREPARING,PLANNING,POLICY_CHECK,NEEDS_APPROVAL,APPLYING,FINISHED,FAILED,DISCARDED,CANCELED,PREVIEW,EXECUTING,PARTIAL,SCHEDULED,REFRESHING,DRIFT_FOUND,CLEAN",
	}
	protoregistry.GlobalFiles.RangeFilesByPackage("forge.v1", func(file protoreflect.FileDescriptor) bool {
		for i := 0; i < file.Enums().Len(); i++ {
			d := file.Enums().Get(i)
			prefix := strings.TrimSuffix(string(d.Values().Get(0).Name()), "UNSPECIFIED")
			var got []string
			for j := 0; j < d.Values().Len(); j++ {
				v := d.Values().Get(j)
				if v.Number() != protoreflect.EnumNumber(j) {
					t.Fatalf("changed enum number: %s", v.FullName())
				}
				got = append(got, strings.TrimPrefix(string(v.Name()), prefix))
			}
			if strings.Join(got, ",") != want[d.Name()] {
				t.Fatalf("changed enum vocabulary: %s", d.FullName())
			}
		}
		return true
	})
}

func TestRegisteredServices(t *testing.T) {
	protoregistry.GlobalFiles.RangeFilesByPackage("forge.v1", func(file protoreflect.FileDescriptor) bool {
		for i := 0; i < file.Services().Len(); i++ {
			d := file.Services().Get(i)
			if d.FullName() != "forge.v1.FoundationService" || d.Methods().Len() != 1 {
				t.Fatalf("unreviewed service: %s", d.FullName())
			}
			m := d.Methods().Get(0)
			if m.Name() != "GetInfo" || m.Input().FullName() != "forge.v1.GetInfoRequest" || m.Output().FullName() != "forge.v1.GetInfoResponse" || m.IsStreamingClient() || m.IsStreamingServer() {
				t.Fatalf("changed public RPC: %s", m.FullName())
			}
		}
		return true
	})
}

func checkContract(t *testing.T, d protoreflect.MessageDescriptor) {
	t.Helper()
	want, ok := fields[d.Name()]
	if !ok {
		t.Fatalf("unreviewed message %s", d.FullName())
	}
	m := dynamicpb.NewMessage(d)
	var got []string
	for i := 0; i < d.Fields().Len(); i++ {
		f := d.Fields().Get(i)
		if f.Number() != protoreflect.FieldNumber(i+1) || f.IsList() || f.IsMap() {
			t.Fatalf("changed field shape: %s", f.FullName())
		}
		kind := f.Kind().String()
		switch f.Kind() {
		case protoreflect.StringKind:
			m.Set(f, protoreflect.ValueOfString(fmt.Sprintf("field-%d", f.Number())))
		case protoreflect.Int64Kind:
			m.Set(f, protoreflect.ValueOfInt64(42))
		case protoreflect.BoolKind:
			m.Set(f, protoreflect.ValueOfBool(true))
		case protoreflect.EnumKind:
			kind = string(f.Enum().FullName())
			m.Set(f, protoreflect.ValueOfEnum(f.Enum().Values().Get(1).Number()))
		case protoreflect.MessageKind:
			kind = string(f.Message().FullName())
			value := dynamicpb.NewMessage(f.Message())
			value.Set(f.Message().Fields().ByName("seconds"), protoreflect.ValueOfInt64(123))
			m.Set(f, protoreflect.ValueOfMessage(value))
		default:
			t.Fatalf("unreviewed field type: %s", f.FullName())
		}
		got = append(got, string(f.Name())+":"+kind)
	}
	if strings.Join(got, ",") != want {
		t.Fatalf("changed metadata contract: %v; want %s", got, want)
	}
	wire, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	decoded := dynamicpb.NewMessage(d)
	if err := proto.Unmarshal(wire, decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(m, decoded) {
		t.Fatal("protobuf wire roundtrip changed fields")
	}
}
