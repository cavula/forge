package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"testing"

	"github.com/cavula/forge/internal/testutil"
)

const lineage = "10000000-0000-0000-0000-000000000001"
const required = `"version":4,"serial":0,"lineage":"` + lineage + `"`

func requireInvalid(t *testing.T, input []byte) {
	t.Helper()
	snapshot, err := ValidateSnapshot(input)
	if snapshot != nil || err != ErrInvalidSnapshot {
		t.Fatal("invalid snapshot accepted or diagnostic changed")
	}
	testutil.NoSecrets(t, fmt.Sprint(err), string(input), "private-state-probe")
}

func TestSnapshotExactBytesMetadataAndIsolation(t *testing.T) {
	input := []byte(" \n{ " + required + `,"resources":[{"unknown":{"outputs":[true,null,1e20000,"München 東京","private-state-probe"]}}],"future":{} }` + "\t\n")
	original := bytes.Clone(input)
	snapshot, err := ValidateSnapshot(input)
	if err != nil {
		t.Fatal("valid snapshot rejected")
	}
	metadata, err := snapshot.Metadata()
	digest := sha256.Sum256(original)
	if err != nil || metadata.Version != 4 || metadata.Serial != 0 || metadata.Lineage != lineage || metadata.SizeBytes != int64(len(original)) || metadata.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("trusted exact-byte metadata mismatch")
	}
	input[0] = 'x'
	revealed, err := snapshot.CloneBytes()
	if err != nil || !bytes.Equal(revealed, original) {
		t.Fatal("input mutation changed the snapshot")
	}
	revealed[0] = 'y'
	metadata.Lineage = "changed"
	second, _ := snapshot.CloneBytes()
	current, _ := snapshot.Metadata()
	if !bytes.Equal(second, original) || current.Lineage != lineage {
		t.Fatal("returned copy changed retained state")
	}
	compact, _ := ValidateSnapshot([]byte("{" + required + "}"))
	compactMetadata, _ := compact.Metadata()
	if compactMetadata.SHA256 == current.SHA256 {
		t.Fatal("exact-byte identity was normalized")
	}
	for _, value := range []*Snapshot{nil, {}} {
		if metadata, err := value.Metadata(); metadata != (SnapshotMetadata{}) || err != ErrInvalidSnapshot {
			t.Fatal("zero snapshot metadata trusted")
		}
		if data, err := value.CloneBytes(); data != nil || err != ErrInvalidSnapshot {
			t.Fatal("zero snapshot revealed bytes")
		}
	}
}

func TestSnapshotSyntaxAndRequiredFields(t *testing.T) {
	for name, input := range map[string][]byte{
		"empty": nil, "root-array": []byte("[{}]"), "root-scalar": []byte("4"), "root-null": []byte("null"),
		"missing": []byte("{}"), "missing-lineage": []byte(`{"version":4,"serial":0}`),
		"missing-serial":  []byte(`{"version":4,"lineage":"` + lineage + `"}`),
		"case-alias":      []byte(`{"Version":4,"serial":0,"lineage":"` + lineage + `"}`),
		"trailing-object": []byte("{" + required + "} {}"), "trailing-token": []byte("{" + required + "} true"),
		"trailing-garbage": []byte("{" + required + "}private-state-probe"), "unfinished": []byte("{" + required + `,"resources":[`),
		"bad-delimiter": []byte("{" + required + `,"resources":[1}`), "bad-key": []byte("{" + required + `,true:0}`),
		"BOM":          append([]byte{0xef, 0xbb, 0xbf}, []byte("{"+required+"}")...),
		"invalid-UTF8": append([]byte("{"+required+`,"value":"`), 0xff, '"', '}'),
		"comment":      []byte("{" + required + "}/*private-state-probe*/"),
	} {
		t.Run(name, func(t *testing.T) { requireInvalid(t, input) })
	}
}

func TestSnapshotCanonicalMetadata(t *testing.T) {
	for _, serial := range []string{"0", "1", "9007199254740993", "9223372036854775807"} {
		snapshot, err := ValidateSnapshot([]byte(`{"version":4,"serial":` + serial + `,"lineage":"` + lineage + `"}`))
		if err != nil {
			t.Fatal("valid integer rejected")
		}
		metadata, _ := snapshot.Metadata()
		if strconv.FormatInt(metadata.Serial, 10) != serial {
			t.Fatal("serial lost precision")
		}
	}
	for _, serial := range []string{"-0", "-1", "01", "+1", "1.0", "1e0", "9223372036854775808", "18446744073709551615", `"0"`, "null", "false", "[]", "{}"} {
		requireInvalid(t, []byte(`{"version":4,"serial":`+serial+`,"lineage":"`+lineage+`"}`))
	}
	for _, version := range []string{"0", "3", "5", "-4", "+4", "04", "4.0", "4e0", `"4"`, "null", "true", "[]", "{}"} {
		requireInvalid(t, []byte(`{"version":`+version+`,"serial":0,"lineage":"`+lineage+`"}`))
	}
	for _, id := range []string{"", "00000000-0000-0000-0000-000000000000", "AAAA0000-0000-0000-0000-000000000001", lineage + " ", lineage[:35], strings.ReplaceAll(lineage, "-", ""), "10000000_0000-0000-0000-000000000001", "g0000000-0000-0000-0000-000000000001", "private-state-probe"} {
		requireInvalid(t, []byte(`{"version":4,"serial":0,"lineage":`+strconv.Quote(id)+`}`))
	}
	for _, id := range []string{"null", "1", "[]", "{}"} {
		requireInvalid(t, []byte(`{"version":4,"serial":0,"lineage":`+id+`}`))
	}
}

func TestSnapshotRejectsDuplicateDecodedKeysAtEveryDepth(t *testing.T) {
	for _, name := range []string{"Version", "VERSION", "Serial", "ſerial", "Lineage", "lInEaGe"} {
		requireInvalid(t, []byte("{"+required+`,"`+name+`":0}`))
	}
	for _, extra := range []string{`,"version":4`, `,"\u0073erial":1`, `,"lineage":"` + lineage + `"`,
		`,"extra":null,"extra":false`, `,"resources":[{"item":{"secret":"private-state-probe","secret":"other"}}]`,
		`,"resources":[{"name":"first","\u006eame":"second"}]`, `,"future":{"é":1,"\u00e9":2}`,
	} {
		requireInvalid(t, []byte("{"+required+extra+"}"))
	}
	// Escaped spelling is decoded for names, while exact original bytes are kept.
	input := []byte(`{"\u0076ersion":4,"serial":0,"lineage":"\u00310000000-0000-0000-0000-000000000001","futureVersion":3,"resources":[{"x":1,"Serial":1,"serial":0,"ſerial":2,"Version":3,"Lineage":"provider"},{"x":2}]}`)
	snapshot, err := ValidateSnapshot(input)
	if err != nil {
		t.Fatal("distinct objects or valid escaped metadata rejected")
	}
	copied, _ := snapshot.CloneBytes()
	if !bytes.Equal(copied, input) {
		t.Fatal("escaped bytes were normalized")
	}
}

func TestSnapshotContainerDepthAndSizeBounds(t *testing.T) {
	for _, object := range []bool{false, true} {
		open, close := "[", "]"
		if object {
			open, close = `{"x":`, "}"
		}
		for _, depth := range []int{127, 128} {
			input := []byte("{" + required + `,"resources":` + strings.Repeat(open, depth) + "0" + strings.Repeat(close, depth) + "}")
			if depth == 128 {
				requireInvalid(t, input)
			} else if _, err := ValidateSnapshot(input); err != nil {
				t.Fatal("128 container levels rejected")
			}
		}
	}
	prefix, suffix := "{"+required+`,"resources":"`, `"}`
	input := []byte(prefix + strings.Repeat("x", MaxSnapshotBytes-len(prefix)-len(suffix)) + suffix)
	snapshot, err := ValidateSnapshot(input)
	if err != nil {
		t.Fatal("exact 16MiB snapshot rejected")
	}
	metadata, _ := snapshot.Metadata()
	if metadata.SizeBytes != MaxSnapshotBytes {
		t.Fatal("size bound changed")
	}
	requireInvalid(t, append(input, ' '))
}

func TestSnapshotDiagnosticsAreRedacted(t *testing.T) {
	snapshot, err := ValidateSnapshot([]byte("{" + required + `,"secret":"private-state-probe"}`))
	if err != nil {
		t.Fatal(err)
	}
	metadata, _ := snapshot.Metadata()
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	for _, value := range []any{snapshot, *snapshot, metadata} {
		fmt.Fprintf(&output, "%v %+v %#v %s %q", value, value, value, value, value)
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		output.Write(encoded)
		logger.Info("snapshot", "value", value)
	}
	text, _ := snapshot.MarshalText()
	metaText, _ := metadata.MarshalText()
	output.Write(text)
	output.Write(metaText)
	testutil.NoSecrets(t, output.String(), "private-state-probe", lineage, metadata.SHA256)
}

func FuzzSnapshotValidation(f *testing.F) {
	for _, input := range []string{"{" + required + "}", "{}", "null", "{" + required + `,"x":{"a":1,"a":2}}`} {
		f.Add([]byte(input))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		snapshot, err := ValidateSnapshot(input)
		if err != nil {
			if err != ErrInvalidSnapshot || snapshot != nil {
				t.Fatal("unsafe error result")
			}
			return
		}
		copied, err := snapshot.CloneBytes()
		if err != nil || !bytes.Equal(input, copied) || !json.Valid(input) {
			t.Fatal("successful validation changed bytes or accepted invalid JSON")
		}
	})
}
