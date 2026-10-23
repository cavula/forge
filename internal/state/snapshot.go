// Package state validates sensitive snapshots without granting storage authority.
package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxSnapshotBytes = 16 << 20
const maxSnapshotDepth = 128

var ErrInvalidSnapshot = errors.New("invalid state snapshot")

// Snapshot retains an immutable copy; ordinary diagnostics never expose it.
// Callers must not mutate input concurrently with ValidateSnapshot.
type Snapshot struct {
	data     []byte
	metadata SnapshotMetadata
}

type SnapshotMetadata struct {
	Version         int
	Serial          int64
	Lineage, SHA256 string
	SizeBytes       int64
}

func (Snapshot) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "[redacted state snapshot]") }
func (Snapshot) MarshalJSON() ([]byte, error) { return []byte(`"[redacted state snapshot]"`), nil }
func (Snapshot) MarshalText() ([]byte, error) { return []byte("[redacted state snapshot]"), nil }
func (Snapshot) LogValue() slog.Value         { return slog.StringValue("[redacted state snapshot]") }
func (SnapshotMetadata) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted state metadata]")
}
func (SnapshotMetadata) MarshalJSON() ([]byte, error) {
	return []byte(`"[redacted state metadata]"`), nil
}
func (SnapshotMetadata) MarshalText() ([]byte, error) {
	return []byte("[redacted state metadata]"), nil
}
func (SnapshotMetadata) LogValue() slog.Value { return slog.StringValue("[redacted state metadata]") }

// Metadata returns a copy; lineage is client metadata, never tenant authority.
func (snapshot *Snapshot) Metadata() (SnapshotMetadata, error) {
	if snapshot == nil || len(snapshot.data) == 0 {
		return SnapshotMetadata{}, ErrInvalidSnapshot
	}
	return snapshot.metadata, nil
}

// CloneBytes reveals a new plaintext copy only for an authorized encryption or
// HTTP boundary. The caller must bound its lifetime and avoid logging it.
func (snapshot *Snapshot) CloneBytes() ([]byte, error) {
	if snapshot == nil || len(snapshot.data) == 0 {
		return nil, ErrInvalidSnapshot
	}
	return bytes.Clone(snapshot.data), nil
}

func ValidateSnapshot(input []byte) (*Snapshot, error) {
	if len(input) == 0 || len(input) > MaxSnapshotBytes || !utf8.Valid(input) || bytes.HasPrefix(input, []byte{0xef, 0xbb, 0xbf}) {
		return nil, ErrInvalidSnapshot
	}
	data := bytes.Clone(input)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	fields := snapshotFields{}
	if _, err := scanSnapshot(decoder, 1, &fields); err != nil || fields.present != 7 {
		clear(data)
		return nil, ErrInvalidSnapshot
	}
	if _, err := decoder.Token(); err != io.EOF {
		clear(data)
		return nil, ErrInvalidSnapshot
	}
	digest := sha256.Sum256(data)
	return &Snapshot{data, SnapshotMetadata{Version: 4, Serial: fields.serial, Lineage: fields.lineage, SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(data))}}, nil
}

type snapshotFields struct {
	serial  int64
	lineage string
	present uint8
}

// Scan tokens instead of materializing resource values. Root is depth1; only
// containers add nesting depth. Decoded keys catch escaped duplicate aliases.
func scanSnapshot(decoder *json.Decoder, depth int, fields *snapshotFields) (json.Token, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, ErrInvalidSnapshot
	}
	delimiter, container := token.(json.Delim)
	if fields != nil && (!container || delimiter != '{') {
		return nil, ErrInvalidSnapshot
	}
	if !container {
		return token, nil
	}
	if depth > maxSnapshotDepth || (delimiter != '{' && delimiter != '[') {
		return nil, ErrInvalidSnapshot
	}
	var keys map[string]bool
	if delimiter == '{' {
		keys = make(map[string]bool)
	}
	for decoder.More() {
		name := ""
		if delimiter == '{' {
			key, err := decoder.Token()
			var valid bool
			name, valid = key.(string)
			if err != nil || !valid || keys[name] {
				return nil, ErrInvalidSnapshot
			}
			keys[name] = true
			if fields != nil && name != "version" && name != "serial" && name != "lineage" &&
				(strings.EqualFold(name, "version") || strings.EqualFold(name, "serial") || strings.EqualFold(name, "lineage")) {
				return nil, ErrInvalidSnapshot
			}
		}
		value, err := scanSnapshot(decoder, depth+1, nil)
		if err != nil {
			return nil, ErrInvalidSnapshot
		}
		if fields != nil {
			switch name {
			case "version":
				if value != json.Number("4") {
					return nil, ErrInvalidSnapshot
				}
				fields.present |= 1
			case "serial":
				number, valid := value.(json.Number)
				if !valid || !snapshotInteger(string(number)) {
					return nil, ErrInvalidSnapshot
				}
				fields.serial, err = strconv.ParseInt(string(number), 10, 64)
				if err != nil {
					return nil, ErrInvalidSnapshot
				}
				fields.present |= 2
			case "lineage":
				lineage, valid := value.(string)
				if !valid || !snapshotUUID(lineage) {
					return nil, ErrInvalidSnapshot
				}
				fields.lineage = lineage
				fields.present |= 4
			}
		}
	}
	closing, err := decoder.Token()
	expected := json.Delim(']')
	if delimiter == '{' {
		expected = '}'
	}
	if err != nil || closing != expected {
		return nil, ErrInvalidSnapshot
	}
	return nil, nil
}

func snapshotInteger(value string) bool {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return false
	}
	for _, digit := range []byte(value) {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

func snapshotUUID(value string) bool {
	if len(value) != 36 || value == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i, digit := range []byte(value) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if digit != '-' {
				return false
			}
		} else if !((digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f')) {
			return false
		}
	}
	return true
}
