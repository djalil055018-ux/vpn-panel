package botbridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

var ErrRequest = errors.New("invalid bot request")

// Mutation fields are case-sensitive and unique. Validation precedes decoding
// into a DTO so aliases such as days/Days cannot select different effects in
// different parsers. The v1 DTOs contain scalars and arrays of strings only.
func DecodeRequest(raw []byte, dst any, allowed ...string) error {
	return DecodeRequestLimit(raw, dst, 16384, allowed...)
}

// DecodeRequestLimit keeps the same strict field contract for bounded owner
// preparation payloads that carry public certificate chains. Existing bot
// callers retain their original 16 KiB limit through DecodeRequest.
func DecodeRequestLimit(raw []byte, dst any, limit int, allowed ...string) error {
	if limit <= 0 || len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return ErrRequest
	}
	fields := map[string]bool{}
	for _, name := range allowed {
		fields[name] = true
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return ErrRequest
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || !fields[name] || seen[name] {
			return ErrRequest
		}
		seen[name] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrRequest
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return ErrRequest
	}
	if _, err = d.Token(); err != io.EOF {
		return ErrRequest
	}
	if json.Unmarshal(raw, dst) != nil {
		return ErrRequest
	}
	return nil
}
