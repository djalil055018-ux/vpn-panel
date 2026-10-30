package xrayprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

var ErrProfile = errors.New("invalid or unsupported imported Xray profile")
var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var shortID = regexp.MustCompile(`^(?:[0-9a-fA-F]{2}){0,8}$`)

const blockTag = "vpn-platform-api-block"
const maxConfigBytes = 1024 * 1024

// Reject duplicate keys at every depth, non-UTF8 and trailing documents before
// map decoding. A profile must mean the same thing in every involved parser.
func decode(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > maxConfigBytes || !utf8.Valid(raw) {
		return nil, ErrProfile
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := readValue(d, 0)
	if err != nil {
		return nil, ErrProfile
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrProfile
	}
	result, ok := value.(map[string]any)
	if !ok {
		return nil, ErrProfile
	}
	return result, nil
}

func readValue(d *json.Decoder, depth int) (any, error) {
	if depth > 24 {
		return nil, ErrProfile
	}
	token, err := d.Token()
	if err != nil {
		return nil, ErrProfile
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return token, nil
	}
	switch delim {
	case '{':
		object := map[string]any{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return nil, ErrProfile
			}
			if _, exists := object[name]; exists {
				return nil, ErrProfile
			}
			value, err := readValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			object[name] = value
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, ErrProfile
		}
		return object, nil
	case '[':
		values := []any{}
		for d.More() {
			value, err := readValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
			if len(values) > 10000 {
				return nil, ErrProfile
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, ErrProfile
		}
		return values, nil
	default:
		return nil, ErrProfile
	}
}

func obj(v any, allowed ...string) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	fields := map[string]bool{}
	for _, key := range allowed {
		fields[key] = true
	}
	for key, value := range m {
		if !fields[key] || value == nil {
			return nil, false
		}
	}
	return m, true
}
func str(v any) string       { s, _ := v.(string); return s }
func strNumber(v any) string { n, _ := v.(json.Number); return string(n) }
func stringValue(v any, empty bool) bool {
	s, ok := v.(string)
	return ok && len(s) <= 4096 && (empty || s != "") && !strings.ContainsAny(s, "\x00\r\n")
}
func integer(v any, low, high int64) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	value, err := n.Int64()
	return err == nil && value >= low && value <= high
}
func boolean(v any) bool { _, ok := v.(bool); return ok }
func oneOf(v any, options ...string) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, option := range options {
		if s == option {
			return true
		}
	}
	return false
}
func stringsArray(v any, min, max int, empty bool) bool {
	values, ok := v.([]any)
	if !ok || len(values) < min || len(values) > max {
		return false
	}
	for _, value := range values {
		if !stringValue(value, empty) {
			return false
		}
	}
	return true
}
func optional(m map[string]any, key string, check func(any) bool) bool {
	value, exists := m[key]
	return !exists || check(value)
}
func text(v any) bool      { return stringValue(v, false) }
func maybeText(v any) bool { return stringValue(v, true) }
