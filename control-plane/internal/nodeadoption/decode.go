package nodeadoption

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"
)

// DecodePlan rejects duplicate keys at every depth and case aliases, including
// fields which encoding/json would otherwise match case-insensitively.
func DecodePlan(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return ErrMaterial
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if tokenValue(d, 0) != nil {
		return ErrMaterial
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrMaterial
	}
	var value any
	d = json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&value) != nil || value == nil || !exactFields(value, reflect.TypeOf(out), 0) {
		return ErrMaterial
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrMaterial
	}
	return nil
}
func tokenValue(d *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrMaterial
	}
	t, err := d.Token()
	if err != nil {
		return ErrMaterial
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			s, ok := k.(string)
			if e != nil || !ok || seen[s] {
				return ErrMaterial
			}
			seen[s] = true
			if tokenValue(d, depth+1) != nil {
				return ErrMaterial
			}
		}
		t, err = d.Token()
		if err != nil || t != json.Delim('}') {
			return ErrMaterial
		}
	case '[':
		for d.More() {
			if tokenValue(d, depth+1) != nil {
				return ErrMaterial
			}
		}
		t, err = d.Token()
		if err != nil || t != json.Delim(']') {
			return ErrMaterial
		}
	default:
		return ErrMaterial
	}
	return nil
}
func exactFields(v any, t reflect.Type, depth int) bool {
	if t == nil || depth > 32 {
		return false
	}
	for t.Kind() == reflect.Pointer {
		if v == nil {
			return true
		}
		t = t.Elem()
	}
	if t == reflect.TypeOf(time.Time{}) {
		_, ok := v.(string)
		return ok
	}
	switch t.Kind() {
	case reflect.Struct:
		obj, ok := v.(map[string]any)
		if !ok {
			return false
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "-" || f.PkgPath != "" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			fields[name] = f.Type
		}
		for name, x := range obj {
			ft, ok := fields[name]
			if !ok || !exactFields(x, ft, depth+1) {
				return false
			}
		}
	case reflect.Slice:
		if v == nil {
			return true
		}
		a, ok := v.([]any)
		if !ok {
			return false
		}
		for _, x := range a {
			if !exactFields(x, t.Elem(), depth+1) {
				return false
			}
		}
	}
	return true
}
