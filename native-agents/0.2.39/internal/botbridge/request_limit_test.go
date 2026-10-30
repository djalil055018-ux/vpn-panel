package botbridge

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeRequestLimits(t *testing.T) {
	type request struct {
		Value string `json:"value"`
	}
	raw, _ := json.Marshal(request{Value: strings.Repeat("a", 20<<10)})
	var out request
	if DecodeRequest(raw, &out, "value") == nil {
		t.Fatal("default bot request size limit changed")
	}
	if DecodeRequestLimit(raw, &out, 96<<10, "value") != nil || len(out.Value) != 20<<10 {
		t.Fatal("explicit bounded payload rejected")
	}
	for _, limit := range []int{-1, 0, len(raw) - 1} {
		if DecodeRequestLimit(raw, &out, limit, "value") == nil {
			t.Fatal("invalid limit accepted")
		}
	}
	for _, bad := range []string{`{"value":"a","value":"b"}`, `{"Value":"a"}`, `{"value":null}`, `{"value":"a","private_key":"no"}`, `{"value":"a"}{}`} {
		if DecodeRequestLimit([]byte(bad), &out, 96<<10, "value") == nil {
			t.Fatal("larger limit weakened field validation")
		}
	}
}
