package botbridge

import "testing"

func TestMutationBodyRejectsAmbiguousRequests(t *testing.T) {
	for _, raw := range []string{`{"days":1,"days":2}`, `{"days":1,"Days":2}`, `{"days":null}`, `{"days":"1"}`, `{"days":1.5}`, `{"days":1}{}`, `{"other":1}`, `[]`, `null`, `{"days":1,"extra":{}}`} {
		var v struct {
			Days int `json:"days"`
		}
		if DecodeRequest([]byte(raw), &v, "days") == nil {
			t.Fatal("ambiguous mutation accepted")
		}
	}
	var v struct {
		Days int `json:"days"`
	}
	if DecodeRequest([]byte(`{"days":30}`), &v, "days") != nil || v.Days != 30 {
		t.Fatal("valid mutation rejected")
	}
}
