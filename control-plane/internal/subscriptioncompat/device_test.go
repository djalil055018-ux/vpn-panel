package subscriptioncompat

import (
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"testing"
)

func TestSubscriptionDeviceHeaderOracle(t *testing.T) {
	raw, err := os.ReadFile("testdata/device-headers.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Headers  map[string]any     `json:"headers"`
		Expected *DeviceObservation `json:"expected"`
	}
	if json.Unmarshal(raw, &cases) != nil || len(cases) != 12 {
		t.Fatal("device oracle fixture")
	}
	for i, c := range cases {
		headers := http.Header{}
		for key, value := range c.Headers {
			switch v := value.(type) {
			case string:
				headers.Set(key, v)
			case []any:
				for _, item := range v {
					headers.Add(key, item.(string))
				}
			}
		}
		if got := DeviceFromHeaders(headers); !reflect.DeepEqual(got, c.Expected) {
			t.Fatalf("device oracle case %d", i)
		}
	}
	if DeviceFromHeaders(http.Header{"X-Hwid": []string{"bad\nvalue"}}) != nil {
		t.Fatal("invalid device identifier")
	}
}
