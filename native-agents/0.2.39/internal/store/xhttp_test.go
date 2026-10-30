package store

import (
	"testing"
	"vpn-platform/internal/model"
)

func TestXHTTPMinimumCore(t *testing.T) {
	for _, v := range []string{"26.7.28", "26.8.1", "27.1.1"} {
		if !xhttpCoreCompatible(model.CoreRelease{Type: "xray", Version: v}) {
			t.Fatal("supported core rejected")
		}
	}
	for _, v := range []string{"26.7.27", "25.12.1", "26.8.bad", "26.8.1.extra"} {
		if xhttpCoreCompatible(model.CoreRelease{Type: "xray", Version: v}) {
			t.Fatal("unsupported core accepted")
		}
	}
}
