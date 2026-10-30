package xrayprofile

import (
	"testing"
	"vpn-platform/internal/model"
)

func TestImportedVersionFloors(t *testing.T) {
	for _, v := range []string{"0.2.31", "0.2.32", "0.3.0", "1.0.0"} {
		if !AgentCompatible(v) {
			t.Fatal("compatible Agent refused")
		}
	}
	for _, v := range []string{"", "0.2.30", "0.1.99", "00.2.31", "0.2.31-rc1", "9999999.0.0", "0.2.31.1"} {
		if AgentCompatible(v) {
			t.Fatal("unsupported Agent accepted")
		}
	}
	for _, v := range []string{"26.9.9", "26.9.10", "27.1.1"} {
		if !CoreCompatible(model.CoreRelease{Type: "xray", Version: v}) {
			t.Fatal("compatible core refused")
		}
	}
	for _, v := range []string{"26.7.28", "26.3.27", "v26.9.9", "26.9.9-rc1", ""} {
		if CoreCompatible(model.CoreRelease{Type: "xray", Version: v}) {
			t.Fatal("unsupported core accepted")
		}
	}
	if CoreCompatible(model.CoreRelease{Type: "hysteria2", Version: "99.9.9"}) {
		t.Fatal("wrong runtime accepted")
	}
}
