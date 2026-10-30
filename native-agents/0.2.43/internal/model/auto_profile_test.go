package model

import (
	"strings"
	"testing"
)

func TestAutoProfileNames(t *testing.T) {
	for _, name := range []string{"Авто", "Мой VPN", "🌍 Лучшее подключение", strings.Repeat("я", 80)} {
		if !ValidAutoProfileName(name) {
			t.Fatalf("valid display name rejected: %q", name)
		}
	}
	for _, name := range []string{"", " ", " padded", "line\nbreak", "tab\tname", strings.Repeat("я", 81), string([]byte{255})} {
		if ValidAutoProfileName(name) {
			t.Fatal("invalid display name accepted")
		}
	}
}
