package store

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeNodeName(t *testing.T) {
	for _, test := range []struct {
		name string
		want string
		bad  bool
	}{
		{name: "  🇸🇪 Sweden  ", want: "🇸🇪 Sweden"},
		{name: "   ", bad: true},
		{name: "line\nbreak", bad: true},
		{name: "control\x7fchar", bad: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeNodeName(test.name)
			if test.bad {
				if !errors.Is(err, ErrNodeNameInvalid) {
					t.Fatalf("expected invalid name, got %q, %v", got, err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("got %q, %v; want %q", got, err, test.want)
			}
		})
	}
	if _, err := NormalizeNodeName(strings.Repeat("n", 81)); !errors.Is(err, ErrNodeNameInvalid) {
		t.Fatal("names longer than 80 runes should be rejected")
	}
}
