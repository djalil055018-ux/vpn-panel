package model

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestAmneziaWGDialectBoundaries(t *testing.T) {
	for _, version := range []string{"1.0", "1.5", "2.0", "3.0", "3.1"} {
		t.Run(version, func(t *testing.T) {
			s, e := NewAmneziaWGSpec(version)
			if e != nil {
				t.Fatal(e)
			}
			lines, e := s.ConfigLines()
			if e != nil {
				t.Fatal(e)
			}
			if !strings.Contains(lines, "H1 = ") || strings.Contains(lines, "PostUp") {
				t.Fatal("invalid generated directives")
			}
			if version == "1.0" && strings.Contains(lines, "I1 = ") {
				t.Fatal("legacy signature not supported")
			}
			if (version == "1.0" || version == "1.5") && strings.Contains(lines, "S3 = ") {
				t.Fatal("legacy padding not supported")
			}
			if version != "3.1" && strings.Contains(lines, "RandomTrailers") {
				t.Fatal("3.1 option in older dialect")
			}
			if version == "3.1" && !strings.Contains(lines, "RandomTrailers = 1\nDisableCookies = 0\n") {
				t.Fatal("official awg boolean syntax required")
			}
		})
	}
}

func TestAmneziaWGRejectsInjectionAndUnsafeCombinations(t *testing.T) {
	base, e := NewAmneziaWGSpec("3.1")
	if e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name   string
		change func(*AmneziaWGSpec)
	}{
		{"injected_header", func(s *AmneziaWGSpec) { s.H1 = "1\nPostUp = anything" }},
		{"injected_signature", func(s *AmneziaWGSpec) { s.I1 = "<r 64>\nPostUp = anything" }},
		{"overlapping_headers", func(s *AmneziaWGSpec) { s.H2 = s.H1 }},
		{"negative_range", func(s *AmneziaWGSpec) { s.H1 = "-1" }},
		{"overflow_range", func(s *AmneziaWGSpec) { s.H1 = "4294967296" }},
		{"wrong_dialect", func(s *AmneziaWGSpec) { s.Version = "2.0" }},
		{"wrong_key", func(s *AmneziaWGSpec) { s.HeaderProtectionKey = "invalid" }},
		{"insufficient_header_padding", func(s *AmneziaWGSpec) { s.S4 = 11 }},
		{"fragmenting_content_padding", func(s *AmneziaWGSpec) { s.ContentPaddingAddition = "0-128" }},
		{"unbounded_signature", func(s *AmneziaWGSpec) { s.I1 = "<r 1280><r 1>" }},
		{"unknown_signature_tag", func(s *AmneziaWGSpec) { s.I1 = "<c>" }},
		{"rejection_before_rekey", func(s *AmneziaWGSpec) { s.RejectAfterTime = "90-110" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := *base
			tc.change(&s)
			if s.Validate() == nil {
				t.Fatal("invalid configuration accepted")
			}
			if lines, e := s.ConfigLines(); e == nil || lines != "" {
				t.Fatal("invalid configuration emitted")
			}
		})
	}
	for _, s := range []string{"<b 0x00ff><t><r 2><rc 3><rd 4>", "<r 1280>", ""} {
		if !validAWGSignature(s) {
			t.Fatal("valid signature rejected")
		}
	}
	for _, s := range []string{"<b 0xf>", "<r 0>", "<r 1281>", "<r -1>", "<r 2> "} {
		if validAWGSignature(s) {
			t.Fatal("invalid signature accepted")
		}
	}
	base.HeaderProtectionKey = base64.StdEncoding.EncodeToString(make([]byte, 31))
	if base.Validate() == nil {
		t.Fatal("short header key accepted")
	}
}
