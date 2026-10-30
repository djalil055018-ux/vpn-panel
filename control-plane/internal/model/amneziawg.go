package model

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// AmneziaWGSpec contains protocol settings, never wg-quick shell hooks.
// Version is the configuration dialect, independently of the runtime release.
type AmneziaWGSpec struct {
	Version                string `json:"version"`
	Jc                     uint16 `json:"jc"`
	Jmin                   uint16 `json:"jmin"`
	Jmax                   uint16 `json:"jmax"`
	S1                     uint16 `json:"s1"`
	S2                     uint16 `json:"s2"`
	S3                     uint16 `json:"s3,omitempty"`
	S4                     uint16 `json:"s4,omitempty"`
	H1                     string `json:"h1"`
	H2                     string `json:"h2"`
	H3                     string `json:"h3"`
	H4                     string `json:"h4"`
	I1                     string `json:"i1,omitempty"`
	I2                     string `json:"i2,omitempty"`
	I3                     string `json:"i3,omitempty"`
	I4                     string `json:"i4,omitempty"`
	I5                     string `json:"i5,omitempty"`
	HeaderProtectionKey    string `json:"header_protection_key,omitempty"`
	ContentPaddingAddition string `json:"content_padding_addition,omitempty"`
	RekeyAfterTime         string `json:"rekey_after_time,omitempty"`
	RekeyTimeout           string `json:"rekey_timeout,omitempty"`
	RejectAfterTime        string `json:"reject_after_time,omitempty"`
	KeepaliveTimeout       string `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts   string `json:"max_handshake_attempts,omitempty"`
	RandomTrailers         bool   `json:"random_trailers,omitempty"`
	DisableCookies         bool   `json:"disable_cookies,omitempty"`
}

func ValidAmneziaWGVersion(version string) bool {
	switch version {
	case "1.0", "1.5", "2.0", "3.0", "3.1":
		return true
	}
	return false
}

func awgRange(text string, max uint64) (uint64, uint64, error) {
	parts := strings.Split(text, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return 0, 0, errors.New("invalid range")
	}
	parse := func(s string) (uint64, error) {
		n, e := strconv.ParseUint(s, 10, 32)
		if e != nil || strconv.FormatUint(n, 10) != s || n > max {
			return 0, errors.New("invalid range")
		}
		return n, nil
	}
	lo, e := parse(parts[0])
	if e != nil {
		return 0, 0, e
	}
	hi := lo
	if len(parts) == 2 {
		hi, e = parse(parts[1])
		if e != nil {
			return 0, 0, e
		}
	}
	if lo > hi {
		return 0, 0, errors.New("reversed range")
	}
	return lo, hi, nil
}

var awgSignatureTag = regexp.MustCompile(`^<(?:b 0x[0-9a-fA-F]+|r [0-9]+|rc [0-9]+|rd [0-9]+|t)>`)

func validAWGSignature(text string) bool {
	if len(text) > 4096 {
		return false
	}
	size := 0
	for text != "" {
		tag := awgSignatureTag.FindString(text)
		if tag == "" {
			return false
		}
		text = text[len(tag):]
		switch {
		case tag == "<t>":
			size += 4
		case strings.HasPrefix(tag, "<b "):
			n := len(tag) - 6
			if n%2 != 0 {
				return false
			}
			size += n / 2
		default:
			parts := strings.Fields(strings.Trim(tag, "<>"))
			n, e := strconv.Atoi(parts[1])
			if e != nil || n < 1 || n > 1280 {
				return false
			}
			size += n
		}
		if size > 1280 {
			return false
		}
	}
	return true
}

func (s AmneziaWGSpec) Validate() error {
	invalid := func(reason string) error { return fmt.Errorf("invalid AmneziaWG settings: %s", reason) }
	if !ValidAmneziaWGVersion(s.Version) {
		return invalid("unsupported version")
	}
	if s.Jc > 128 || s.Jmin > s.Jmax || s.Jmax > 1280 || s.S1 > 1024 || s.S2 > 1024 || s.S3 > 1024 || s.S4 > 140 {
		return invalid("packet limits")
	}
	legacy := s.Version == "1.0" || s.Version == "1.5"
	headers := []string{s.H1, s.H2, s.H3, s.H4}
	ranges := [4][2]uint64{}
	for i, h := range headers {
		lo, hi, e := awgRange(h, 1<<32-1)
		if e != nil || lo == 0 || (legacy && lo != hi) {
			return invalid("header range")
		}
		ranges[i] = [2]uint64{lo, hi}
		for j := 0; j < i; j++ {
			if lo <= ranges[j][1] && ranges[j][0] <= hi {
				return invalid("overlapping headers")
			}
		}
	}
	if legacy && (s.S3 != 0 || s.S4 != 0) {
		return invalid("S3/S4 require version 2.0 or later")
	}
	for _, signature := range []string{s.I1, s.I2, s.I3, s.I4, s.I5} {
		if !validAWGSignature(signature) || (s.Version == "1.0" && signature != "") {
			return invalid("signature packet")
		}
	}
	modern := s.Version == "3.0" || s.Version == "3.1"
	fields := []string{s.ContentPaddingAddition, s.RekeyAfterTime, s.RekeyTimeout, s.RejectAfterTime, s.KeepaliveTimeout, s.MaxHandshakeAttempts}
	if !modern {
		if s.HeaderProtectionKey != "" {
			return invalid("header protection requires version 3.0 or later")
		}
		for _, v := range fields {
			if v != "" {
				return invalid("timings and content padding require version 3.0 or later")
			}
		}
	}
	if s.HeaderProtectionKey != "" {
		if !ValidShadowsocksKey(s.HeaderProtectionKey) || s.S1 < 12 || s.S2 < 12 || s.S3 < 12 || s.S4 < 12 {
			return invalid("header protection key or padding")
		}
	}
	for i, v := range fields {
		if v == "" {
			continue
		}
		lo, hi, e := awgRange(v, 65535)
		if e != nil || (i > 0 && lo == 0) {
			return invalid("timing or padding range")
		}
		if i == 0 && hi+uint64(s.S4) > 140 {
			return invalid("transport padding exceeds managed MTU budget")
		}
	}
	if s.RekeyAfterTime != "" && s.RejectAfterTime != "" {
		_, a, _ := awgRange(s.RekeyAfterTime, 65535)
		b, _, _ := awgRange(s.RejectAfterTime, 65535)
		if a >= b {
			return invalid("rekey must precede rejection")
		}
	}
	if s.Version != "3.1" && (s.RandomTrailers || s.DisableCookies) {
		return invalid("trailer and cookie options require version 3.1")
	}
	return nil
}

// NewAmneziaWGSpec generates shared settings once for a service. Rebuilding a
// desired generation must retain them, otherwise existing client files break.
func NewAmneziaWGSpec(version string) (*AmneziaWGSpec, error) {
	if !ValidAmneziaWGVersion(version) {
		return nil, errors.New("unsupported AmneziaWG version")
	}
	s := &AmneziaWGSpec{Version: version, Jc: 4, Jmin: 40, Jmax: 80, S1: 32, S2: 48}
	var seed [20]byte
	if _, e := rand.Read(seed[:]); e != nil {
		return nil, e
	}
	headers := [4]string{}
	for i := range headers {
		base := uint64(i+1)*500000000 + uint64(binary.LittleEndian.Uint32(seed[i*4:i*4+4])%100000000)
		headers[i] = strconv.FormatUint(base, 10)
		if version == "2.0" {
			headers[i] += "-" + strconv.FormatUint(base+1023, 10)
		}
	}
	s.H1, s.H2, s.H3, s.H4 = headers[0], headers[1], headers[2], headers[3]
	if version != "1.0" {
		s.I1 = "<r 64>"
	}
	if version == "2.0" || version == "3.0" || version == "3.1" {
		s.S3 = 32
		s.S4 = 32
	}
	if version == "3.0" || version == "3.1" {
		var key [32]byte
		if _, e := rand.Read(key[:]); e != nil {
			return nil, e
		}
		s.HeaderProtectionKey = base64.StdEncoding.EncodeToString(key[:])
		s.H1, s.H2, s.H3, s.H4 = "1", "2", "3", "4"
		s.ContentPaddingAddition = "0-32"
		s.RekeyAfterTime = "110-130"
		s.RekeyTimeout = "4-6"
		s.RejectAfterTime = "170-190"
		s.KeepaliveTimeout = "9-11"
		s.MaxHandshakeAttempts = "16-20"
	}
	if version == "3.1" {
		s.RandomTrailers = true
	}
	return s, s.Validate()
}

// ConfigLines is accepted by the official awg tool. Values are validated before
// emission; no arbitrary configuration directives can be supplied through it.
func (s AmneziaWGSpec) ConfigLines() (string, error) {
	if e := s.Validate(); e != nil {
		return "", e
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Jc = %d\nJmin = %d\nJmax = %d\nS1 = %d\nS2 = %d\nH1 = %s\nH2 = %s\nH3 = %s\nH4 = %s\n", s.Jc, s.Jmin, s.Jmax, s.S1, s.S2, s.H1, s.H2, s.H3, s.H4)
	if s.Version != "1.0" && s.Version != "1.5" {
		fmt.Fprintf(&b, "S3 = %d\nS4 = %d\n", s.S3, s.S4)
	}
	for _, p := range [][2]string{{"I1", s.I1}, {"I2", s.I2}, {"I3", s.I3}, {"I4", s.I4}, {"I5", s.I5}, {"HeaderProtectionKey", s.HeaderProtectionKey}, {"ContentPaddingAddition", s.ContentPaddingAddition}, {"RekeyAfterTime", s.RekeyAfterTime}, {"RekeyTimeout", s.RekeyTimeout}, {"RejectAfterTime", s.RejectAfterTime}, {"KeepaliveTimeout", s.KeepaliveTimeout}, {"MaxHandshakeAttempts", s.MaxHandshakeAttempts}} {
		if p[1] != "" {
			fmt.Fprintf(&b, "%s = %s\n", p[0], p[1])
		}
	}
	if s.Version == "3.1" {
		flag := func(v bool) int {
			if v {
				return 1
			}
			return 0
		}
		fmt.Fprintf(&b, "RandomTrailers = %d\nDisableCookies = %d\n", flag(s.RandomTrailers), flag(s.DisableCookies))
	}
	return b.String(), nil
}
