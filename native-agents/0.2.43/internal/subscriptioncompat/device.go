package subscriptioncompat

import (
	"net/http"
	"regexp"
	"unicode/utf16"
)

var deviceHWID = regexp.MustCompile(`^[a-zA-Z0-9=-]{10,64}$`)

// Network address and user agent are intentionally not device identities.
type DeviceObservation struct {
	HWID      string  `json:"hwid"`
	Platform  *string `json:"platform,omitempty"`
	OSVersion *string `json:"osVersion,omitempty"`
	Model     *string `json:"deviceModel,omitempty"`
}

func (d DeviceObservation) Validate() error {
	if !deviceHWID.MatchString(d.HWID) {
		return ErrProfile
	}
	for _, value := range []*string{d.Platform, d.OSVersion, d.Model} {
		if value != nil && !validPublicText(*value, 2048) {
			return ErrProfile
		}
	}
	return nil
}
func DeviceFromHeaders(headers http.Header) *DeviceObservation {
	first := func(key string) *string {
		values := headers.Values(key)
		if len(values) == 0 {
			return nil
		}
		if !validPublicText(values[0], 16384) {
			return nil
		}
		chars := utf16.Encode([]rune(values[0]))
		if len(chars) > 512 {
			chars = chars[:512]
		}
		value := string(utf16.Decode(chars))
		return &value
	}
	hwids := headers.Values("X-Hwid")
	if len(hwids) == 0 || !deviceHWID.MatchString(hwids[0]) {
		return nil
	}
	d := &DeviceObservation{HWID: hwids[0], Platform: first("X-Device-Os"), OSVersion: first("X-Ver-Os"), Model: first("X-Device-Model")}
	if d.Validate() != nil {
		return nil
	}
	return d
}
