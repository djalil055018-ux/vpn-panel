package subscriptioncompat

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var browserAlias = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

// The installed source uses xbytes1.9.1 parseBytes(iec:true). Its prefix is
// selected in decimal units before rendering the value in binary units.
// Integer rounding also preserves JS toFixed's upwards half-cent ties.
func browserBytes(n int64) string {
	if n == 0 {
		return "0"
	}
	// Preserve xbytes' floating-point prefix choice at large near-boundary
	// values, e.g. 10^15-1 is displayed in PiB by the source.
	exponent := int(math.Floor(math.Log(float64(n)) / math.Log(1000)))
	scale := int64(1) << (10 * exponent)
	hundredths := (n*100 + scale/2) / scale
	unit := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}[exponent]
	return fmt.Sprintf("%d.%02d %s", hundredths/100, hundredths%100, unit)
}

// BrowserInfo is the raw backend contract consumed by the existing subscription
// page. It includes only this account's public information and authorized links.
// HTML, assets and the source page configuration are a separate delivery layer.
func BrowserInfo(p Policy, a ResponseAccount, hosts []Host, credential string, now time.Time) ([]byte, error) {
	if _, err := p.ResponseHeaders(a); err != nil || !browserAlias.MatchString(a.Alias) || now.IsZero() {
		return nil, ErrProfile
	}
	if a.Status != "ACTIVE" {
		hosts = nil
	}
	lines, err := p.Notice(a.Status, len(hosts), a.SubscriptionURL)
	if err != nil {
		return nil, err
	}
	var wire []byte
	if lines != nil {
		wire, err = RenderNotices(lines, Options{}, "XRAY_BASE64")
	} else if len(hosts) > 0 && a.Status == "ACTIVE" {
		wire, err = Render(hosts, Options{}, "XRAY_BASE64", credential)
	} else {
		wire, err = RenderNotices([]string{}, Options{}, "XRAY_BASE64")
	}
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(string(wire))
	if err != nil {
		return nil, ErrProfile
	}
	links := []string{}
	if len(decoded) > 0 {
		links = strings.Split(string(decoded), "\n")
	}
	return json.Marshal(Options{"isFound": true, "subscriptionUrl": a.SubscriptionURL, "links": links, "ssConfLinks": Options{},
		"user": Options{"shortUuid": a.Alias, "daysLeft": (a.ExpiresAt.UnixMilli() - now.UnixMilli()) / 86400000,
			"trafficUsed": browserBytes(a.UsedBytes), "trafficLimit": browserBytes(a.LimitBytes), "lifetimeTrafficUsed": browserBytes(a.LifetimeBytes),
			"trafficUsedBytes": strconv.FormatInt(a.UsedBytes, 10), "trafficLimitBytes": strconv.FormatInt(a.LimitBytes, 10), "lifetimeTrafficUsedBytes": strconv.FormatInt(a.LifetimeBytes, 10),
			"username": a.Username, "expiresAt": a.ExpiresAt.UTC().Format("2006-01-02T15:04:05.000Z"), "isActive": a.Status == "ACTIVE", "userStatus": a.Status, "trafficLimitStrategy": "NO_RESET"}})
}
