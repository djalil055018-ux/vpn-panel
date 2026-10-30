package subscriptioncompat

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Policy contains reviewed public response settings. It grants no VPN access.
// Source HWID is disabled; device history remains separate from enforcement.
type Policy struct {
	Rules       ResponseRules       `json:"rules"`
	Headers     map[string]string   `json:"headers"`
	Remarks     map[string][]string `json:"remarks"`
	ShowRemarks bool                `json:"show_remarks"`
	ServeJSON   bool                `json:"serve_json"`
	HWID        HWIDPolicy          `json:"hwid"`
	PageID      *string             `json:"page_id"`
}
type HWIDPolicy struct {
	Enabled     *bool   `json:"enabled"`
	Fallback    *int    `json:"fallbackDeviceLimit"`
	MaxAnnounce *string `json:"maxDevicesAnnounce"`
}
type ResponseRules struct {
	Version  string         `json:"version"`
	Rules    []ResponseRule `json:"rules"`
	Settings struct {
		DisablePath bool `json:"disableSubscriptionAccessByPath"`
	} `json:"settings"`
}
type ResponseRule struct {
	Name          string              `json:"name"`
	Enabled       *bool               `json:"enabled"`
	Operator      string              `json:"operator"`
	Response      string              `json:"responseType"`
	Conditions    []ResponseCondition `json:"conditions"`
	Modifications Options             `json:"responseModifications"`
}
type ResponseCondition struct {
	Header        string `json:"headerName"`
	Operator      string `json:"operator"`
	Value         string `json:"value"`
	CaseSensitive *bool  `json:"caseSensitive"`
}
type ResponseSelection struct {
	Format       string
	RuleName     string
	ExplicitPath bool
}

var httpHeaderName = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_|~-]+$`)
var jsonClient = regexp.MustCompile(`^(?:[Ss]treisand|Happ/|INCY/|ktor-client|V2Box|io\.github\.saeeddev94\.xray/|(?:v2rayNG|v2rayN|v2plus)/[0-9]+\.[0-9]+\.[0-9]+)`)

func responseFormat(s string) bool {
	switch s {
	case "XRAY_BASE64", "XRAY_JSON", "SINGBOX", "MIHOMO", "STASH", "CLASH", "BROWSER", "BLOCK", "STATUS_CODE_404", "STATUS_CODE_451":
		return true
	}
	return false
}
func validPublicText(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func conditionRegex(c ResponseCondition) (*regexp.Regexp, error) {
	pattern := c.Value
	if !*c.CaseSensitive {
		// Source lowercases the regex string before using the case-insensitive flag.
		pattern = "(?i)" + strings.ToLower(pattern)
	}
	return regexp.Compile(pattern)
}
func (rules ResponseRules) Validate() error {
	if rules.Version != "1" || len(rules.Rules) == 0 || len(rules.Rules) > 100 {
		return ErrProfile
	}
	for _, r := range rules.Rules {
		if r.Enabled == nil || !validPublicText(r.Name, 256) || !responseFormat(r.Response) || (r.Operator != "AND" && r.Operator != "OR") || r.Conditions == nil || len(r.Conditions) > 32 || len(r.Modifications) > 0 {
			return ErrProfile
		}
		for _, c := range r.Conditions {
			if c.CaseSensitive == nil || !httpHeaderName.MatchString(c.Header) || len(c.Header) > 128 || !validPublicText(c.Value, 2048) {
				return ErrProfile
			}
			switch c.Operator {
			case "EQUALS", "NOT_EQUALS", "CONTAINS", "NOT_CONTAINS", "STARTS_WITH", "NOT_STARTS_WITH", "ENDS_WITH", "NOT_ENDS_WITH":
			case "REGEX", "NOT_REGEX":
				if _, err := conditionRegex(c); err != nil {
					return ErrProfile
				}
			default:
				return ErrProfile
			}
		}
	}
	return nil
}
func (c ResponseCondition) matches(headers http.Header) bool {
	values, ok := headers[http.CanonicalHeaderKey(c.Header)]
	if !ok {
		return false
	} // Missing is false even for negative comparisons.
	value, compare := strings.Join(values, ","), c.Value
	if !*c.CaseSensitive {
		value = strings.ToLower(value)
		compare = strings.ToLower(compare)
	}
	switch c.Operator {
	case "EQUALS":
		return value == compare
	case "NOT_EQUALS":
		return value != compare
	case "CONTAINS":
		return strings.Contains(value, compare)
	case "NOT_CONTAINS":
		return !strings.Contains(value, compare)
	case "STARTS_WITH":
		return strings.HasPrefix(value, compare)
	case "NOT_STARTS_WITH":
		return !strings.HasPrefix(value, compare)
	case "ENDS_WITH":
		return strings.HasSuffix(value, compare)
	case "NOT_ENDS_WITH":
		return !strings.HasSuffix(value, compare)
	case "REGEX", "NOT_REGEX":
		re, err := conditionRegex(c)
		if err != nil {
			return false
		}
		found := re.MatchString(value)
		if c.Operator == "NOT_REGEX" {
			return !found
		}
		return found
	}
	return false
}

// Select preserves source rule order and path overrides. It rejects requests
// without a user agent, as the source middleware does.
func (p Policy) Select(headers http.Header, pathFormat string) (ResponseSelection, error) {
	out := ResponseSelection{Format: "BLOCK", ExplicitPath: pathFormat != ""}
	if p.Rules.Validate() != nil {
		return out, ErrProfile
	}
	canonical := http.Header{}
	size := 0
	for key, values := range headers {
		if !httpHeaderName.MatchString(key) {
			return out, ErrProfile
		}
		for _, value := range values {
			size += len(key) + len(value)
			if !validPublicText(value, 16384) || size > 65536 {
				return out, ErrProfile
			}
			canonical.Add(key, value)
		}
	}
	ua := canonical.Get("User-Agent")
	if ua == "" {
		return out, nil
	}
	if pathFormat != "" {
		if p.Rules.Settings.DisablePath {
			return out, nil
		}
		switch pathFormat {
		case "stash":
			out.Format = "STASH"
		case "singbox":
			out.Format = "SINGBOX"
		case "mihomo":
			out.Format = "MIHOMO"
		case "clash":
			out.Format = "CLASH"
		case "json", "v2ray-json":
			out.Format = "XRAY_JSON"
		}
		return out, nil
	}
	for _, rule := range p.Rules.Rules {
		if !*rule.Enabled {
			continue
		}
		matched := len(rule.Conditions) == 0 || rule.Operator == "AND"
		for _, c := range rule.Conditions {
			if rule.Operator == "AND" {
				matched = matched && c.matches(canonical)
			} else {
				matched = matched || c.matches(canonical)
			}
		}
		if matched {
			out.Format = rule.Response
			out.RuleName = rule.Name
			if out.Format == "XRAY_BASE64" && p.ServeJSON && jsonClient.MatchString(ua) {
				out.Format = "XRAY_JSON"
			}
			return out, nil
		}
	}
	return out, nil
}

func validResponseTemplate(s string) bool {
	if !validPublicText(s, 8192) {
		return false
	}
	// Only this placeholder is present in the reviewed source. Reject future
	// template features rather than silently emitting misleading account data.
	rest := strings.ReplaceAll(s, "{{SUBSCRIPTION_URL}}", "")
	return !strings.Contains(rest, "{{") && !strings.Contains(rest, "}}")
}
func allowedResponseHeader(k string) bool {
	switch k {
	case "announce", "profile-title", "profile-update-interval", "profile-web-page-url", "support-url":
		return true
	}
	return false
}
func (p Policy) Validate() error {
	if p.Rules.Validate() != nil || p.HWID.Enabled == nil || *p.HWID.Enabled || p.HWID.Fallback == nil || *p.HWID.Fallback < 0 || *p.HWID.Fallback > 100000 ||
		(p.HWID.MaxAnnounce != nil && !validResponseTemplate(*p.HWID.MaxAnnounce)) || (p.PageID != nil && !credentialPattern.MatchString(*p.PageID)) || p.Headers == nil {
		return ErrProfile
	}
	for k, v := range p.Headers {
		if !allowedResponseHeader(k) || !validResponseTemplate(v) {
			return ErrProfile
		}
	}
	expected := []string{"HWIDMaxDevicesExceeded", "HWIDNotSupported", "disabledUsers", "emptyHosts", "expiredUsers", "limitedUsers"}
	if len(p.Remarks) != len(expected) {
		return ErrProfile
	}
	for _, k := range expected {
		lines, ok := p.Remarks[k]
		if !ok || lines == nil || len(lines) > 30 {
			return ErrProfile
		}
		for _, line := range lines {
			if !validResponseTemplate(line) || len(line) > 4096 || strings.HasPrefix(strings.TrimSpace(line), "{\"f") {
				return ErrProfile
			}
		}
	}
	return nil
}
func responseTemplate(s, subscriptionURL string) string {
	encode := strings.HasPrefix(s, "rwEncodeBase64:")
	if encode {
		s = strings.TrimPrefix(s, "rwEncodeBase64:")
	}
	s = strings.ReplaceAll(s, "{{SUBSCRIPTION_URL}}", subscriptionURL)
	if encode {
		s = "base64:" + base64.StdEncoding.EncodeToString([]byte(s))
	}
	return s
}

type ResponseAccount struct {
	Username        string
	Alias           string
	SubscriptionURL string
	UsedBytes       int64
	LifetimeBytes   int64
	LimitBytes      int64
	ExpiresAt       time.Time
	Status          string
}

func (p Policy) ResponseHeaders(a ResponseAccount) (http.Header, error) {
	out := http.Header{}
	u, err := url.Parse(a.SubscriptionURL)
	if p.Validate() != nil || !validPublicText(a.Username, 256) || a.Username == "" || strings.ContainsAny(a.Username, ";\"\\") ||
		err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !validPublicText(a.SubscriptionURL, 4096) ||
		a.UsedBytes < 0 || a.LimitBytes < 0 || a.LifetimeBytes < 0 || a.UsedBytes > 9007199254740991 || a.LimitBytes > 9007199254740991 || a.LifetimeBytes > 9007199254740991 || a.ExpiresAt.IsZero() {
		return out, ErrProfile
	}
	expire := a.ExpiresAt.Unix()
	if a.ExpiresAt.UTC().Year() == 2099 {
		expire = 0
	}
	out.Set("Content-Disposition", "attachment; filename="+a.Username)
	out.Set("Subscription-Userinfo", "upload=0; download="+strconv.FormatInt(a.UsedBytes, 10)+"; total="+strconv.FormatInt(a.LimitBytes, 10)+"; expire="+strconv.FormatInt(expire, 10))
	for key, value := range p.Headers {
		out.Set(key, responseTemplate(value, a.SubscriptionURL))
	}
	return out, nil
}

// Notice selects display text only. The caller must independently enforce
// current native status, expiry, quota, deletion and effective service access.
func (p Policy) Notice(status string, hostCount int, subscriptionURL string) ([]string, error) {
	if p.Validate() != nil || hostCount < 0 {
		return nil, ErrProfile
	}
	key := ""
	if p.ShowRemarks {
		switch status {
		case "EXPIRED":
			key = "expiredUsers"
		case "DISABLED":
			key = "disabledUsers"
		case "LIMITED":
			key = "limitedUsers"
		case "ACTIVE":
		default:
			return nil, ErrProfile
		}
	}
	if key == "" && hostCount == 0 {
		key = "emptyHosts"
	}
	if key == "" {
		return nil, nil
	}
	out := []string{}
	for _, line := range p.Remarks[key] {
		out = append(out, responseTemplate(line, subscriptionURL))
	}
	return out, nil
}

// OverlayExternal applies removal before addition, as in the source. It clones
// settings to keep one subscriber's external policy out of another's response.
func (p Policy) OverlayExternal(remove []string, add map[string]string, remarks map[string][]string, hwid *HWIDPolicy, pageID *string) (Policy, error) {
	var out Policy
	wire, err := json.Marshal(p)
	if err != nil || json.Unmarshal(wire, &out) != nil || p.Validate() != nil {
		return out, ErrProfile
	}
	for _, key := range remove {
		if !allowedResponseHeader(key) {
			return out, ErrProfile
		}
		delete(out.Headers, key)
	}
	for key, value := range add {
		out.Headers[key] = value
	}
	if len(remarks) > 0 {
		raw, _ := json.Marshal(remarks)
		if json.Unmarshal(raw, &out.Remarks) != nil {
			return out, ErrProfile
		}
	}
	if hwid != nil {
		raw, _ := json.Marshal(hwid)
		if json.Unmarshal(raw, &out.HWID) != nil {
			return out, ErrProfile
		}
	}
	if pageID != nil {
		value := *pageID
		out.PageID = &value
	}
	return out, out.Validate()
}
