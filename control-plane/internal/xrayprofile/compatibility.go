package xrayprofile

import (
	"regexp"
	"strconv"
	"strings"

	"vpn-platform/internal/model"
)

var releaseVersion = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)

func versionAtLeast(value, minimum string) bool {
	if !releaseVersion.MatchString(value) {
		return false
	}
	actual, floor := strings.Split(value, "."), strings.Split(minimum, ".")
	for i := range actual {
		a, _ := strconv.Atoi(actual[i])
		b, _ := strconv.Atoi(floor[i])
		if a != b {
			return a > b
		}
	}
	return true
}

// Registry approval is an additional CP requirement. A version string alone
// never approves a binary; this gate prevents older parsers ignoring the profile.
func DialRaceCoreCompatible(core model.CoreRelease) bool {
	return core.Type == "xray" && versionAtLeast(core.Version, "26.10.21")
}

func AgentCompatible(version string) bool { return versionAtLeast(version, MinimumAgent) }
func CoreCompatible(core model.CoreRelease) bool {
	return core.Type == "xray" && versionAtLeast(core.Version, MinimumCore)
}
