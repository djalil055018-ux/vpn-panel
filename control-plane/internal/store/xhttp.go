package store

import (
	"strconv"
	"strings"
	"vpn-platform/internal/model"
)

func xhttpCoreCompatible(core model.CoreRelease) bool {
	if core.Type != "xray" {
		return false
	}
	parts := strings.Split(core.Version, ".")
	if len(parts) != 3 {
		return false
	}
	minimum := []int{26, 7, 28}
	version := []int{}
	for _, part := range parts {
		n, e := strconv.Atoi(part)
		if e != nil || n < 0 {
			return false
		}
		version = append(version, n)
	}
	for i, n := range version {
		if n > minimum[i] {
			return true
		}
		if n < minimum[i] {
			return false
		}
	}
	return true
}
