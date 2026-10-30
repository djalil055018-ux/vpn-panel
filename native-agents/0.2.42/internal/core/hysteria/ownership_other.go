//go:build !linux

package hysteria

import "os"

func ownedBy(os.FileInfo, int, int) bool { return false }
