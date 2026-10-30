//go:build linux

package hysteria

import (
	"os"
	"syscall"
)

func ownedBy(info os.FileInfo, uid, gid int) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (uid < 0 || stat.Uid == uint32(uid)) && (gid < 0 || stat.Gid == uint32(gid))
}
