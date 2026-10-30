package main

import "syscall"

func operationsFreeBytes() int64 {
	var s syscall.Statfs_t
	if syscall.Statfs("/var/lib/vpn-platform", &s) != nil {
		return -1
	}
	return int64(s.Bavail) * s.Bsize
}
