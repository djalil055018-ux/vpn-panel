//go:build !linux

package monitoring

func freeBytes() int64 { return -1 }
