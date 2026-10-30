//go:build !linux

package main

func operationsFreeBytes() int64 { return -1 }
