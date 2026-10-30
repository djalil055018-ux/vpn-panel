//go:build linux

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func reserveTrafficSequence(path string) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return 0, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return 0, err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return 0, err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	raw, err := os.ReadFile(path)
	var previous int64
	if err == nil {
		previous, err = strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil || previous < 0 || previous >= 9000000000000000 {
			return 0, fmt.Errorf("invalid traffic sequence checkpoint")
		}
	} else if !os.IsNotExist(err) {
		return 0, err
	}
	next := previous + 1
	file, err := os.CreateTemp(filepath.Dir(path), ".traffic-sequence-")
	if err != nil {
		return 0, err
	}
	defer os.Remove(file.Name())
	if _, err = file.WriteString(strconv.FormatInt(next, 10) + "\n"); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return 0, err
	}
	if closeErr != nil {
		return 0, closeErr
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return 0, err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return 0, err
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return 0, err
	}
	return next, nil
}
