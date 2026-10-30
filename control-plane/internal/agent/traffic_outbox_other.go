//go:build !linux

package agent

import "errors"

func lockTrafficOutbox(string) (func(), error) {
	return nil, errors.New("durable traffic delivery requires Linux")
}
