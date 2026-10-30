//go:build !linux

package agent

import (
	"context"
	"errors"
)

func lockTrafficCapture(context.Context, string) (func(), error) {
	return nil, errors.New("durable traffic capture requires Linux")
}
