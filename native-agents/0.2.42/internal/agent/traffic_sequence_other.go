//go:build !linux

package agent

import "fmt"

func reserveTrafficSequence(string) (int64, error) {
	return 0, fmt.Errorf("durable traffic collection requires Linux")
}
