package store

import "testing"

func TestTrafficDelta(t *testing.T) {
	if got := trafficDelta(120, 100); got != 20 {
		t.Fatalf("increment delta=%d", got)
	}
	if got := trafficDelta(10, 100); got != 10 {
		t.Fatalf("reset delta=%d", got)
	}
	if got := trafficDelta(100, 100); got != 0 {
		t.Fatalf("stable delta=%d", got)
	}
}
