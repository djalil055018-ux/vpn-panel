package agent

import "testing"

func TestParseCPU(t *testing.T) {
	total, idle, ok := parseCPU("cpu  10 2 3 40 5 1 2 3 0 0\ncpu0 1 1 1 1")
	if !ok || total != 66 || idle != 45 {
		t.Fatalf("total=%d idle=%d ok=%v", total, idle, ok)
	}
	if _, _, ok = parseCPU("not-cpu"); ok {
		t.Fatal("invalid CPU sample accepted")
	}
}

func TestCPUPercentUsesCounterDelta(t *testing.T) {
	cpuSample.Lock()
	cpuSample.set = false
	cpuSample.total = 0
	cpuSample.idle = 0
	cpuSample.Unlock()
	if got := cpuPercent("cpu 10 0 10 80"); got != 0 {
		t.Fatalf("first sample=%v", got)
	}
	if got := cpuPercent("cpu 20 0 20 160"); got != 20 {
		t.Fatalf("second sample=%v", got)
	}
}

func TestParseMemoryAndNetwork(t *testing.T) {
	total, used := parseMemory("MemTotal: 1000 kB\nMemAvailable: 250 kB\n")
	if total != 1024000 || used != 768000 {
		t.Fatalf("memory total=%d used=%d", total, used)
	}
	rx, tx := parseNetwork("Inter-|header\n lo: 10 0 0 0 0 0 0 0 20\n eth0: 100 0 0 0 0 0 0 0 200\n wg0: 3 0 0 0 0 0 0 0 4")
	if rx != 103 || tx != 204 {
		t.Fatalf("network rx=%d tx=%d", rx, tx)
	}
}
