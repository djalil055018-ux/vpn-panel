package agent

import (
	"bufio"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"vpn-platform/internal/model"
)

var cpuSample struct {
	sync.Mutex
	total uint64
	idle  uint64
	set   bool
}

func parseCPU(data string) (uint64, uint64, bool) {
	fields := strings.Fields(strings.SplitN(data, "\n", 2)[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, false
	}
	values := make([]uint64, 0, 8)
	for _, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		values = append(values, value)
		if len(values) == 8 {
			break
		}
	}
	if len(values) < 4 {
		return 0, 0, false
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	idle := values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	return total, idle, true
}

func cpuPercent(data string) float64 {
	total, idle, ok := parseCPU(data)
	if !ok {
		return 0
	}
	cpuSample.Lock()
	defer cpuSample.Unlock()
	previousTotal, previousIdle, previousSet := cpuSample.total, cpuSample.idle, cpuSample.set
	cpuSample.total, cpuSample.idle, cpuSample.set = total, idle, true
	if !previousSet || total <= previousTotal || idle < previousIdle {
		return 0
	}
	deltaTotal, deltaIdle := total-previousTotal, idle-previousIdle
	if deltaIdle > deltaTotal {
		return 0
	}
	return math.Round((100-float64(deltaIdle)*100/float64(deltaTotal))*10) / 10
}

func parseMemory(data string) (int64, int64) {
	values := map[string]int64{}
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ":")
		if name != "MemTotal" && name != "MemAvailable" {
			continue
		}
		value, err := strconv.ParseInt(fields[1], 10, 64)
		if err == nil && value >= 0 {
			values[name] = value * 1024
		}
	}
	total, available := values["MemTotal"], values["MemAvailable"]
	if available > total {
		available = total
	}
	return total, total - available
}

func parseNetwork(data string) (int64, int64) {
	var rx, tx int64
	for _, line := range strings.Split(data, "\n") {
		name, values, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) == "lo" {
			continue
		}
		fields := strings.Fields(values)
		if len(fields) < 9 {
			continue
		}
		received, rxErr := strconv.ParseInt(fields[0], 10, 64)
		transmitted, txErr := strconv.ParseInt(fields[8], 10, 64)
		if rxErr == nil && txErr == nil && received >= 0 && transmitted >= 0 {
			rx += received
			tx += transmitted
		}
	}
	return rx, tx
}

func CollectMetrics() *model.NodeMetrics {
	cpu, cpuErr := os.ReadFile("/proc/stat")
	memory, memoryErr := os.ReadFile("/proc/meminfo")
	network, networkErr := os.ReadFile("/proc/net/dev")
	uptime, uptimeErr := os.ReadFile("/proc/uptime")
	load, loadErr := os.ReadFile("/proc/loadavg")
	var disk syscall.Statfs_t
	diskErr := syscall.Statfs("/var/lib/vpn-platform", &disk)
	if cpuErr != nil || memoryErr != nil || networkErr != nil || uptimeErr != nil || loadErr != nil || diskErr != nil {
		return nil
	}
	totalMemory, usedMemory := parseMemory(string(memory))
	rx, tx := parseNetwork(string(network))
	uptimeFields, loadFields := strings.Fields(string(uptime)), strings.Fields(string(load))
	if totalMemory <= 0 || len(uptimeFields) == 0 || len(loadFields) == 0 {
		return nil
	}
	uptimeValue, uptimeParseErr := strconv.ParseFloat(uptimeFields[0], 64)
	loadValue, loadParseErr := strconv.ParseFloat(loadFields[0], 64)
	if uptimeParseErr != nil || loadParseErr != nil || uptimeValue < 0 || loadValue < 0 {
		return nil
	}
	totalDisk := int64(disk.Blocks) * int64(disk.Bsize)
	freeDisk := int64(disk.Bavail) * int64(disk.Bsize)
	if freeDisk > totalDisk {
		freeDisk = totalDisk
	}
	return &model.NodeMetrics{CPUPercent: cpuPercent(string(cpu)), Load1: loadValue, MemoryTotal: totalMemory, MemoryUsed: usedMemory, DiskTotal: totalDisk, DiskUsed: totalDisk - freeDisk, NetworkRX: rx, NetworkTX: tx, UptimeSeconds: int64(uptimeValue)}
}
