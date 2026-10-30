package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpn-platform/internal/model"
)

const xrayBinary = "/var/lib/vpn-platform/cores/xray/current/xray"

var trafficIdentity = regexp.MustCompile(`^client-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})@vpn-platform\.invalid$`)
var trafficMu sync.Mutex
var trafficAt time.Time
var trafficCache *model.ClientTrafficSnapshot
var runTrafficEpochCommand = func(ctx context.Context) (string, error) {
	raw, err := exec.CommandContext(ctx, "systemctl", "show", "--property=InvocationID", "--value", "vpn-platform-xray.service").Output()
	epoch := strings.TrimSpace(string(raw))
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(epoch) || epoch == strings.Repeat("0", 32) {
		return "", fmt.Errorf("Xray invocation identity unavailable")
	}
	return epoch, nil
}
var nextTrafficSequence = func() (int64, error) {
	state := strings.TrimSpace(os.Getenv("VPN_AGENT_STATE"))
	if state == "" {
		state = "/var/lib/vpn-platform/agent/state.json"
	}
	return reserveTrafficSequence(filepath.Join(filepath.Dir(state), "traffic-sequence"))
}
var runTrafficCountersCommand = func(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, xrayBinary, "api", "statsquery", "--server=127.0.0.1:10085", "-pattern", "user>>>").Output()
}
var runOnlineClientsCommand = func(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, xrayBinary, "api", "statsonlineiplist", "--server=127.0.0.1:10085", "-all").Output()
}

func trafficInt(raw json.RawMessage) (int64, bool) {
	var number int64
	if json.Unmarshal(raw, &number) == nil {
		return number, number >= 0
	}
	var text string
	if json.Unmarshal(raw, &text) != nil {
		return 0, false
	}
	value, err := strconv.ParseInt(text, 10, 64)
	return value, err == nil && value >= 0
}

func clientIDFromStatsEmail(email string) string {
	match := trafficIdentity.FindStringSubmatch(strings.ToLower(email))
	if match == nil {
		return ""
	}
	return match[1]
}

func parseTrafficCounters(raw []byte) []model.ClientTraffic {
	var document struct {
		Stats []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
		} `json:"stat"`
	}
	if json.Unmarshal(raw, &document) != nil {
		return nil
	}
	byClient := map[string]*model.ClientTraffic{}
	for _, stat := range document.Stats {
		parts := strings.Split(stat.Name, ">>>")
		if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" || (parts[3] != "uplink" && parts[3] != "downlink") {
			continue
		}
		clientID := clientIDFromStatsEmail(parts[1])
		value, ok := trafficInt(stat.Value)
		if clientID == "" || !ok {
			continue
		}
		item := byClient[clientID]
		if item == nil {
			item = &model.ClientTraffic{ClientID: clientID}
			byClient[clientID] = item
		}
		if parts[3] == "uplink" {
			item.Uplink = value
		} else {
			item.Downlink = value
		}
	}
	ids := make([]string, 0, len(byClient))
	for id := range byClient {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]model.ClientTraffic, 0, len(ids))
	for _, id := range ids {
		out = append(out, *byClient[id])
	}
	return out
}

func parseOnlineClientCounts(raw []byte) map[string]int {
	var document struct {
		Users []struct {
			Email string            `json:"email"`
			IPs   []json.RawMessage `json:"ips"`
		} `json:"users"`
	}
	if json.Unmarshal(raw, &document) != nil {
		return nil
	}
	out := map[string]int{}
	for _, user := range document.Users {
		if id := clientIDFromStatsEmail(user.Email); id != "" {
			out[id] = len(user.IPs)
		}
	}
	return out
}

func cloneTrafficSnapshot(value *model.ClientTrafficSnapshot) *model.ClientTrafficSnapshot {
	if value == nil {
		return nil
	}
	out := *value
	out.Clients = append([]model.ClientTraffic(nil), value.Clients...)
	return &out
}

func CollectClientTraffic() *model.ClientTrafficSnapshot {
	value, _ := CollectTrafficDelivery(context.Background(), false)
	if value == nil {
		return nil
	}
	return &value.Snapshot
}

func CollectTrafficDelivery(parent context.Context, force bool) (*model.TrafficDelivery, error) {
	trafficMu.Lock()
	defer trafficMu.Unlock()
	if !force && trafficCache != nil && time.Since(trafficAt) < 30*time.Second {
		return &model.TrafficDelivery{RecordedAt: trafficAt.UTC(), Snapshot: *cloneTrafficSnapshot(trafficCache)}, nil
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	epoch, err := runTrafficEpochCommand(ctx)
	if err != nil {
		return nil, fmt.Errorf("runtime identity unavailable")
	}
	sequence, err := nextTrafficSequence()
	if err != nil {
		return nil, fmt.Errorf("traffic sequence unavailable")
	}
	counters, err := runTrafficCountersCommand(ctx)
	if err != nil {
		return nil, fmt.Errorf("traffic counters unavailable")
	}
	traffic := parseTrafficCounters(counters)
	if traffic == nil {
		return nil, fmt.Errorf("invalid traffic counters")
	}
	if online, onlineErr := runOnlineClientsCommand(ctx); onlineErr == nil {
		counts := parseOnlineClientCounts(online)
		for i := range traffic {
			traffic[i].ActiveIPs = counts[traffic[i].ClientID]
		}
	}
	afterEpoch, err := runTrafficEpochCommand(ctx)
	if err != nil || afterEpoch != epoch {
		return nil, fmt.Errorf("runtime changed during traffic collection")
	}
	trafficCache = &model.ClientTrafficSnapshot{Epoch: epoch, Sequence: sequence, Clients: traffic}
	trafficAt = time.Now().UTC()
	return &model.TrafficDelivery{RecordedAt: trafficAt, Snapshot: *cloneTrafficSnapshot(trafficCache)}, nil
}
