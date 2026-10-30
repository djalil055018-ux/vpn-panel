//go:build linux

package wireguard

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"vpn-platform/internal/model"
)

var ErrTraffic = errors.New("native WireGuard traffic state requires repair")
var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var epochPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type Counter struct {
	Uplink   int64
	Downlink int64
}
type PeerCounter struct {
	ClientID string
	Counter  Counter
}
type trafficState struct {
	Format         int
	Epoch          string
	InterfaceEpoch string
	Totals         map[string]Counter
	Peers          map[string]PeerCounter
}
type TrafficLedger struct {
	mu   sync.Mutex
	root string
}

func OpenTrafficLedger(root string) (*TrafficLedger, error) {
	if err := privateDirectory(root, false); err != nil {
		return nil, err
	}
	return &TrafficLedger{root: root}, nil
}

// ParseTransfers consumes `wg show <owned-interface> transfer`, not `dump`, so
// neither server private keys nor preshared keys enter diagnostics or counters.
func ParseTransfers(raw string, owners map[string]string) (map[string]PeerCounter, error) {
	result := map[string]PeerCounter{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			return nil, ErrTraffic
		}
		id, ok := owners[f[0]]
		if !ok || !uuid.MatchString(id) || !model.ValidShadowsocksKey(f[0]) {
			return nil, ErrTraffic
		}
		if _, exists := result[f[0]]; exists {
			return nil, ErrTraffic
		}
		rx, e1 := strconv.ParseInt(f[1], 10, 64)
		tx, e2 := strconv.ParseInt(f[2], 10, 64)
		if e1 != nil || e2 != nil || rx < 0 || tx < 0 {
			return nil, ErrTraffic
		}
		result[f[0]] = PeerCounter{id, Counter{rx, tx}}
	}
	if len(result) != len(owners) {
		return nil, ErrTraffic
	}
	return result, nil
}
func validCounter(c Counter) bool { return c.Uplink >= 0 && c.Downlink >= 0 }
func validateTraffic(s trafficState) error {
	if s.Format != 1 || !epochPattern.MatchString(s.Epoch) || !epochPattern.MatchString(s.InterfaceEpoch) || s.Totals == nil || s.Peers == nil || len(s.Totals) > 100000 || len(s.Peers) > 65536 {
		return ErrTraffic
	}
	for id, c := range s.Totals {
		if !uuid.MatchString(id) || !validCounter(c) {
			return ErrTraffic
		}
	}
	for key, p := range s.Peers {
		if !model.ValidShadowsocksKey(key) || !uuid.MatchString(p.ClientID) || !validCounter(p.Counter) {
			return ErrTraffic
		}
	}
	return nil
}

// Sample stores absolute totals and the current interface baseline together.
// Retrying the same sample after a network failure cannot double-count it.
// The caller owns the interface epoch and must close access before its final
// sample, then delete the interface. Reusing an epoch after counter reset fails.
func (l *TrafficLedger) Sample(interfaceEpoch string, peers map[string]PeerCounter) (string, []model.ClientTraffic, error) {
	return l.sample(interfaceEpoch, peers, false)
}

// Transition is used only after a verified syncconf under the kernel mutex.
// Existing peers retain their counters; removed peers retain the last sample.
// Unlike an interface restart, this must not reset baselines of surviving peers.
func (l *TrafficLedger) Transition(interfaceEpoch string, peers map[string]PeerCounter) (string, []model.ClientTraffic, error) {
	return l.sample(interfaceEpoch, peers, true)
}

func (l *TrafficLedger) sample(interfaceEpoch string, peers map[string]PeerCounter, transition bool) (string, []model.ClientTraffic, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !epochPattern.MatchString(interfaceEpoch) {
		return "", nil, ErrTraffic
	}
	s := trafficState{}
	raw, err := readPrivate(filepath.Join(l.root, "traffic.json"), 32<<20)
	if os.IsNotExist(err) {
		if transition {
			return "", nil, ErrTraffic
		}
		var b [16]byte
		if _, err = rand.Read(b[:]); err != nil {
			return "", nil, err
		}
		s = trafficState{1, hex.EncodeToString(b[:]), interfaceEpoch, map[string]Counter{}, map[string]PeerCounter{}}
	} else if err != nil {
		return "", nil, err
	} else {
		if json.Unmarshal(raw, &s) != nil || validateTraffic(s) != nil {
			return "", nil, ErrTraffic
		}
		if transition && s.InterfaceEpoch != interfaceEpoch {
			return "", nil, ErrTraffic
		}
		if !transition && s.InterfaceEpoch == interfaceEpoch && len(s.Peers) != len(peers) {
			return "", nil, ErrTraffic
		}
	}
	for key, p := range peers {
		if !model.ValidShadowsocksKey(key) || !uuid.MatchString(p.ClientID) || !validCounter(p.Counter) {
			return "", nil, ErrTraffic
		}
		delta := p.Counter
		if s.InterfaceEpoch == interfaceEpoch {
			old, exists := s.Peers[key]
			if exists {
				if old.ClientID != p.ClientID || p.Counter.Uplink < old.Counter.Uplink || p.Counter.Downlink < old.Counter.Downlink {
					return "", nil, ErrTraffic
				}
				delta.Uplink -= old.Counter.Uplink
				delta.Downlink -= old.Counter.Downlink
			} else if len(s.Peers) > 0 && !transition {
				return "", nil, ErrTraffic
			}
		}
		total := s.Totals[p.ClientID]
		if total.Uplink > math.MaxInt64-delta.Uplink || total.Downlink > math.MaxInt64-delta.Downlink {
			return "", nil, ErrTraffic
		}
		s.Totals[p.ClientID] = Counter{total.Uplink + delta.Uplink, total.Downlink + delta.Downlink}
	}
	s.InterfaceEpoch = interfaceEpoch
	s.Peers = peers
	if err = validateTraffic(s); err != nil {
		return "", nil, err
	}
	raw, err = json.Marshal(s)
	if err == nil {
		err = writePrivate(filepath.Join(l.root, "traffic.json"), raw)
	}
	if err != nil {
		return "", nil, err
	}
	result := make([]model.ClientTraffic, 0, len(s.Totals))
	for id, c := range s.Totals {
		result = append(result, model.ClientTraffic{ClientID: id, Uplink: c.Uplink, Downlink: c.Downlink, ActiveIPsUnavailable: true})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ClientID < result[j].ClientID })
	return s.Epoch, result, nil
}
