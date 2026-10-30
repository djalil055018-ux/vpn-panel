//go:build linux

package openvpn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"vpn-platform/internal/model"
)

var ErrTraffic = errors.New("OpenVPN traffic ledger requires repair")
var clientName = regexp.MustCompile(`^client-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
var invocationID = regexp.MustCompile(`^[0-9a-f]{32}$`)

type Session struct {
	ClientID     string
	Invocation   string
	Started      int64
	Remote       string
	Uplink       int64
	Downlink     int64
	ObserveAfter int64
	ObservedAt   int64
}
type counters struct {
	Uplink   int64
	Downlink int64
}
type ledger struct {
	Format   int
	Epoch    string
	Totals   map[string]counters
	Active   map[string]Session
	Sessions map[string]Session `json:",omitempty"`
}

func validSession(s Session) bool {
	return clientName.MatchString("client-"+s.ClientID) && invocationID.MatchString(s.Invocation) && s.Started > 0 && s.Uplink >= 0 && s.Downlink >= 0
}
func addCounters(a, b counters) (counters, error) {
	if a.Uplink < 0 || a.Downlink < 0 || b.Uplink < 0 || b.Downlink < 0 || a.Uplink > math.MaxInt64-b.Uplink || a.Downlink > math.MaxInt64-b.Downlink {
		return counters{}, ErrTraffic
	}
	return counters{a.Uplink + b.Uplink, a.Downlink + b.Downlink}, nil
}
func (l *ledger) finish(id string) error {
	s, ok := l.Active[id]
	if !ok {
		return nil
	}
	value, err := addCounters(l.Totals[id], counters{s.Uplink, s.Downlink})
	if err != nil {
		return err
	}
	l.Totals[id] = value
	delete(l.Active, id)
	return nil
}
func (l *ledger) normalize() error {
	if !invocationID.MatchString(l.Epoch) {
		return ErrTraffic
	}
	if l.Format == 0 {
		if l.Totals != nil || l.Active != nil {
			return ErrTraffic
		}
		l.Totals = map[string]counters{}
		l.Active = map[string]Session{}
		for _, s := range l.Sessions {
			if !validSession(s) {
				return ErrTraffic
			}
			value, err := addCounters(l.Totals[s.ClientID], counters{s.Uplink, s.Downlink})
			if err != nil {
				return err
			}
			l.Totals[s.ClientID] = value
		}
		l.Sessions = nil
		l.Format = 2
	}
	if l.Format != 2 || l.Totals == nil || l.Active == nil || len(l.Totals) > 100000 || len(l.Active) > 252 {
		return ErrTraffic
	}
	for id, c := range l.Totals {
		if !clientName.MatchString("client-"+id) || c.Uplink < 0 || c.Downlink < 0 {
			return ErrTraffic
		}
	}
	for id, s := range l.Active {
		if id != s.ClientID || !validSession(s) {
			return ErrTraffic
		}
	}
	return nil
}

// OpenVPN 2.6.19 synchronously disconnects the old common-name instance before
// its next client-connect hook. duplicate-cn is never enabled. Hook boundaries
// distinguish rapid reconnects; roaming remote addresses are not session keys.
func (l *ledger) apply(invocation, event string, updates []Session, now int64) error {
	if event == "" || event == "client-connect" {
		for id, s := range l.Active {
			if s.Invocation != invocation {
				if err := l.finish(id); err != nil {
					return err
				}
			}
		}
	}
	for _, s := range updates {
		if !validSession(s) {
			return ErrTraffic
		}
		switch event {
		case "client-connect":
			if err := l.finish(s.ClientID); err != nil {
				return err
			}
			if len(l.Active) >= 252 {
				return ErrTraffic
			}
			// Ignore the pre-connect status publication, even within the same second.
			// Short-lived connections are accounted by their final disconnect hook.
			s.Uplink = 0
			s.Downlink = 0
			s.ObserveAfter = now + 2
			s.ObservedAt = 0
			l.Active[s.ClientID] = s
		case "client-disconnect", "":
			active, ok := l.Active[s.ClientID]
			if !ok || active.Invocation != s.Invocation || active.Started != s.Started {
				continue
			}
			if event == "" && s.ObservedAt < active.ObserveAfter {
				continue
			}
			if s.Uplink > active.Uplink {
				active.Uplink = s.Uplink
			}
			if s.Downlink > active.Downlink {
				active.Downlink = s.Downlink
			}
			l.Active[s.ClientID] = active
			if event == "client-disconnect" {
				if err := l.finish(s.ClientID); err != nil {
					return err
				}
			}
		default:
			return ErrTraffic
		}
	}
	return nil
}
func (l *ledger) counts() ([]model.ClientTraffic, error) {
	values := map[string]counters{}
	for id, c := range l.Totals {
		values[id] = c
	}
	for id, s := range l.Active {
		value, err := addCounters(values[id], counters{s.Uplink, s.Downlink})
		if err != nil {
			return nil, err
		}
		values[id] = value
	}
	result := make([]model.ClientTraffic, 0, len(values))
	for id, c := range values {
		result = append(result, model.ClientTraffic{ClientID: id, Uplink: c.Uplink, Downlink: c.Downlink, ActiveIPsUnavailable: true})
	}
	return result, nil
}
func trafficLedger(ctx context.Context, root, invocation, event string, updates []Session) (string, []model.ClientTraffic, error) {
	if err := privateDirectory(root, false); err != nil {
		return "", nil, err
	}
	f, err := os.OpenFile(filepath.Join(root, "traffic.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK {
			return "", nil, err
		}
		select {
		case <-ctx.Done():
			return "", nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	path := filepath.Join(root, "traffic.json")
	raw, err := readPrivate(path, 64<<20)
	l := ledger{}
	if os.IsNotExist(err) {
		b := make([]byte, 16)
		if _, err = rand.Read(b); err != nil {
			return "", nil, err
		}
		l.Epoch = hex.EncodeToString(b)
	} else if err != nil || json.Unmarshal(raw, &l) != nil {
		return "", nil, ErrTraffic
	}
	if err = l.normalize(); err != nil {
		return "", nil, err
	}
	if err = l.apply(invocation, event, updates, time.Now().Unix()); err != nil {
		return "", nil, err
	}
	counts, err := l.counts()
	if err != nil {
		return "", nil, err
	}
	raw, err = json.Marshal(l)
	if err != nil {
		return "", nil, err
	}
	if err = writePrivate(path, raw); err != nil {
		return "", nil, err
	}
	return l.Epoch, counts, nil
}
func parseStatus(raw []byte, invocation string) ([]Session, error) {
	if !invocationID.MatchString(invocation) {
		return nil, ErrTraffic
	}
	headers := map[string]int{}
	sessions := []Session{}
	complete := false
	timestamp := int64(0)
	for _, line := range strings.Split(string(raw), "\n") {
		columns := strings.Split(strings.TrimSuffix(line, "\r"), "\t")
		if len(columns) == 0 {
			continue
		}
		if columns[0] == "END" {
			complete = true
		}
		if columns[0] == "TIME" && len(columns) == 3 {
			var err error
			timestamp, err = strconv.ParseInt(columns[2], 10, 64)
			if err != nil {
				return nil, ErrTraffic
			}
		}
		if len(columns) > 2 && columns[0] == "HEADER" && columns[1] == "CLIENT_LIST" {
			for i, label := range columns[2:] {
				headers[label] = i + 1
			}
			continue
		}
		if columns[0] != "CLIENT_LIST" {
			continue
		}
		get := func(label string) (string, error) {
			i, ok := headers[label]
			if !ok || i >= len(columns) {
				return "", ErrTraffic
			}
			return columns[i], nil
		}
		name, e := get("Common Name")
		if e != nil || !clientName.MatchString(name) {
			return nil, ErrTraffic
		}
		started, e := get("Connected Since (time_t)")
		if e != nil {
			return nil, e
		}
		up, e := get("Bytes Received")
		if e != nil {
			return nil, e
		}
		down, e := get("Bytes Sent")
		if e != nil {
			return nil, e
		}
		s := Session{ClientID: strings.TrimPrefix(name, "client-"), Invocation: invocation}
		s.Started, e = strconv.ParseInt(started, 10, 64)
		if e != nil {
			return nil, e
		}
		s.Uplink, e = strconv.ParseInt(up, 10, 64)
		if e != nil {
			return nil, e
		}
		s.Downlink, e = strconv.ParseInt(down, 10, 64)
		if e != nil {
			return nil, e
		}
		sessions = append(sessions, s)
	}
	now := time.Now().Unix()
	if !complete || timestamp < now-5 || timestamp > now+5 {
		return nil, ErrTraffic
	}
	for i := range sessions {
		sessions[i].ObservedAt = timestamp
	}
	return sessions, nil
}
func RecordTrafficEnvironment(ctx context.Context, base string, env func(string) string) error {
	event := env("script_type")
	if event != "client-connect" && event != "client-disconnect" {
		return ErrTraffic
	}
	name := env("common_name")
	if !clientName.MatchString(name) {
		return ErrTraffic
	}
	s := Session{ClientID: strings.TrimPrefix(name, "client-"), Invocation: env("VPN_PLATFORM_OPENVPN_INVOCATION")}
	var err error
	s.Started, err = strconv.ParseInt(env("time_unix"), 10, 64)
	if err != nil {
		return ErrTraffic
	}
	if event == "client-disconnect" {
		s.Uplink, err = strconv.ParseInt(env("bytes_received"), 10, 64)
		if err != nil {
			return ErrTraffic
		}
		s.Downlink, err = strconv.ParseInt(env("bytes_sent"), 10, 64)
		if err != nil {
			return ErrTraffic
		}
	}
	_, _, err = trafficLedger(ctx, filepath.Join(base, "openvpn"), s.Invocation, event, []Session{s})
	return err
}
