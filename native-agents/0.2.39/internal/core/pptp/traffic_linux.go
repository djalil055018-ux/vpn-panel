//go:build linux

package pptp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"vpn-platform/internal/model"
)

var ErrTraffic = errors.New("PPTP traffic ledger requires repair")
var clientIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var invocationPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var sessionPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)
var interfacePattern = regexp.MustCompile(`^vppptp[0-9]{1,8}$`)

const maxCounter = int64(9000000000000000)

type counters struct {
	Uplink   int64
	Downlink int64
}
type Session struct {
	ID       string
	ClientID string
	Uplink   int64
	Downlink int64
}
type ledger struct {
	Format     int
	Epoch      string
	Invocation string
	Totals     map[string]counters
	Active     map[string]Session
}

func add(a, b counters) (counters, error) {
	if a.Uplink < 0 || a.Downlink < 0 || b.Uplink < 0 || b.Downlink < 0 || a.Uplink > maxCounter-b.Uplink || a.Downlink > maxCounter-b.Downlink {
		return counters{}, ErrTraffic
	}
	return counters{a.Uplink + b.Uplink, a.Downlink + b.Downlink}, nil
}
func validSession(s Session) bool {
	return sessionPattern.MatchString(s.ID) && clientIDPattern.MatchString(s.ClientID) && s.Uplink >= 0 && s.Downlink >= 0 && s.Uplink <= maxCounter && s.Downlink <= maxCounter
}
func (l *ledger) validate() error {
	if l.Format != 1 || !invocationPattern.MatchString(l.Epoch) || (l.Invocation != "" && !invocationPattern.MatchString(l.Invocation)) || l.Active == nil || l.Totals == nil || len(l.Active) > 252 || len(l.Totals) > 100000 {
		return ErrTraffic
	}
	for id, c := range l.Totals {
		if !clientIDPattern.MatchString(id) {
			return ErrTraffic
		}
		if _, e := add(c, counters{}); e != nil {
			return e
		}
	}
	for id, s := range l.Active {
		if id != s.ID || !validSession(s) {
			return ErrTraffic
		}
	}
	return nil
}
func (l *ledger) finish(id string) error {
	s, ok := l.Active[id]
	if !ok {
		return nil
	}
	c, e := add(l.Totals[s.ClientID], counters{s.Uplink, s.Downlink})
	if e != nil {
		return e
	}
	l.Totals[s.ClientID] = c
	delete(l.Active, id)
	return nil
}
func (l *ledger) apply(invocation, event string, updates []Session) error {
	if event == "initialize" || event == "read" {
		return nil
	}
	if !invocationPattern.MatchString(invocation) {
		return ErrTraffic
	}
	if event == "begin" {
		if l.Invocation == invocation {
			return nil
		}
		for id := range l.Active {
			if e := l.finish(id); e != nil {
				return e
			}
		}
		l.Invocation = invocation
		return nil
	}
	if l.Invocation != invocation {
		return ErrTraffic
	}
	if event != "start" && event != "finish" && event != "sample" {
		return ErrTraffic
	}
	for _, s := range updates {
		if !validSession(s) {
			return ErrTraffic
		}
		active, exists := l.Active[s.ID]
		if event == "start" {
			if exists {
				if active.ClientID != s.ClientID {
					return ErrTraffic
				}
				continue
			}
			if len(l.Active) >= 252 {
				return ErrTraffic
			}
			for _, a := range l.Active {
				if a.ClientID == s.ClientID {
					return ErrTraffic
				}
			}
			s.Uplink = 0
			s.Downlink = 0
			l.Active[s.ID] = s
			continue
		}
		if !exists {
			continue
		} // Completed hooks and samples are idempotent; never resurrect a finished session.
		if active.ClientID != s.ClientID {
			return ErrTraffic
		}
		if s.Uplink > active.Uplink {
			active.Uplink = s.Uplink
		}
		if s.Downlink > active.Downlink {
			active.Downlink = s.Downlink
		}
		l.Active[s.ID] = active
		if event == "finish" {
			if e := l.finish(s.ID); e != nil {
				return e
			}
		}
	}
	return nil
}
func (l *ledger) counts() ([]model.ClientTraffic, error) {
	totals := map[string]counters{}
	for id, c := range l.Totals {
		totals[id] = c
	}
	for _, s := range l.Active {
		c, e := add(totals[s.ClientID], counters{s.Uplink, s.Downlink})
		if e != nil {
			return nil, e
		}
		totals[s.ClientID] = c
	}
	result := make([]model.ClientTraffic, 0, len(totals))
	for id, c := range totals {
		result = append(result, model.ClientTraffic{ClientID: id, Uplink: c.Uplink, Downlink: c.Downlink, ActiveIPsUnavailable: true})
	}
	return result, nil
}
func trafficLedger(ctx context.Context, root, invocation, event string, updates []Session) (string, []model.ClientTraffic, error) {
	if e := privateDirectory(root, false); e != nil {
		return "", nil, e
	}
	f, e := os.OpenFile(filepath.Join(root, "traffic.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return "", nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return "", nil, ErrTraffic
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return "", nil, ErrTraffic
	}
	for {
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			break
		}
		if e != syscall.EWOULDBLOCK {
			return "", nil, e
		}
		select {
		case <-ctx.Done():
			return "", nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	path := filepath.Join(root, "traffic.json")
	raw, e := readPrivate(path, 32<<20)
	l := ledger{}
	if os.IsNotExist(e) && event == "initialize" {
		b := make([]byte, 16)
		if _, e = rand.Read(b); e != nil {
			return "", nil, e
		}
		l = ledger{Format: 1, Epoch: hex.EncodeToString(b), Totals: map[string]counters{}, Active: map[string]Session{}}
	} else if e != nil || json.Unmarshal(raw, &l) != nil {
		return "", nil, ErrTraffic
	}
	if e = l.validate(); e != nil {
		return "", nil, e
	}
	if e = l.apply(invocation, event, updates); e != nil {
		return "", nil, e
	}
	clients, e := l.counts()
	if e != nil {
		return "", nil, e
	}
	if event == "read" {
		return l.Epoch, clients, nil
	}
	raw, e = json.Marshal(l)
	if e != nil {
		return "", nil, e
	}
	if e = writePrivate(path, raw); e != nil {
		return "", nil, e
	}
	return l.Epoch, clients, nil
}

func control(ctx context.Context, root, command string) ([]byte, error) {
	secret, e := readPrivate(filepath.Join(root, "cli-password"), 128)
	if e != nil || !regexp.MustCompile(`^[a-f0-9]{64}$`).Match(secret) {
		return nil, ErrRuntime
	}
	conn, e := (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:2002")
	if e != nil {
		return nil, e
	}
	defer conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	if e = conn.SetDeadline(deadline); e != nil {
		return nil, e
	}
	if _, e = io.WriteString(conn, string(secret)+"\n"+command+"\nexit\n"); e != nil {
		return nil, e
	}
	raw, e := io.ReadAll(io.LimitReader(conn, 1<<20))
	if e != nil || len(raw) >= 1<<20 {
		return nil, ErrTraffic
	}
	return raw, nil
}
func parseSessions(raw []byte) ([]Session, error) {
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 2 || len(lines) > 254 {
		return nil, ErrTraffic
	}
	header := strings.Split(lines[0], "|")
	want := []string{"sid", "username", "rx-bytes-raw", "tx-bytes-raw", "state", "ifname"}
	if len(header) != len(want) {
		return nil, ErrTraffic
	}
	for i, v := range header {
		if strings.TrimSpace(v) != want[i] {
			return nil, ErrTraffic
		}
	}
	if strings.Trim(lines[1], "-+ \r") != "" {
		return nil, ErrTraffic
	}
	result := []Session{}
	seen := map[string]bool{}
	for _, line := range lines[2:] {
		fields := strings.Split(line, "|")
		if len(fields) != 6 {
			return nil, ErrTraffic
		}
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		if fields[4] != "active" {
			continue
		}
		s := Session{ID: fields[0], ClientID: fields[1]}
		var e error
		s.Uplink, e = strconv.ParseInt(fields[2], 10, 64)
		if e != nil {
			return nil, ErrTraffic
		}
		s.Downlink, e = strconv.ParseInt(fields[3], 10, 64)
		if e != nil || !validSession(s) || !interfacePattern.MatchString(fields[5]) || seen[s.ID] {
			return nil, ErrTraffic
		}
		seen[s.ID] = true
		result = append(result, s)
	}
	return result, nil
}

func RecordTrafficEnvironment(ctx context.Context, root, revision, event string, env func(string) string) error {
	if event != "start" && event != "finish" {
		return ErrTraffic
	}
	if !digestPattern.MatchString(revision) {
		return ErrTraffic
	}
	dir := filepath.Join(root, "revisions", revision)
	if e := privateDirectory(dir, false); e != nil {
		return e
	}
	invocation, e := readPrivate(filepath.Join(dir, "invocation"), 64)
	if e != nil {
		return e
	}
	s := Session{ID: env("VPN_SESSION_ID"), ClientID: env("PEERNAME")}
	if event == "finish" {
		s.Uplink, e = strconv.ParseInt(env("BYTES_RCVD"), 10, 64)
		if e != nil {
			return ErrTraffic
		}
		s.Downlink, e = strconv.ParseInt(env("BYTES_SENT"), 10, 64)
		if e != nil {
			return ErrTraffic
		}
	}
	_, _, e = trafficLedger(ctx, root, string(invocation), event, []Session{s})
	return e
}
