package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"
	"vpn-platform/internal/model"
)

var ErrTrafficOutboxFull = errors.New("traffic outbox capacity reached")
var ErrTrafficOutboxCorrupt = errors.New("traffic outbox requires repair")
var outboxFilePattern = regexp.MustCompile(`^[0-9]{16}\.json$`)
var outboxUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var outboxEpochPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

const maxTrafficRecordBytes = 2 << 20

type TrafficOutbox struct {
	directory  string
	nodeID     string
	maxRecords int
	maxBytes   int64
}
type TrafficOutboxStatus struct {
	Pending int
	Bytes   int64
	Oldest  time.Time
}
type trafficEnvelope struct {
	Data   json.RawMessage `json:"data"`
	SHA256 string          `json:"sha256"`
}

func NewTrafficOutbox(directory, nodeID string) (*TrafficOutbox, error) {
	if !outboxUUIDPattern.MatchString(nodeID) {
		return nil, ErrTrafficOutboxCorrupt
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrTrafficOutboxCorrupt
	}
	if err = os.Chmod(directory, 0700); err != nil {
		return nil, err
	}
	out := &TrafficOutbox{directory: directory, nodeID: nodeID, maxRecords: 4096, maxBytes: 128 << 20}
	unlock, err := lockTrafficOutbox(directory)
	if err != nil {
		return nil, err
	}
	defer unlock()
	ownerPath := filepath.Join(directory, "owner")
	raw, err := readTrafficFile(ownerPath, 128)
	if os.IsNotExist(err) {
		entries, _, readErr := out.entries()
		if readErr != nil {
			return nil, readErr
		}
		if len(entries) > 0 {
			return nil, ErrTrafficOutboxCorrupt
		}
		err = atomicTrafficFile(ownerPath, []byte(nodeID+"\n"))
	} else if err == nil && string(raw) != nodeID+"\n" {
		err = ErrTrafficOutboxCorrupt
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func readTrafficFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, ErrTrafficOutboxCorrupt
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if int64(len(raw)) > limit {
		return nil, ErrTrafficOutboxCorrupt
	}
	return raw, err
}

func atomicTrafficFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".traffic-write-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return err
	}
	return syncTrafficDirectory(filepath.Dir(path))
}

func syncTrafficDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// Caller holds the directory lock. Unknown files are preserved and treated as
// corruption; pending samples are never evicted to make room for newer samples.
func (o *TrafficOutbox) entries() ([]string, int64, error) {
	values, err := os.ReadDir(o.directory)
	if err != nil {
		return nil, 0, err
	}
	names := []string{}
	var size int64
	for _, value := range values {
		name := value.Name()
		if name == "owner" || name == "lock" {
			continue
		}
		if len(name) > 15 && name[:15] == ".traffic-write-" {
			info, err := value.Info()
			if err != nil {
				return nil, 0, err
			}
			if !info.Mode().IsRegular() {
				return nil, 0, ErrTrafficOutboxCorrupt
			}
			if err = os.Remove(filepath.Join(o.directory, name)); err != nil {
				return nil, 0, err
			}
			continue
		}
		if !outboxFilePattern.MatchString(name) {
			return nil, 0, ErrTrafficOutboxCorrupt
		}
		info, err := value.Info()
		if err != nil {
			return nil, 0, err
		}
		if !info.Mode().IsRegular() || info.Size() > maxTrafficRecordBytes {
			return nil, 0, ErrTrafficOutboxCorrupt
		}
		names = append(names, name)
		size += info.Size()
	}
	sort.Strings(names)
	return names, size, nil
}

func validOutboxDelivery(value model.TrafficDelivery) bool {
	snapshot := value.Snapshot
	if value.RecordedAt.IsZero() || value.RecordedAt.Year() < 2000 || !outboxEpochPattern.MatchString(snapshot.Epoch) || snapshot.Epoch == "00000000000000000000000000000000" || snapshot.Sequence <= 0 || snapshot.Sequence > 9000000000000000 || len(snapshot.Clients) > 10000 {
		return false
	}
	seen := map[string]bool{}
	for _, client := range snapshot.Clients {
		if !outboxUUIDPattern.MatchString(client.ClientID) || seen[client.ClientID] || client.Uplink < 0 || client.Downlink < 0 || client.Uplink > 9000000000000000 || client.Downlink > 9000000000000000 || client.ActiveIPs < 0 || client.ActiveIPs > 10000 || (client.ActiveIPsUnavailable && client.ActiveIPs != 0) {
			return false
		}
		seen[client.ClientID] = true
	}
	return true
}

func (o *TrafficOutbox) Put(value model.TrafficDelivery) error {
	if !validOutboxDelivery(value) {
		return ErrTrafficOutboxCorrupt
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(trafficEnvelope{Data: data, SHA256: fmt.Sprintf("%x", sha256.Sum256(data))})
	if err != nil {
		return err
	}
	if len(raw) > maxTrafficRecordBytes {
		return ErrTrafficOutboxCorrupt
	}
	unlock, err := lockTrafficOutbox(o.directory)
	if err != nil {
		return err
	}
	defer unlock()
	path := filepath.Join(o.directory, fmt.Sprintf("%016d.json", value.Snapshot.Sequence))
	previous, err := readTrafficFile(path, maxTrafficRecordBytes)
	if err == nil {
		if !bytes.Equal(previous, raw) {
			return ErrTrafficOutboxCorrupt
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	names, size, err := o.entries()
	if err != nil {
		return err
	}
	if len(names) >= o.maxRecords || size+int64(len(raw)) > o.maxBytes {
		return ErrTrafficOutboxFull
	}
	return atomicTrafficFile(path, raw)
}

func (o *TrafficOutbox) readEntry(name string) (model.TrafficDelivery, error) {
	var value model.TrafficDelivery
	raw, err := readTrafficFile(filepath.Join(o.directory, name), maxTrafficRecordBytes)
	if err != nil {
		return value, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var envelope trafficEnvelope
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF || envelope.SHA256 != fmt.Sprintf("%x", sha256.Sum256(envelope.Data)) {
		return value, ErrTrafficOutboxCorrupt
	}
	decoder = json.NewDecoder(bytes.NewReader(envelope.Data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF || !validOutboxDelivery(value) || fmt.Sprintf("%016d.json", value.Snapshot.Sequence) != name {
		return value, ErrTrafficOutboxCorrupt
	}
	return value, nil
}

func (o *TrafficOutbox) Peek() (*model.TrafficDelivery, error) {
	unlock, err := lockTrafficOutbox(o.directory)
	if err != nil {
		return nil, err
	}
	defer unlock()
	names, _, err := o.entries()
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, nil
	}
	value, err := o.readEntry(names[0])
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func (o *TrafficOutbox) Acknowledge(sequence int64) error {
	if sequence <= 0 {
		return ErrTrafficOutboxCorrupt
	}
	unlock, err := lockTrafficOutbox(o.directory)
	if err != nil {
		return err
	}
	defer unlock()
	names, _, err := o.entries()
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return nil
	}
	oldest, err := strconv.ParseInt(names[0][:16], 10, 64)
	if err != nil {
		return ErrTrafficOutboxCorrupt
	}
	if sequence < oldest {
		return nil
	}
	if sequence != oldest {
		return errors.New("out-of-order traffic acknowledgement")
	}
	if err = os.Remove(filepath.Join(o.directory, names[0])); err != nil {
		return err
	}
	return syncTrafficDirectory(o.directory)
}

func (o *TrafficOutbox) Status() (TrafficOutboxStatus, error) {
	var status TrafficOutboxStatus
	unlock, err := lockTrafficOutbox(o.directory)
	if err != nil {
		return status, err
	}
	defer unlock()
	names, size, err := o.entries()
	if err != nil {
		return status, err
	}
	status.Pending = len(names)
	status.Bytes = size
	if len(names) > 0 {
		value, err := o.readEntry(names[0])
		if err != nil {
			return status, err
		}
		status.Oldest = value.RecordedAt
	}
	return status, nil
}
