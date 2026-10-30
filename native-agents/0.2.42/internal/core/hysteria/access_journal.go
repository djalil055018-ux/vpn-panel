package hysteria

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
)

var ErrAccessConflict = errors.New("Hysteria access generation conflicts with committed policy")
var ErrAccessJournal = errors.New("Hysteria access checkpoint unavailable or invalid")

const maxAccessJournal = 16 * 1024 * 1024

type accessEntry struct {
	Hash string `json:"hash"`
	ID   string `json:"id"`
}
type accessRecord struct {
	Format             int           `json:"format"`
	Generation         int64         `json:"generation"`
	Allowed            []accessEntry `json:"allowed"`
	PendingRevocations []string      `json:"pending_revocations"`
}
type accessEnvelope struct {
	Record json.RawMessage `json:"record"`
	SHA256 string          `json:"sha256"`
}
type accessJournal struct {
	path       string
	generation int64
	pending    []string
	uncertain  bool
	save       func(string, []byte) (bool, error)
}

// OpenPersistentAuthorizer restores only hashed credentials from a protected
// checkpoint. Missing state starts deny-all. Invalid state is never accepted.
func OpenPersistentAuthorizer(path string) (*Authorizer, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrAccessJournal
	}
	parent, err := os.Lstat(filepath.Dir(absolute))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0022 != 0 {
		return nil, ErrAccessJournal
	}
	a := &Authorizer{persistent: &accessJournal{path: absolute, save: saveAccessRecord}}
	info, err := os.Lstat(absolute)
	if os.IsNotExist(err) {
		return a, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxAccessJournal {
		return nil, ErrAccessJournal
	}
	raw, err := os.ReadFile(absolute)
	if err != nil {
		return nil, ErrAccessJournal
	}
	record, s, err := decodeAccessRecord(raw)
	if err != nil {
		return nil, err
	}
	a.current.Store(s)
	a.persistent.generation = record.Generation
	a.persistent.pending = append([]string(nil), record.PendingRevocations...)
	return a, nil
}
func decodeStrict(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return ErrAccessJournal
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrAccessJournal
	}
	return nil
}
func decodeAccessRecord(raw []byte) (accessRecord, *snapshot, error) {
	var envelope accessEnvelope
	var record accessRecord
	if len(raw) > maxAccessJournal || decodeStrict(raw, &envelope) != nil {
		return record, nil, ErrAccessJournal
	}
	sum := sha256.Sum256(envelope.Record)
	if hex.EncodeToString(sum[:]) != envelope.SHA256 || decodeStrict(envelope.Record, &record) != nil || record.Format != 1 || record.Generation <= 0 || len(record.Allowed) > 100000 || len(record.PendingRevocations) > 100000 {
		return record, nil, ErrAccessJournal
	}
	s := &snapshot{allowed: map[[32]byte]string{}}
	ids := map[string]bool{}
	for _, entry := range record.Allowed {
		raw, err := hex.DecodeString(entry.Hash)
		if err != nil || len(raw) != 32 || !identity.MatchString(entry.ID) || ids[entry.ID] {
			return record, nil, ErrAccessJournal
		}
		var hash [32]byte
		copy(hash[:], raw)
		if _, exists := s.allowed[hash]; exists {
			return record, nil, ErrAccessJournal
		}
		s.allowed[hash] = entry.ID
		ids[entry.ID] = true
	}
	seen := map[string]bool{}
	for _, id := range record.PendingRevocations {
		if !identity.MatchString(id) || seen[id] {
			return record, nil, ErrAccessJournal
		}
		seen[id] = true
	}
	return record, s, nil
}
func encodeAccessRecord(generation int64, s *snapshot, pending []string) ([]byte, error) {
	if generation <= 0 || len(pending) > 100000 || (s != nil && len(s.allowed) > 100000) {
		return nil, ErrAccessJournal
	}
	record := accessRecord{Format: 1, Generation: generation, Allowed: []accessEntry{}, PendingRevocations: append([]string{}, pending...)}
	if s != nil {
		for hash, id := range s.allowed {
			record.Allowed = append(record.Allowed, accessEntry{Hash: hex.EncodeToString(hash[:]), ID: id})
		}
	}
	sort.Slice(record.Allowed, func(i, j int) bool { return record.Allowed[i].ID < record.Allowed[j].ID })
	sort.Strings(record.PendingRevocations)
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, ErrAccessJournal
	}
	sum := sha256.Sum256(raw)
	envelope, err := json.Marshal(accessEnvelope{Record: raw, SHA256: hex.EncodeToString(sum[:])})
	if err != nil || len(envelope) > maxAccessJournal {
		return nil, ErrAccessJournal
	}
	return envelope, nil
}

// The bool distinguishes a failure before atomic rename from an uncertain
// directory-sync result after rename. After rename memory follows the new deny
// policy and preserves its pending kicks, while the caller still receives error.
func saveAccessRecord(path string, raw []byte) (bool, error) {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return false, ErrAccessJournal
	}
	if info, err = os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		return false, ErrAccessJournal
	} else if err != nil && !os.IsNotExist(err) {
		return false, ErrAccessJournal
	}
	file, err := os.CreateTemp(parent, ".access-")
	if err != nil {
		return false, ErrAccessJournal
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(raw); err != nil {
		file.Close()
		return false, ErrAccessJournal
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return false, ErrAccessJournal
	}
	if err = file.Close(); err != nil {
		return false, ErrAccessJournal
	}
	if err = os.Rename(name, path); err != nil {
		return false, ErrAccessJournal
	}
	directory, err := os.Open(parent)
	if err != nil {
		return true, ErrAccessJournal
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return true, ErrAccessJournal
	}
	return true, nil
}
func equalSnapshot(a, b *snapshot) bool {
	if a == nil {
		return len(b.allowed) == 0
	}
	if len(a.allowed) != len(b.allowed) {
		return false
	}
	for hash, id := range a.allowed {
		if b.allowed[hash] != id {
			return false
		}
	}
	return true
}

// Commit publishes a generation only after its atomic checkpoint rename. The
// returned IDs identify revoked sessions; the old runtime must be stopped before
// the generation is acknowledged as applied. /kick alone is insufficient.
// A retry of the same generation cannot replace its authorization policy.
func (a *Authorizer) Commit(generation int64, clients []Client) ([]string, error) {
	next, err := buildSnapshot(clients)
	if err != nil || generation <= 0 {
		return nil, ErrAccessJournal
	}
	a.write.Lock()
	defer a.write.Unlock()
	journal := a.persistent
	if journal == nil {
		return nil, ErrAccessJournal
	}
	if generation < journal.generation {
		return nil, ErrAccessConflict
	}
	old := a.current.Load()
	if generation == journal.generation {
		if !equalSnapshot(old, next) {
			return nil, ErrAccessConflict
		}
		if journal.uncertain {
			raw, err := encodeAccessRecord(generation, next, journal.pending)
			if err != nil {
				return nil, err
			}
			renamed, err := journal.save(journal.path, raw)
			if !renamed || err != nil {
				return append([]string(nil), journal.pending...), ErrAccessJournal
			}
			journal.uncertain = false
		}
		return append([]string(nil), journal.pending...), nil
	}
	pending := map[string]bool{}
	for _, id := range journal.pending {
		pending[id] = true
	}
	if old != nil {
		for hash, id := range old.allowed {
			if next.allowed[hash] != id {
				pending[id] = true
			}
		}
	}
	ids := make([]string, 0, len(pending))
	for id := range pending {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	raw, err := encodeAccessRecord(generation, next, ids)
	if err != nil {
		return nil, err
	}
	renamed, err := journal.save(journal.path, raw)
	if renamed {
		a.current.Store(next)
		journal.generation = generation
		journal.pending = ids
		journal.uncertain = err != nil
	}
	if !renamed || err != nil {
		return append([]string(nil), journal.pending...), ErrAccessJournal
	}
	return append([]string(nil), ids...), nil
}
func (a *Authorizer) PendingRevocations() (int64, []string) {
	a.write.Lock()
	defer a.write.Unlock()
	if a.persistent == nil {
		return 0, nil
	}
	return a.persistent.generation, append([]string(nil), a.persistent.pending...)
}

// AcknowledgeStoppedRuntime is called only after the old runtime is fully stopped.
// A successful /kick response does not prove all connections were revoked.
// Generation matching prevents an old in-flight response clearing a newer list.
func (a *Authorizer) AcknowledgeStoppedRuntime(generation int64) error {
	a.write.Lock()
	defer a.write.Unlock()
	j := a.persistent
	if j == nil || generation <= 0 || j.generation != generation {
		return ErrAccessJournal
	}
	raw, err := encodeAccessRecord(generation, a.current.Load(), nil)
	if err != nil {
		return err
	}
	renamed, err := j.save(j.path, raw)
	if renamed {
		j.pending = nil
		j.uncertain = err != nil
	}
	if !renamed || err != nil {
		return ErrAccessJournal
	}
	return nil
}
