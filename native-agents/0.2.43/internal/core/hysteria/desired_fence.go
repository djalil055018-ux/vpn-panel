package hysteria

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"vpn-platform/internal/model"
)

var ErrDesiredFence = errors.New("Hysteria desired generation checkpoint unavailable or invalid")

type desiredFence struct{ path string }
type desiredFenceRecord struct {
	Format     int    `json:"format"`
	Generation int64  `json:"generation"`
	Digest     string `json:"digest"`
}
type desiredFenceEnvelope struct {
	Record desiredFenceRecord `json:"record"`
	SHA256 string             `json:"sha256"`
}

// The desired generation binds the entire requested structure and credential
// snapshot, not just authorization. Local TLS version paths and release channels
// are deliberately excluded: renewal must not manufacture a desired generation.
// Only digests are stored, never raw credentials or full desired-state payloads.
func desiredDigest(state model.DesiredState) (string, error) {
	state.Generation = 0
	state.Core.Channel = ""
	state.Services = append([]model.ServiceSpec(nil), state.Services...)
	for i := range state.Services {
		state.Services[i].Clients = append([]model.ClientSpec(nil), state.Services[i].Clients...)
		sort.Slice(state.Services[i].Clients, func(a, b int) bool {
			return state.Services[i].Clients[a].StatsKey < state.Services[i].Clients[b].StatsKey
		})
	}
	sort.Slice(state.Services, func(a, b int) bool { return state.Services[a].ID < state.Services[b].ID })
	raw, err := json.Marshal(state)
	if err != nil {
		return "", ErrDesiredFence
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func (f desiredFence) read(minimum int64) (desiredFenceRecord, error) {
	var empty desiredFenceRecord
	if !filepath.IsAbs(f.path) || protectedDirectory(filepath.Dir(f.path), false) != nil {
		return empty, ErrDesiredFence
	}
	if _, err := os.Lstat(f.path); os.IsNotExist(err) {
		if minimum == 0 {
			return empty, nil
		}
		return empty, ErrDesiredFence
	} else if err != nil {
		return empty, ErrDesiredFence
	}
	raw, err := readTLSFile(f.path, 4096, 0600, -1)
	if err != nil {
		return empty, ErrDesiredFence
	}
	var envelope desiredFenceEnvelope
	if decodeStrict(raw, &envelope) != nil || envelope.Record.Format != 1 || envelope.Record.Generation <= 0 || envelope.Record.Generation < minimum || !materialDigest.MatchString(envelope.Record.Digest) {
		return empty, ErrDesiredFence
	}
	canonical, err := json.Marshal(envelope.Record)
	if err != nil {
		return empty, ErrDesiredFence
	}
	sum := sha256.Sum256(canonical)
	if envelope.SHA256 != hex.EncodeToString(sum[:]) {
		return empty, ErrDesiredFence
	}
	return envelope.Record, nil
}
func (f desiredFence) check(state model.DesiredState, minimum int64) error {
	previous, err := f.read(minimum)
	if err != nil {
		return err
	}
	digest, err := desiredDigest(state)
	if err != nil {
		return err
	}
	if state.Generation <= 0 {
		return ErrDesiredFence
	}
	if state.Generation < previous.Generation || (state.Generation == previous.Generation && digest != previous.Digest) {
		return ErrAccessConflict
	}
	return nil
}

// The intent is durable before applying authorization or switching runtime.
// Rollback restores runtime material only. Retrying this generation must retain
// exactly the original desired structure; a corrected intent needs a new generation.
func (f desiredFence) commit(ctx context.Context, state model.DesiredState, minimum int64) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := f.check(state, minimum); err != nil {
		return err
	}
	digest, err := desiredDigest(state)
	if err != nil {
		return err
	}
	record := desiredFenceRecord{1, state.Generation, digest}
	canonical, err := json.Marshal(record)
	if err != nil {
		return ErrDesiredFence
	}
	sum := sha256.Sum256(canonical)
	raw, err := json.Marshal(desiredFenceEnvelope{record, hex.EncodeToString(sum[:])})
	if err != nil {
		return ErrDesiredFence
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if _, err = saveAccessRecord(f.path, raw); err != nil {
		return ErrDesiredFence
	}
	return nil
}
