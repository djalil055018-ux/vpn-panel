package hysteria

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"vpn-platform/internal/model"
)

var ErrConfirmedRuntime = errors.New("confirmed Hysteria runtime checkpoint unavailable or conflicting")

type confirmedRuntime struct {
	Format            int    `json:"format"`
	AppliedGeneration int64  `json:"applied_generation"`
	StructureDigest   string `json:"structure_digest"`
	CoreVersion       string `json:"core_version"`
}
type confirmedEnvelope struct {
	Record confirmedRuntime `json:"record"`
	SHA256 string           `json:"sha256"`
}
type confirmedCheckpoint struct{ path string }

func structuralDigest(state model.DesiredState) (string, error) {
	state.Services = append([]model.ServiceSpec(nil), state.Services...)
	for i := range state.Services {
		state.Services[i].Clients = nil
	}
	return desiredDigest(state)
}
func runtimeVersion(state model.DesiredState) string {
	if len(state.Services) == 0 {
		return ""
	}
	return state.Core.Version
}
func (c confirmedCheckpoint) read() (confirmedRuntime, bool, error) {
	var empty confirmedRuntime
	if !filepath.IsAbs(c.path) || protectedDirectory(filepath.Dir(c.path), false) != nil {
		return empty, false, ErrConfirmedRuntime
	}
	if _, err := os.Lstat(c.path); os.IsNotExist(err) {
		return empty, false, nil
	} else if err != nil {
		return empty, false, ErrConfirmedRuntime
	}
	raw, err := readTLSFile(c.path, 4096, 0600, -1)
	if err != nil {
		return empty, false, ErrConfirmedRuntime
	}
	var envelope confirmedEnvelope
	if decodeStrict(raw, &envelope) != nil {
		return empty, false, ErrConfirmedRuntime
	}
	record := envelope.Record
	if record.Format != 1 || record.AppliedGeneration <= 0 || !materialDigest.MatchString(record.StructureDigest) || (record.CoreVersion != "" && record.CoreVersion != PinnedVersion && record.CoreVersion != model.HysteriaLegacyVersion) {
		return empty, false, ErrConfirmedRuntime
	}
	canonical, err := json.Marshal(record)
	if err != nil {
		return empty, false, ErrConfirmedRuntime
	}
	sum := sha256.Sum256(canonical)
	if envelope.SHA256 != hex.EncodeToString(sum[:]) {
		return empty, false, ErrConfirmedRuntime
	}
	return record, true, nil
}

// The caller has verified an authoritative healthy CP result against the actual
// runtime and durable access intent. This receipt contains no credentials and
// cannot rewind a newer confirmation or silently replace damaged evidence.
func (c confirmedCheckpoint) commit(ctx context.Context, generation int64, state model.DesiredState) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	next, err := c.next(generation, state)
	if err != nil {
		return err
	}
	previous, exists, err := c.read()
	if err != nil {
		return err
	}
	if exists && previous == next {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A prior file was already synced before rename; sync its directory again
		// after an uncertain rename result without rewriting every healthy poll.
		if syncDirectory(filepath.Dir(c.path)) != nil {
			return ErrConfirmedRuntime
		}
		return nil
	}
	canonical, err := json.Marshal(next)
	if err != nil {
		return ErrConfirmedRuntime
	}
	sum := sha256.Sum256(canonical)
	raw, err := json.Marshal(confirmedEnvelope{next, hex.EncodeToString(sum[:])})
	if err != nil {
		return ErrConfirmedRuntime
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if _, err = saveAccessRecord(c.path, raw); err != nil {
		return ErrConfirmedRuntime
	}
	return nil
}
func (c confirmedCheckpoint) next(generation int64, state model.DesiredState) (confirmedRuntime, error) {
	var empty confirmedRuntime
	digest, err := structuralDigest(state)
	if err != nil || generation <= 0 {
		return empty, ErrConfirmedRuntime
	}
	next := confirmedRuntime{1, generation, digest, runtimeVersion(state)}
	previous, exists, err := c.read()
	if err != nil {
		return empty, err
	}
	if exists && (next.AppliedGeneration < previous.AppliedGeneration || (next.AppliedGeneration == previous.AppliedGeneration && next != previous)) {
		return empty, ErrConfirmedRuntime
	}
	return next, nil
}
