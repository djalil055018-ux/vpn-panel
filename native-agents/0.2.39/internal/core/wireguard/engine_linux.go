//go:build linux

package wireguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

// ManagedRuntime owns only the dedicated native WireGuard interface. Stop must
// persist traffic and close access; Start must return only after kernel verification.
// It must never run wg-quick scripts or accept interface names from API data.
type ManagedRuntime interface {
	Stop(context.Context) error
	Start(context.Context, model.ServiceSpec, []byte) error
	Healthy(context.Context) error
}

// PeerUpdater preserves kernel sessions when only peer membership changes.
// It returns false without mutation when a full restart is required.
type PeerUpdater interface {
	Update(context.Context, model.ServiceSpec, []byte) (bool, error)
}
type receipt struct {
	Format     int    `json:"format"`
	Generation int64  `json:"generation"`
	Digest     string `json:"digest"`
	Active     bool   `json:"active"`
	Empty      bool   `json:"empty"`
}
type Engine struct {
	mu      sync.Mutex
	root    string
	runtime ManagedRuntime
	current receipt
}

// OpenEngine deliberately closes any inherited interface before accepting new
// assignments. A saved receipt alone is not evidence of a healthy running kernel.
func OpenEngine(ctx context.Context, root string, runtime ManagedRuntime) (*Engine, error) {
	if runtime == nil {
		return nil, ErrRuntime
	}
	if err := privateDirectory(root, false); err != nil {
		return nil, err
	}
	e := &Engine{root: root, runtime: runtime}
	old, err := e.read()
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.Join(err, e.cleanup())
	}
	if err = runtime.Stop(ctx); err != nil {
		return nil, err
	}
	old.Active = false
	e.current = old
	return e, nil
}
func (e *Engine) read() (receipt, error) {
	var r receipt
	raw, err := readPrivate(filepath.Join(e.root, "checkpoint.json"), 4096)
	if err != nil {
		return r, err
	}
	if json.Unmarshal(raw, &r) != nil || r.Format != 1 || r.Generation <= 0 {
		return r, ErrRuntime
	}
	digest, err := hex.DecodeString(r.Digest)
	if err != nil || len(digest) != sha256.Size {
		return r, ErrRuntime
	}
	return r, nil
}
func (e *Engine) save(r receipt) error {
	raw, err := json.Marshal(r)
	if err == nil {
		err = writePrivate(filepath.Join(e.root, "checkpoint.json"), raw)
	}
	if err == nil {
		e.current = r
	}
	return err
}
func compile(state model.DesiredState) (receipt, []byte, error) {
	if state.Generation <= 0 || state.Core.Type != "wireguard" || len(state.Services) > 1 {
		return receipt{}, nil, ErrRuntime
	}
	var cfg []byte
	var err error
	if len(state.Services) == 1 {
		cfg, err = compiler.CompileKernelWireGuard(state.Services[0])
		if err != nil {
			return receipt{}, nil, err
		}
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return receipt{}, nil, err
	}
	digest := sha256.Sum256(raw)
	return receipt{Format: 1, Generation: state.Generation, Digest: hex.EncodeToString(digest[:]), Empty: len(state.Services) == 0}, cfg, nil
}
func (e *Engine) Reconcile(ctx context.Context, state model.DesiredState) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	next, cfg, err := compile(state)
	if err != nil {
		return err
	}
	prior, err := e.read()
	if err != nil && (!os.IsNotExist(err) || e.current.Generation > 0) {
		return e.fail(err)
	}
	if next.Generation < prior.Generation || (next.Generation == prior.Generation && next.Digest != prior.Digest) {
		return ErrRuntime
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	canUpdate := prior == e.current && prior.Active && !prior.Empty && !next.Empty
	if canUpdate {
		if err = e.runtime.Healthy(ctx); err != nil {
			return e.fail(err)
		}
	}
	// Publish the durable high-water mark first. Even failed Start cannot permit
	// an older assignment after reopening the engine or reinstalling its binary.
	if err = e.save(next); err != nil {
		return e.fail(err)
	}
	updated := false
	if updater, ok := e.runtime.(PeerUpdater); ok && canUpdate {
		updated, err = updater.Update(ctx, state.Services[0], cfg)
		if err != nil {
			return e.fail(err)
		}
	}
	if !updated {
		if err = e.runtime.Stop(ctx); err != nil {
			return e.fail(err)
		}
	}
	if err = ctx.Err(); err != nil {
		return e.fail(err)
	}
	if !next.Empty {
		if !updated {
			if err = e.runtime.Start(ctx, state.Services[0], cfg); err != nil {
				return errors.Join(err, e.cleanup())
			}
		}
		if err = e.runtime.Healthy(ctx); err != nil {
			return errors.Join(err, e.cleanup())
		}
	}
	next.Active = true
	if err = e.save(next); err != nil {
		return errors.Join(err, e.cleanup())
	}
	return nil
}
func (e *Engine) Health(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.current.Active {
		return ErrRuntime
	}
	saved, err := e.read()
	if err != nil {
		return e.fail(err)
	}
	if saved != e.current {
		return e.fail(ErrRuntime)
	}
	if e.current.Empty {
		return nil
	}
	if err = e.runtime.Healthy(ctx); err != nil {
		return e.fail(err)
	}
	return nil
}
func (e *Engine) Close(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.current.Active = false
	return e.runtime.Stop(ctx)
}

func (e *Engine) cleanup() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return e.runtime.Stop(ctx)
}

// Call while holding mu. Verification/storage failure cannot leave previously
// allowed peers running. Cleanup uses a separate deadline even if the request
// context expired; the kernel driver closes the link before final accounting.
func (e *Engine) fail(err error) error {
	e.current.Active = false
	return errors.Join(err, e.cleanup())
}
