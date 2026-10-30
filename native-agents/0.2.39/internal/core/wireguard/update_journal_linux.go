//go:build linux

package wireguard

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

// The journal lets Stop account and close a partially applied peer set after a
// crash between kernel syncconf, ledger persistence and interface receipt save.
// It never authorizes restoring an assignment; the engine generation fence does.
type updateJournal struct {
	Format        int
	Before, After interfaceReceipt
}

func (k *KernelRuntime) saveUpdateJournal(before, after interfaceReceipt) error {
	if _, err := os.Lstat(filepath.Join(k.root, "interface-update.json")); !os.IsNotExist(err) {
		return ErrRuntime
	}
	j := updateJournal{1, before, after}
	if !validJournal(j, before) {
		return ErrRuntime
	}
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return writePrivate(filepath.Join(k.root, "interface-update.json"), raw)
}
func validJournal(j updateJournal, r interfaceReceipt) bool {
	if j.Format != 1 || !validAddresses(j.Before) || !validAddresses(j.After) {
		return false
	}
	if !reflect.DeepEqual(r, j.Before) && !reflect.DeepEqual(r, j.After) {
		return false
	}
	a, b := j.Before, j.After
	if a.Format != 1 || b.Format != 1 || !a.Configured || !b.Configured || a.Epoch != b.Epoch || a.Index != b.Index || a.PublicKey != b.PublicKey || a.Port != b.Port {
		return false
	}
	for key, id := range a.Owners {
		if other, ok := b.Owners[key]; ok && other != id {
			return false
		}
	}
	return true
}
func (k *KernelRuntime) removeUpdateJournal() error {
	err := os.Remove(filepath.Join(k.root, "interface-update.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	d, err := os.Open(k.root)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func (k *KernelRuntime) finishAbsentUpdate(r interfaceReceipt) error {
	raw, err := readPrivate(filepath.Join(k.root, "interface-update.json"), 32<<20)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var j updateJournal
	if json.Unmarshal(raw, &j) != nil || !validJournal(j, r) {
		return ErrRuntime
	}
	return k.removeUpdateJournal()
}
func (k *KernelRuntime) sampleForStop(ctx context.Context, r interfaceReceipt) error {
	raw, err := readPrivate(filepath.Join(k.root, "interface-update.json"), 32<<20)
	if os.IsNotExist(err) {
		_, _, err = k.sample(ctx, r)
		return err
	}
	if err != nil {
		return err
	}
	var j updateJournal
	if json.Unmarshal(raw, &j) != nil || !validJournal(j, r) {
		return ErrRuntime
	}
	transfers, err := kernelCommand(ctx, "/usr/bin/wg", "show", InterfaceName, "transfer")
	if err != nil {
		return err
	}
	owners := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(transfers)), "\n") {
		if line == "" {
			continue
		}
		p := strings.Fields(line)
		if len(p) != 3 {
			return ErrTraffic
		}
		id, ok := j.After.Owners[p[0]]
		if !ok {
			id, ok = j.Before.Owners[p[0]]
		}
		if !ok {
			return ErrTraffic
		}
		owners[p[0]] = id
	}
	peers, err := ParseTransfers(string(transfers), owners)
	if err != nil {
		return err
	}
	_, _, err = k.ledger.Transition(r.Epoch, peers)
	return err
}
