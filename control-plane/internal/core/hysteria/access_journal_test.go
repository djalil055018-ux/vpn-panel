package hysteria

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func persistentFixture(t *testing.T) (*Authorizer, string) {
	t.Helper()
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private directory failed")
	}
	path := filepath.Join(dir, "access.json")
	a, e := OpenPersistentAuthorizer(path)
	if e != nil {
		t.Fatal("empty checkpoint failed")
	}
	return a, path
}
func TestAccessCheckpointRestartAndPendingRevocation(t *testing.T) {
	a, path := persistentFixture(t)
	one, two := strings.Repeat("a", 32), strings.Repeat("b", 32)
	if _, e := a.Replace([]Client{{"id-a", one}}); e == nil {
		t.Fatal("persistent policy bypassed checkpoint")
	}
	if _, e := a.Commit(1, []Client{{"id-a", one}, {"id-b", two}}); e != nil {
		t.Fatal("initial checkpoint failed")
	}
	raw, e := os.ReadFile(path)
	if e != nil || bytes.Contains(raw, []byte(one)) || bytes.Contains(raw, []byte(two)) {
		t.Fatal("checkpoint exposes plaintext credential")
	}
	removed, e := a.Commit(2, []Client{{"id-b", two}})
	if e != nil || !reflect.DeepEqual(removed, []string{"id-a"}) {
		t.Fatal("revocation checkpoint failed")
	}
	restored, e := OpenPersistentAuthorizer(path)
	if e != nil {
		t.Fatal("checkpoint restore failed")
	}
	if _, ok := restored.allowed(one); ok {
		t.Fatal("removed client returned after agent restart")
	}
	if id, ok := restored.allowed(two); !ok || id != "id-b" {
		t.Fatal("retained client lost after restart")
	}
	generation, pending := restored.PendingRevocations()
	if generation != 2 || !reflect.DeepEqual(pending, []string{"id-a"}) {
		t.Fatal("unfinished runtime kicks lost on restart")
	}
	if e = restored.AcknowledgeStoppedRuntime(1); e == nil {
		t.Fatal("stale kick acknowledgement accepted")
	}
	if e = restored.AcknowledgeStoppedRuntime(2); e != nil {
		t.Fatal("kick acknowledgement failed")
	}
	final, e := OpenPersistentAuthorizer(path)
	if e != nil {
		t.Fatal("final restore failed")
	}
	_, pending = final.PendingRevocations()
	if len(pending) != 0 {
		t.Fatal("acknowledged kicks returned")
	}
	if _, e = final.Commit(1, nil); e == nil {
		t.Fatal("older generation accepted")
	}
	if _, e = final.Commit(2, nil); e == nil {
		t.Fatal("same generation policy replaced")
	}
	if _, e = final.Commit(2, []Client{{"id-b", two}}); e != nil {
		t.Fatal("idempotent generation replay rejected")
	}
}
func TestAccessCheckpointFailureBoundaries(t *testing.T) {
	a, path := persistentFixture(t)
	one, two := strings.Repeat("a", 32), strings.Repeat("b", 32)
	_, e := a.Commit(1, []Client{{"id-a", one}})
	if e != nil {
		t.Fatal("setup failed")
	}
	before, _ := os.ReadFile(path)
	a.persistent.save = func(string, []byte) (bool, error) { return false, errors.New("test disk failure") }
	if _, e = a.Commit(2, []Client{{"id-b", two}}); e != ErrAccessJournal {
		t.Fatal("write failure accepted")
	}
	if _, ok := a.allowed(one); !ok {
		t.Fatal("failure before rename changed live policy")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed staging changed durable policy")
	}
	a.persistent.save = func(p string, raw []byte) (bool, error) {
		renamed, err := saveAccessRecord(p, raw)
		if err != nil {
			t.Fatal("fixture rename failed")
		}
		return renamed, errors.New("test directory sync failure")
	}
	removed, e := a.Commit(2, []Client{{"id-b", two}})
	if e != ErrAccessJournal || !reflect.DeepEqual(removed, []string{"id-a"}) {
		t.Fatal("post-rename uncertainty or kick list lost")
	}
	if _, ok := a.allowed(one); ok {
		t.Fatal("post-rename policy re-authorized removed client")
	}
	if _, e = a.Commit(2, []Client{{"id-b", two}}); e != ErrAccessJournal {
		t.Fatal("uncertain replay skipped durable sync")
	}
	a.persistent.save = saveAccessRecord
	if _, e = a.Commit(2, []Client{{"id-b", two}}); e != nil || a.persistent.uncertain {
		t.Fatal("durable retry did not resolve uncertainty")
	}
}
func TestAccessCheckpointRejectsCorruptionAndPermissions(t *testing.T) {
	a, path := persistentFixture(t)
	_, e := a.Commit(1, []Client{{"id-a", strings.Repeat("a", 32)}})
	if e != nil {
		t.Fatal("setup failed")
	}
	raw, _ := os.ReadFile(path)
	if os.Chmod(path, 0644) != nil {
		t.Fatal("permission fixture failed")
	}
	if _, e = OpenPersistentAuthorizer(path); e != ErrAccessJournal {
		t.Fatal("public-readable checkpoint accepted")
	}
	_ = os.Chmod(path, 0600)
	changed := bytes.Replace(raw, []byte("id-a"), []byte("id-b"), 1)
	_ = os.WriteFile(path, changed, 0600)
	if _, e = OpenPersistentAuthorizer(path); e != ErrAccessJournal {
		t.Fatal("corrupted checkpoint accepted")
	}
	_ = os.Remove(path)
	if os.Symlink("missing", path) == nil {
		if _, e = OpenPersistentAuthorizer(path); e != ErrAccessJournal {
			t.Fatal("checkpoint symlink accepted")
		}
	}
}
func TestAccessCheckpointRejectsWritableParentEvenWhenMissing(t *testing.T) {
	a, path := persistentFixture(t)
	if _, err := a.Commit(1, []Client{{"id-a", strings.Repeat("a", 32)}}); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(path)
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(parent, 0700)
	if _, err := OpenPersistentAuthorizer(path); err != ErrAccessJournal {
		t.Fatal("writable parent accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPersistentAuthorizer(path); err != ErrAccessJournal {
		t.Fatal("missing checkpoint under writable parent accepted")
	}
}
func TestAccessCheckpointWriterRejectsUnreadableRecordSize(t *testing.T) {
	if _, err := encodeAccessRecord(1, nil, make([]string, 100001)); err != ErrAccessJournal {
		t.Fatal("oversized pending list accepted")
	}
	if _, err := encodeAccessRecord(0, nil, nil); err != ErrAccessJournal {
		t.Fatal("invalid generation accepted")
	}
}
