package xray

import (
	"os"
	"path/filepath"
	"testing"
	"vpn-platform/internal/model"
)

func TestAuthorizationRemovalDetectsEveryNativeCredential(t *testing.T) {
	for _, field := range []string{"clients", "peers"} {
		before := []byte(`{"inbounds":[{"tag":"service-one","protocol":"native","settings":{"` + field + `":[{"id":"a","password":"secret"},{"id":"b"}]}}]}`)
		added := []byte(`{"inbounds":[{"tag":"service-one","protocol":"native","settings":{"` + field + `":[{"password":"secret","id":"a"},{"id":"b"},{"id":"c"}]}}]}`)
		removed := []byte(`{"inbounds":[{"tag":"service-one","protocol":"native","settings":{"` + field + `":[{"id":"b"}]}}]}`)
		if got, err := authorizationRemoved(before, added); err != nil || got {
			t.Fatal("addition or JSON field ordering treated as revoke")
		}
		if got, err := authorizationRemoved(before, removed); err != nil || !got {
			t.Fatal("credential removal missed")
		}
		if got, err := authorizationRemoved(before, []byte(`{"inbounds":[]}`)); err != nil || !got {
			t.Fatal("listener removal missed")
		}
	}
}
func TestAccessFenceSurvivesRestartAndRejectsOlderIntent(t *testing.T) {
	d := New(t.TempDir())
	if err := os.Mkdir(d.xrayDir(), 0755); err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"inbounds":[]}`)
	os.WriteFile(d.configPath(), config, 0600)
	state := model.DesiredState{Generation: 5}
	intent, err := d.accessIntent(state)
	if err != nil {
		t.Fatal(err)
	}
	intent.ConfigSHA256 = configDigest(config)
	intent.Blocked = true
	if err = d.writeAccessFence(intent); err != nil {
		t.Fatal(err)
	}
	reopened := New(d.BaseDir)
	if reopened.CheckAccessFence() == nil {
		t.Fatal("blocked runtime allowed after restart")
	}
	state.Generation = 4
	if _, err = reopened.accessIntent(state); err == nil {
		t.Fatal("older generation accepted")
	}
	intent.Blocked = false
	d.writeAccessFence(intent)
	if err = d.CheckAccessFence(); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(d.configPath(), []byte(`{"inbounds":[{}]}`), 0600)
	if d.CheckAccessFence() == nil {
		t.Fatal("old or modified config passed startup guard")
	}
	os.WriteFile(filepath.Join(d.xrayDir(), "access-fence.json"), []byte("broken"), 0600)
	if d.CheckAccessFence() == nil {
		t.Fatal("corrupt fence passed")
	}
}
