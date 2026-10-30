//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestTrafficSequencePersistsAndSerializes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "sequence")
	var wg sync.WaitGroup
	results := make(chan int64, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := reserveTrafficSequence(path)
			if err != nil {
				t.Error(err)
				return
			}
			results <- n
		}()
	}
	wg.Wait()
	close(results)
	seen := map[int64]bool{}
	for n := range results {
		if seen[n] {
			t.Fatal("duplicate persisted sequence")
		}
		seen[n] = true
	}
	if len(seen) != 20 {
		t.Fatal("sequence allocation missing")
	}
	n, err := reserveTrafficSequence(path)
	if err != nil || n != 21 {
		t.Fatalf("checkpoint did not persist: %d %v", n, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatal("checkpoint readable by other users")
	}
	if err = os.WriteFile(path, []byte("corrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = reserveTrafficSequence(path); err == nil {
		t.Fatal("corrupt checkpoint reset sequence")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "corrupted" {
		t.Fatal("corrupt checkpoint overwritten")
	}
}
