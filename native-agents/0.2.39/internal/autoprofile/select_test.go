package autoprofile

import (
	"fmt"
	"testing"
)

func TestSelectDistributesByNodeAndSurvivesPoolChanges(t *testing.T) {
	pool := []Endpoint{{NodeID: "node-a", ServiceID: "a-1", Healthy: true}, {NodeID: "node-b", ServiceID: "b-1", Healthy: true}, {NodeID: "node-c", ServiceID: "c-1", Healthy: true}}
	counts := map[string]int{}
	for i := 0; i < 12000; i++ {
		key := fmt.Sprintf("synthetic-client-%d", i)
		first, ok := Select(key, pool)
		if !ok {
			t.Fatal("expected an eligible server")
		}
		counts[first.NodeID]++
		reordered, _ := Select(key, []Endpoint{pool[2], pool[0], pool[1]})
		if reordered != first {
			t.Fatal("input order changed the assignment")
		}
		extra := append(append([]Endpoint{}, pool...), Endpoint{NodeID: "node-a", ServiceID: "a-2", Healthy: true, Preference: 1})
		withProtocol, _ := Select(key, extra)
		if withProtocol != first {
			t.Fatal("extra protocol changed the node weight")
		}
		withoutC, _ := Select(key, pool[:2])
		if first.NodeID != "node-c" && withoutC != first {
			t.Fatal("unaffected client moved after another server disappeared")
		}
	}
	for node, count := range counts {
		if count < 3600 || count > 4400 {
			t.Fatalf("imbalanced assignment for %s: %d", node, count)
		}
	}
}

func TestSelectRejectsUnavailablePoolAndUsesSupportedPreference(t *testing.T) {
	pool := []Endpoint{{NodeID: "down", ServiceID: "down-1", Healthy: false}, {NodeID: "up", ServiceID: "tls", Healthy: true, Preference: 0}, {NodeID: "up", ServiceID: "other", Healthy: true, Preference: 10}}
	selected, ok := Select("synthetic-client", pool)
	if !ok || selected.ServiceID != "tls" {
		t.Fatal("must select the healthy preferred transport")
	}
	for _, input := range [][]Endpoint{nil, pool[:1], {{NodeID: "", ServiceID: "missing-node", Healthy: true}}} {
		if _, ok := Select("synthetic-client", input); ok {
			t.Fatal("must not invent an endpoint")
		}
	}
	if _, ok := Select("", pool); ok {
		t.Fatal("empty identity is not eligible")
	}
}
