//go:build linux

package wireguard

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"vpn-platform/internal/model"
)

type updateRuntime struct {
	fakeRuntime
	updates    int
	failUpdate bool
}

func (r *updateRuntime) Update(context.Context, model.ServiceSpec, []byte) (bool, error) {
	r.updates++
	if r.failUpdate {
		return false, ErrRuntime
	}
	return true, nil
}
func TestPeerUpdateKeepsRuntimeAndFailedUpdateFences(t *testing.T) {
	ctx := context.Background()
	r := &updateRuntime{}
	e, err := OpenEngine(ctx, testRoot(t), r)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Reconcile(ctx, desired(1)); err != nil {
		t.Fatal(err)
	}
	if err = e.Reconcile(ctx, desired(2)); err != nil || r.starts != 1 || r.updates != 1 || !r.running {
		t.Fatal("update restarted unchanged runtime", err)
	}
	r.failUpdate = true
	if e.Reconcile(ctx, desired(3)) == nil || r.running {
		t.Fatal("failed update left access open")
	}
	if e.Reconcile(ctx, desired(2)) == nil {
		t.Fatal("older generation accepted after failed peer update")
	}
}
func TestTrafficPeerTransitionPreservesSurvivorBaseline(t *testing.T) {
	l, err := OpenTrafficLedger(testRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	a := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	b := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	aid := "11111111-1111-4111-8111-111111111111"
	bid := "22222222-2222-4222-8222-222222222222"
	ep := strings.Repeat("f", 32)
	initial := map[string]PeerCounter{a: {aid, Counter{100, 200}}, b: {bid, Counter{300, 400}}}
	_, _, err = l.Sample(ep, initial)
	if err != nil {
		t.Fatal(err)
	}
	onlyB := map[string]PeerCounter{b: {bid, Counter{310, 420}}}
	if _, _, err = l.Sample(ep, onlyB); err == nil {
		t.Fatal("unplanned membership drift accepted")
	}
	_, totals, err := l.Transition(ep, onlyB)
	if err != nil || len(totals) != 2 || totals[0].Uplink != 100 || totals[1].Uplink != 310 {
		t.Fatal("removed or surviving counters lost/doubled", totals, err)
	}
	_, totals, err = l.Transition(ep, onlyB)
	if err != nil || totals[1].Downlink != 420 {
		t.Fatal("transition retry double counts", err)
	}
	restored := map[string]PeerCounter{a: {aid, Counter{5, 7}}, b: {bid, Counter{312, 423}}}
	_, totals, err = l.Transition(ep, restored)
	if err != nil || totals[0].Uplink != 105 || totals[1].Uplink != 312 {
		t.Fatal("restored peer baseline incorrect", totals, err)
	}
	restored[b] = PeerCounter{aid, Counter{320, 430}}
	if _, _, err = l.Transition(ep, restored); err == nil {
		t.Fatal("peer identity substitution accepted")
	}
	if _, _, err = l.Transition(strings.Repeat("e", 32), onlyB); err == nil {
		t.Fatal("unexpected epoch transition accepted")
	}
}
