package compiler

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestCascadeDialPreservesAuthRoutingAndOriginalGraph(t *testing.T) {
	s := cascadeFixture()
	s.Core.Version = "26.10.21"
	original, err := CompileXray(s)
	if err != nil {
		t.Fatal(err)
	}
	s.XrayCascades.Entries[0].Exit.ConnectRaceIP = "192.0.2.10"
	s.XrayCascades.Entries[0].Exit.ConnectRaceAttempts = 16
	before, _ := json.Marshal(s)
	raw, err := CompileXray(s)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(s)
	if !bytes.Equal(before, after) {
		t.Fatal("mutated assignment")
	}
	old, doc := cascadeDocument(t, original), cascadeDocument(t, raw)
	for _, key := range []string{"inbounds", "routing", "policy", "stats", "api"} {
		if !reflect.DeepEqual(old[key], doc[key]) {
			t.Fatal("changed authorization, API guard, accounting or route")
		}
	}
	obs := doc["outbounds"].([]any)
	oldObs := old["outbounds"].([]any)
	if !reflect.DeepEqual(obs[:2], oldObs[:2]) {
		t.Fatal("ordinary outbounds changed")
	}
	out := obs[2].(map[string]any)
	previous := oldObs[2].(map[string]any)
	stream := out["streamSettings"].(map[string]any)
	if !reflect.DeepEqual(stream["realitySettings"], previous["streamSettings"].(map[string]any)["realitySettings"]) {
		t.Fatal("REALITY identity changed")
	}
	server := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	previousServer := previous["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	if !reflect.DeepEqual(server["users"], previousServer["users"]) || server["port"] != previousServer["port"] {
		t.Fatal("credentials or destination port changed")
	}
	alias := server["address"].(string)
	hosts := doc["dns"].(map[string]any)["hosts"].(map[string]any)
	ips := hosts["full:"+alias].([]any)
	if len(ips) != 16 {
		t.Fatal("race count mismatch")
	}
	for _, ip := range ips {
		if ip != "192.0.2.10" {
			t.Fatal("unexpected race destination")
		}
	}
	sock := stream["sockopt"].(map[string]any)
	if sock["domainStrategy"] != "ForceIPv4" || sock["happyEyeballs"].(map[string]any)["maxConcurrentTry"] != float64(16) {
		t.Fatal("race is not bounded")
	}
}

func TestCascadeDialRejectsOldCoreBadPolicyAndReservedHostCollision(t *testing.T) {
	for _, attempts := range []int{-1, 1, 17} {
		s := cascadeFixture()
		s.Core.Version = "26.10.21"
		s.XrayCascades.Entries[0].Exit.ConnectRaceIP = "192.0.2.10"
		s.XrayCascades.Entries[0].Exit.ConnectRaceAttempts = attempts
		if _, err := CompileXray(s); err == nil {
			t.Fatal("unbounded policy accepted")
		}
	}
	s := cascadeFixture()
	s.XrayCascades.Entries[0].Exit.ConnectRaceIP = "192.0.2.10"
	s.XrayCascades.Entries[0].Exit.ConnectRaceAttempts = 4
	s.Core.Version = "26.10.20"
	if _, err := CompileXray(s); err == nil {
		t.Fatal("old core accepted")
	}
	s.Core.Version = "26.10.21"
	base, err := compileXrayBase(s)
	if err != nil {
		t.Fatal(err)
	}
	cfg := cascadeDocument(t, base)
	cfg["dns"] = map[string]any{"hosts": map[string]any{"full:pauk-cascade-dial-" + cascadeID + ".invalid": "203.0.113.8"}}
	base, _ = json.Marshal(cfg)
	if _, err := compileXrayCascades(base, s); err == nil {
		t.Fatal("reserved host collision accepted")
	}
}
