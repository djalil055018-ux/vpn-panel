package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"vpn-platform/internal/nodeadoption"
)

func TestCLIInspectAndGenericFailureOutput(t *testing.T) {
	root := t.TempDir()
	host, _ := os.Hostname()
	private := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{51}, 32))
	cfg := []byte(`{"inbounds":[{"tag":"source","listen":"0.0.0.0","port":443,"protocol":"vless","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"raw","security":"reality","realitySettings":{"dest":"example.org:443","serverNames":["example.org"],"shortIds":[""],"privateKey":"` + private + `"}}}],"outbounds":[{"tag":"DIRECT","protocol":"freedom"}],"routing":{"rules":[]}}`)
	sum := sha256.Sum256(cfg)
	id := "11111111-1111-4111-8111-111111111111"
	p := nodeadoption.InspectionPlan{Version: 1, TenantID: id, ImportID: id, NodeID: id, SourceNodeID: id, ReviewedSHA256: hex.EncodeToString(sum[:]), SourceConfigSHA256: hex.EncodeToString(sum[:]), ExpectedHostname: host}
	raw, _ := json.Marshal(p)
	if os.WriteFile(root+"/plan", raw, 0600) != nil || os.WriteFile(root+"/config", cfg, 0600) != nil {
		t.Fatal("fixture")
	}
	args := []string{"inspect", "--plan", root + "/plan", "--config", root + "/config", "--out", root + "/output"}
	var stdout, stderr bytes.Buffer
	if execute(args, &stdout, &stderr, 0) != 0 {
		t.Fatal("valid CLI inspection rejected")
	}
	var result nodeadoption.Summary
	if json.Unmarshal(stdout.Bytes(), &result) != nil || result.CutoverReady || result.Kind != "node-material-inspection" {
		t.Fatal("CLI summary")
	}
	if bytes.Contains(stdout.Bytes(), []byte(private)) || bytes.Contains(stdout.Bytes(), []byte(id)) || stderr.Len() != 0 {
		t.Fatal("private stdout")
	}
	for _, test := range []struct {
		args []string
		uid  int
	}{{args, 1000}, {[]string{"stage", "--plan", root + "/plan", "--config", root + "/config", "--out", root + "/stage"}, 0}, {[]string{"activate", private}, 0}, {append(args, "--unknown="+private), 0}} {
		stdout.Reset()
		stderr.Reset()
		if execute(test.args, &stdout, &stderr, test.uid) == 0 || stdout.Len() != 0 || bytes.Contains(stderr.Bytes(), []byte(private)) || bytes.Contains(stderr.Bytes(), []byte(root)) {
			t.Fatal("CLI failure leaked input or succeeded")
		}
	}
}
