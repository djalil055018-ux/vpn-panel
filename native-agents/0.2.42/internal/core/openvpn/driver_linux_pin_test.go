//go:build linux

package openvpn

import (
	"testing"
	"vpn-platform/internal/model"
)

func TestDesiredCheckpointMatchesControlPlaneOpenVPNRelease(t *testing.T) {
	state := model.DesiredState{
		Generation: 98,
		Core: model.CoreRelease{
			Type:        "openvpn",
			Version:     "2.6.19",
			SHA256:      "d288c3789e825b140258da3e2c40bdb8f07820b8e69ca6480b619b83af8f108a",
			DownloadURL: "https://security.ubuntu.com/ubuntu/pool/main/o/openvpn/openvpn_2.6.19-0ubuntu0.24.04.4_amd64.deb",
		},
	}
	got, err := desiredCheckpoint(state)
	if err != nil {
		t.Fatalf("Control Plane's approved OpenVPN release rejected: %v", err)
	}
	if got.Generation != state.Generation || !got.Empty || got.Active {
		t.Fatalf("unexpected initial checkpoint: %+v", got)
	}
}

func TestDesiredCheckpointRejectsPreviousOpenVPNPackagePin(t *testing.T) {
	state := model.DesiredState{
		Generation: 98,
		Core: model.CoreRelease{
			Type:        "openvpn",
			Version:     "2.6.19",
			SHA256:      "7b3d55c8f2f876a1add623cc60ef62e1232be436ce2f321172d04990e652221e",
			DownloadURL: "https://archive.ubuntu.com/ubuntu/pool/main/o/openvpn/openvpn_2.6.19-0ubuntu0.24.04.3_amd64.deb",
		},
	}
	if _, err := desiredCheckpoint(state); err == nil {
		t.Fatal("previous OpenVPN package pin unexpectedly accepted")
	}
}
