//go:build integration

package store

import (
	"testing"
)

func TestVPNServiceConfigurationRebuildIntegration(t *testing.T) {
	ctx, p := deletionStore(t)
	_, services := nativeAccessFixture(t, ctx, p)
	serviceID := services[0]
	var nodeID string
	var generationBefore int64
	if err := p.Pool.QueryRow(ctx, `SELECT node_id::text FROM vpn_services WHERE id=$1::uuid`, serviceID).Scan(&nodeID); err != nil {
		t.Fatal(err)
	}
	if err := p.Pool.QueryRow(ctx, `SELECT desired_generation FROM nodes WHERE id=$1::uuid`, nodeID).Scan(&generationBefore); err != nil {
		t.Fatal(err)
	}

	service, desired, err := p.UpdateVPNServiceConfigurationAndRebuild(
		ctx,
		serviceID,
		"Renamed VLESS listener",
		"0.0.0.0",
		5443,
		"tcp",
		"vpn.example.test",
		443,
	)
	if err != nil {
		t.Fatal("configuration update failed", err)
	}
	if service.Name != "Renamed VLESS listener" || service.Listen != "0.0.0.0" || service.Port != 5443 || service.PublicAddress == nil || *service.PublicAddress != "vpn.example.test" || service.PublicPort == nil || *service.PublicPort != 443 {
		t.Fatalf("updated service fields were not returned: %+v", service)
	}
	if desired.Generation <= generationBefore {
		t.Fatalf("listener change did not create a new desired generation: before=%d after=%d", generationBefore, desired.Generation)
	}
	var actualPort int
	var actualPublicAddress string
	var currentGeneration int64
	if err = p.Pool.QueryRow(ctx, `SELECT s.port,s.public_address,n.desired_generation FROM vpn_services s JOIN nodes n ON n.id=s.node_id WHERE s.id=$1::uuid`, serviceID).Scan(&actualPort, &actualPublicAddress, &currentGeneration); err != nil {
		t.Fatal(err)
	}
	if actualPort != 5443 || actualPublicAddress != "vpn.example.test" || currentGeneration != desired.Generation {
		t.Fatalf("configuration and desired generation were not persisted together: port=%d address=%s generation=%d expected=%d", actualPort, actualPublicAddress, currentGeneration, desired.Generation)
	}
	if _, _, err = p.UpdateVPNServiceConfigurationAndRebuild(ctx, serviceID, "", "0.0.0.0", 5444, "grpc", "vpn.example.test", 443); err != ErrVPNServiceTransportImmutable {
		t.Fatalf("non-OpenVPN transport change was accepted: %v", err)
	}
}
