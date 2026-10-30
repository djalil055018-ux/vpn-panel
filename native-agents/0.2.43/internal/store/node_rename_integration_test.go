//go:build integration

package store

import (
	"errors"
	"testing"

	"vpn-platform/internal/model"
)

func TestNodeRenameIntegration(t *testing.T) {
	ctx, p := deletionStore(t)
	tenantID, services := nativeAccessFixture(t, ctx, p)
	var firstNode, secondNode string
	if err := p.Pool.QueryRow(ctx, `SELECT node_id::text FROM vpn_services WHERE id=$1::uuid`, services[0]).Scan(&firstNode); err != nil {
		t.Fatal(err)
	}
	if err := p.Pool.QueryRow(ctx, `SELECT node_id::text FROM vpn_services WHERE id=$1::uuid`, services[1]).Scan(&secondNode); err != nil {
		t.Fatal(err)
	}
	var generationBefore int64
	if err := p.Pool.QueryRow(ctx, `SELECT desired_generation FROM nodes WHERE id=$1::uuid`, firstNode).Scan(&generationBefore); err != nil {
		t.Fatal(err)
	}
	owner := WithAdminPrincipal(ctx, model.AdminSession{Account: model.AdminAccount{Role: "owner"}})
	admin := WithAdminPrincipal(ctx, model.AdminSession{Account: model.AdminAccount{Role: "admin"}})
	if _, err := p.RenameNode(admin, firstNode, "Renamed node"); !errors.Is(err, ErrAdminPermission) {
		t.Fatal("non-owner could rename a node", err)
	}
	if _, err := p.RenameNode(owner, firstNode, "second"); !errors.Is(err, ErrNodeNameConflict) {
		t.Fatal("rename accepted another node's name", err)
	}
	if _, err := p.RenameNode(owner, firstNode, "  \n  "); !errors.Is(err, ErrNodeNameInvalid) {
		t.Fatal("rename accepted an empty name", err)
	}
	result, err := p.RenameNode(owner, firstNode, "  🇫🇮 Finland Router  ")
	if err != nil || !result.Changed || result.Name != "🇫🇮 Finland Router" {
		t.Fatalf("unexpected rename result: %+v, %v", result, err)
	}
	var persisted, auditCount int
	if err = p.Pool.QueryRow(ctx, `SELECT count(*) FROM nodes WHERE id=$1::uuid AND tenant_id=$2::uuid AND name=$3`, firstNode, tenantID, result.Name).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if err = p.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE node_id=$1::uuid AND event_type='node.renamed'`, firstNode).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	var generationAfter int64
	if err = p.Pool.QueryRow(ctx, `SELECT desired_generation FROM nodes WHERE id=$1::uuid`, firstNode).Scan(&generationAfter); err != nil {
		t.Fatal(err)
	}
	if persisted != 1 || auditCount != 1 || generationAfter != generationBefore {
		t.Fatalf("rename persistence/audit/generation mismatch: persisted=%d audit=%d generation_before=%d generation_after=%d", persisted, auditCount, generationBefore, generationAfter)
	}
}
