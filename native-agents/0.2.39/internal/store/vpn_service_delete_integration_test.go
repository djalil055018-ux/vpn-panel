//go:build integration

package store

import (
	"errors"
	"testing"

	"vpn-platform/internal/model"
)

func TestVPNServiceDeleteRebuildIntegration(t *testing.T) {
	ctx, p := deletionStore(t)
	tenantID, services := nativeAccessFixture(t, ctx, p)
	serviceID := services[0]
	var nodeID, serviceName string
	if err := p.Pool.QueryRow(ctx, `SELECT node_id::text,name FROM vpn_services WHERE id=$1::uuid`, serviceID).Scan(&nodeID, &serviceName); err != nil {
		t.Fatal(err)
	}
	client, err := p.CreateVPNClient(ctx, tenantID, "Service deletion survivor", nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := p.CreateVPNAccessPlan(ctx, tenantID, "Service deletion plan", "service-delete-integration", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.AttachVPNClientAndRebuild(ctx, serviceID, client.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = p.SetVPNAccessPlanService(ctx, plan.ID, serviceID, true); err != nil {
		t.Fatal(err)
	}
	if _, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, true); err != nil {
		t.Fatal(err)
	}
	connections, err := p.ListVPNClientConnections(ctx, client.ID)
	if err != nil || len(connections) != 1 {
		t.Fatal("synthetic service grants were not visible before delete", err)
	}
	var generationBefore int64
	if err = p.Pool.QueryRow(ctx, `SELECT desired_generation FROM nodes WHERE id=$1::uuid`, nodeID).Scan(&generationBefore); err != nil {
		t.Fatal(err)
	}
	owner := WithAdminPrincipal(ctx, model.AdminSession{Account: model.AdminAccount{Role: "owner"}})
	admin := WithAdminPrincipal(ctx, model.AdminSession{Account: model.AdminAccount{Role: "admin"}})
	if _, err = p.DeleteVPNServiceAndRebuild(admin, serviceID, serviceName); !errors.Is(err, ErrAdminPermission) {
		t.Fatal("non-owner could delete a protocol", err)
	}
	if _, err = p.DeleteVPNServiceAndRebuild(owner, serviceID, "incorrect name"); !errors.Is(err, ErrVPNServiceDeleteConfirmation) {
		t.Fatal("protocol deletion accepted a mismatched confirmation", err)
	}
	result, err := p.DeleteVPNServiceAndRebuild(owner, serviceID, serviceName)
	if err != nil {
		t.Fatal("protocol deletion failed", err)
	}
	if !result.Deleted || result.ServiceID != serviceID || result.NodeID != nodeID || result.Generation <= generationBefore || result.AffectedClients != 1 || result.AffectedPlans != 1 {
		t.Fatalf("unexpected deletion result: %+v", result)
	}
	var serviceCount, directGrantCount, planGrantCount, currentDesiredServices, auditCount int
	for _, query := range []struct {
		dest any
		sql  string
	}{
		{&serviceCount, `SELECT count(*) FROM vpn_services WHERE id=$1::uuid`},
		{&directGrantCount, `SELECT count(*) FROM vpn_client_services WHERE service_id=$1::uuid`},
		{&planGrantCount, `SELECT count(*) FROM vpn_access_plan_services WHERE service_id=$1::uuid`},
	} {
		if err = p.Pool.QueryRow(ctx, query.sql, serviceID).Scan(query.dest); err != nil {
			t.Fatal(err)
		}
	}
	if err = p.Pool.QueryRow(ctx, `SELECT jsonb_array_length(d.document->'services') FROM desired_states d JOIN nodes n ON n.id=d.node_id AND n.desired_generation=d.generation WHERE n.id=$1::uuid`, nodeID).Scan(&currentDesiredServices); err != nil {
		t.Fatal(err)
	}
	if err = p.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE node_id=$1::uuid AND event_type='vpn_service.deleted'`, nodeID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if serviceCount != 0 || directGrantCount != 0 || planGrantCount != 0 || currentDesiredServices != 0 || auditCount != 1 {
		t.Fatalf("delete did not atomically remove service, grants, desired listener, and audit evidence: service=%d direct=%d plan=%d desired=%d audit=%d", serviceCount, directGrantCount, planGrantCount, currentDesiredServices, auditCount)
	}
	connections, err = p.ListVPNClientConnections(ctx, client.ID)
	if err != nil || len(connections) != 0 {
		t.Fatal("deleted protocol remains in the client subscription", err)
	}
	var clientCount, planMembershipCount int
	if err = p.Pool.QueryRow(ctx, `SELECT count(*) FROM vpn_clients WHERE id=$1::uuid`, client.ID).Scan(&clientCount); err != nil {
		t.Fatal(err)
	}
	if err = p.Pool.QueryRow(ctx, `SELECT count(*) FROM vpn_client_access_plans WHERE client_id=$1::uuid AND plan_id=$2::uuid`, client.ID, plan.ID).Scan(&planMembershipCount); err != nil {
		t.Fatal(err)
	}
	if clientCount != 1 || planMembershipCount != 1 {
		t.Fatal("protocol removal deleted the client or its plan membership")
	}
}
