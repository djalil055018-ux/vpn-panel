package main

import (
	"context"
	"fmt"
	"os"
	"time"
	"vpn-platform/internal/store"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	p, err := store.NewPostgres(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "access reconciler database unavailable")
		os.Exit(1)
	}
	defer p.Close()
	count, err := p.ReconcileInactiveVPNClients(ctx)
	fmt.Printf("inactive_access_nodes_rebuilt=%d\n", count)
	if err != nil {
		fmt.Fprintln(os.Stderr, "some inactive access could not be reconciled; retry required")
	}
	cascades, cascadeErr := p.ReconcileVPNCascades(ctx)
	fmt.Printf("cascade_nodes_rebuilt=%d\n", cascades)
	if cascadeErr != nil {
		fmt.Fprintln(os.Stderr, "cascade access requires retry")
	}
	// Certificate maintenance must never postpone expiration/quota revocations.
	maintained, maintenanceErr := p.ReconcileOpenVPNMaintenance(ctx)
	fmt.Printf("openvpn_material_nodes_rebuilt=%d\n", maintained)
	if maintenanceErr != nil {
		fmt.Fprintln(os.Stderr, "OpenVPN maintenance requires retry")
	}
	if err != nil || maintenanceErr != nil || cascadeErr != nil {
		os.Exit(1)
	}
}
