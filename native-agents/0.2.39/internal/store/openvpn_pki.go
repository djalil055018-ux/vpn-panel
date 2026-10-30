package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
	"vpn-platform/internal/pki"
)

func fillOpenVPNPKITx(ctx context.Context, tx pgx.Tx, services []model.ServiceSpec) error {
	now := time.Now().UTC()
	for i := range services {
		s := &services[i]
		if s.Protocol != "openvpn" {
			continue
		}
		var ca pki.KeyPair
		var material model.OpenVPNSpec
		err := tx.QueryRow(ctx, `SELECT ca_certificate,ca_private_key,server_certificate,server_private_key,tls_crypt_key FROM vpn_service_openvpn WHERE service_id=$1::uuid FOR UPDATE`, s.ID).Scan(&ca.Certificate, &ca.PrivateKey, &material.ServerCertificate, &material.ServerPrivateKey, &material.TLSCryptKey)
		if errors.Is(err, pgx.ErrNoRows) {
			ca, err = pki.NewAuthority("vpn-service-"+s.ID, now)
			if err != nil {
				return err
			}
			server, e := pki.Issue(ca, "server-"+s.ID, true, now)
			if e != nil {
				return e
			}
			material.ServerCertificate = server.Certificate
			material.ServerPrivateKey = server.PrivateKey
			material.TLSCryptKey, err = pki.TLSCryptKey()
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `INSERT INTO vpn_service_openvpn(service_id,tenant_id,ca_certificate,ca_private_key,server_certificate,server_private_key,tls_crypt_key) SELECT id,tenant_id,$2,$3,$4,$5,$6 FROM vpn_services WHERE id=$1::uuid`, s.ID, ca.Certificate, ca.PrivateKey, material.ServerCertificate, material.ServerPrivateKey, material.TLSCryptKey)
		}
		if err != nil {
			return err
		}
		serverCert, err := pki.ParseCertificate(material.ServerCertificate)
		if err != nil {
			return err
		}
		if serverCert.NotAfter.Before(now.AddDate(0, 0, 30)) {
			server, e := pki.Issue(ca, "server-"+s.ID, true, now)
			if e != nil {
				return e
			}
			material.ServerCertificate = server.Certificate
			material.ServerPrivateKey = server.PrivateKey
			_, err = tx.Exec(ctx, `UPDATE vpn_service_openvpn SET server_certificate=$2,server_private_key=$3 WHERE service_id=$1::uuid`, s.ID, server.Certificate, server.PrivateKey)
			if err != nil {
				return err
			}
		}
		material.CACertificate = ca.Certificate
		allowed := map[string]bool{}
		for j := range s.Clients {
			c := &s.Clients[j]
			var serial string
			err = tx.QueryRow(ctx, `SELECT serial FROM vpn_client_openvpn_certificates WHERE service_id=$1::uuid AND client_id=$2::uuid AND credential_uuid=$3::uuid AND expires_at>$4 ORDER BY created_at DESC,serial DESC LIMIT 1`, s.ID, c.StatsKey, c.ID, now.AddDate(0, 0, 30)).Scan(&serial)
			if errors.Is(err, pgx.ErrNoRows) {
				pair, e := pki.Issue(ca, "client-"+c.StatsKey, false, now)
				if e != nil {
					return e
				}
				certificate, e := pki.ParseCertificate(pair.Certificate)
				if e != nil {
					return e
				}
				err = tx.QueryRow(ctx, `INSERT INTO vpn_client_openvpn_certificates(service_id,client_id,tenant_id,credential_uuid,serial,certificate,private_key,expires_at) SELECT s.id,c.id,c.tenant_id,c.vless_uuid,$4,$5,$6,$7 FROM vpn_clients c JOIN vpn_services s ON s.tenant_id=c.tenant_id WHERE s.id=$1::uuid AND c.id=$2::uuid AND c.vless_uuid=$3::uuid RETURNING serial`, s.ID, c.StatsKey, c.ID, pair.Serial, pair.Certificate, pair.PrivateKey, certificate.NotAfter).Scan(&serial)
				serial = pair.Serial
			}
			if err != nil {
				return err
			}
			allowed[serial] = true
			// Renewal must not revoke an already downloaded, unexpired profile.
			// Every certificate for this effective credential remains valid until
			// expiry; removing access or rotating the credential revokes them all.
			validRows, e := tx.Query(ctx, `SELECT serial FROM vpn_client_openvpn_certificates WHERE service_id=$1::uuid AND client_id=$2::uuid AND credential_uuid=$3::uuid AND expires_at>$4`, s.ID, c.StatsKey, c.ID, now)
			if e != nil {
				return e
			}
			for validRows.Next() {
				var activeSerial string
				if e = validRows.Scan(&activeSerial); e != nil {
					validRows.Close()
					return e
				}
				allowed[activeSerial] = true
			}
			e = validRows.Err()
			validRows.Close()
			if e != nil {
				return e
			}
			c.ID = c.StatsKey
		}
		rows, err := tx.Query(ctx, `SELECT serial FROM vpn_client_openvpn_certificates WHERE service_id=$1::uuid ORDER BY serial`, s.ID)
		if err != nil {
			return err
		}
		revoked := []string{}
		for rows.Next() {
			var serial string
			if err = rows.Scan(&serial); err != nil {
				rows.Close()
				return err
			}
			if !allowed[serial] {
				revoked = append(revoked, serial)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		material.CRL, err = pki.SignCRL(ca, revoked, now)
		if err != nil {
			return err
		}
		s.OpenVPN = &material
		_, err = tx.Exec(ctx, `UPDATE vpn_service_openvpn SET next_refresh_at=$2 WHERE service_id=$1::uuid`, s.ID, now.AddDate(0, 0, 7))
		if err != nil {
			return err
		}
	}
	return nil
}

func validateOpenVPNDesiredTx(ctx context.Context, tx pgx.Tx, nodeID string, state model.DesiredState, releaseID string) error {
	if state.Core.Type != "openvpn" {
		return nil
	}
	if state.Core.Version != model.OpenVPNPinnedVersion || state.Core.SHA256 != model.OpenVPNPinnedSHA256 || state.Core.DownloadURL != model.OpenVPNPinnedDownloadURL || len(state.Services) > 1 {
		return errors.New("OpenVPN requires the reviewed package and one service per node")
	}
	var agent string
	var compatible bool
	err := tx.QueryRow(ctx, `SELECT COALESCE(agent_version,''),runtime_core='openvpn' AND os_name='ubuntu' AND os_version='24.04' AND architecture='amd64' FROM nodes WHERE id=$1::uuid`, nodeID).Scan(&agent, &compatible)
	if err != nil {
		return err
	}
	if !compatible || !model.OpenVPNAgentCompatible(agent) {
		return ErrNodeRuntime
	}
	var approved bool
	err = tx.QueryRow(ctx, `SELECT approved AND NOT revoked AND core_type='openvpn' AND version=$2 AND sha256=$3 AND download_url=$4 AND os='linux' AND architecture='amd64' FROM core_releases WHERE id=$1::uuid FOR SHARE`, releaseID, state.Core.Version, state.Core.SHA256, state.Core.DownloadURL).Scan(&approved)
	if err != nil {
		return err
	}
	if !approved {
		return ErrPinnedCoreReleaseUnavailable
	}
	for _, s := range state.Services {
		if err = compiler.ValidateOpenVPNService(s, time.Now().UTC()); err != nil {
			return err
		}
		var owned bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vpn_services s JOIN vpn_service_openvpn p ON p.service_id=s.id AND p.tenant_id=s.tenant_id WHERE s.id=$1::uuid AND s.node_id=$2::uuid AND p.ca_certificate=$3 AND p.server_certificate=$4 AND p.server_private_key=$5 AND p.tls_crypt_key=$6)`, s.ID, nodeID, s.OpenVPN.CACertificate, s.OpenVPN.ServerCertificate, s.OpenVPN.ServerPrivateKey, s.OpenVPN.TLSCryptKey).Scan(&owned)
		if err != nil {
			return err
		}
		if !owned {
			return ErrNodeRuntime
		}
	}
	return nil
}

func (p *Postgres) listOpenVPNConnections(ctx context.Context, clientID string) ([]model.VPNClientConnection, error) {
	rows, err := p.Pool.Query(ctx, `SELECT c.id::text,c.name,s.id::text,s.name,COALESCE(s.subscription_name,''),s.public_address,s.public_port,s.transport,p.ca_certificate,p.tls_crypt_key,k.certificate,k.private_key
	 FROM vpn_clients c JOIN vpn_effective_client_services cs ON cs.client_id=c.id AND cs.tenant_id=c.tenant_id
	 JOIN vpn_services s ON s.id=cs.service_id AND s.tenant_id=cs.tenant_id
	 JOIN vpn_service_openvpn p ON p.service_id=s.id AND p.tenant_id=s.tenant_id
	 JOIN LATERAL(SELECT certificate,private_key FROM vpn_client_openvpn_certificates k WHERE k.service_id=s.id AND k.client_id=c.id AND k.tenant_id=c.tenant_id AND k.credential_uuid=c.vless_uuid AND k.expires_at>now() ORDER BY k.created_at DESC,k.serial DESC LIMIT 1)k ON true
	 WHERE c.id=$1::uuid AND c.status='active' AND (c.expires_at IS NULL OR c.expires_at>now()) AND s.enabled AND s.protocol='openvpn' AND s.transport IN ('udp','tcp') AND s.security='tls' AND s.public_address IS NOT NULL AND s.public_port IS NOT NULL
	 AND NOT vpn_client_quota_exceeded(c.id)
	 ORDER BY s.created_at,s.id`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []model.VPNClientConnection{}
	for rows.Next() {
		c := model.VPNClientConnection{RuntimeCore: "openvpn", Protocol: "openvpn", Security: "tls"}
		var ca, crypt, cert, key string
		if err = rows.Scan(&c.ClientID, &c.ClientName, &c.ServiceID, &c.ServiceName, &c.SubscriptionName, &c.Address, &c.Port, &c.Transport, &ca, &crypt, &cert, &key); err != nil {
			return nil, err
		}
		c.Config, err = compiler.OpenVPNProfile(model.VPNService{ID: c.ServiceID, Protocol: c.Protocol, Transport: c.Transport, PublicAddress: &c.Address, PublicPort: &c.Port}, ca, cert, key, crypt, c.ClientID, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		certificate, e := pki.ParseCertificate(cert)
		if e != nil {
			return nil, e
		}
		c.ConfigExpiresAt = &certificate.NotAfter
		c.ConfigFilename = "vpn-" + c.ServiceID[:8] + ".ovpn"
		result = append(result, c)
	}
	return result, rows.Err()
}

func (p *Postgres) ReconcileOpenVPNMaintenance(ctx context.Context) (int, error) {
	rows, err := p.Pool.Query(ctx, `SELECT DISTINCT s.node_id::text FROM vpn_services s JOIN vpn_service_openvpn p ON p.service_id=s.id WHERE s.enabled AND p.next_refresh_at<=now() ORDER BY s.node_id::text LIMIT 50`)
	if err != nil {
		return 0, err
	}
	nodes := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		nodes = append(nodes, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	count := 0
	var all error
	for _, id := range nodes {
		if _, err = p.RebuildNodeDesiredState(ctx, id); err != nil {
			all = errors.Join(all, err)
		} else {
			count++
		}
	}
	return count, all
}
