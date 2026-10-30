package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/jackc/pgx/v5"
)

var botDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type botResult struct {
	Status int
	Body   json.RawMessage
}

func botFingerprint(method, path string, validatedPayload any) (string, error) {
	raw, err := json.Marshal(struct {
		Method, Path string
		Payload      any
	}{method, path, validatedPayload})
	if err != nil {
		return "", ErrBotBridgeRequest
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func botTenant(ctx context.Context) (string, error) {
	principal, ok := TenantPrincipal(ctx)
	if !ok || principal.Role != "operator" || principal.TenantID == "" {
		return "", ErrNotFound
	}
	return principal.TenantID, nil
}

// The caller supplies a fingerprint of the validated method, actual target and
// body. The operation key deliberately omits numeric targets on the bot side.
// All effects, generation rebuilds, audit and receipt must use the provided tx;
// no remote I/O or separately committing Store methods belong in effect.
func (p *Postgres) runBotOperation(ctx context.Context, key, fingerprint string, effect func(pgx.Tx, string) (botResult, error)) (out botResult, err error) {
	return p.runBotMutation(ctx, key, fingerprint, true, effect)
}
func (p *Postgres) runBotMutation(ctx context.Context, key, fingerprint string, requiresKey bool, effect func(pgx.Tx, string) (botResult, error)) (out botResult, err error) {
	tenant, err := botTenant(ctx)
	if err != nil {
		return out, err
	}
	if (key != "" || requiresKey) && !botDigest.MatchString(key) || !botDigest.MatchString(fingerprint) {
		return out, ErrBotBridgeRequest
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	// Same ordering as native create and reviewed migration. Access lock also
	// serializes native expiry/limits/deletion/traffic with bot mutations.
	if err = lockTenantResource(ctx, tx, tenant); err != nil {
		return out, err
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return out, err
	}
	var active bool
	err = tx.QueryRow(ctx, `SELECT COALESCE(b.state='active' AND b.source_identity_reviewed AND b.activated_at IS NOT NULL AND (b.profile_kind='native' OR (b.profile_kind='imported' AND b.inventory_sha256=h.inventory_sha256)),false)
 FROM bot_profiles b LEFT JOIN remnawave_import_heads h ON h.import_id=b.import_id WHERE b.tenant_id=$1::uuid FOR UPDATE OF b`, tenant).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrBotBridgeHeld
	}
	if err != nil {
		return out, err
	}
	if !active {
		return out, ErrBotBridgeHeld
	}
	if key != "" {
		var prior string
		err = tx.QueryRow(ctx, `SELECT fingerprint,status_code,response FROM bot_operations WHERE tenant_id=$1::uuid AND operation_key=$2`, tenant, key).Scan(&prior, &out.Status, &out.Body)
		if err == nil {
			if prior != fingerprint {
				return botResult{}, ErrBotBridgeConflict
			}
			return out, tx.Commit(ctx)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return out, err
		}
	}
	out, err = effect(tx, tenant)
	if err != nil {
		return botResult{}, err
	}
	if (out.Status != 200 && out.Status != 201 && out.Status != 204) || !json.Valid(out.Body) || len(out.Body) > 262144 {
		return botResult{}, ErrBotBridgeRequest
	}
	if key != "" {
		_, err = tx.Exec(ctx, `INSERT INTO bot_operations(tenant_id,operation_key,fingerprint,status_code,response) VALUES($1::uuid,$2,$3,$4,$5::jsonb)`, tenant, key, fingerprint, out.Status, out.Body)
		if err != nil {
			return botResult{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return botResult{}, err
	}
	return out, nil
}
