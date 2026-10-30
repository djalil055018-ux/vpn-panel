package store

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrNodeNameInvalid = errors.New("node name is invalid")
var ErrNodeNameConflict = errors.New("node name already exists")

type NodeRename struct {
	NodeID  string `json:"node_id"`
	Name    string `json:"name"`
	Changed bool   `json:"changed"`
}

func NormalizeNodeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 80 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", ErrNodeNameInvalid
	}
	return name, nil
}

func (p *Postgres) RenameNode(ctx context.Context, id, name string) (NodeRename, error) {
	out := NodeRename{NodeID: id}
	if !adminOwnerAllowed(ctx) {
		return out, ErrAdminPermission
	}
	name, err := NormalizeNodeName(name)
	if err != nil {
		return out, err
	}

	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))

	var tenant, current, status string
	if err = tx.QueryRow(ctx, `SELECT tenant_id::text,name,status FROM nodes WHERE id=$1::uuid FOR UPDATE`, id).Scan(&tenant, &current, &status); errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	} else if err != nil {
		return out, err
	}
	if status == "retired" {
		return out, ErrNodeRetired
	}
	if current == name {
		out.Name = current
		return out, tx.Commit(ctx)
	}

	var conflict bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE tenant_id=$1::uuid AND name=$2 AND id<>$3::uuid)`, tenant, name, id).Scan(&conflict); err != nil {
		return out, err
	}
	if conflict {
		return out, ErrNodeNameConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE nodes SET name=$2 WHERE id=$1::uuid`, id, name); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "nodes_tenant_name_unique" {
			return out, ErrNodeNameConflict
		}
		return out, err
	}
	actorType, actorID := accessActor(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,node_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,$2::uuid,'node.renamed',$3,$4,jsonb_build_object('old_name',$5::text,'new_name',$6::text))`, tenant, id, actorType, actorID, current, name); err != nil {
		return out, err
	}
	if err = tx.Commit(ctx); err != nil {
		return out, err
	}
	out.Name = name
	out.Changed = true
	return out, nil
}
