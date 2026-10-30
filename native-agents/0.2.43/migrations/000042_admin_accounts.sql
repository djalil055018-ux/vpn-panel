BEGIN;
CREATE TABLE admin_accounts (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 username TEXT NOT NULL CHECK(username ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
 password_hash TEXT NOT NULL CHECK(length(password_hash) BETWEEN 40 AND 256),
 role TEXT NOT NULL CHECK(role IN ('owner','admin','monitor')),
 enabled BOOLEAN NOT NULL DEFAULT true,
 security_version BIGINT NOT NULL DEFAULT 1 CHECK(security_version>0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 last_login_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX admin_accounts_username_key ON admin_accounts(lower(username));
CREATE TABLE admin_sessions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 account_id UUID NOT NULL REFERENCES admin_accounts(id) ON DELETE CASCADE,
 token_hash TEXT NOT NULL UNIQUE CHECK(token_hash ~ '^[0-9a-f]{64}$'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 expires_at TIMESTAMPTZ NOT NULL CHECK(expires_at>created_at),
 last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX admin_sessions_account_idx ON admin_sessions(account_id);
CREATE INDEX admin_sessions_expiry_idx ON admin_sessions(expires_at);
COMMIT;
