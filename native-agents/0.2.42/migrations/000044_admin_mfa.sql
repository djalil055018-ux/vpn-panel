BEGIN;
ALTER TABLE admin_accounts ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT false;
-- Older password verifiers reject the marker. Older reset code cannot remove it
-- while MFA remains enabled, even when application binaries are rolled back.
ALTER TABLE admin_accounts ADD CONSTRAINT admin_mfa_password_marker
 CHECK (mfa_enabled = (left(password_hash,4)='mfa$'));
CREATE TABLE admin_mfa (
 account_id UUID PRIMARY KEY REFERENCES admin_accounts(id) ON DELETE CASCADE,
 secret_ciphertext TEXT,
 pending_ciphertext TEXT,
 pending_expires_at TIMESTAMPTZ,
 pending_security_version BIGINT,
 last_totp_step BIGINT NOT NULL DEFAULT -1 CHECK(last_totp_step>=-1),
 recovery_hashes TEXT[] NOT NULL DEFAULT '{}' CHECK(cardinality(recovery_hashes)<=10),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 CHECK((pending_ciphertext IS NULL)=(pending_expires_at IS NULL)),
 CHECK((pending_ciphertext IS NULL)=(pending_security_version IS NULL))
);
COMMIT;
