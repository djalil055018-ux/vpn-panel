#!/usr/bin/env python3
"""Host-root emergency MFA reset with a verified backup and transactional audit."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

BACKUP_TOOL=Path('/usr/local/libexec/vpn-platform/platform-backup.py')

class RecoveryError(Exception):pass

def sql(statement,**variables):
    command=['docker','exec','-i','vpn-platform-postgres','sh','-c','exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At -v ON_ERROR_STOP=1 "$@"','mfa-recovery']
    for key,value in variables.items():command.extend(['-v',key+'='+value])
    result=subprocess.run(command,input=statement,text=True,capture_output=True,timeout=30)
    if result.returncode:raise RecoveryError('Database operation failed; any uncommitted reset was rolled back')
    return result.stdout.strip()

def verified_backup():
    result=subprocess.run(['python3',str(BACKUP_TOOL),'control-plane','create','--keep','7'],text=True,capture_output=True,timeout=1800)
    if result.returncode:raise RecoveryError('Verified backup could not be created; MFA was not changed')
    try:value=json.loads(result.stdout)
    except ValueError:raise RecoveryError('Backup result is invalid; MFA was not changed') from None
    if value.get('status')!='verified' or not re.fullmatch(r'\d{8}T\d{6}Z-[0-9a-f]{8}',value.get('id','')):raise RecoveryError('Backup verification failed; MFA was not changed')
    return value['id']

def recover(username,confirm):
    if getattr(os,'geteuid',lambda:-1)()!=0:raise RecoveryError('Run this recovery command as root on the Control Plane host')
    if not confirm:raise RecoveryError('Use --confirm-reset-mfa to authorize the selected account reset')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}',username):raise RecoveryError('Invalid account name')
    raw=sql("SELECT id::text||'|'||mfa_enabled::text FROM admin_accounts WHERE lower(username)=lower(:'account_name');",account_name=username)
    try:identity,enabled=raw.split('|');identity=str(uuid.UUID(identity))
    except ValueError:raise RecoveryError('Account was not found') from None
    if enabled!='true':return {'status':'already_disabled'}
    backup=verified_backup()
    statement="""BEGIN;
SET LOCAL lock_timeout='5s';
SELECT pg_advisory_xact_lock(1448103506,1);
SELECT 1 FROM admin_accounts WHERE id=:'account_id'::uuid FOR UPDATE;
WITH changed AS (
 UPDATE admin_accounts SET mfa_enabled=false,password_hash=substring(password_hash FROM 5),security_version=security_version+1,updated_at=now()
 WHERE id=:'account_id'::uuid AND mfa_enabled RETURNING id
), removed_factor AS (
 DELETE FROM admin_mfa WHERE account_id IN(SELECT id FROM changed)
), removed_sessions AS (
 DELETE FROM admin_sessions WHERE account_id IN(SELECT id FROM changed)
)
INSERT INTO audit_events(event_type,actor_type,actor_id,payload)
SELECT 'admin_mfa.emergency_reset','system','host-root-recovery',jsonb_build_object('admin_account_id',id::text,'backup_id',:'backup_id') FROM changed;
COMMIT;"""
    sql(statement,account_id=identity,backup_id=backup)
    return {'status':'mfa_reset','backup_id':backup,'sessions_revoked':True}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--username',required=True)
    parser.add_argument('--confirm-reset-mfa',action='store_true')
    args=parser.parse_args()
    try:print(json.dumps(recover(args.username,args.confirm_reset_mfa)))
    except (RecoveryError,subprocess.TimeoutExpired,OSError) as error:
        message=str(error) if isinstance(error,RecoveryError) else 'Recovery operation unavailable; inspect local service status'
        print('MFA_RECOVERY_FAILED: '+message,file=sys.stderr);return 1
    return 0

if __name__=='__main__':sys.exit(main())
