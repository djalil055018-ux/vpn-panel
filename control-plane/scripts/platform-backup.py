#!/usr/bin/env python3
"""Protected local snapshots and isolated restore verification. Never restores production."""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urlsplit
from urllib.request import Request,build_opener,HTTPRedirectHandler
import uuid

ROOT=Path('/var/backups/vpn-platform/managed')
STATUS=Path('/var/lib/vpn-platform/operations')
LOCK=Path('/run/lock/vpn-platform-backup.lock')
ID=re.compile(r'^\d{8}T\d{6}Z-[0-9a-f]{8}$')
VERIFY_DB=re.compile(r'^vpn_restore_verify_[0-9a-f]{16}$')
class BackupError(Exception):pass
class BackupReportError(BackupError):pass
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args):raise BackupError('redirect refused')
def now():return dt.datetime.now(dt.timezone.utc).isoformat()
def atomic(path,value,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,temp=tempfile.mkstemp(dir=path.parent,prefix='.'+path.name)
    try:
        with os.fdopen(fd,'w') as stream:json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
        os.chmod(temp,mode);os.replace(temp,path)
    finally:
        if os.path.exists(temp):os.unlink(temp)
def checksum(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
    return h.hexdigest()
def run(args,stdin=None,stdout=subprocess.PIPE,timeout=900):
    try:p=subprocess.run(args,stdin=stdin,stdout=stdout,stderr=subprocess.PIPE,timeout=timeout)
    except Exception:raise BackupError('backup command unavailable or timed out') from None
    if p.returncode:raise BackupError('backup command failed; credentials and raw database output suppressed')
    return p.stdout
def docker(command,*args,stdin=None,stdout=subprocess.PIPE):
    return run(['docker','exec','-i','vpn-platform-postgres','sh','-c',command,'backup',*args],stdin=stdin,stdout=stdout)
def manifest(path):
    if not ID.fullmatch(path.name) or path.is_symlink() or path.resolve().parent!=ROOT.joinpath(path.parent.name).resolve():raise BackupError('invalid backup path')
    value=json.loads((path/'manifest.json').read_text())
    if value.get('id')!=path.name or value.get('role')!=path.parent.name:raise BackupError('backup identity mismatch')
    return value
def write_status(role,values):
    STATUS.mkdir(parents=True,exist_ok=True,mode=0o755);os.chmod(STATUS,0o755)
    path=STATUS/(role+'-backup.json');previous={}
    if path.exists():
        try:previous=json.loads(path.read_text())
        except Exception:pass
    previous.update(values);previous['role']=role;previous['updated_at']=now()
    previous['free_bytes']=shutil.disk_usage(ROOT).free
    atomic(path,previous,0o644)
def archive_paths(role):
    paths=[Path('/etc/vpn-platform'),Path('/usr/local/libexec/vpn-platform')]
    paths.extend(p for p in Path('/etc/systemd/system').glob('vpn-platform-*') if p.is_file() or p.is_symlink())
    if role=='control-plane':
        base=Path('/opt/vpn-platform')
        paths.extend(base/p for p in ['cmd','internal','migrations','scripts','go.mod','go.sum','bin','web/src','web/public','web/package.json','web/package-lock.json','web/next.config.ts','web/tsconfig.json','web/postcss.config.mjs','web/eslint.config.mjs'])
        paths.extend(base.glob('*.md'))
        paths.extend([Path('/etc/nginx/sites-available/vpn-platform'),Path('/etc/nginx/conf.d/vpn-platform-tenant-api-limits.conf'),Path('/etc/letsencrypt')])
    else:
        base=Path('/var/lib/vpn-platform')
        paths.extend(base/p for p in ['agent','secrets','xray','certificates','acme','snapshots'])
        paths.append(Path('/usr/local/bin/vpn-node-agent'))
    return [p for p in paths if p.exists() or p.is_symlink()]
def verify_archive(path):
    with tarfile.open(path,'r:gz') as archive:
        for item in archive:
            parts=Path(item.name).parts
            if item.name.startswith('/') or '..' in parts:raise BackupError('archive has an unsafe member path')
            if item.isfile():
                stream=archive.extractfile(item)
                while stream.read(1024*1024):pass
def verify_database(dump):
    name='vpn_restore_verify_'+uuid.uuid4().hex[:16]
    if not VERIFY_DB.fullmatch(name):raise BackupError('invalid verification database name')
    created=False
    try:
        docker('createdb -U "$POSTGRES_USER" "$1"',name);created=True
        with dump.open('rb') as source:docker('pg_restore -U "$POSTGRES_USER" -d "$1" --exit-on-error --no-owner --no-privileges',name,stdin=source,stdout=subprocess.DEVNULL)
        query="SELECT json_build_object('tenants',(SELECT count(*) FROM tenants),'nodes',(SELECT count(*) FROM nodes),'clients',(SELECT count(*) FROM vpn_clients),'services',(SELECT count(*) FROM vpn_services),'plans',(SELECT count(*) FROM vpn_access_plans),'certificates',(SELECT count(*) FROM node_certificates),'desired_states',(SELECT count(*) FROM desired_states));"
        raw=docker('psql -U "$POSTGRES_USER" -d "$1" -At -v ON_ERROR_STOP=1 -c "$2"',name,query)
        counts=json.loads(raw)
        if not all(isinstance(v,int) and v>=0 for v in counts.values()):raise BackupError('restored schema verification failed')
        return counts
    finally:
        # Only the exact database created by this invocation may be dropped.
        if created and VERIFY_DB.fullmatch(name):docker('dropdb -U "$POSTGRES_USER" --force "$1"',name)
def verify(path):
    value=manifest(path)
    expected={'configuration.tgz'}|({'database.dump'} if value['role']=='control-plane' else set())
    if set(value.get('files',{}))!=expected:raise BackupError('backup file manifest incomplete')
    for name,record in value['files'].items():
        file=path/name
        if file.is_symlink() or not file.is_file() or checksum(file)!=record['sha256']:raise BackupError('backup integrity check failed')
    verify_archive(path/'configuration.tgz')
    if value['role']=='control-plane':value['restored_counts']=verify_database(path/'database.dump')
    value['verified_at']=now();value['status']='verified';atomic(path/'manifest.json',value)
    write_status(value['role'],{'id':value['id'],'status':'verified','last_success_at':value['created_at'],'last_verified_at':value['verified_at'],'size_bytes':value['size_bytes'],'verification':'database_restore' if value['role']=='control-plane' else 'archive_integrity','error':None})
    return value
def retain(role,keep):
    base=ROOT/role;valid=[]
    for path in base.iterdir():
        if not path.is_dir() or path.is_symlink() or not ID.fullmatch(path.name):continue
        try:value=manifest(path)
        except Exception:continue
        if value.get('status')=='verified':valid.append(path)
    for path in sorted(valid,reverse=True)[keep:]:
        if path.resolve().parent!=base.resolve() or path.is_symlink():raise BackupError('retention path escaped its root')
        shutil.rmtree(path)
def create(role,keep):
    root=ROOT/role;root.mkdir(parents=True,exist_ok=True,mode=0o700);os.chmod(ROOT,0o700);os.chmod(root,0o700)
    if shutil.disk_usage(root).free<1024**3:raise BackupError('less than 1 GiB free; backup not started')
    name=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]
    path=root/name;path.mkdir(mode=0o700)
    with tarfile.open(path/'configuration.tgz','w:gz',dereference=False) as archive:
        for source in archive_paths(role):archive.add(source,arcname=str(source).lstrip('/'),recursive=True)
    if role=='control-plane':
        with (path/'database.dump').open('wb') as target:docker('pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc',stdout=target)
    files={p.name:{'sha256':checksum(p),'size_bytes':p.stat().st_size} for p in path.iterdir()}
    value={'schema_version':1,'role':role,'id':name,'created_at':now(),'status':'created','files':files,'size_bytes':sum(v['size_bytes'] for v in files.values())}
    atomic(path/'manifest.json',value)
    value=verify(path);retain(role,keep);return value
def report_node():
    status=json.loads((STATUS/'node-backup.json').read_text())
    local=json.loads(Path('/var/lib/vpn-platform/agent/state.json').read_text())
    config={}
    for line in Path('/etc/vpn-platform/node-agent.env').read_text().splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key,value=line.split('=',1);parts=shlex.split(value);config[key]=parts[0] if parts else ''
    cp=config.get('VPN_CONTROL_PLANE','').rstrip('/');u=urlsplit(cp)
    if u.scheme!='https' or not u.hostname or u.username or u.password or u.query or u.fragment or u.path:raise BackupError('node report requires canonical HTTPS Control Plane')
    safe={key:status.get(key) for key in ['id','status','last_success_at','last_verified_at','size_bytes','verification','free_bytes']}
    req=Request(cp+'/api/v1/agent/backup-status',data=json.dumps(safe).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+local['agent_token']},method='POST')
    try:
        with build_opener(NoRedirect).open(req,timeout=20) as response:
            if response.status!=204:raise BackupError('backup status report rejected')
    except Exception:raise BackupReportError('backup saved locally but status delivery failed') from None
def execute(args):
    if os.geteuid()!=0:raise BackupError('run as root')
    if not 1<=args.keep<=365:raise BackupError('retention must be between 1 and 365')
    LOCK.parent.mkdir(parents=True,exist_ok=True)
    with LOCK.open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if args.command=='failed':
            write_status(args.role,{'status':'failed','error':'scheduled_backup_failed'})
            if args.role=='node':report_node()
            print('BACKUP_FAILURE_STATUS_RECORDED');return
        if args.command=='create':value=create(args.role,args.keep)
        elif args.command=='verify':
            if not args.id or not ID.fullmatch(args.id):raise BackupError('valid backup ID required')
            value=verify(ROOT/args.role/args.id)
        elif args.command=='report':
            if args.role!='node':raise BackupError('only node backups need remote reports')
            report_node();print('NODE_BACKUP_STATUS_REPORTED');return
        else:
            path=STATUS/(args.role+'-backup.json')
            print(path.read_text() if path.exists() else json.dumps({'role':args.role,'status':'missing'}));return
        if args.role=='node' and not args.no_report:report_node()
        print(json.dumps({k:value[k] for k in ['id','role','status','created_at','verified_at','size_bytes']}))
def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description='Create protected backups and verify them without touching production data')
    p.add_argument('role',choices=['control-plane','node']);p.add_argument('command',choices=['create','verify','status','report','failed']);p.add_argument('--id');p.add_argument('--keep',type=int,default=7);p.add_argument('--no-report',action='store_true')
    args=p.parse_args()
    try:execute(args)
    except Exception as e:
        if args.command in ('create','verify') and not isinstance(e,BackupReportError):
            try:write_status(args.role,{'status':'failed','error':'backup_or_verification_failed'})
            except Exception:pass
        print('BACKUP_FAILED: '+str(e) if isinstance(e,BackupError) else 'BACKUP_FAILED: details suppressed',file=sys.stderr);return 1
    return 0
if __name__=='__main__':sys.exit(main())
