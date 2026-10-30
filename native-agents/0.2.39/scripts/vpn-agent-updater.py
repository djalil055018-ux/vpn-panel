#!/usr/bin/env python3
"""Independent, durable updater for CP-assigned published Agent releases.

The node token only traverses authenticated HTTPS. Assignment data never becomes
a shell command. Installer logs and credentials remain root-only on the node.
"""
import ast
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

VERSION='0.1.0'
ROOT=Path('/var/lib/vpn-platform-updater')
ENV=Path('/etc/vpn-platform/node-agent.env')
BINARY=Path('/usr/local/bin/vpn-node-agent')
VERSION_RE=re.compile(r'^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$')
SHA_RE=re.compile(r'^[0-9a-f]{64}$')

class UpdateError(Exception): pass
class HTTPFailure(UpdateError):
    def __init__(self,status): self.status=status

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): raise UpdateError('redirect refused')

def atomic(path,value):
    raw=(json.dumps(value,sort_keys=True)+'\n').encode()
    temp=path.with_suffix('.tmp')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out: out.write(raw);out.flush();os.fsync(out.fileno())
    os.replace(temp,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)

def protected(path,directory=False):
    info=path.lstat()
    if info.st_uid!=0 or info.st_mode&0o022 or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise UpdateError('unprotected file')

def version(value):
    if not isinstance(value,str) or not VERSION_RE.fullmatch(value): raise UpdateError('invalid version')
    return tuple(map(int,value.split('.')))

def validate_assignment(value,node_id):
    if not isinstance(value,dict): raise UpdateError('invalid assignment')
    for key in ['job_id','run_id','node_id','claim_id']:
        if str(uuid.UUID(value[key]))!=value[key]: raise UpdateError('invalid assignment identity')
    if value['node_id']!=node_id or type(value['can_execute']) is not bool: raise UpdateError('wrong assignment scope')
    release=value['release']
    if version(release['version'])<(0,2,30): raise UpdateError('unsupported release')
    for key in ['binary_sha256','installer_sha256']:
        if not SHA_RE.fullmatch(release[key]): raise UpdateError('invalid release digest')
    return {k:value[k] for k in ['job_id','run_id','node_id','claim_id','from_version','release']}

def installer_identity(raw,release):
    # Inspect only literal release constants. Never import downloaded Python.
    constants={}
    for node in ast.parse(raw).body:
        if isinstance(node,ast.Assign) and isinstance(node.value,ast.Constant):
            for target in node.targets:
                if isinstance(target,ast.Name): constants[target.id]=node.value.value
    if constants.get('VERSION')!=release['version'] or constants.get('SHA256')!=release['binary_sha256']:
        raise UpdateError('installer and binary release differ')

class Client:
    def __init__(self):
        protected(ENV)
        values={}
        for line in ENV.read_text().splitlines():
            if '=' in line and not line.lstrip().startswith('#'):
                key,raw=line.split('=',1);parts=shlex.split(raw);values[key.strip()]=parts[0] if parts else ''
        self.base=values.get('VPN_CONTROL_PLANE','').rstrip('/')
        url=urllib.parse.urlsplit(self.base)
        if url.scheme!='https' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path:
            raise UpdateError('HTTPS control-plane origin required')
        self.data=Path(values.get('VPN_AGENT_DATA','/var/lib/vpn-platform'))
        if not self.data.is_absolute() or self.data.resolve()!=self.data or self.data==Path('/'):
            raise UpdateError('invalid data directory')
        state=Path(values.get('VPN_AGENT_STATE',str(self.data/'agent/state.json')))
        protected(state)
        value=json.loads(state.read_text());self.node_id=str(uuid.UUID(value['node_id']));self.token=value['agent_token']
        if not isinstance(self.token,str) or not self.token: raise UpdateError('registered node required')
        self.http=urllib.request.build_opener(NoRedirect)

    def api(self,path,data=None):
        request=urllib.request.Request(self.base+path,data=None if data is None else json.dumps(data).encode(),headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json'})
        try:
            with self.http.open(request,timeout=20) as response:
                raw=response.read(1024*1024+1)
                if len(raw)>1024*1024: raise UpdateError('oversized API response')
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc: raise HTTPFailure(exc.code) from None

    def claim(self): return self.api('/api/v1/agent/update/claim',{'updater_version':VERSION})['assignment']

    def download(self,path,target,expected,limit):
        temp=target.with_suffix('.download')
        try:
            with self.http.open(self.base+path,timeout=45) as response:
                fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as out:
                    size=0; digest=hashlib.sha256()
                    while True:
                        block=response.read(1024*1024)
                        if not block: break
                        size+=len(block)
                        if size>limit: raise UpdateError('oversized release')
                        digest.update(block);out.write(block)
                    out.flush();os.fsync(out.fileno())
            if size==0 or digest.hexdigest()!=expected: raise UpdateError('release digest mismatch')
            os.replace(temp,target)
        finally: temp.unlink(missing_ok=True)

def digest(path):
    protected(path)
    with path.open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()

def pending_rollback(client):
    latest=client.data/'maintenance/latest-backup'
    if not latest.exists():return False
    protected(latest)
    name=latest.read_text().strip()
    if not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',name):raise UpdateError('invalid backup identity')
    backup=Path('/var/backups/vpn-platform/node-tool')/name
    protected(backup,True)
    return not (backup/'committed').exists() and not (backup/'rolled-back').exists()

def healthy(client,release,started):
    value=client.api('/api/v1/agent/status')
    checked=datetime.datetime.fromisoformat(value['health_checked_at'].replace('Z','+00:00')).timestamp()
    return value['node_id']==client.node_id and value['agent_version']==release['version'] and value['healthy'] and value['health_fresh'] and value['desired_generation']==value['applied_generation'] and checked>=started and digest(BINARY)==release['binary_sha256']

def report(client,directory,assignment,result):
    payload={'claim_id':assignment['claim_id'],**result}
    client.api('/api/v1/agent/update/'+assignment['job_id']+'/report',payload)
    atomic(directory/'reported.json',{'at':time.time()})

def execute(client,value):
    assignment=validate_assignment(value,client.node_id)
    directory=ROOT/(assignment['job_id']+'-'+assignment['claim_id'])
    directory.mkdir(mode=0o700,exist_ok=True);protected(directory,True)
    saved=directory/'assignment.json'
    if saved.exists():
        protected(saved)
        if json.loads(saved.read_text())!=assignment: raise UpdateError('assignment identity changed')
    else: atomic(saved,assignment)
    result_path=directory/'result.json'; started_path=directory/'started.json'
    if result_path.exists():
        report(client,directory,assignment,json.loads(result_path.read_text()));return
    result={'status':'failed','binary_sha256':'','code':'preflight_failed'}
    if started_path.exists():
        # On a crash, the installer's independent guard may still be restoring.
        # Never rerun an uncertain installer or free the CP slot prematurely.
        start=json.loads(started_path.read_text())['at']
        if time.time()<start+420 or pending_rollback(client):return
        if healthy(client,assignment['release'],start):
            result={'status':'succeeded','binary_sha256':assignment['release']['binary_sha256'],'code':'ready'}
        else: result['code']='interrupted'
        atomic(result_path,result);report(client,directory,assignment,result);return
    if not value['can_execute']:
        result['code']='release_revoked';atomic(result_path,result);report(client,directory,assignment,result);return
    release=assignment['release']
    try:
        if pending_rollback(client):return
        current=client.api('/api/v1/agent/status')
        if not current['healthy'] or not current['health_fresh'] or current['desired_generation']!=current['applied_generation'] or version(current['agent_version'])>version(release['version']):
            raise UpdateError('node state changed')
        result['code']='download_failed'
        artifact=directory/'agent';installer=directory/'tool.py'
        client.download('/artifacts/node-agent/'+release['version']+'/linux-amd64/vpn-node-agent',artifact,release['binary_sha256'],64*1024*1024)
        client.download('/install/vpn-node-tool-v'+release['version']+'.py',installer,release['installer_sha256'],2*1024*1024)
        installer_identity(installer.read_bytes(),release)
        fresh=client.claim()
        if fresh is None or validate_assignment(fresh,client.node_id)!=assignment or not fresh['can_execute']:
            result['code']='release_revoked';raise UpdateError('assignment no longer executable')
        result['code']='installer_failed'
        started=time.time();atomic(started_path,{'at':started})
        with (directory/'installer.log').open('wb') as log:
            completed=subprocess.run(['/usr/bin/python3',str(installer),'upgrade','--artifact-file',str(artifact),'--data-dir',str(client.data)],stdout=log,stderr=subprocess.STDOUT,timeout=300)
        if completed.returncode:raise UpdateError('installer failed')
        for _ in range(20):
            if healthy(client,release,started):break
            time.sleep(3)
        else:raise UpdateError('fresh health not confirmed')
        result={'status':'succeeded','binary_sha256':release['binary_sha256'],'code':'ready'}
    except (UpdateError,OSError,ValueError,KeyError,subprocess.SubprocessError):
        # A timed-out or failed installer can still have an independent rollback
        # in progress. Keep the fleet claim until the recovery branch above has
        # observed its guard settling; never release another node immediately.
        if started_path.exists():return
    atomic(result_path,result)
    report(client,directory,assignment,result)

def main():
    os.umask(0o077)
    if os.geteuid()!=0:raise UpdateError('root required')
    ROOT.mkdir(mode=0o700,exist_ok=True);protected(ROOT,True)
    fd=os.open(ROOT/'updater.lock',os.O_CREAT|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return
        client=Client()
        value=client.claim()
        if value is not None: execute(client,value)

if __name__=='__main__':
    try:main()
    except Exception:
        # Never emit exception text containing request URLs, tokens or logs.
        print('AGENT_UPDATER_RETRY_REQUIRED',flush=True)
        raise SystemExit(1)
