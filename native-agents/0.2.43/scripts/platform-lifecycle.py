#!/usr/bin/env python3
"""Build and apply verified VPN Platform Control Plane release bundles."""
import argparse
import datetime as dt
try:import fcntl
except ImportError:
 class fcntl: # Unit tests may inspect bundle logic on non-Linux hosts.
  LOCK_EX=2
  @staticmethod
  def flock(*_):return None
import gzip
import hashlib
import hmac
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.request import Request,urlopen
import uuid

TOOL_VERSION='0.1.6'
HYSTERIA_MIN_CP_VERSION='0.1.88'
LIVE=Path('/opt/vpn-platform')
STATE=Path('/var/lib/vpn-platform/lifecycle-state.json')
BACKUPS=Path('/var/backups/vpn-platform/lifecycle')
LOCK=Path('/run/lock/vpn-platform-lifecycle.lock')
UNITS=Path('/etc/systemd/system')
TOOL=Path('/usr/local/libexec/vpn-platform/platform-lifecycle.py')
BACKUP_TOOL=Path('/usr/local/libexec/vpn-platform/platform-backup.py')
POSTGRES_CONTAINER='vpn-platform-postgres'
VERSION=re.compile(r'^\d+\.\d+\.\d+$')
BACKUP_ID=re.compile(r'^\d{8}T\d{6}Z-[0-9a-f]{8}$')
MIGRATION=re.compile(r'^(\d{6})_[a-z0-9_]+\.sql$')
BINARIES=('access-reconciler','certificate-renewer','control-plane','core-sync','incident-monitor','webhook-dispatcher')
OPTIONAL_BINARIES=('deployment-observer','rollout-sweeper','verify-restored-mfa')
SOURCE_ENTRIES=('cmd','internal','migrations','scripts','deploy','go.mod','go.sum')
WEB_ENTRIES=('src','public','package.json','package-lock.json','next.config.ts','tsconfig.json','postcss.config.mjs','eslint.config.mjs')
WEB_RUNTIME='standalone'
MANAGED_UNIT_DROPINS=('vpn-platform-web.service.d/zz-pauk-standalone.conf',)
MANAGED_UNIT_DROPIN_MARKER='# Managed by VPN Platform lifecycle.'
CORE_SERVICES=('vpn-platform-control-plane.service','vpn-platform-web.service')
TIMERS=('vpn-platform-access-reconciler.timer','vpn-platform-certificate-renewer.timer','vpn-platform-core-sync.timer','vpn-platform-incident-monitor.timer','vpn-platform-webhook-dispatcher.timer')
OPTIONAL_TIMERS=(('vpn-platform-deployment-observer.timer','/etc/vpn-platform/deployment-observer.env'),('vpn-platform-rollout-sweeper.timer','/etc/vpn-platform/rollout-sweeper.env'),('vpn-platform-managed-backup.timer','/usr/local/libexec/vpn-platform/platform-backup.py'))

class LifecycleError(Exception):pass

def now():return dt.datetime.now(dt.timezone.utc).isoformat()
def build_time():
 value=os.environ.get('SOURCE_DATE_EPOCH')
 if value is None:return now()
 try:return dt.datetime.fromtimestamp(int(value),dt.timezone.utc).isoformat()
 except (ValueError,OverflowError):raise LifecycleError('SOURCE_DATE_EPOCH is invalid') from None
def version_tuple(value):
 if not VERSION.fullmatch(str(value)):raise LifecycleError('version is invalid')
 return tuple(int(part) for part in value.split('.'))
def sha256(path):
 h=hashlib.sha256()
 with path.open('rb') as stream:
  for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
 return h.hexdigest()
def require_digest(bundle,expected):
 actual=sha256(bundle)
 if not re.fullmatch(r'[0-9a-f]{64}',str(expected)) or not hmac.compare_digest(actual,expected):raise LifecycleError('release bundle SHA-256 does not match the trusted value')
 return actual
def atomic_json(path,value,mode=0o644):
 path.parent.mkdir(parents=True,exist_ok=True)
 fd,temp=tempfile.mkstemp(dir=path.parent,prefix='.'+path.name)
 try:
  with os.fdopen(fd,'w') as stream:json.dump(value,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
  os.chmod(temp,mode);os.replace(temp,path)
 finally:
  if os.path.exists(temp):os.unlink(temp)
def run(args,**kwargs):
 try:result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=kwargs.pop('timeout',900),**kwargs)
 except Exception:raise LifecycleError('required command unavailable or timed out') from None
 if result.returncode:raise LifecycleError('command failed; output suppressed')
 return result
def require_root():
 if os.geteuid()!=0:raise LifecycleError('run as root')
def read_json(path):
 try:return json.loads(path.read_text())
 except Exception:raise LifecycleError('invalid JSON state') from None
def release_version_from_source(source):
 text=(source/'cmd/control-plane/main.go').read_text()
 matches=re.findall(r'"version"\s*:\s*"(\d+\.\d+\.\d+)"',text)
 if not matches:
  frontend=(source/'cmd/control-plane/imported_subscription_frontend.go').read_text()
  matches=re.findall(r'\bconst\s+controlPlaneVersion\s*=\s*"(\d+\.\d+\.\d+)"',frontend)
 if len(set(matches))!=1:raise LifecycleError('cannot determine one Control Plane version from source')
 return matches[0]
def migration_number(source):
 values=[int(match.group(1)) for path in (source/'migrations').glob('*.sql') if (match:=MIGRATION.fullmatch(path.name))]
 if not values or sorted(values)!=list(range(1,max(values)+1)):raise LifecycleError('migration sequence is incomplete')
 return max(values)
def copy_entry(source,target):
 if source.is_dir():shutil.copytree(source,target,symlinks=False,ignore=shutil.ignore_patterns('node_modules','.next','.git','__pycache__'))
 elif source.is_file():target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target)
 else:raise LifecycleError('required release source entry is missing')
def deterministic_bundle(root,output):
 manifest=root/'manifest.json';paths=sorted([manifest]+[p for p in (root/'payload').rglob('*') if p.is_file()],key=lambda p:p.relative_to(root).as_posix())
 output.parent.mkdir(parents=True,exist_ok=True)
 with output.open('wb') as raw:
  with gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as zipped:
   with tarfile.open(fileobj=zipped,mode='w') as archive:
    for path in paths:
     name=path.relative_to(root).as_posix();info=archive.gettarinfo(str(path),arcname=name);info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0
     with path.open('rb') as stream:archive.addfile(info,stream)
def build(args):
 source=Path(args.source).resolve();output=Path(args.output).resolve()
 if not source.is_dir():raise LifecycleError('source directory does not exist')
 actual=release_version_from_source(source)
 if args.version!=actual:raise LifecycleError('requested version does not match source health version')
 schema=migration_number(source)
 with tempfile.TemporaryDirectory(prefix='vpn-platform-release-') as temporary:
  root=Path(temporary);payload=root/'payload';(payload/'bin').mkdir(parents=True)
  if not args.skip_tests:
   run(['/usr/local/go/bin/go','test','./...'],cwd=source,timeout=1800)
   run(['/usr/local/go/bin/go','vet','./...'],cwd=source,timeout=1800)
  built=[]
  for name in BINARIES+OPTIONAL_BINARIES:
   command=source/'cmd'/name
   if not command.is_dir():
    if name in BINARIES:raise LifecycleError('required command source is missing')
    continue
   target=payload/'bin'/name
   run(['/usr/local/go/bin/go','build','-trimpath','-ldflags=-buildid=','-o',str(target),'./cmd/'+name],cwd=source,timeout=1800)
   target.chmod(0o755);built.append(name)
  for name in SOURCE_ENTRIES:copy_entry(source/name,payload/'source'/name)
  for name in WEB_ENTRIES:copy_entry(source/'web'/name,payload/'web'/name)
  unit_source=source/'deploy/systemd'
  if not unit_source.is_dir():raise LifecycleError('systemd release templates are missing')
  copy_entry(unit_source,payload/'systemd')
  files={p.relative_to(root).as_posix():{'sha256':sha256(p),'size_bytes':p.stat().st_size} for p in sorted(payload.rglob('*')) if p.is_file()}
  manifest_value={'format':1,'product':'vpn-platform-control-plane','version':args.version,'schema_version':schema,'tool_version':TOOL_VERSION,'built_at':build_time(),'platform':'linux-amd64','schema_policy':'additive_forward_only','binaries':built,'files':files}
  atomic_json(root/'manifest.json',manifest_value)
  deterministic_bundle(root,output)
 print(json.dumps({'status':'built','version':args.version,'schema_version':schema,'bundle':str(output),'sha256':sha256(output),'files':len(files)}))
def safe_name(name):
 path=PurePosixPath(name)
 return bool(name) and not name.startswith('/') and '..' not in path.parts and str(path)==name and '\\' not in name
def extract_bundle(bundle,target):
 seen=set()
 try:archive=tarfile.open(bundle,'r:gz')
 except Exception:raise LifecycleError('release bundle is unreadable') from None
 with archive:
  members=archive.getmembers()
  for member in members:
   if not safe_name(member.name) or member.name in seen or not member.isfile():raise LifecycleError('release bundle contains unsafe or unsupported entries')
   seen.add(member.name)
  if 'manifest.json' not in seen:raise LifecycleError('release manifest is missing')
  for member in members:
   destination=target/member.name;destination.parent.mkdir(parents=True,exist_ok=True)
   stream=archive.extractfile(member)
   if stream is None:raise LifecycleError('release member cannot be read')
   with destination.open('wb') as output:shutil.copyfileobj(stream,output)
   destination.chmod(member.mode&0o777)
 manifest=read_json(target/'manifest.json')
 if manifest.get('format')!=1 or manifest.get('product')!='vpn-platform-control-plane' or not VERSION.fullmatch(str(manifest.get('version',''))):raise LifecycleError('release identity is invalid')
 if manifest.get('platform')!='linux-amd64' or manifest.get('schema_policy')!='additive_forward_only':raise LifecycleError('release compatibility policy is invalid')
 expected=manifest.get('files')
 if not isinstance(expected,dict) or set(expected)!=set(seen)-{'manifest.json'}:raise LifecycleError('release file manifest is incomplete')
 for name,record in expected.items():
  path=target/name
  if not safe_name(name) or not path.is_file() or sha256(path)!=record.get('sha256') or path.stat().st_size!=record.get('size_bytes'):raise LifecycleError('release integrity check failed')
 binaries=manifest.get('binaries')
 if not isinstance(binaries,list) or not set(BINARIES).issubset(binaries):raise LifecycleError('release binaries are incomplete')
 if not isinstance(manifest.get('schema_version'),int) or manifest['schema_version']<1:raise LifecycleError('release schema version is invalid')
 return manifest
def verify(args):
 bundle=Path(args.bundle).resolve()
 if args.sha256:require_digest(bundle,args.sha256)
 with tempfile.TemporaryDirectory(prefix='vpn-platform-verify-') as temporary:manifest=extract_bundle(bundle,Path(temporary))
 print(json.dumps({'status':'verified','version':manifest['version'],'schema_version':manifest['schema_version'],'sha256':sha256(bundle),'files':len(manifest['files'])}))
def health():
 try:
  with urlopen('http://127.0.0.1:8080/healthz',timeout=10) as response:
   value=json.load(response)
  if response.status!=200 or value.get('status')!='ok':raise ValueError()
  return value
 except Exception:raise LifecycleError('Control Plane health check failed') from None
def unit_active(name):return subprocess.run(['systemctl','is-active','--quiet',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
def status(_args):
 value=read_json(STATE) if STATE.exists() else {'managed':False}
 result={'tool_version':TOOL_VERSION,'managed':STATE.exists(),'control_plane':health(),'core_services':{name:unit_active(name) for name in CORE_SERVICES},'timers':{name:unit_active(name) for name in TIMERS}}
 for key in ('version','schema_version','applied_at','mode','bundle_sha256','backup_id'):result[key]=value.get(key)
 print(json.dumps(result))
def validate_host(install=False):
 if os.uname().machine!='x86_64':raise LifecycleError('only amd64 hosts are supported')
 for command in ('systemctl','docker','python3','npm','node'):
  if shutil.which(command) is None:raise LifecycleError('required host command is missing')
 for path in (Path('/etc/vpn-platform/control-plane.env'),Path('/etc/vpn-platform/web.env')):
  if not path.is_file() or path.stat().st_mode&0o077:raise LifecycleError('required environment file is absent or too permissive')
 if subprocess.run(['docker','inspect',POSTGRES_CONTAINER],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:raise LifecycleError('PostgreSQL container is unavailable')
 if not install and not (LIVE/'bin/control-plane').is_file():raise LifecycleError('existing Control Plane installation is missing')
def adopt(args):
 require_root();validate_host()
 if STATE.exists() and not args.replace:raise LifecycleError('installation is already managed')
 bundle=Path(args.bundle).resolve();digest=require_digest(bundle,args.sha256)
 with tempfile.TemporaryDirectory(prefix='vpn-platform-adopt-') as temporary:manifest=extract_bundle(bundle,Path(temporary))
 current=health().get('version')
 if current!=manifest['version']:raise LifecycleError('running version does not match release bundle')
 if args.schema!=manifest['schema_version']:raise LifecycleError('declared schema does not match release bundle')
 value={'format':1,'managed':True,'version':current,'schema_version':args.schema,'mode':'adopted','bundle_sha256':digest,'applied_at':now(),'backup_id':None}
 atomic_json(STATE,value)
 print(json.dumps({'status':'adopted','version':current,'schema_version':args.schema}))
def snapshot_application(identifier):
 root=BACKUPS/identifier;root.mkdir(parents=True,mode=0o700)
 include=[]
 for name in BINARIES+OPTIONAL_BINARIES:
  path=LIVE/'bin'/name
  if path.is_file():include.append(path)
 for name in SOURCE_ENTRIES:
  path=LIVE/name
  if path.exists():include.append(path)
 for name in WEB_ENTRIES+('.next',WEB_RUNTIME):
  path=LIVE/'web'/name
  if path.exists():include.append(path)
 for path in UNITS.glob('vpn-platform-*.service'):include.append(path)
 for path in UNITS.glob('vpn-platform-*.timer'):include.append(path)
 for path in UNITS.glob('vpn-platform-*.service.d'):
  if path.is_symlink() or not path.is_dir():raise LifecycleError('systemd drop-in directory is unsafe')
  if any(child.is_symlink() for child in path.rglob('*')):raise LifecycleError('systemd drop-in contains an unsafe link')
  include.append(path)
 archive_path=root/'application.tgz'
 with tarfile.open(archive_path,'w:gz',dereference=False) as archive:
  for source in include:archive.add(source,arcname=str(source).lstrip('/'),recursive=True)
 previous=read_json(STATE) if STATE.exists() else None
 atomic_json(root/'manifest.json',{'format':1,'id':identifier,'created_at':now(),'application_sha256':sha256(archive_path),'previous_state':previous},0o600)
 return root
def managed_backup():
 if not BACKUP_TOOL.is_file():raise LifecycleError('managed backup tool is missing')
 result=run(['python3',str(BACKUP_TOOL),'control-plane','create','--keep','7','--no-report'],timeout=1800)
 try:value=json.loads(result.stdout)
 except Exception:raise LifecycleError('managed backup did not return a valid result') from None
 if value.get('status')!='verified':raise LifecycleError('managed backup was not verified')
 return value['id']
def arm_guard(identifier):
 if not TOOL.is_file():raise LifecycleError('installed lifecycle tool is missing')
 run(['systemd-run','--unit=vpn-platform-lifecycle-guard-'+identifier[-8:],'--on-active=10m',str(TOOL),'rollback','--backup',identifier,'--automatic'])
def disarm_guard(identifier):
 subprocess.run(['systemctl','stop','vpn-platform-lifecycle-guard-'+identifier[-8:]+'.timer'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
def apply_migrations(stage,current,target,on_applied=None):
 if target<current:raise LifecycleError('database downgrade is not supported')
 files={int(match.group(1)):path for path in (stage/'payload/source/migrations').glob('*.sql') if (match:=MIGRATION.fullmatch(path.name))}
 for number in range(current+1,target+1):
  path=files.get(number)
  if path is None:raise LifecycleError('required migration is missing')
  run(['docker','exec','-i',POSTGRES_CONTAINER,'sh','-c','psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1'],input=path.read_bytes(),timeout=900)
  if on_applied:on_applied(number)
def install_units(stage):
 for path in (stage/'payload/systemd').glob('vpn-platform-*'):
  if path.is_file():
   shutil.copy2(path,UNITS/path.name);os.chmod(UNITS/path.name,0o644)
   continue
  if not path.is_dir():continue
  for source in path.rglob('*'):
   if not source.is_file():continue
   relative=(Path(path.name)/source.relative_to(path)).as_posix()
   if relative not in MANAGED_UNIT_DROPINS or source.is_symlink():raise LifecycleError('release contains an unapproved systemd drop-in')
   if not source.read_text(encoding='utf-8').startswith(MANAGED_UNIT_DROPIN_MARKER):raise LifecycleError('release systemd drop-in lacks lifecycle marker')
   target=UNITS/relative
   if target.exists():
    if target.is_symlink() or not target.is_file() or not target.read_text(encoding='utf-8').startswith(MANAGED_UNIT_DROPIN_MARKER):raise LifecycleError('refusing to replace an unmanaged systemd drop-in')
   target.parent.mkdir(parents=True,exist_ok=True)
   shutil.copy2(source,target);os.chmod(target,0o644)
 run(['systemctl','daemon-reload'])
def validate_managed_unit_dropins(stage):
 for relative in MANAGED_UNIT_DROPINS:
  source=stage/'payload/systemd'/relative
  target=UNITS/relative
  if source.exists() and (source.is_symlink() or not source.is_file() or not source.read_text(encoding='utf-8').startswith(MANAGED_UNIT_DROPIN_MARKER)):
   raise LifecycleError('release systemd drop-in is invalid')
  if target.exists() and (target.is_symlink() or not target.is_file() or not target.read_text(encoding='utf-8').startswith(MANAGED_UNIT_DROPIN_MARKER)):
   raise LifecycleError('refusing to replace an unmanaged systemd drop-in')
def install_payload(stage):
 if not (stage/'payload/web'/WEB_RUNTIME/'server.js').is_file():raise LifecycleError('Next.js standalone server entry is missing')
 LIVE.mkdir(parents=True,exist_ok=True);os.chmod(LIVE,0o755)
 (LIVE/'bin').mkdir(parents=True,exist_ok=True);os.chmod(LIVE/'bin',0o755)
 for path in (stage/'payload/bin').iterdir():
  target=LIVE/'bin'/path.name;temporary=target.with_name('.'+target.name+'.lifecycle')
  shutil.copy2(path,temporary);os.chmod(temporary,0o755);os.replace(temporary,target)
 for name in SOURCE_ENTRIES:
  source=stage/'payload/source'/name;target=LIVE/name
  if target.exists():shutil.rmtree(target) if target.is_dir() else target.unlink()
  copy_entry(source,target)
 web=LIVE/'web';web.mkdir(parents=True,exist_ok=True);os.chmod(web,0o755)
 for name in WEB_ENTRIES:
  source=stage/'payload/web'/name;target=web/name
  if target.exists():shutil.rmtree(target) if target.is_dir() else target.unlink()
  copy_entry(source,target)
 for name in ('.next','node_modules'):
  source=stage/'payload/web'/name;target=web/name
  if target.exists():shutil.rmtree(target) if target.is_dir() else target.unlink()
 for name in (WEB_RUNTIME,):
  source=stage/'payload/web'/name;target=web/name
  if target.exists():shutil.rmtree(target) if target.is_dir() else target.unlink()
  if not source.is_dir() or source.is_symlink():raise LifecycleError('standalone runtime directory is missing or unsafe')
  shutil.copytree(source,target,symlinks=False)
 shutil.chown(web,user='vpnplatform-web',group='vpnplatform-web')
 for path in web.rglob('*'):
  try:shutil.chown(path,user='vpnplatform-web',group='vpnplatform-web')
  except FileNotFoundError:pass
 install_units(stage)
 shutil.copy2(stage/'payload/source/scripts/platform-lifecycle.py',TOOL);os.chmod(TOOL,0o700)
 sync_operation_tools()

def sync_operation_tools():
 for name in ('platform-backup.py','platform-restore-drill.py'):
  source=LIVE/'scripts'/name
  if source.is_file():
   target=TOOL.parent/name;shutil.copy2(source,target);os.chmod(target,0o700)
def build_web(stage):
 web=stage/'payload/web';environment={**os.environ,'NEXT_TELEMETRY_DISABLED':'1'}
 run(['npm','ci','--include=dev','--no-audit','--no-fund'],cwd=web,env=environment,timeout=1800)
 run(['npm','run','build'],cwd=web,env=environment,timeout=1800)
 source=web/'.next/standalone';runtime=web/WEB_RUNTIME
 if not source.is_dir():raise LifecycleError('Next.js standalone output is missing')
 if runtime.exists():shutil.rmtree(runtime)
 shutil.copytree(source,runtime)
 public=web/'public'
 if public.is_dir():shutil.copytree(public,runtime/'public',dirs_exist_ok=True)
 static=web/'.next/static'
 if not static.is_dir():raise LifecycleError('Next.js static output is missing')
 shutil.copytree(static,runtime/'.next/static',dirs_exist_ok=True)
 if not (runtime/'server.js').is_file():raise LifecycleError('Next.js standalone server entry is missing')
def restore_web_snapshot(restored):
 web=LIVE/'web';web.mkdir(parents=True,exist_ok=True)
 for name in WEB_ENTRIES+('.next','node_modules',WEB_RUNTIME):
  source=restored/'opt/vpn-platform/web'/name;target=web/name
  if target.exists():shutil.rmtree(target) if target.is_dir() else target.unlink()
  if source.exists():
   if name==WEB_RUNTIME:
    if not source.is_dir() or source.is_symlink():raise LifecycleError('rollback standalone runtime is unsafe')
    shutil.copytree(source,target,symlinks=False)
   else:copy_entry(source,target)
 if not (web/WEB_RUNTIME/'server.js').is_file():
  run(['npm','ci','--include=dev','--no-audit','--no-fund'],cwd=web,env={**os.environ,'NEXT_TELEMETRY_DISABLED':'1'},timeout=1800)
 shutil.chown(web,user='vpnplatform-web',group='vpnplatform-web')
 for path in web.rglob('*'):
  try:shutil.chown(path,user='vpnplatform-web',group='vpnplatform-web')
  except FileNotFoundError:pass
def restore_managed_unit_dropins(restored):
 for relative in MANAGED_UNIT_DROPINS:
  target=UNITS/relative;source=restored/'etc/systemd/system'/relative
  if target.exists() and (target.is_symlink() or not target.is_file() or not target.read_text(encoding='utf-8').startswith(MANAGED_UNIT_DROPIN_MARKER)):
   raise LifecycleError('managed systemd drop-in changed after release; refusing to overwrite it')
  if source.exists():
   if source.is_symlink() or not source.is_file():raise LifecycleError('rollback systemd drop-in is unsafe')
   target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target)
  elif target.exists():target.unlink()
def ensure_users():
 for name in ('vpnplatform','vpnplatform-web'):
  if subprocess.run(['id','-u',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
   run(['useradd','--system','--home','/nonexistent','--shell','/usr/sbin/nologin',name])
def ensure_administrator_owner():
 # Bootstrap under the release rollback guard. Never overwrite an existing
 # account or infer a reset from a changed environment credential.
 try:
  values={}
  for line in Path('/etc/vpn-platform/web.env').read_text().splitlines():
   if not line.strip() or line.lstrip().startswith('#') or '=' not in line:continue
   key,value=line.split('=',1);parts=shlex.split(value);values[key.strip()]=parts[0] if parts else ''
  token=values['CONTROL_PLANE_ADMIN_TOKEN'];base='http://127.0.0.1:8080'
  headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'}
  def accounts():
   with urlopen(Request(base+'/api/v1/admin/accounts',headers=headers),timeout=10) as response:return json.load(response)['accounts']
  current=accounts()
  if not current:
   payload=json.dumps({'username':values['WEB_ADMIN_USER'],'password_hash':values['WEB_ADMIN_PASSWORD_HASH']}).encode()
   with urlopen(Request(base+'/api/v1/admin/bootstrap',headers=headers,data=payload,method='POST'),timeout=10) as response:json.load(response)
   current=accounts()
  if not any(item.get('enabled') and item.get('role')=='owner' for item in current):raise ValueError()
 except Exception:raise LifecycleError('administrator bootstrap or owner verification failed; credentials suppressed') from None

def restart_and_check(version):
 for service in CORE_SERVICES:run(['systemctl','enable',service])
 run(['systemctl','restart','vpn-platform-control-plane.service'])
 for _ in range(30):
  try:
   if health().get('version')==version:break
  except LifecycleError:pass
  time.sleep(1)
 else:raise LifecycleError('new Control Plane did not become healthy')
 if version_tuple(version)>=(0,1,81):ensure_administrator_owner()
 run(['systemctl','restart','vpn-platform-web.service'])
 for _ in range(30):
  try:
   with urlopen('http://127.0.0.1:3000/login',timeout=5) as response:
    if response.status==200:break
  except Exception:pass
  time.sleep(1)
 else:raise LifecycleError('new web interface did not become healthy')
 for timer in TIMERS:run(['systemctl','enable','--now',timer])
 for timer,requirement in OPTIONAL_TIMERS:
  if Path(requirement).exists():run(['systemctl','enable','--now',timer])
 for service in CORE_SERVICES:
  if not unit_active(service):raise LifecycleError('core service is inactive after release')
def apply_release(args,mode):
 require_root();installing=mode=='install';validate_host(install=installing)
 bundle=Path(args.bundle).resolve();digest=require_digest(bundle,args.sha256)
 existing=read_json(STATE) if STATE.exists() else None
 if installing and existing and not (existing.get('mode')=='installing' and existing.get('bundle_sha256')==digest):raise LifecycleError('managed installation already exists')
 if not installing and not STATE.exists():raise LifecycleError('adopt the current installation first')
 with tempfile.TemporaryDirectory(prefix='vpn-platform-apply-',dir='/opt') as temporary:
  stage=Path(temporary);manifest=extract_bundle(bundle,stage);build_web(stage)
  state=read_json(STATE) if STATE.exists() else {'schema_version':0,'version':None}
  if mode=='upgrade' and version_tuple(manifest['version'])<=version_tuple(state.get('version','')):raise LifecycleError('upgrade requires a newer version')
  if mode=='repair' and manifest['version']!=state.get('version'):raise LifecycleError('repair requires the managed version')
  if manifest['schema_version']<state.get('schema_version',0):raise LifecycleError('release schema is older than installed schema')
  validate_managed_unit_dropins(stage)
  managed_id=managed_backup() if not installing else None
  identifier=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]
  backup=snapshot_application(identifier) if not installing else None
  if installing:ensure_users();LIVE.mkdir(parents=True,exist_ok=True)
  else:arm_guard(identifier)
  try:
   def record_schema(number):
    progress=dict(state);progress['format']=1;progress['schema_version']=number;progress['applied_at']=now()
    if installing:progress.update({'managed':True,'version':manifest['version'],'mode':'installing','bundle_sha256':digest,'backup_id':None})
    else:progress['mode']='migration_applied_pending_release'
    atomic_json(STATE,progress)
   apply_migrations(stage,state.get('schema_version',0),manifest['schema_version'],record_schema)
   install_payload(stage);restart_and_check(manifest['version'])
   value={'format':1,'managed':True,'version':manifest['version'],'schema_version':manifest['schema_version'],'mode':mode,'bundle_sha256':digest,'applied_at':now(),'backup_id':identifier if backup else None,'managed_backup_id':managed_id}
   atomic_json(STATE,value)
   if backup:
    (backup/'committed').touch(mode=0o600);disarm_guard(identifier)
  except Exception:
   if backup:rollback_value(identifier,automatic=True)
   raise
 outcome={'install':'installed','upgrade':'upgraded','repair':'repaired'}[mode]
 print(json.dumps({'status':outcome,'version':manifest['version'],'schema_version':manifest['schema_version'],'backup_id':identifier if backup else None,'managed_backup_id':managed_id}))
def restore_tar(archive,root):
 with tarfile.open(archive,'r:gz') as tar:
  members=tar.getmembers()
  for member in members:
   if not safe_name(member.name) or not (member.isfile() or member.isdir()):raise LifecycleError('rollback archive is unsafe')
  for member in members:
   target=root/member.name
   if member.isdir():target.mkdir(parents=True,exist_ok=True);continue
   target.parent.mkdir(parents=True,exist_ok=True);stream=tar.extractfile(member)
   with target.open('wb') as output:shutil.copyfileobj(stream,output)
   target.chmod(member.mode&0o777)
def database_boolean(statement):
 result=run(['docker','exec','-i',POSTGRES_CONTAINER,'sh','-c','exec psql -X -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At -v ON_ERROR_STOP=1'],input=statement.encode(),timeout=30)
 value=result.stdout.strip()
 if value not in (b't',b'f'):raise LifecycleError('database compatibility check returned an invalid result')
 return value==b't'

def hysteria_rollback_blocker(previous_version):
 if version_tuple(previous_version)<version_tuple(HYSTERIA_MIN_CP_VERSION):
  return "SELECT EXISTS(SELECT 1 FROM public.nodes WHERE runtime_core='hysteria2');"
 # Registry approval is API-only. Refusing once the new release is approved
 # also closes the background-rollout race before stopping the API writer.
 # Check current/applied intent as well, including a later registry revocation.
 return "SELECT EXISTS(SELECT 1 FROM public.core_releases WHERE core_type='hysteria2' AND version='2.13.0' AND approved AND NOT revoked) OR EXISTS(SELECT 1 FROM public.nodes n JOIN public.desired_states d ON d.node_id=n.id AND d.generation IN (n.desired_generation,n.applied_generation) WHERE n.runtime_core='hysteria2' AND d.document #>> '{core,version}'='2.13.0');"
def prepare_runtime_rollback(previous):
 if not isinstance(previous,dict):raise LifecycleError('rollback has no prior release identity')
 if version_tuple(previous.get('version',''))>=(0,1,147):return
 has_identity=database_boolean("SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='nodes' AND column_name='runtime_core');")
 if not has_identity:return
 statement=hysteria_rollback_blocker(previous.get('version',''))
 if database_boolean(statement):raise LifecycleError('rollback target cannot read the approved or active Hysteria release; current Control Plane retained')
 # Node creation is an API operation. Quiesce its sole application writer and
 # recheck before replacing files, closing the first-check/new-node race.
 # The lifecycle lock already excludes concurrent migrations and releases.
 service='vpn-platform-control-plane.service'
 running=unit_active(service)
 try:
  # Stop also cancels an inactive unit's pending automatic restart.
  run(['systemctl','stop',service],timeout=60)
  if database_boolean(statement):raise LifecycleError('a Hysteria node appeared during rollback preparation; current release retained')
 except Exception:
  if running:run(['systemctl','start',service],timeout=60)
  raise

def rollback_value(identifier,automatic=False):
 if not BACKUP_ID.fullmatch(identifier):raise LifecycleError('invalid lifecycle backup ID')
 backup=BACKUPS/identifier
 if backup.is_symlink() or backup.resolve().parent!=BACKUPS.resolve():raise LifecycleError('rollback path escaped backup root')
 manifest=read_json(backup/'manifest.json');archive=backup/'application.tgz'
 if manifest.get('id')!=identifier or sha256(archive)!=manifest.get('application_sha256'):raise LifecycleError('rollback backup integrity check failed')
 if automatic and (backup/'committed').exists():return
 if (backup/'rolled-back').exists():return
 prepare_runtime_rollback(manifest.get('previous_state'))
 subprocess.run(['systemctl','stop','vpn-platform-web.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 run(['systemctl','stop','vpn-platform-control-plane.service'],timeout=60)
 with tempfile.TemporaryDirectory(prefix='vpn-platform-rollback-',dir='/opt') as temporary:
  restored=Path(temporary);restore_tar(archive,restored)
  for name in BINARIES+OPTIONAL_BINARIES:
   source=restored/'opt/vpn-platform/bin'/name
   if source.is_file():shutil.copy2(source,LIVE/'bin'/name);os.chmod(LIVE/'bin'/name,0o755)
  for name in SOURCE_ENTRIES:
   source=restored/'opt/vpn-platform'/name
   if not source.exists():continue
   target=LIVE/name
   if target.exists():shutil.rmtree(target) if target.is_dir() else target.unlink()
   copy_entry(source,target)
  restore_web_snapshot(restored)
  for path in (restored/'etc/systemd/system').glob('vpn-platform-*'):
   if path.is_file():shutil.copy2(path,UNITS/path.name)
  restore_managed_unit_dropins(restored)
  run(['systemctl','daemon-reload'])
 previous=manifest.get('previous_state')
 sync_operation_tools()
 if previous:
  current=read_json(STATE) if STATE.exists() else {}
  previous['schema_version']=max(previous.get('schema_version',0),current.get('schema_version',0))
  previous['mode']='rollback';previous['applied_at']=now();previous['backup_id']=identifier
  atomic_json(STATE,previous)
 restart_and_check(previous['version'])
 (backup/'rolled-back').touch(mode=0o600);disarm_guard(identifier)
 print(json.dumps({'status':'rolled_back','backup_id':identifier,'automatic':automatic,'database_schema_retained':True}))
def rollback(args):require_root();rollback_value(args.backup,args.automatic)
def parser():
 p=argparse.ArgumentParser(description='VPN Platform Control Plane lifecycle tool');p.add_argument('--tool-version',action='version',version=TOOL_VERSION);sub=p.add_subparsers(dest='command',required=True)
 b=sub.add_parser('build');b.add_argument('--source',required=True);b.add_argument('--output',required=True);b.add_argument('--version',required=True);b.add_argument('--skip-tests',action='store_true');b.set_defaults(function=build)
 v=sub.add_parser('verify');v.add_argument('--bundle',required=True);v.add_argument('--sha256');v.set_defaults(function=verify)
 s=sub.add_parser('status');s.set_defaults(function=status)
 a=sub.add_parser('adopt');a.add_argument('--bundle',required=True);a.add_argument('--sha256',required=True);a.add_argument('--schema',type=int,required=True);a.add_argument('--replace',action='store_true');a.set_defaults(function=adopt)
 for name in ('install','upgrade','repair'):
  command=sub.add_parser(name);command.add_argument('--bundle',required=True);command.add_argument('--sha256',required=True);command.set_defaults(function=lambda args,n=name:apply_release(args,n))
 r=sub.add_parser('rollback');r.add_argument('--backup',required=True);r.add_argument('--automatic',action='store_true',help=argparse.SUPPRESS);r.set_defaults(function=rollback)
 return p
def main():
 os.umask(0o077)
 try:
  args=parser().parse_args()
  if args.command in ('adopt','install','upgrade','repair','rollback','status'):
   LOCK.parent.mkdir(parents=True,exist_ok=True)
   with LOCK.open('a') as lock:fcntl.flock(lock,fcntl.LOCK_EX);args.function(args)
  else:args.function(args)
  return 0
 except LifecycleError as error:print('LIFECYCLE_FAILED: '+str(error),file=sys.stderr);return 1
 except KeyboardInterrupt:print('LIFECYCLE_INTERRUPTED: rollback guard remains active for unfinished changes',file=sys.stderr);return 130
if __name__=='__main__':sys.exit(main())
