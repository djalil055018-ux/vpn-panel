#!/usr/bin/env python3
"""Boot a verified Control Plane backup in a disposable local database and directory."""
import argparse,base64,fcntl,hashlib,hmac,importlib.util,json,os,re,secrets,shlex,shutil,signal,socket,subprocess,sys,tarfile,time,uuid
from pathlib import Path
from urllib.parse import urlsplit,urlunsplit,parse_qsl
from urllib.request import Request,urlopen
spec=importlib.util.spec_from_file_location('backup',Path(__file__).with_name('platform-backup.py'))
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
BASE=Path('/var/lib/vpn-platform/restore-drills')
DB=re.compile(r'^vpn_restore_drill_[0-9a-f]{16}$')
class DrillError(Exception):pass
MFA_VERIFIER='opt/vpn-platform/bin/verify-restored-mfa'
RESTORED_COUNTS_SQL="SELECT json_build_object('tenants',(SELECT count(*) FROM tenants),'nodes',(SELECT count(*) FROM nodes WHERE status<>'retired'),'clients',(SELECT count(*) FROM vpn_clients));"
def run(args,**kwargs):
 process=None
 try:
  timeout=kwargs.pop('timeout',600);process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,**kwargs)
  stdout,_=process.communicate(timeout=timeout)
  if process.returncode:raise DrillError('restore command failed; raw output suppressed')
  return stdout
 except BaseException:
  if process is not None and process.poll() is None:
   os.killpg(process.pid,signal.SIGKILL);process.wait()
  raise DrillError('restore command unavailable, interrupted or failed; raw output suppressed') from None
def env_values(data):
 out={}
 for line in data.decode().splitlines():
  if not line.strip() or line.lstrip().startswith('#') or '=' not in line:continue
  k,v=line.split('=',1);parts=shlex.split(v);out[k.strip()]=parts[0] if parts else ''
 return out
def clone_dsn(value,name):
 if not DB.fullmatch(name):raise DrillError('invalid disposable database name')
 u=urlsplit(value)
 params=parse_qsl(u.query,keep_blank_values=True,strict_parsing=True)
 if u.scheme not in ('postgres','postgresql') or u.hostname not in ('127.0.0.1','localhost','::1') or not u.path or u.fragment or any(k!='sslmode' or v not in ('disable','allow','prefer','require','verify-ca','verify-full') for k,v in params) or len(params)>1:raise DrillError('restore requires a local database URL with only an optional sslmode')
 return urlunsplit((u.scheme,u.netloc,'/'+name,u.query,''))
def extract_selected(archive,destination):
 exact={'etc/vpn-platform/control-plane.env','etc/vpn-platform/web.env','opt/vpn-platform/bin/control-plane'}
 web='opt/vpn-platform/web/'
 configs={'package.json','package-lock.json','next.config.ts','tsconfig.json','postcss.config.mjs','eslint.config.mjs'}
 seen=set()
 with tarfile.open(archive,'r:gz') as tar:
  for item in tar:
   name=item.name
   if name.startswith('/') or '..' in Path(name).parts:raise DrillError('unsafe archive path')
   selected=name in exact or name==MFA_VERIFIER or name.startswith(web+'src/') or name.startswith(web+'public/') or name.removeprefix(web) in configs and name.startswith(web)
   if not selected:continue
   if item.isdir():continue
   if not item.isfile() or name in seen:raise DrillError('restore input has a link or duplicate member')
   seen.add(name);target=destination/name
   if destination.resolve() not in target.resolve().parents:raise DrillError('restore path escaped its target')
   target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
   with tar.extractfile(item) as source,target.open('xb') as output:shutil.copyfileobj(source,output)
   target.chmod(0o700 if name in ('opt/vpn-platform/bin/control-plane',MFA_VERIFIER) else 0o600)
 required=exact|{web+name for name in ['package.json','package-lock.json','postcss.config.mjs','tsconfig.json']}
 if not required.issubset(seen):raise DrillError('backup lacks files required for a complete web rebuild')
def free_port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def get(base,path,token=None,cookie=None):
 headers={}
 if token:headers['Authorization']='Bearer '+token
 if cookie:headers['Cookie']='vpn_platform_session='+cookie
 with urlopen(Request(base+path,headers=headers),timeout=15) as r:
  if r.status!=200 or r.url!=base+path:raise DrillError('restored application redirected or rejected a check')
  return r.read()
def ready(base,path,process):
 for _ in range(60):
  if process.poll() is not None:raise DrillError('restored process exited before readiness')
  try:return get(base,path)
  except Exception:time.sleep(.5)
 raise DrillError('restored application readiness timed out')
def verify_mfa(directory,env,version):
 verifier=directory/MFA_VERIFIER
 match=re.fullmatch(r'(\d+)\.(\d+)\.(\d+)',version)
 if not match:raise DrillError('restored version is invalid')
 if not verifier.is_file():
  if tuple(map(int,match.groups()))>=(0,1,85):raise DrillError('backup lacks required MFA verifier')
  return {'status':'not_supported_by_archived_release'}
 try:result=json.loads(run([str(verifier)],env=env,timeout=40))
 except Exception:raise DrillError('restored MFA verification failed') from None
 if not isinstance(result,dict) or result.get('status')!='verified' or type(result.get('key_configured')) is not bool or any(type(result.get(k)) is not int or result[k]<0 for k in ('enabled_accounts','pending_enrollments')):raise DrillError('invalid MFA verification result')
 return {k:result[k] for k in ('status','enabled_accounts','pending_enrollments','key_configured')}

def drill(backup_id):
 if not b.ID.fullmatch(backup_id):raise DrillError('invalid backup ID')
 path=b.ROOT/'control-plane'/backup_id;manifest=b.manifest(path)
 if manifest.get('status')!='verified' or set(manifest.get('files',{}))!={'configuration.tgz','database.dump'}:raise DrillError('verified complete backup required')
 for name,record in manifest['files'].items():
  file=path/name
  if file.is_symlink() or not file.is_file() or b.checksum(file)!=record['sha256']:raise DrillError('backup checksum mismatch')
 BASE.mkdir(parents=True,exist_ok=True,mode=0o700)
 if BASE.is_symlink():raise DrillError('restore root cannot be a symlink')
 if shutil.disk_usage(BASE).free<4*1024**3:raise DrillError('restore drill requires 4 GiB free')
 suffix=uuid.uuid4().hex[:16];name='vpn_restore_drill_'+suffix;directory=BASE/suffix;directory.mkdir(mode=0o700)
 created=False;processes=[];started=time.monotonic();result=None
 try:
  extract_selected(path/'configuration.tgz',directory)
  cp=env_values((directory/'etc/vpn-platform/control-plane.env').read_bytes());web=env_values((directory/'etc/vpn-platform/web.env').read_bytes())
  dsn=clone_dsn(cp['DATABASE_URL'],name)
  b.docker('createdb -U "$POSTGRES_USER" "$1"',name);created=True
  with (path/'database.dump').open('rb') as source:b.docker('pg_restore -U "$POSTGRES_USER" -d "$1" --exit-on-error --no-owner --no-privileges',name,stdin=source,stdout=subprocess.DEVNULL)
  # Seed a disposable session only in the verified clone, before making it
  # read-only. Personal sessions replace synthetic legacy cookies in CP >= .81.
  modern_cookie=None
  accounts=b.docker('psql -U "$POSTGRES_USER" -d "$1" -At -v ON_ERROR_STOP=1 -c "$2"',name,"SELECT to_regclass('public.admin_accounts') IS NOT NULL").strip()==b't'
  auth_source=directory/'opt/vpn-platform/web/src/lib/auth.ts'
  if accounts and auth_source.is_file() and 'vpa1_' in auth_source.read_text():
   modern_cookie='vpa1_'+secrets.token_urlsafe(32);digest=hashlib.sha256(modern_cookie.encode()).hexdigest()
   sql="INSERT INTO admin_sessions(account_id,token_hash,expires_at) SELECT id,'"+digest+"',now()+interval '20 minutes' FROM admin_accounts WHERE enabled AND role='owner' ORDER BY created_at LIMIT 1 RETURNING id;"
   inserted=b.docker('psql -U "$POSTGRES_USER" -d "$1" -At -v ON_ERROR_STOP=1 -c "$2"',name,sql)
   if b'INSERT 0 1' not in inserted:raise DrillError('restored database has no active owner')
  # No background workers are launched. The clone defaults to read-only and
  # both servers bind only to random loopback ports with fresh admin/session keys.
  b.docker('psql -U "$POSTGRES_USER" -d "$1" -v ON_ERROR_STOP=1 -c "$2"',name,'ALTER DATABASE '+name+' SET default_transaction_read_only=on')
  counts=json.loads(b.docker('psql -U "$POSTGRES_USER" -d "$1" -At -v ON_ERROR_STOP=1 -c "$2"',name,RESTORED_COUNTS_SQL))
  print('RESTORE_DRILL_DATABASE_READ_ONLY_CLONE_GREEN',flush=True)
  admin=secrets.token_urlsafe(32);cpport=free_port();cpbase='http://127.0.0.1:'+str(cpport)
  env={**os.environ,**cp,'DATABASE_URL':dsn,'ADMIN_TOKEN':admin,'LISTEN_ADDR':'127.0.0.1:'+str(cpport)}
  process=subprocess.Popen([str(directory/'opt/vpn-platform/bin/control-plane')],cwd=directory,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True);processes.append(process)
  health=json.loads(ready(cpbase,'/healthz',process));tenants=json.loads(get(cpbase,'/api/v1/tenants',admin))['tenants'];nodes=json.loads(get(cpbase,'/api/v1/nodes',admin))['nodes']
  mfa_verification=verify_mfa(directory,env,health['version'])
  print('RESTORE_DRILL_MFA_STATE_CHECK='+mfa_verification['status'],flush=True)
  if len(tenants)!=counts['tenants'] or len(nodes)!=counts['nodes']:raise DrillError('restored application counts differ from restored database')
  for route in ['/api/v1/audit-event-types','/api/v1/operations/incidents','/api/v1/webhooks/status']:get(cpbase,route,admin)
  for tenant in tenants:
   tid=str(uuid.UUID(tenant['id']))
   for route in ['vpn-clients','access-plans','api-tokens','branding','children','webhooks']:get(cpbase,'/api/v1/tenants/'+tid+'/'+route,admin)
  print('RESTORE_DRILL_CONTROL_PLANE_BOOT_AND_API_GREEN',flush=True)
  webdir=directory/'opt/vpn-platform/web';node='/usr/local/bin/node';npm='/usr/local/bin/npm';session=secrets.token_urlsafe(32)
  we={**os.environ,**web,'PATH':'/usr/local/bin:'+os.environ.get('PATH',''),'CONTROL_PLANE_URL':cpbase,'CONTROL_PLANE_ADMIN_TOKEN':admin,'WEB_SESSION_SECRET':session,'WEB_ADMIN_USER':'restore-drill','WEB_ADMIN_PASSWORD_HASH':secrets.token_urlsafe(32),'NEXT_TELEMETRY_DISABLED':'1'}
  run([npm,'ci','--include=dev','--no-audit','--no-fund'],cwd=webdir,env=we)
  print('RESTORE_DRILL_LOCKED_WEB_DEPENDENCIES_INSTALLED',flush=True)
  run([npm,'run','build'],cwd=webdir,env=we)
  print('RESTORE_DRILL_WEB_REBUILT_FROM_BACKUP_GREEN',flush=True)
  runtime=webdir/'standalone';source=webdir/'.next/standalone'
  if runtime.exists():shutil.rmtree(runtime)
  if not source.is_dir():raise DrillError('restored standalone web output is missing')
  shutil.copytree(source,runtime)
  if (webdir/'public').is_dir():shutil.copytree(webdir/'public',runtime/'public',dirs_exist_ok=True)
  if not (webdir/'.next/static').is_dir():raise DrillError('restored static web output is missing')
  shutil.copytree(webdir/'.next/static',runtime/'.next/static',dirs_exist_ok=True)
  wp=free_port();webbase='http://127.0.0.1:'+str(wp)
  webenv={**we,'HOSTNAME':'127.0.0.1','PORT':str(wp)}
  process=subprocess.Popen([node,str(runtime/'server.js')],cwd=runtime,env=webenv,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True);processes.append(process);ready(webbase,'/login',process)
  b64=lambda v:base64.urlsafe_b64encode(v).rstrip(b'=').decode();body=b64(json.dumps({'user':'restore-drill','exp':int(time.time())+120}).encode());cookie=body+'.'+b64(hmac.new(session.encode(),body.encode(),hashlib.sha256).digest())
  if modern_cookie:cookie=modern_cookie
  checks={'/limits':'Лимиты владельцев','/partners':'Партнёры','/audit':'Журнал действий','/webhooks':'Исходящие webhooks','/incidents':'Инциденты','/branding':'Оформление кабинета','/billing':'Биллинг','/api-access':'Доступ к API','/operations':'Состояние платформы','/access-plans':'Группы доступа','/clients':'Клиенты','/nodes':'Серверы (Смартфоны)'}
  if modern_cookie:checks.update({'/administrators':'Администраторы','/account':'Мой аккаунт','/monitor':'Наблюдение за платформой'})
  for route,label in checks.items():
   html=get(webbase,route,cookie=cookie).decode()
   if label not in html or admin in html or session in html:raise DrillError('restored web page or secret protection check failed')
  result={'schema_version':1,'status':'verified','backup_id':backup_id,'verified_at':b.now(),'control_plane_version':health['version'],'web_pages':len(checks),'database_counts':counts,'duration_seconds':int(time.monotonic()-started),'verification':'database_and_application_boot','mfa_verification':mfa_verification}
 finally:
  for process in reversed(processes):
   if process.poll() is None:
    process.terminate()
    try:process.wait(timeout=15)
    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
  if created and DB.fullmatch(name):b.docker('dropdb -U "$POSTGRES_USER" --force "$1"',name)
  if directory.exists() and directory.resolve().parent==BASE.resolve() and not directory.is_symlink():shutil.rmtree(directory)
 return result
def main():
 os.umask(0o077);p=argparse.ArgumentParser(description=__doc__);p.add_argument('--id',required=True);args=p.parse_args()
 if os.geteuid()!=0:raise SystemExit('RESTORE_DRILL_FAILED: run as root')
 def interrupted(*_):raise DrillError('restore drill interrupted')
 signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
 with b.LOCK.open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  try:result=drill(args.id)
  except Exception:
   b.atomic(b.STATUS/'restore-drill.json',{'schema_version':1,'status':'failed','checked_at':b.now(),'error':'isolated_restore_drill_failed'},0o644)
   print('RESTORE_DRILL_FAILED: isolated restore or application check failed; details suppressed',file=sys.stderr);return 1
  b.atomic(b.STATUS/'restore-drill.json',result,0o644);print(json.dumps(result));return 0
if __name__=='__main__':sys.exit(main())
