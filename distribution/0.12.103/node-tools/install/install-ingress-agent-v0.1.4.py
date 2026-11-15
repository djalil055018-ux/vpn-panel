#!/usr/bin/python3
"""Install only the PAUK ingress companion beside an already registered agent."""
import argparse,re,hashlib,json,os,pathlib,platform,stat,subprocess,tempfile,urllib.request,urllib.parse
P=pathlib.Path;DIGEST='c75e33b056b412df99d08805fb084d67a0930bb2cd741b544f25754511ab0100'
BIN=P('/opt/vpn-platform/bin/pauk-ingress-agent');CFG=P('/etc/vpn-platform/ingress-agent.json');UNIT=P('/etc/systemd/system/pauk-ingress-agent.service');STATE=P('/var/lib/vpn-platform/agent/state.json')
def run(a):return subprocess.run(a,capture_output=True,check=True,timeout=20).stdout
def safe_dir(p,mode=0o755):
 for parent in reversed([p,*p.parents][:-1]):
  if not parent.exists():parent.mkdir(mode=mode)
  s=parent.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'unsafe_directory'
def safe_file(p):
 s=p.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==0 and not s.st_mode&0o022,'unsafe_file';return s
def write(p,b,mode):
 safe_dir(p.parent)
 if p.exists()or p.is_symlink():safe_file(p)
 fd,n=tempfile.mkstemp(prefix='.pauk-ingress-',dir=p.parent)
 try:
  with os.fdopen(fd,'wb')as f:f.write(b);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),mode)
  os.replace(n,p)
 finally:
  if os.path.exists(n):os.unlink(n)
def protected():
 result={}
 for n in('vpn-platform-node-agent','vpn-platform-xray','vpn-platform-hysteria','vpn-platform-wireguard','vpn-platform-amneziawg','vpn-platform-openvpn','vpn-platform-pptp','pauk-mobile-ingress','pauk-secondary-ingress'):
  result[n]=run(['systemctl','show',n,'-p','MainPID,InvocationID,ActiveState'])
 config=P('/var/lib/vpn-platform/xray/config.json')
 if config.exists():result['native_config']=hashlib.sha256(config.read_bytes()).digest()
 return result
def main():
 assert os.geteuid()==0 and platform.system()=='Linux'and platform.machine()in('x86_64','amd64'),'linux_amd64_root_required'
 s=safe_file(STATE);assert not s.st_mode&0o077,'private_agent_identity_required';identity=json.loads(STATE.read_bytes());node=identity['node_id'];assert identity.get('agent_token'),'registered_agent_required'
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--panel-origin',required=True)
 parser.add_argument('--infrastructure',type=P)
 args=parser.parse_args()
 url=urllib.parse.urlsplit(args.panel_origin)
 assert url.scheme=='https' and re.fullmatch(r'[a-zA-Z0-9.-]+(?::[0-9]+)?',url.netloc) and url.path in ('','/') and not url.query and not url.fragment,'invalid_panel_origin'
 public_origin=urllib.parse.urlunsplit(('https',url.netloc,'','',''))
 infra={}
 if args.infrastructure:
  safe_file(args.infrastructure)
  infra=json.loads(args.infrastructure.read_bytes())
  assert isinstance(infra,dict),'invalid_infrastructure'
 role='origin' if node==infra.get('origin_node_id') else 'bridge' if node==infra.get('bridge_node_id') else 'entry'
 if role=='origin':assert P('/etc/pauk-managed-ingress/origin-template.conf').is_file(),'origin_template_required'
 origin=public_origin
 if role=='origin':origin='http://127.0.0.1:8080'
 cfg={'control_plane':origin,'state_path':str(STATE),'role':role,'infrastructure':infra}
 before=protected();opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
 with opener.open(public_origin+'/artifacts/ingress-agent/0.1.3/linux-amd64/pauk-ingress-agent',timeout=25)as r:
  assert r.status==200;binary=r.read(16*1024*1024)
 assert hashlib.sha256(binary).hexdigest()==DIGEST,'component_digest_mismatch'
 safe_dir(P('/var/lib/pauk-ingress-agent'),0o700);safe_dir(P('/etc/pauk-managed-ingress'))
 unit='''[Unit]
Description=PAUK ingress provisioning companion
After=network-online.target vpn-platform-node-agent.service
Wants=network-online.target
[Service]
Type=simple
ExecStart=/opt/vpn-platform/bin/pauk-ingress-agent worker
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadWritePaths=/var/lib/pauk-ingress-agent /etc/pauk-managed-ingress /etc/systemd/system
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
MemoryMax=192M
TasksMax=96
'''
 if role=='origin':unit+='ReadWritePaths=/etc/nginx/conf.d /var/www/pauk-finland-acme\nCapabilityBoundingSet=CAP_NET_ADMIN\n'
 elif role=='entry':unit+='CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n'
 else:unit+='CapabilityBoundingSet=\n'
 unit+='[Install]\nWantedBy=multi-user.target\n'
 new={BIN:(binary,0o755),CFG:((json.dumps(cfg,sort_keys=True)+'\n').encode(),0o600),UNIT:(unit.encode(),0o644)}
 old={p:(p.read_bytes(),stat.S_IMODE(safe_file(p).st_mode))if p.exists()else None for p in new}
 marker=P('/var/lib/pauk-ingress-agent/component-install.json')
 if any(v is not None for v in old.values()):
  assert marker.exists(),'unmanaged_component_files'
  metadata=json.loads(marker.read_bytes());assert metadata['component']=='pauk-ingress-agent','unknown_component'
  assert old[BIN]is not None and hashlib.sha256(old[BIN][0]).hexdigest()==metadata['binary_sha256'],'component_integrity_changed'
 if old[BIN] is not None:
  assert old[CFG] is not None and old[CFG][0]==new[CFG][0] and old[UNIT] is not None and old[UNIT][0]==new[UNIT][0],'component_configuration_changed'
 backup=P('/var/backups/vpn-platform/ingress-companion-0.1.3');safe_dir(backup,0o700)
 for index,(p,v)in enumerate(old.items()):
  if v is not None and not(backup/('before-'+str(index))).exists():write(backup/('before-'+str(index)),v[0],0o600)
 changed=any(old[p]is None or old[p][0]!=b for p,(b,mode)in new.items())
 try:
  for p,(b,mode)in new.items():write(p,b,mode)
  run(['systemctl','daemon-reload']);run(['systemctl','enable','pauk-ingress-agent.service'])
  run(['systemctl','restart'if changed else'start','pauk-ingress-agent.service'])
  assert run(['systemctl','show','pauk-ingress-agent.service','-p','ActiveState','--value']).strip()==b'active','component_not_active'
  protocol_unit=P('/etc/systemd/system/pauk-protocol-ingress.service')
  if changed and protocol_unit.exists():
   content=protocol_unit.read_text();assert 'ExecStart=/opt/vpn-platform/bin/pauk-ingress-agent protocol-relay\n'in content,'protocol_component_unit_changed'
   if run(['systemctl','show','pauk-protocol-ingress.service','-p','ActiveState','--value']).strip()==b'active':run(['systemctl','restart','pauk-protocol-ingress.service'])
  assert protected()==before,'native_runtime_changed'
  write(marker,(json.dumps({'component':'pauk-ingress-agent','version':'0.1.3','binary_sha256':DIGEST,'node_id':node,'role':role})+'\n').encode(),0o600)
 except BaseException:
  subprocess.run(['systemctl','stop','pauk-ingress-agent.service'],capture_output=True,timeout=15)
  for p,v in old.items():
   if v is None:
    if p.exists():p.unlink()
   else:write(p,v[0],v[1])
  subprocess.run(['systemctl','daemon-reload'],capture_output=True,timeout=15)
  if old[BIN]is not None:subprocess.run(['systemctl','start','pauk-ingress-agent.service'],capture_output=True,timeout=15)
  raise
 print(json.dumps({'status':'installed','component':'ingress-agent','version':'0.1.3','role':role,'native_runtime_changed':False}))
if __name__=='__main__':
 try:main()
 except BaseException as e:
  print(json.dumps({'status':'failed','error':str(e)if isinstance(e,AssertionError)else type(e).__name__}));raise SystemExit(1)
