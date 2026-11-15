#!/usr/bin/env python3
"""Prepare the local HTTPS page for an existing PAUK node and certificate."""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys


AGENT_SHA = '9179331f96e1053a3e823111072af5e291d194f887fc21cb2b3cde0f84b819a3'
DOMAIN = re.compile(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\Z')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
WORKER = '#!/usr/bin/python3\n"""Install a loopback HTTPS cover and HTTP01 routing, with bounded recovery.\n\nNative VPN configuration and key material are deliberately untouched here.\n"""\nimport pathlib,json,os,subprocess,hashlib,time,sys,ssl,socket,stat,shutil,fcntl,contextlib\nP=pathlib.Path;R=P(__file__).parent;S=json.loads((R/\'spec.json\').read_bytes());J=R/\'journal.json\';sha=lambda b:hashlib.sha256(b).hexdigest()\ndef cmd(a,t=20,check=True):\n p=subprocess.run(a,capture_output=True,timeout=t)\n if check and p.returncode:raise AssertionError(\'COMMAND_FAILED_\'+P(a[0]).name)\n return p.stdout\ndef write(p,b,mode=0o644):\n p=P(p);p.parent.mkdir(exist_ok=True,parents=True);tmp=p.with_name(\'.\'+p.name+\'.pauk-next\');fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)\n with os.fdopen(fd,\'wb\')as f:f.write(b);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),mode)\n os.replace(tmp,p)\ndef unit(n):return cmd([\'systemctl\',\'show\',n,\'-p\',\'MainPID,ActiveState,InvocationID\'])\ndef edit(path,data,mode=0o644):\n p=P(path);j=json.loads(J.read_bytes());assert path not in j[\'files\']\n if p.exists():\n  st=p.lstat();assert p.resolve()==p and stat.S_ISREG(st.st_mode)and st.st_nlink==1;old=p.read_bytes();name=\'old-\'+str(len(j[\'files\']));write(R/name,old,0o600);row={\'old\':name,\'sha\':sha(old),\'mode\':stat.S_IMODE(st.st_mode)}\n else:row={\'old\':None}\n row[\'new_sha\']=sha(data);j[\'files\'][path]=row;write(J,json.dumps(j).encode(),0o600);write(path,data,mode)\ndef restart_routes():\n if S[\'role\']==\'origin\':cmd([\'nginx\',\'-t\']);cmd([\'systemctl\',\'reload\',\'nginx\'])\n if S[\'role\'] in(\'primary\',\'secondary\'):\n  conf=\'/etc/pauk-mobile-ingress/nginx.conf\'if S[\'role\']==\'primary\'else\'/etc/pauk-secondary-entry/nginx.conf\'\n  cmd([\'nginx\',\'-t\',\'-c\',conf]);cmd([\'systemctl\',\'reload\',\'pauk-mobile-ingress\'if S[\'role\']==\'primary\'else\'pauk-secondary-ingress\'])\ndef recover():\n if (R/\'COMMITTED.json\').exists()or (R/\'ROLLED_BACK.json\').exists()or not J.exists():return\n j=json.loads(J.read_bytes());cmd([\'systemctl\',\'disable\',\'--now\',\'pauk-node-cover\',\'pauk-node-cover-renew.timer\'],check=False)\n for path,row in reversed(list(j[\'files\'].items())):\n  p=P(path)\n  if p.exists():assert sha(p.read_bytes())in(row.get(\'sha\'),row[\'new_sha\']),\'RECOVERY_CONTENT_CHANGED\'\n  if row[\'old\']:write(p,(R/row[\'old\']).read_bytes(),row[\'mode\'])\n  elif p.exists():p.unlink()\n cmd([\'systemctl\',\'daemon-reload\']);restart_routes()\n if \'/etc/systemd/system/vpn-platform-node-agent.service.d/40-pauk-acme-listener.conf\' in j[\'files\']:cmd([\'systemctl\',\'restart\',\'vpn-platform-node-agent\'])\n # Keep the newly installed default nginx unit masked after rollback; only the task-owned cover may bind HTTP.\n\n write(R/\'ROLLED_BACK.json\',b\'{"phase":"ROLLED_BACK"}\',0o600)\ndef tls_probe(domain,version):\n ctx=ssl.create_default_context();ctx.minimum_version=version;ctx.maximum_version=version\n with socket.create_connection((\'127.0.0.1\',18443),3)as raw:\n  with ctx.wrap_socket(raw,server_hostname=domain)as s:\n   s.settimeout(3);s.sendall((\'GET / HTTP/1.1\\r\\nHost: \'+domain+\'\\r\\nConnection: close\\r\\n\\r\\n\').encode());data=b\'\'\n   while b\'\\r\\n\\r\\n\'not in data:\n    chunk=s.recv(4096)\n    if not chunk:break\n    data+=chunk\n   assert data.startswith(b\'HTTP/1.1 200\')and b\'Strict-Transport-Security: max-age=15552000\'in data,\'COVER_HTTP_FAILED\'\n   return s.version()\ndef install():\n assert json.loads(P(\'/var/lib/vpn-platform/agent/state.json\').read_bytes())[\'node_id\']==S[\'node_id\'],\'WRONG_NODE\'\n assert not J.exists();assert sha(P(\'/usr/local/bin/vpn-node-agent\').read_bytes())==S[\'old_agent_sha\'],\'AGENT_BASELINE_CHANGED\'\n cfg=P(\'/var/lib/vpn-platform/xray/config.json\');core_before=unit(\'vpn-platform-xray\');cfg_before=sha(cfg.read_bytes());other_before={n:unit(n)for n in(\'pauk-country-reserve\',\'pauk-protocol-ingress\')}\n write(R/\'native-config-before.sha256\',cfg_before.encode(),0o600);write(R/\'native-core-before.txt\',core_before,0o600)\n cert=P(S[\'cert\']);key=cert.with_name(\'private.key\');assert cert.is_file()and key.is_file();assert stat.S_IMODE(key.stat().st_mode)&0o007==0,\'TLS_PRIVATE_KEY_PERMISSIONS\'\n cmd([\'openssl\',\'x509\',\'-in\',str(cert),\'-noout\',\'-checkhost\',S[\'domain\']]);cmd([\'openssl\',\'x509\',\'-in\',str(cert),\'-noout\',\'-checkend\',\'86400\'])\n assert cmd([\'openssl\',\'x509\',\'-in\',str(cert),\'-pubkey\',\'-noout\'])==cmd([\'openssl\',\'pkey\',\'-in\',str(key),\'-pubout\']),\'TLS_KEY_MISMATCH\'\n assert S[\'ip\']in{r[4][0]for r in socket.getaddrinfo(S[\'domain\'],443,socket.AF_INET)},\'DNS_MISMATCH\'\n with socket.socket()as test:test.bind((\'127.0.0.1\',18443))\n write(J,b\'{"files":{}}\',0o600)\n if not P(\'/usr/sbin/nginx\').exists():\n  default_unit=P(\'/etc/systemd/system/nginx.service\')\n  already_masked=default_unit.is_symlink() and default_unit.readlink()==P(\'/dev/null\')\n  assert already_masked or (not default_unit.exists() and not default_unit.is_symlink()),\'NGINX_UNIT_EXISTS\'\n  plan=cmd([\'apt-get\',\'-s\',\'--no-upgrade\',\'install\',\'--no-install-recommends\',\'nginx=\'+S[\'nginx_version\'],\'nginx-common=\'+S[\'nginx_version\']],40).decode();assert \'\\nRemv \'not in plan,\'UNSAFE_PACKAGE_PLAN\';write(R/\'nginx-package-plan.txt\',plan.encode(),0o600)\n  assert {line.split()[1] for line in plan.splitlines() if line.startswith(\'Inst \')}<={\'nginx\',\'nginx-common\'},\'UNEXPECTED_PACKAGE_CHANGE\'\n  assert not any(line.split()[2].startswith(\'[\') for line in plan.splitlines() if line.startswith(\'Inst \')),\'PACKAGE_UPGRADE_NOT_ALLOWED\'\n  if not already_masked:\n   cmd([\'systemctl\',\'mask\',\'nginx\']);j=json.loads(J.read_bytes());j[\'nginx_mask_created\']=True;write(J,json.dumps(j).encode(),0o600)\n  env=os.environ|{\'DEBIAN_FRONTEND\':\'noninteractive\',\'NEEDRESTART_MODE\':\'l\'};p=subprocess.run([\'apt-get\',\'-y\',\'--no-upgrade\',\'install\',\'--no-install-recommends\',\'nginx=\'+S[\'nginx_version\'],\'nginx-common=\'+S[\'nginx_version\']],capture_output=True,env=env,timeout=140);write(R/\'nginx-install.log\',p.stdout+p.stderr,0o600);assert p.returncode==0,\'NGINX_INSTALL_FAILED\'\n  assert unit(\'vpn-platform-xray\')==core_before,\'PACKAGE_CHANGED_CORE\'\n domain=S[\'domain\'];role=S[\'role\'];challenge=\'location = /.well-known/pauk-node-\'+S[\'node_id\']+\' { return 204; } location ^~ /.well-known/acme-challenge/ { if ($request_method !~ ^(GET|HEAD)$) { return 405; } proxy_pass http://127.0.0.1:18080; proxy_set_header Host $host; proxy_connect_timeout 2s; proxy_read_timeout 8s; }\'\n http_server=\'server { listen \'+S[\'ip\']+\':80; server_name \'+domain+\'; \'+challenge+\' location / { return 301 https://\'+domain+\'$request_uri; } }\'\n conf=\'\'\'user www-data;\nworker_processes 1;\npid /run/pauk-node-cover/nginx.pid;\nerror_log stderr warn;\nevents { worker_connections 256; }\nhttp { server_tokens off; access_log off; client_max_body_size 1k; client_body_timeout 5s; client_header_timeout 5s; keepalive_timeout 10s; send_timeout 5s;\nclient_body_temp_path /run/pauk-node-cover/client;\nproxy_temp_path /run/pauk-node-cover/proxy;\nfastcgi_temp_path /run/pauk-node-cover/fastcgi;\nuwsgi_temp_path /run/pauk-node-cover/uwsgi;\nscgi_temp_path /run/pauk-node-cover/scgi;\nserver { listen 127.0.0.1:18443 ssl http2 default_server; server_name DOMAIN;\nssl_certificate CERT; ssl_certificate_key KEY;\nssl_protocols TLSv1.2 TLSv1.3;\nssl_session_cache shared:cover:1m; ssl_session_timeout 10m; ssl_session_tickets off;\nadd_header Strict-Transport-Security "max-age=15552000" always;\nadd_header X-Content-Type-Options nosniff always;\nadd_header Content-Security-Policy "default-src \'none\'; style-src \'unsafe-inline\'; frame-ancestors \'none\'" always;\ndefault_type text/html; location / { if ($request_method !~ ^(GET|HEAD)$) { return 405; } return 200 \'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Network service</title><style>body{font:18px system-ui;max-width:42rem;margin:12vh auto;padding:2rem;color:#243349;background:#f6f8fb}h1{font-size:2rem}</style><h1>Network service</h1><p>This service is online.</p></html>\'; }\n}\nHTTP\n}\n\'\'\'.replace(\'DOMAIN\',domain).replace(\'CERT\',str(cert)).replace(\'KEY\',str(key)).replace(\'HTTP\',http_server+\'\\nserver { listen \'+S[\'ip\']+\':80 default_server; server_name _; return 444; }\'if role==\'ordinary\'else\'\')\n edit(\'/etc/pauk-node-cover/nginx.conf\',conf.encode())\n unit_text=\'\'\'[Unit]\nDescription=Local HTTPS cover\nAfter=network.target\n[Service]\nType=forking\nPIDFile=/run/pauk-node-cover/nginx.pid\nRuntimeDirectory=pauk-node-cover\nRuntimeDirectoryMode=0755\nExecStartPre=/usr/sbin/nginx -t -c /etc/pauk-node-cover/nginx.conf\nExecStart=/usr/sbin/nginx -c /etc/pauk-node-cover/nginx.conf\nExecReload=/bin/kill -HUP $MAINPID\nExecStop=/bin/kill -QUIT $MAINPID\nRestart=on-failure\nRestartSec=3\nTimeoutStopSec=15\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nReadWritePaths=/run/pauk-node-cover\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_READ_SEARCH CAP_KILL\nMemoryMax=96M\nTasksMax=32\n[Install]\nWantedBy=multi-user.target\n\'\'\'\n edit(\'/etc/systemd/system/pauk-node-cover.service\',unit_text.encode())\n # The agent\'s HTTP01 solver is reachable only through named challenge routes.\n edit(\'/etc/systemd/system/vpn-platform-node-agent.service.d/40-pauk-acme-listener.conf\',b\'[Service]\\nEnvironment=VPN_ACME_HTTP_LISTEN=127.0.0.1:18080\\n\')\n if role==\'origin\':edit(\'/etc/nginx/conf.d/pauk-node-cover-http.conf\',http_server.encode())\n elif role==\'primary\':\n  p=P(\'/etc/pauk-mobile-ingress/nginx.conf\');text=p.read_text();assert text.count(\'http {\')==1 and domain not in text;idx=text.rfind(\'\\n}\');assert idx>0;edit(str(p),(text[:idx]+\'\\n\'+http_server+\'\\n\'+text[idx:]).encode())\n elif role==\'secondary\':\n  p=P(\'/etc/pauk-secondary-entry/nginx.conf\');text=p.read_text();old=\'listen 2.26.104.31:80;\';assert text.count(old)==1 and \'http {\'not in text;text=text.replace(old,\'listen 127.0.0.1:18081;\')\n  names=\'pauk.panel.winphonestore.name pauk.sub.winphonestore.name pauk.winphonestore.name sub.winphonestore.name\'\n  text+=\'\\nhttp { server_tokens off; access_log off; client_header_timeout 10s; \'+http_server+\'\\nserver { listen 2.26.104.31:80; server_name \'+names+\'; location ^~ /.well-known/acme-challenge/ { if ($request_method !~ ^(GET|HEAD)$) { return 405; } proxy_pass http://127.0.0.1:18081; proxy_set_header Host $host; proxy_connect_timeout 3s; proxy_read_timeout 10s; } location / { return 301 https://$host$request_uri; } } server { listen 2.26.104.31:80 default_server; server_name _; return 444; } }\\n\'\n  edit(str(p),text.encode())\n # Reload cover after renewal without exposing or moving the certificate key.\n renew=\'\'\'import pathlib,hashlib,subprocess\nP=pathlib.Path\ncert=P(CERT)\ndigest=hashlib.sha256(cert.read_bytes()).hexdigest()\nstamp=P(\'/var/lib/pauk-node-cover/certificate.sha256\')\nif not stamp.exists() or stamp.read_text()!=digest:\n subprocess.run([\'/usr/sbin/nginx\',\'-t\',\'-c\',\'/etc/pauk-node-cover/nginx.conf\'],check=True,capture_output=True,timeout=8)\n subprocess.run([\'systemctl\',\'reload\',\'pauk-node-cover\'],check=True,capture_output=True,timeout=8)\n stamp.write_text(digest)\n\'\'\'.replace(\'CERT\',repr(str(cert)))\n edit(\'/etc/pauk-node-cover/renew.py\',renew.encode())\n edit(\'/etc/systemd/system/pauk-node-cover-renew.service\',b\'[Unit]\\nDescription=Reload renewed HTTPS cover certificate\\n[Service]\\nType=oneshot\\nExecStart=/usr/bin/python3 /etc/pauk-node-cover/renew.py\\nStateDirectory=pauk-node-cover\\nStateDirectoryMode=0700\\nNoNewPrivileges=yes\\nProtectSystem=strict\\nProtectHome=yes\\nPrivateTmp=yes\\nReadWritePaths=/run/pauk-node-cover /var/lib/pauk-node-cover\\n\')\n edit(\'/etc/systemd/system/pauk-node-cover-renew.timer\',b\'[Unit]\\nDescription=Check HTTPS cover certificate renewal\\n[Timer]\\nOnBootSec=3min\\nOnUnitActiveSec=15min\\nRandomizedDelaySec=60s\\nPersistent=true\\n[Install]\\nWantedBy=timers.target\\n\')\n cmd([\'systemctl\',\'daemon-reload\']);restart_routes();cmd([\'systemctl\',\'enable\',\'--now\',\'pauk-node-cover\']);cmd([\'systemctl\',\'enable\',\'--now\',\'pauk-node-cover-renew.timer\'])\n versions=[tls_probe(domain,v)for v in(ssl.TLSVersion.TLSv1_2,ssl.TLSVersion.TLSv1_3)]\n\n ctx=ssl.create_default_context();ctx.minimum_version=ssl.TLSVersion.TLSv1_3;ctx.set_alpn_protocols([\'h2\'])\n with socket.create_connection((\'127.0.0.1\',18443),3) as conn:\n  with ctx.wrap_socket(conn,server_hostname=domain) as tls:\n   assert tls.selected_alpn_protocol()==\'h2\',\'COVER_H2_FAILED\'\n cmd([\'systemctl\',\'restart\',\'vpn-platform-node-agent\']);time.sleep(3)\n assert sha(P(\'/usr/local/bin/vpn-node-agent\').read_bytes())==S[\'old_agent_sha\'],\'AGENT_BINARY_CHANGED\'\n assert b\'ActiveState=active\'in unit(\'vpn-platform-node-agent\');assert b\'ActiveState=active\'in unit(\'vpn-platform-xray\')and sha(cfg.read_bytes())==cfg_before,\'NATIVE_CONFIG_CHANGED\';assert all(unit(n)==v for n,v in other_before.items()),\'RESERVE_CORE_CHANGED\'\n result={\'phase\':\'LOCAL_VERIFIED\',\'node_id\':S[\'node_id\'],\'domain\':domain,\'TLS_versions\':versions,\'HSTS\':True,\'http2\':True,\'agent\':\'0.2.51\',\'native_core_restarted\':unit(\'vpn-platform-xray\')!=core_before,\'native_config_changed\':False,\'planned_agent_restart\':True,\'role\':role,\'router_VPN_started\':False};write(R/\'LOCAL_VERIFIED.json\',json.dumps(result).encode(),0o600);return result\nif __name__==\'__main__\':\n with contextlib.ExitStack()as stack:\n  fd=stack.enter_context(open(\'/run/lock/pauk-node-local-cover.lock\',\'w\'));fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\n  if len(sys.argv)>1 and sys.argv[1]==\'recover\':recover()\n  else:\n   try:print(json.dumps(install()))\n   except BaseException as e:\n    write(R/\'FAILED.json\',json.dumps({\'phase\':\'FAIL\',\'error_type\':type(e).__name__,\'reason\':str(e)if isinstance(e,AssertionError)else None}).encode(),0o600)\n    recover();raise\n'


def run(*args, timeout=30):
    process = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if process.returncode:
        raise RuntimeError('COMMAND_FAILED_'+Path(args[0]).name)
    return process.stdout


def tls_ready(domain):
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['h2'])
    with socket.create_connection(('127.0.0.1',18443),timeout=5) as connection:
        with context.wrap_socket(connection,server_hostname=domain) as tls:
            return tls.selected_alpn_protocol()=='h2'


def local_address(domain):
    addresses = {item[4][0] for item in socket.getaddrinfo(domain,80,socket.AF_INET,socket.SOCK_STREAM)}
    local = {value['local'] for entry in json.loads(run('/usr/sbin/ip','-j','-4','address','show','scope','global'))
             for value in entry['addr_info']}
    if len(addresses)!=1 or not addresses.issubset(local) or not all(ipaddress.ip_address(ip).is_global for ip in addresses):
        raise RuntimeError('DNS_MUST_POINT_TO_THIS_NODE')
    return addresses.pop()


def prepare(arguments):
    assert os.geteuid()==0 and 'VERSION_ID="24.04"' in Path('/etc/os-release').read_text()
    assert DOMAIN.fullmatch(arguments.domain) and len(arguments.domain)<=253
    assert UUID.fullmatch(arguments.node) and UUID.fullmatch(arguments.certificate)
    base = Path('/var/lib/vpn-platform')
    assert json.loads((base/'agent/state.json').read_bytes())['node_id']==arguments.node
    digest = hashlib.sha256(Path('/usr/local/bin/vpn-node-agent').read_bytes()).hexdigest()
    assert digest==AGENT_SHA
    ip = local_address(arguments.domain)
    cert = base/'certificates'/arguments.certificate/'current/fullchain.pem'
    assert cert.is_file() and cert.resolve().is_relative_to(base/'certificates'/arguments.certificate)
    assert cert.with_name('private.key').stat().st_mode&0o077==0
    run('/usr/bin/openssl','x509','-in',str(cert),'-noout','-checkhost',arguments.domain)
    run('/usr/bin/openssl','x509','-in',str(cert),'-noout','-checkend','86400')
    config = Path('/etc/pauk-node-cover/nginx.conf')
    if config.exists():
        content = config.read_text()
        assert 'server_name '+arguments.domain+';' in content
        assert '/.well-known/pauk-node-'+arguments.node in content
        assert str(cert) in content and tls_ready(arguments.domain)
        print(json.dumps({'status':'ready','domain':arguments.domain,'existing':True}))
        return

    with socket.socket() as listener:
        listener.bind((ip,80))
    nginx_version = ''
    if not Path('/usr/sbin/nginx').is_file():
        policy = run('/usr/bin/apt-cache','policy','nginx')
        candidate = re.search(r'^\s*Candidate:\s*([0-9][A-Za-z0-9.+:~\-]*)\s*$',policy,re.M)
        if not candidate:
            run('/usr/bin/apt-get','-o','Acquire::Retries=1','update',timeout=140)
            policy = run('/usr/bin/apt-cache','policy','nginx')
            candidate = re.search(r'^\s*Candidate:\s*([0-9][A-Za-z0-9.+:~\-]*)\s*$',policy,re.M)
        assert candidate
        nginx_version = candidate[1]

    root = Path('/var/lib/pauk-rebuild')
    root.mkdir(mode=0o700,exist_ok=True)
    assert root.resolve()==root and root.stat().st_uid==0 and root.stat().st_mode&0o077==0
    directory = root/('node-cover-'+secrets.token_hex(8))
    directory.mkdir(mode=0o700)
    spec = {'node_id':arguments.node,'ip':ip,'domain':arguments.domain,'cert':str(cert),'role':'ordinary',
            'old_agent_sha':digest,'nginx_version':nginx_version}
    (directory/'spec.json').write_text(json.dumps(spec))
    worker = directory/'worker.py'
    worker.write_text(WORKER)
    try:
        run('/usr/bin/python3',str(worker),timeout=230)
        result = json.loads((directory/'LOCAL_VERIFIED.json').read_bytes())
        assert result['phase']=='LOCAL_VERIFIED' and result['http2'] and result['HSTS']
        (directory/'COMMITTED.json').write_text('{"phase":"COMMITTED"}')
    except BaseException:
        subprocess.run(['/usr/bin/python3',str(worker),'recover'],capture_output=True,timeout=60)
        raise
    print(json.dumps({'status':'ready','domain':arguments.domain,'tls13_h2':True,'hsts':True}))


if __name__=='__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--node',required=True)
    parser.add_argument('--domain',required=True)
    parser.add_argument('--certificate',required=True)
    options = parser.parse_args()
    try:
        prepare(options)
    except Exception as error:
        reason = str(error) if isinstance(error,RuntimeError) else type(error).__name__
        print(json.dumps({'status':'failed','reason':reason}),file=sys.stderr)
        sys.exit(1)
