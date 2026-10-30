#!/usr/bin/env python3
"""Install the pinned independent updater after CP102 is available.

This changes only the updater's own executable and systemd units. Node tokens
remain in the existing protected registration state and are never printed.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import tempfile

VERSION='0.1.0'
SHA256='485a34aca4630548f2930f24a0f7ae73cf910611749bcd649a0126597cdb7fde'
TARGET=Path('/usr/local/libexec/vpn-platform/vpn-agent-updater.py')
UNITS=Path('/etc/systemd/system')
SERVICE='vpn-platform-agent-updater.service'
TIMER='vpn-platform-agent-updater.timer'
SERVICE_TEXT='''[Unit]
Description=VPN Platform sequential Agent updater
Wants=network-online.target
After=network-online.target vpn-platform-node-agent.service
ConditionPathExists=/etc/vpn-platform/node-agent.env

[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStart=/usr/bin/python3 /usr/local/libexec/vpn-platform/vpn-agent-updater.py
TimeoutStartSec=540
TimeoutStopSec=5
KillMode=control-group
Nice=10
'''
TIMER_TEXT='''[Unit]
Description=Poll VPN Platform for approved Agent updates

[Timer]
OnBootSec=120
OnUnitInactiveSec=30
RandomizedDelaySec=10
AccuracySec=1
Unit=vpn-platform-agent-updater.service

[Install]
WantedBy=timers.target
'''

def protected(path,directory=False):
    info=path.lstat()
    if info.st_uid!=0 or info.st_mode&0o022 or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise RuntimeError('Unsafe updater installation path')

def atomic(path,raw,mode):
    fd,name=tempfile.mkstemp(prefix='.updater-',dir=path.parent)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
        fd=os.open(path.parent,os.O_DIRECTORY|os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if os.path.exists(name):os.unlink(name)

def command(*args):
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
    if result.returncode:raise RuntimeError('Updater service operation failed')
    return result.stdout.decode().strip()

def install(source,start):
    if os.geteuid()!=0:raise RuntimeError('Root required')
    os.umask(0o077);source=source.resolve();protected(source)
    raw=source.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SHA256:raise RuntimeError('Updater checksum mismatch')
    spec=importlib.util.spec_from_file_location('pinned_updater',source)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    if module.VERSION!=VERSION:raise RuntimeError('Updater version mismatch')
    # Read-only connectivity check. Do not claim a fleet job during installation.
    client=module.Client();health=client.api('/healthz')
    if health.get('service')!='vpn-platform-control-plane' or module.version(health.get('version'))<(0,1,102):
        raise RuntimeError('Control plane102 or newer required')
    status=client.api('/api/v1/agent/status')
    if status.get('node_id')!=client.node_id:raise RuntimeError('Node registration mismatch')
    for parent in reversed(TARGET.parent.parents):
        if parent.exists():protected(parent,True)
    TARGET.parent.mkdir(mode=0o755,parents=True,exist_ok=True);protected(TARGET.parent,True);protected(UNITS,True)
    payloads={TARGET:(raw,0o755),UNITS/SERVICE:(SERVICE_TEXT.encode(),0o644),UNITS/TIMER:(TIMER_TEXT.encode(),0o644)}
    # First installation or exact replay only. Never overwrite an unknown local
    # operator customisation or change a running updater's executable.
    if command('systemctl','show',SERVICE,'-p','ActiveState','--value') in ('active','activating','deactivating'):
        raise RuntimeError('Updater currently running')
    for path,(data,_) in payloads.items():
        if path.exists() or path.is_symlink():
            protected(path)
            if path.read_bytes()!=data:raise RuntimeError('Existing updater installation differs')
    for path,(data,mode) in payloads.items():
        if not path.exists():atomic(path,data,mode)
    command('systemctl','daemon-reload')
    command('systemctl','enable',TIMER)
    if start:
        command('systemctl','start',TIMER)
        if command('systemctl','is-active',TIMER)!='active':raise RuntimeError('Updater timer did not start')
    print('AGENT_UPDATER_INSTALLED '+VERSION+(' TIMER_ACTIVE' if start else ' TIMER_ENABLED'),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--artifact-file',type=Path,required=True);parser.add_argument('--start',action='store_true');args=parser.parse_args()
    try:install(args.artifact_file,args.start)
    except Exception:
        print('AGENT_UPDATER_INSTALL_FAILED',flush=True)
        raise SystemExit(1)
