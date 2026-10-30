#!/usr/bin/env python3
"""VPN Platform node lifecycle tool. Never prints credentials or raw agent logs."""
import argparse
import contextlib
import fcntl
import getpass
import warnings
import grp
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import urlsplit
from urllib.error import HTTPError
from urllib.request import Request, build_opener, HTTPRedirectHandler
import uuid

# Runtime support uses a reviewed artifact. Keep this exact digest
# paired with the versioned binary after lifecycle and platform verification.
VERSION = '0.2.40'
SHA256 = 'a25cb26fec733e673e49de03296060bb82e158fa30f4a736d15a9438e32ffbcf'
DEFAULT_CP = ''
ARTIFACT = DEFAULT_CP + '/artifacts/node-agent/' + VERSION + '/linux-amd64/vpn-node-agent'
BINARY = Path('/usr/local/bin/vpn-node-agent')
ENV = Path('/etc/vpn-platform/node-agent.env')
DATA = Path('/var/lib/vpn-platform')
XRAY_DATA = Path('/var/lib/vpn-platform')
STATE = DATA / 'agent/state.json'
UNIT = Path('/etc/systemd/system/vpn-platform-node-agent.service')
HYSTERIA_UNIT = Path('/etc/systemd/system/vpn-platform-hysteria.service')
BACKUPS = Path('/var/backups/vpn-platform/node-tool')
MAINTENANCE = DATA / 'maintenance'
LOCK = Path('/run/lock/vpn-platform-node-tool.lock')
SERVICE = 'vpn-platform-node-agent.service'
HYSTERIA_SERVICE = 'vpn-platform-hysteria.service'
HYSTERIA_OPERATIONAL_MIN_AGENT = '0.2.25'
OPENVPN_UNIT = Path('/etc/systemd/system/vpn-platform-openvpn.service')
XRAY_UNIT = Path('/etc/systemd/system/vpn-platform-xray.service')
OPENVPN_NETWORK_UNIT = Path('/etc/systemd/system/vpn-platform-openvpn-network.service')
WIREGUARD_DROPIN = Path('/etc/systemd/system/vpn-platform-node-agent.service.d/60-wireguard-stop.conf')
OPENVPN_DROPIN = Path('/etc/systemd/system/vpn-platform-node-agent.service.d/50-openvpn-network.conf')
OPENVPN_PACKAGE_URL = DEFAULT_CP + '/artifacts/openvpn/2.6.19-0ubuntu0.24.04.4/linux-amd64/openvpn.deb'
OPENVPN_PACKAGE_SHA256 = 'd288c3789e825b140258da3e2c40bdb8f07820b8e69ca6480b619b83af8f108a'
OPENVPN_BINARY_SHA256 = 'b02701de7661bae5a46699341d29438948ca00da56965da88d0ad597323f3667'

PPTP_ROOT = Path('/opt/vpn-platform-pptp')
PPTP_VERSION = '1.14.0-platform.1'
PPTP_SHA256 = 'd6960405b74030750e7b835e3dafef76e26f1d2748a4d347578204fabcdd08a6'
PPTP_MANIFEST_SHA256 = '24c056748c71e1351de89c6fa29ad60612b971fd719b79ec182c95b500eb0b69'
PPTP_ARTIFACT = DEFAULT_CP + '/artifacts/pptp/' + PPTP_VERSION + '/linux-amd64/pptp-accel-' + PPTP_VERSION + '-linux-amd64.tar.gz'
PPTP_UNIT = Path('/etc/systemd/system/vpn-platform-pptp.service')
PPTP_NETWORK_UNIT = Path('/etc/systemd/system/vpn-platform-pptp-network.service')
PPTP_DROPIN = Path('/etc/systemd/system/vpn-platform-node-agent.service.d/70-pptp-network.conf')


def configure_download_origin(cp):
    """Download node runtimes only from the installation selected by its owner."""
    global ARTIFACT, OPENVPN_PACKAGE_URL, PPTP_ARTIFACT, AMNEZIAWG_ARTIFACT
    ARTIFACT = cp + '/artifacts/node-agent/' + VERSION + '/linux-amd64/vpn-node-agent'
    OPENVPN_PACKAGE_URL = cp + '/artifacts/openvpn/2.6.19-0ubuntu0.24.04.4/linux-amd64/openvpn.deb'
    PPTP_ARTIFACT = cp + '/artifacts/pptp/' + PPTP_VERSION + '/linux-amd64/pptp-accel-' + PPTP_VERSION + '-linux-amd64.tar.gz'
    if 'AMNEZIAWG_VERSION' in globals():
        AMNEZIAWG_ARTIFACT = cp + '/artifacts/cores/amneziawg/' + AMNEZIAWG_VERSION + '/linux-amd64.tar.gz'



def pptp_manifest(raw):
    if hashlib.sha256(raw).hexdigest() != PPTP_MANIFEST_SHA256:
        raise ToolError('PPTP manifest differs from the reviewed release')
    value = json.loads(raw)
    if value.get('format') != 1 or value.get('version') != PPTP_VERSION or len(value.get('files', [])) != 16:
        raise ToolError('Invalid PPTP manifest')
    return {entry['path']: entry for entry in value['files']}


def verify_pptp_package(root):
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ToolError('PPTP package directory is unsafe')
    manifest = root / 'manifest.json'
    info = manifest.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 16384:
        raise ToolError('PPTP package manifest is unsafe')
    entries = pptp_manifest(manifest.read_bytes())
    expected = set(entries) | {'manifest.json'}
    directories = {str(parent) for name in expected for parent in Path(name).parents if str(parent) != '.'}
    observed = set()
    for path in root.rglob('*'):
        name = str(path.relative_to(root)); info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ToolError('PPTP package ownership or permissions differ')
        if stat.S_ISDIR(info.st_mode) and name in directories: continue
        if not stat.S_ISREG(info.st_mode) or name not in expected:
            raise ToolError('PPTP package contains an unexpected entry')
        observed.add(name)
        if name == 'manifest.json': continue
        entry = entries[name]
        if info.st_size != entry['size'] or stat.S_IMODE(info.st_mode) != entry['mode'] or digest(path) != entry['sha256']:
            raise ToolError('PPTP package file differs from the reviewed release')
    if observed != expected: raise ToolError('PPTP package is incomplete')


def prepare_pptp_package(directory, source=None):
    # All package bytes are pinned. Local artifacts enable an isolated install
    # without bypassing the digest, ownership or archive-entry checks.
    if PPTP_ROOT.exists() or PPTP_ROOT.is_symlink():
        verify_pptp_package(PPTP_ROOT)
    else:
        package = directory / 'pptp-runtime.tar.gz'
        try:
            if source:
                fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                stream = os.fdopen(fd, 'rb'); info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or not 0 < info.st_size <= 8*1024*1024:
                    stream.close(); raise ToolError('Local PPTP artifact must be a protected root-owned regular file')
            else: stream = HTTP.open(PPTP_ARTIFACT, timeout=60)
            with stream:
                raw = stream.read(8*1024*1024+1)
            if len(raw) > 8*1024*1024 or hashlib.sha256(raw).hexdigest() != PPTP_SHA256:
                raise ToolError('PPTP runtime artifact digest mismatch')
            package.write_bytes(raw)
        except ToolError: raise
        except Exception: raise ToolError('PPTP runtime artifact download failed') from None
        parent = PPTP_ROOT.parent; info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or parent.resolve() != parent:
            raise ToolError('PPTP package parent directory is unsafe')
        with tempfile.TemporaryDirectory(prefix='.vpn-pptp-', dir=parent) as temporary:
            stage = Path(temporary) / PPTP_ROOT.name; stage.mkdir(mode=0o755)
            with tarfile.open(package, 'r:gz') as archive:
                members = archive.getmembers()
                if len(members) > 32 or sum(m.size for m in members) > 16*1024*1024:
                    raise ToolError('PPTP archive exceeds its bounds')
                seen = set(); prefix = PPTP_ROOT.name + '/'
                for member in members:
                    if member.name in seen: raise ToolError('PPTP archive repeats an entry')
                    seen.add(member.name)
                    if member.name == PPTP_ROOT.name and member.isdir(): continue
                    if not member.name.startswith(prefix): raise ToolError('PPTP archive has an unexpected root')
                    relative = member.name[len(prefix):]
                    path = Path(relative)
                    if not relative or path.is_absolute() or '..' in path.parts or str(path) != relative or not (member.isfile() or member.isdir()):
                        raise ToolError('PPTP archive contains an unsafe entry')
                    target = stage / path
                    if member.isdir(): target.mkdir(mode=0o755, parents=True, exist_ok=True)
                    else:
                        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                        with archive.extractfile(member) as stream: atomic(target, stream.read(), member.mode)
            verify_pptp_package(stage)
            os.rename(stage, PPTP_ROOT)
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
    packages = ('libssl3t64', 'libpcre2-8-0', 'kmod', 'iptables', 'iproute2')
    missing = []
    for name in packages:
        result = run(['dpkg-query', '-W', '-f=${Status}', name], check=False)
        if result.returncode or result.stdout.strip() != 'install ok installed': missing.append(name)
    if missing:
        run(['apt-get', 'update'], timeout=180)
        run(['apt-get', 'install', '-y', '--no-install-recommends'] + missing, timeout=180)
    verify_pptp_package(PPTP_ROOT)


def prepare_openvpn_package(directory):
    binary=Path('/usr/sbin/openvpn')
    package_needed=not binary.exists() or digest(binary)!=OPENVPN_BINARY_SHA256
    if package_needed:
        if any(Path('/etc/openvpn').rglob('*.conf')):
            raise ToolError('Existing unmanaged OpenVPN configuration found; use a fresh node')
        package=directory/'openvpn-reviewed.deb'
        try:
            with HTTP.open(OPENVPN_PACKAGE_URL,timeout=60) as response, package.open('wb') as output:
                raw=response.read(16*1024*1024+1)
                if len(raw)>16*1024*1024:raise ToolError('OpenVPN package is unexpectedly large')
                output.write(raw)
        except ToolError:raise
        except Exception:raise ToolError('Reviewed OpenVPN package download failed') from None
        if digest(package)!=OPENVPN_PACKAGE_SHA256:raise ToolError('OpenVPN package digest mismatch; installation refused')
    if package_needed or not all(shutil.which(name) for name in ('iptables','ip6tables','ip')):
        run(['apt-get','update'],timeout=180)
        packages=([str(package)] if package_needed else [])+['iptables','iproute2']
        run(['apt-get','install','-y','--no-install-recommends']+packages,timeout=180)
    if not binary.exists() or digest(binary)!=OPENVPN_BINARY_SHA256:
        raise ToolError('Installed OpenVPN binary does not match the reviewed build')


def prepare_wireguard_packages(directory):
    if any(Path('/etc/wireguard').glob('*.conf')):
        raise ToolError('Unmanaged WireGuard configurations found; use a fresh dedicated node')
    packages=[
        ('wireguard-tools','https://archive.ubuntu.com/ubuntu/pool/main/w/wireguard/wireguard-tools_1.0.20210914-1ubuntu4_amd64.deb','19790a3203a12791bfaf622ea000780a7558de858766100d52f802079d44c400',Path('/usr/bin/wg'),'db75235c853de9bb1c20df798ab86c9a3bc4bdf3fc66758e1aaed6f5e23973a8'),
        ('nftables','https://archive.ubuntu.com/ubuntu/pool/main/n/nftables/nftables_1.0.9-1ubuntu0.1_amd64.deb','d648859fccde3c17b8b9b89993427564f91f394a39306db1f67bd5ea3ac42c6e',Path('/usr/sbin/nft'),'3f1c21553e62716ef1abfcf31f51ff94eb73ff4234a6653bac754a42f936d1c7')]
    install=[]
    for name,url,checksum,binary,expected in packages:
        if binary.exists() and digest(binary)==expected:continue
        package=directory/(name+'-reviewed.deb')
        try:
            with HTTP.open(url,timeout=60) as response:
                raw=response.read(4*1024*1024+1)
            if len(raw)>4*1024*1024:raise ToolError('Reviewed network package is unexpectedly large')
            package.write_bytes(raw)
        except ToolError:raise
        except Exception:raise ToolError('Reviewed network package download failed') from None
        if digest(package)!=checksum:raise ToolError('Reviewed network package digest mismatch; refused')
        install.append(str(package))
    if install or not shutil.which('ip'):
        run(['apt-get','update'],timeout=180)
        run(['apt-get','install','-y','--no-install-recommends']+install+['iproute2'],timeout=180)
    for _,_,_,binary,expected in packages:
        if not binary.exists() or digest(binary)!=expected:raise ToolError('Installed native WireGuard tools differ from reviewed binaries')
def release_version(value):
    try:
        parts = value.split('.')
        parsed = tuple(int(v) for v in parts)
        if len(parts) != 3 or any(v < 0 or str(v) != text for v, text in zip(parsed, parts)): raise ValueError()
        return parsed
    except Exception: raise ToolError('Agent release version is invalid') from None

def configure_data_directory(requested=None):
    global DATA, STATE, MAINTENANCE
    cfg = config()
    configured = cfg.get('VPN_AGENT_DATA')
    value = requested or configured or str(DATA)
    path = Path(value)
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', value) or value == '/' or '..' in path.parts or str(path) != value or path.resolve() != path:
        raise ToolError('Node data path must be a canonical absolute directory without symlinks')
    if configured and requested and configured != requested:
        raise ToolError('Changing an installed node data directory is not supported')
    if cfg.get('VPN_AGENT_STATE', str(path/'agent/state.json')) != str(path/'agent/state.json'):
        raise ToolError('The configured agent state path does not match this data directory')
    parent = path
    while not parent.exists(): parent = parent.parent
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ToolError('Node data directory or nearest existing parent is not protected and root-owned')
    DATA = path; STATE = DATA/'agent/state.json'; MAINTENANCE = DATA/'maintenance'

def runtime_selection():
    if DATA.exists() or DATA.is_symlink():
        info = DATA.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ToolError('Node data directory must be a protected root-owned directory; nothing changed')
    path = DATA / 'runtime-selection.json'
    if not path.exists() and not path.is_symlink():
        if any(path.exists() or path.is_symlink() for path in (DATA / 'hysteria2', DATA / 'cores/hysteria2', DATA / 'openvpn', DATA / 'wireguard', DATA / 'pptp')):
            raise ToolError('Hysteria runtime selection is missing; preserve current state and repair its selection')
        return {'format': 1, 'core': 'xray', 'minimum_agent': '0.2.23'}
    try:
        parent = DATA.lstat(); info = path.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022: raise ValueError()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1024: raise ValueError()
        record = json.loads(path.read_text())
        floors = {'xray': '0.2.23', 'hysteria2': '0.2.24', 'openvpn': '0.2.27', 'wireguard': '0.2.28', 'pptp': '0.2.30'}
        if isinstance(record, dict) and record.get('core') == 'xray' and record.get('minimum_agent') in ('0.2.31', '0.2.34'):
            floors['xray'] = record['minimum_agent']
        if not isinstance(record, dict) or type(record.get('format')) is not int: raise ValueError()
        if record != {'format': 1, 'core': record['core'], 'minimum_agent': floors[record['core']]}: raise ValueError()
        for other in ('xray', 'hysteria2', 'openvpn', 'wireguard', 'pptp'):
            if other != record['core'] and any(path.exists() or path.is_symlink() for path in (DATA / other, DATA / 'cores' / other)): raise ValueError()
        return record
    except Exception: raise ToolError('Runtime selection is invalid; no lifecycle files were changed') from None

def required_runtime_minimum(selection):
    minimum = selection['minimum_agent']
    if selection['core'] == 'wireguard' and ((DATA/'wireguard/interface-update.json').exists() or (DATA/'wireguard/interface-update.json').is_symlink()):
        return '0.2.29'
    fence=DATA/'xray/access-fence.json'
    if selection['core']=='xray' and (fence.exists() or fence.is_symlink()) and release_version(minimum)<release_version('0.2.27'):
        return '0.2.27'
    if selection['core'] == 'hysteria2' and release_version(minimum) < release_version(HYSTERIA_OPERATIONAL_MIN_AGENT):
        return HYSTERIA_OPERATIONAL_MIN_AGENT
    return minimum

def require_runtime_compatible(agent_version, selection=None):
    selection = selection or runtime_selection()
    minimum = required_runtime_minimum(selection)
    if not agent_version or release_version(agent_version) < release_version(minimum):
        raise ToolError('Selected runtime requires agent ' + minimum + ' or newer; downgrade refused')

def planned_runtime_core(requested=None):
    selected = runtime_selection()
    if requested is None or requested == selected['core']: return selected
    if requested not in ('hysteria2','openvpn','wireguard','pptp'): raise ToolError('Runtime migration is not supported; use a separately provisioned node')
    present = lambda path: path.exists() or path.is_symlink()
    if any(present(path) for path in (DATA/'runtime-selection.json', DATA/'xray', DATA/'cores/xray', BINARY, UNIT)) or state().get('agent_token'):
        raise ToolError('The selected runtime requires a fresh node; existing node migration is refused')
    return {'format': 1, 'core': requested, 'minimum_agent': {'hysteria2':'0.2.24','openvpn':'0.2.27','wireguard':'0.2.28','pptp':'0.2.30'}[requested]}

def require_runtime_data_traversal(selected):
    if selected['core'] != 'hysteria2':
        # The existing Xray systemd unit uses fixed runtime paths. A custom
        # agent directory would report registration success but fail deployment.
        if DATA != XRAY_DATA:
            raise ToolError('Xray requires /var/lib/vpn-platform; a custom data directory is supported only for Hysteria')
        return
    try: managed_gid = grp.getgrnam('vpnplatform-hysteria').gr_gid
    except KeyError: managed_gid = None
    # Provisioning manages DATA itself. It must never open up a private ancestor
    # such as /root or the protected candidate/backup directory automatically.
    for parent in DATA.parents:
        try: info = parent.lstat()
        except OSError: raise ToolError('Hysteria requires an existing traversable parent for its data directory') from None
        accessible = bool(info.st_mode & stat.S_IXOTH) or (managed_gid not in (None, 0) and info.st_gid == managed_gid and bool(info.st_mode & stat.S_IXGRP))
        if not stat.S_ISDIR(info.st_mode) or not accessible:
            raise ToolError('Hysteria cannot access a private data ancestor; use a separate traversable parent, without changing existing private directory permissions')

@contextlib.contextmanager
def node_ownership():
    # The agent is stopped before this lock is acquired. A manual competing
    # process makes the operation fail before lifecycle files are changed.
    try:
        info = DATA.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022: raise ValueError()
        descriptor = os.open(DATA/'agent-lifecycle.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    except (OSError, ValueError): raise ToolError('Node ownership directory is unsafe or unavailable') from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise ToolError('Node ownership lock is unsafe')
        try: fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError: raise ToolError('Another agent owns this node; no lifecycle files were changed') from None
        try: yield descriptor
        finally: fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally: os.close(descriptor)

def installed_binary_version(binary_hash):
    known = {'a188a347e8c1121e8db957dc79a84c7da9c74ca65c035cec38d94f5cc651ee96': '0.2.24', '30dc683b51a3d5a20ff85fc3e21f7e4b3c0977fb1e4c95931cd2aaf7841c346d': '0.2.23', 'a95c3cd0d5ba008d06eb91d53c2c41053a6d11e99c9eecf0a9a53a0bb79f43c8': '0.2.31', '7499b627f25c9298e8289480cd22471f7360f58cd509c18fbc27d133b0cb12c3': '0.2.32', '4728463b3db4418408512ffa5bbb75afae7e217b1e60240718860a5aa95ca048': '0.2.33', SHA256: VERSION}
    if binary_hash in known: return known[binary_hash]
    path = DATA / 'agent/binary-release.json'
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1024: return None
        record = json.loads(path.read_text())
        if record.get('sha256') != binary_hash: return None
        release_version(record.get('version'))
        return record['version']
    except Exception: return None

class ToolError(Exception):
    pass

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ToolError('HTTP redirects are not allowed; use the canonical Control Plane URL')

HTTP = build_opener(NoRedirect)

def run(args, check=True, timeout=45, pass_fds=()):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, pass_fds=pass_fds)
    except (OSError, subprocess.TimeoutExpired):
        raise ToolError('Command unavailable or timed out: ' + args[0]) from None
    if check and p.returncode:
        raise ToolError('Command failed: ' + args[0] + '; inspect local service status')
    return p

def atomic(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data if isinstance(data, bytes) else data.encode())
            out.flush(); os.fsync(out.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(name): os.unlink(name)

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''): h.update(block)
    return h.hexdigest()

def config():
    result = {}
    if ENV.exists():
        for line in ENV.read_text().splitlines():
            if '=' not in line or line.lstrip().startswith('#'): continue
            key, value = line.split('=', 1)
            parts = shlex.split(value)
            result[key.strip()] = parts[0] if parts else ''
    return result

def state():
    if not STATE.exists(): return {}
    try:
        value = json.loads(STATE.read_text())
        if value.get('agent_token'):
            uuid.UUID(value['node_id']); uuid.UUID(value['tenant_id'])
        return value
    except Exception:
        raise ToolError('Agent state is invalid; preserve it and restore a known backup') from None

def validate_url(value, allow_http_test=False):
    u = urlsplit(value)
    if not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ('', '/'):
        raise ToolError('Control Plane must be an origin URL without credentials or query parameters')
    if u.scheme == 'https': return value.rstrip('/')
    try: private = ipaddress.ip_address(u.hostname).is_private
    except ValueError: private = False
    if u.scheme == 'http' and allow_http_test and private: return value.rstrip('/')
    raise ToolError('HTTPS is required for Control Plane connections')

def request(cp, path, payload=None, token=None, missing_ok=False):
    if not cp:
        raise ToolError('Configure the node Control Plane or pass --control-plane during installation')
    headers = {'Accept': 'application/json'}
    if token: headers['Authorization'] = 'Bearer ' + token
    if payload is not None: headers['Content-Type'] = 'application/json'
    req = Request(cp + path, data=None if payload is None else json.dumps(payload).encode(), headers=headers)
    try:
        with HTTP.open(req, timeout=15) as response:
            raw = response.read(256 * 1024 + 1)
            if len(raw) > 256 * 1024: raise ToolError('Control Plane response exceeds the limit')
            return json.loads(raw)
    except ToolError: raise
    except HTTPError as exc:
        if missing_ok and exc.code == 404: return None
        raise ToolError('Control Plane request failed; no credentials were printed') from None
    except Exception: raise ToolError('Control Plane request failed; no credentials were printed') from None

def read_bootstrap_credential(token_file=None):
    if token_file:
        try:
            descriptor=os.open(token_file,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(descriptor,'rb') as source:
                info=os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o077 or not 0<info.st_size<=1025:
                    raise ValueError()
                token=source.read(1026).decode('utf-8').strip()
        except (OSError,ValueError,UnicodeError):
            raise ToolError('Bootstrap file must be a small root-owned private regular file without symlinks') from None
    else:
        try:
            # A terminal cannot seek; buffered r+ opens fail before the prompt.
            # getpass opens its own controlling terminal for input. The supplied
            # write-only stream is used only for the prompt, including when stdin
            # is redirected. Never fall back to echoed credential input.
            with warnings.catch_warnings():
                warnings.simplefilter('error', getpass.GetPassWarning)
                with open('/dev/tty', 'w', encoding='utf-8') as tty:
                    token = getpass.getpass('Bootstrap token (hidden): ', stream=tty).strip()
        except (OSError, EOFError, getpass.GetPassWarning):
            raise ToolError('A terminal with hidden input or --bootstrap-token-file is required for initial registration') from None
    if not token or len(token)>1024 or any(ord(char)<33 or ord(char)>126 for char in token):
        raise ToolError('Bootstrap token is missing or invalid')
    return token

def runtime_server_preflight(cp,selected,registered,token_file=None):
    capabilities=request(cp,'/api/v1/agent/capabilities',missing_ok=True)
    if capabilities is None:
        if selected['core']=='xray':return None
        raise ToolError('Control Plane does not support Hysteria provisioning; update the server before installing this node')
    if not isinstance(capabilities,dict) or type(capabilities.get('format')) is not int or capabilities['format']!=1 or capabilities.get('runtime_selection') is not True or capabilities.get('bootstrap_inspection') is not True:
        raise ToolError('Control Plane provisioning capabilities are unsupported')
    runtimes=capabilities.get('runtimes')
    profile=runtimes.get(selected['core']) if isinstance(runtimes,dict) else None
    if not isinstance(profile,dict) or profile.get('provisioning') is not True or release_version(profile.get('minimum_agent'))>release_version(VERSION):
        raise ToolError('This agent release cannot provision the selected server runtime')
    if selected['core']=='hysteria2' and capabilities.get('traffic_address_availability') is not True:
        raise ToolError('Control Plane cannot preserve Hysteria traffic telemetry')
    if registered:
        if self_status(cp).get('runtime_core')!=selected['core']:
            raise ToolError('Registered server runtime differs from this node; lifecycle files were not changed')
        return None
    token=read_bootstrap_credential(token_file)
    info=request(cp,'/api/v1/agent/bootstrap-info',token=token)
    try:
        if not isinstance(info,dict) or info.get('runtime_core')!=selected['core']:raise ValueError()
        node_id=info['node_id']
        if str(uuid.UUID(node_id))!=node_id:raise ValueError()
    except (ValueError,KeyError,TypeError,AttributeError):
        raise ToolError('Bootstrap belongs to a different or invalid node runtime; lifecycle files were not changed') from None
    # Reuse the inspected credential; re-reading a changed file after provisioning
    # could register a different node. This proof is never persisted or logged.
    return (token,node_id)

def self_status(cp):
    local = state()
    if not local.get('agent_token'): raise ToolError('Node is not registered')
    value = request(cp, '/api/v1/agent/status', token=local['agent_token'])
    if value.get('node_id') != local['node_id']: raise ToolError('Control Plane returned a different node identity')
    return {key: value.get(key) for key in (
        'node_id', 'state', 'registered', 'online', 'agent_version', 'desired_generation',
        'applied_generation', 'generation_drift', 'healthy', 'health_fresh', 'health_checked_at', 'last_seen_at', 'runtime_core')}

def ready(value, expected=VERSION, previous_health=None, require_new_health=False):
    if require_new_health and (not value.get('health_checked_at') or value.get('health_checked_at') == previous_health): return False
    if runtime_selection()['core'] != 'xray' and value.get('runtime_core') != runtime_selection()['core']: return False
    return bool(value.get('registered') and value.get('online') and value.get('agent_version') == expected
        and value.get('health_fresh') and value.get('desired_generation') == value.get('applied_generation')
        and (value.get('desired_generation') == 0 or value.get('healthy')))

def wait_ready(cp, expected=VERSION, previous_health=None, require_new_health=False):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            result = self_status(cp)
            if ready(result, expected, previous_health, require_new_health): return result
        except ToolError: pass
        time.sleep(min(3, max(0, deadline - time.monotonic())))
    raise ToolError('Control Plane did not confirm the expected agent version and healthy state within 120 seconds')

def preflight(cp):
    if os.geteuid() != 0: raise ToolError('Run this tool as root')
    release = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            k, v = line.split('=', 1); release[k] = v.strip('"')
    if release.get('ID') != 'ubuntu' or release.get('VERSION_ID') != '24.04' or os.uname().machine != 'x86_64':
        raise ToolError('This release supports Ubuntu 24.04 amd64')
    for command in ('systemctl', 'systemd-run', 'sha256sum'):
        if not shutil.which(command): raise ToolError('Required program missing: ' + command)
    cfg = config()
    if cfg.get('VPN_AGENT_STATE', str(STATE)) != str(STATE) or cfg.get('VPN_AGENT_DATA', str(DATA)) != str(DATA):
        raise ToolError('Custom agent state/data paths require a matching installer configuration; nothing changed')
    health = request(cp, '/healthz')
    if health.get('service') != 'vpn-platform-control-plane': raise ToolError('Unexpected Control Plane service')
    try: version = tuple(int(v) for v in health['version'].split('.'))
    except Exception: raise ToolError('Control Plane version unavailable') from None
    if version < (0, 1, 83): raise ToolError('Control Plane 0.1.83 or newer is required')

def download(target, source=None):
    try:
        if source is not None:
            descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            response = os.fdopen(descriptor, 'rb')
            info = os.fstat(response.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or not 0 < info.st_size <= 64*1024*1024:
                response.close(); raise ToolError('Local agent artifact must be a protected root-owned regular file')
        else: response = HTTP.open(ARTIFACT, timeout=60)
        with response, target.open('wb') as out:
            total = 0
            while True:
                block = response.read(1024 * 1024)
                if not block: break
                total += len(block)
                if total > 64 * 1024 * 1024: raise ToolError('Agent artifact is unexpectedly large')
                out.write(block)
    except ToolError: raise
    except Exception: raise ToolError('Agent download failed') from None
    if digest(target) != SHA256: raise ToolError('Agent SHA-256 mismatch; installed files were not changed')

def snapshot():
    BACKUPS.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(BACKUPS, 0o700)
    backup = BACKUPS / (time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8])
    backup.mkdir(mode=0o700)
    records = []
    for name, path in [('binary', BINARY), ('environment', ENV), ('unit', UNIT), ('hysteria-unit', HYSTERIA_UNIT), ('openvpn-unit',OPENVPN_UNIT),('openvpn-network-unit',OPENVPN_NETWORK_UNIT),('openvpn-dropin',OPENVPN_DROPIN),('xray-unit',XRAY_UNIT),('wireguard-dropin',WIREGUARD_DROPIN),('pptp-unit',PPTP_UNIT),('pptp-network-unit',PPTP_NETWORK_UNIT),('pptp-dropin',PPTP_DROPIN)]:
        entry = {'name': name, 'path': str(path), 'exists': path.exists()}
        if path.exists():
            shutil.copy2(path, backup / name); entry['sha256'] = digest(backup / name)
            if name == 'binary': entry['agent_version'] = installed_binary_version(entry['sha256'])
        records.append(entry)
    # Retained for disaster recovery only. Rollback never overwrites identity,
    # current generations, REALITY material or newly issued certificates.
    with tarfile.open(backup / 'state-and-keys.tgz', 'w:gz') as archive:
        for name in ('agent', 'secrets', 'xray', 'certificates', 'acme', 'runtime-selection.json', 'hysteria2', 'cores/hysteria2', 'openvpn', 'wireguard', 'pptp'):
            path = DATA / name
            if path.exists(): archive.add(path, arcname=name, recursive=True)
    os.chmod(backup / 'state-and-keys.tgz', 0o600)
    atomic(backup / 'manifest.json', json.dumps(records))
    atomic(backup / 'data-directory', str(DATA) + '\n')
    shutil.copy2(Path(__file__).resolve(), backup / 'tool.py')
    MAINTENANCE.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic(MAINTENANCE / 'latest-backup', backup.name)
    return backup

def guard_name(backup): return 'vpn-node-tool-guard-' + backup.name.lower()

def arm_guard(backup):
    deadline = int(time.time()) + 300
    calendar = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(deadline))
    run(['systemd-run', '--unit=' + guard_name(backup), '--on-calendar=' + calendar,
         '--timer-property=AccuracySec=1s', '--property=TimeoutStartSec=180s',
         sys.executable, str(backup / 'tool.py'), 'rollback', '--backup', backup.name, '--automatic', '--data-dir', str(DATA)])
    observed = run(['systemctl', 'show', guard_name(backup) + '.timer', '--property=NextElapseUSecRealtime', '--value']).stdout.strip()
    check = run(['date', '-u', '-d', observed, '+%s']).stdout.strip()
    if not check.isdigit() or abs(int(check) - deadline) > 1:
        run(['systemctl', 'stop', guard_name(backup) + '.timer'], check=False)
        raise ToolError('Rollback timer deadline could not be verified; installation refused')
    atomic(backup / 'guard-deadline.json', json.dumps({'epoch': deadline, 'calendar': calendar}))

def resolve_backup(name=None):
    if not name:
        if not (MAINTENANCE / 'latest-backup').exists(): raise ToolError('No backup is recorded')
        name = (MAINTENANCE / 'latest-backup').read_text().strip()
    backup = (BACKUPS / name).resolve()
    if backup.parent != BACKUPS.resolve() or not (backup / 'manifest.json').is_file():
        raise ToolError('Invalid backup selection')
    return backup

def restore(backup, automatic=False):
    if automatic and (backup / 'committed').exists(): return
    if (backup / 'rolled-back').exists(): return
    directory_record = backup/'data-directory'
    if directory_record.exists():
        if directory_record.read_text().strip() != str(DATA): raise ToolError('Backup belongs to a different node data directory')
    elif DATA != Path('/var/lib/vpn-platform'):
        raise ToolError('Legacy backup requires the original default node data directory')
    records = json.loads((backup / 'manifest.json').read_text())
    allowed = {'binary': str(BINARY), 'environment': str(ENV), 'unit': str(UNIT), 'hysteria-unit': str(HYSTERIA_UNIT),'openvpn-unit':str(OPENVPN_UNIT),'openvpn-network-unit':str(OPENVPN_NETWORK_UNIT),'openvpn-dropin':str(OPENVPN_DROPIN),'xray-unit':str(XRAY_UNIT),'wireguard-dropin':str(WIREGUARD_DROPIN),'pptp-unit':str(PPTP_UNIT),'pptp-network-unit':str(PPTP_NETWORK_UNIT),'pptp-dropin':str(PPTP_DROPIN)}
    names = {entry.get('name') for entry in records}
    legacy={'binary','environment','unit'}
    prior = set(allowed) - {'pptp-unit','pptp-network-unit','pptp-dropin'}
    if len(records) != len(names) or names not in (set(allowed),prior,prior-{'xray-unit'},prior-{'wireguard-dropin'},prior-{'wireguard-dropin','xray-unit'}, legacy, legacy|{'hysteria-unit'}):
        raise ToolError('Backup manifest is incomplete')
    for entry in records:
        if entry['path'] != allowed[entry['name']]:
            raise ToolError('Backup manifest contains an unexpected path')
        if entry['exists'] and digest(backup / entry['name']) != entry['sha256']:
            raise ToolError('Backup integrity check failed')
    # A node selected for Hysteria cannot boot an Xray-only agent. The current
    # selection and access state are preserved; rollback never extracts the DR tar.
    selected = runtime_selection()
    if selected['core']=='xray' and 'xray-unit' not in names and XRAY_UNIT.exists() and 'xray-runtime-check' in XRAY_UNIT.read_text():
        raise ToolError('Backup lacks the managed Xray unit required for this runtime; rollback refused')
    binary_record = next(entry for entry in records if entry['name'] == 'binary')
    if selected['core'] == 'hysteria2' and 'hysteria-unit' not in names:
        raise ToolError('Backup predates managed Hysteria unit support; rollback refused')
    if selected['core']=='wireguard' and 'wireguard-dropin' not in names:
        raise ToolError('Backup predates native WireGuard stop protection; rollback refused')
    if selected['core']=='pptp' and not {'pptp-unit','pptp-network-unit','pptp-dropin'}.issubset(names):
        raise ToolError('Backup predates PPTP support; rollback refused')
    if selected['core'] == 'openvpn' and not {'openvpn-unit','openvpn-network-unit','openvpn-dropin'}.issubset(names):
        raise ToolError('Backup predates OpenVPN support; rollback refused')
    if selected['core']=='xray' and selected['minimum_agent']=='0.2.31' and not binary_record['exists']:
        raise ToolError('Imported Xray profile requires an Agent; rollback cannot remove its binary')
    if binary_record['exists'] and (selected['core']!='xray' or (DATA/'xray/access-fence.json').exists() or selected['minimum_agent']=='0.2.31'):
        require_runtime_compatible(installed_binary_version(binary_record['sha256']) or binary_record.get('agent_version'))
    run(['systemctl', 'stop', '--job-mode=replace-irreversibly', SERVICE], check=selected['core'] in ('hysteria2','wireguard') and UNIT.exists())
    if selected['core'] == 'hysteria2' and HYSTERIA_UNIT.exists():
        run(['systemctl', 'stop', HYSTERIA_SERVICE])
    if selected['core']=='xray' and XRAY_UNIT.exists():run(['systemctl','stop','vpn-platform-xray.service'])
    if selected['core']=='openvpn' and OPENVPN_UNIT.exists():
        run(['systemctl','stop','vpn-platform-openvpn.service'])
        if not binary_record['exists']:run(['systemctl','disable','--now','vpn-platform-openvpn-network.service'],check=False)
    if selected['core']=='pptp' and PPTP_UNIT.exists():
        run(['systemctl','stop','vpn-platform-pptp.service'])
        if not binary_record['exists']:run(['systemctl','disable','--now','vpn-platform-pptp-network.service'],check=False)
    with node_ownership():
        if not next(entry['exists'] for entry in records if entry['name'] == 'unit'):
            run(['systemctl', 'disable', SERVICE], check=False)
        for entry in records:
            target = Path(entry['path'])
            if entry['exists']:
                mode = 0o755 if target == BINARY else 0o644 if target in (UNIT, HYSTERIA_UNIT,OPENVPN_UNIT,OPENVPN_NETWORK_UNIT,OPENVPN_DROPIN,XRAY_UNIT,WIREGUARD_DROPIN,PPTP_UNIT,PPTP_NETWORK_UNIT,PPTP_DROPIN) else 0o600
                atomic(target, (backup / entry['name']).read_bytes(), mode)
            elif target == ENV and state().get('agent_token'):
                # Keep the Control Plane address needed to recover a new registration.
                continue
            else:
                target.unlink(missing_ok=True)
        release_record = DATA / 'agent/binary-release.json'
        if binary_record['exists'] and binary_record.get('agent_version'):
            atomic(release_record, json.dumps({'version': binary_record['agent_version'], 'sha256': binary_record['sha256']}))
        else:
            release_record.unlink(missing_ok=True)
    run(['systemctl', 'daemon-reload'])
    restored_node = BINARY.exists() and UNIT.exists() and state().get('agent_token')
    previous_health = None
    cp = config().get('VPN_CONTROL_PLANE', DEFAULT_CP)
    if restored_node:
        try: previous_health = self_status(cp).get('health_checked_at')
        except ToolError: pass
    if BINARY.exists() and UNIT.exists(): run(['systemctl', 'restart', SERVICE])
    atomic(backup / 'rolled-back', 'complete\n')
    run(['systemctl', 'stop', guard_name(backup) + '.timer'], check=False)
    if restored_node:
        expected = binary_record.get('agent_version')
        if not expected:
            print('ROLLBACK_FILES_RESTORED_HEALTH_UNCONFIRMED backup=' + backup.name)
            return
        try: wait_ready(cp, expected, previous_health, True)
        except ToolError:
            raise ToolError('Rollback files restored, but fresh healthy state was not confirmed; inspect the node before continuing') from None
    print('ROLLBACK_COMPLETE backup=' + backup.name)

def register(cp, token_file=None, inspected=None):
    if state().get('agent_token'): return
    token = inspected[0] if inspected is not None else read_bootstrap_credential(token_file)
    selected = runtime_selection()['core']
    payload = {'agent_version': VERSION, 'os_name': 'ubuntu', 'os_version': '24.04', 'architecture': 'amd64'}
    if selected != 'xray': payload['runtime_core'] = selected
    result = request(cp, '/api/v1/agent/register', payload, token)
    token = None
    if result.get('runtime_core', 'xray') != selected: raise ToolError('Registered runtime differs from local selection; preserve this installation and investigate the server response')
    if inspected is not None and result.get('node_id') != inspected[1]: raise ToolError('Registered node differs from the inspected bootstrap identity')
    try:
        uuid.UUID(result['node_id']); uuid.UUID(result['tenant_id'])
        if not isinstance(result['agent_token'], str) or not result['agent_token']: raise ValueError()
    except Exception: raise ToolError('Invalid registration response') from None
    STATE.parent.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(STATE.parent, 0o700)
    atomic(STATE, json.dumps({key: result[key] for key in ('node_id', 'tenant_id', 'agent_token')} | {'applied_generation': 0}))
    print('REGISTRATION_SAVED')

def install_files(cp, artifact, selected_core=None):
    cfg = config(); cfg['VPN_CONTROL_PLANE'] = cp; cfg['VPN_AGENT_STATE'] = str(STATE); cfg['VPN_AGENT_DATA'] = str(DATA)
    if selected_core is not None: cfg['VPN_RUNTIME_CORE'] = selected_core
    cfg.pop('VPN_BOOTSTRAP_TOKEN', None)
    atomic(ENV, '\n'.join(k + '=' + shlex.quote(v) for k, v in cfg.items()) + '\n')
    atomic(BINARY, artifact.read_bytes(), 0o755)
    atomic(DATA / 'agent/binary-release.json', json.dumps({'version': VERSION, 'sha256': digest(BINARY)}))
    unit = '''[Unit]
Description=VPN Platform Node Agent
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
EnvironmentFile=/etc/vpn-platform/node-agent.env
ExecStart=/usr/local/bin/vpn-node-agent
Restart=always
RestartSec=3
UMask=0077
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
'''
    atomic(UNIT, unit, 0o644)
    if selected_core=='wireguard':
        # systemd runs this after the Agent exits, including SIGKILL. The helper
        # takes node ownership, closes the link, then persists final counters.
        dropin='[Service]\nTimeoutStartSec=100\nTimeoutStopSec=30\nExecStartPre=/usr/local/bin/vpn-node-agent provision-runtime --core wireguard --data-dir='+str(DATA)+'\nExecStopPost=/usr/local/bin/vpn-node-agent wireguard-runtime-stop --data-dir='+str(DATA)+'\n'
        atomic(WIREGUARD_DROPIN,dropin,0o644)

def expected_enrollment_node(args):
    expected = getattr(args, 'expected_node_id', None)
    if expected is None:
        return None
    try:
        if args.command != 'install' or str(uuid.UUID(expected)) != expected:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ToolError('Expected node identity must be canonical and is valid only with install') from None
    return expected


def require_initial_install_retry():
    # Only a completed rollback of a failed FIRST installation may be resumed
    # by the website command. Never turn it into a repair of a working node.
    backup = resolve_backup()
    if (backup / 'committed').exists() or not (backup / 'rolled-back').is_file():
        raise ToolError('No completed first-install rollback is available; inspect status before continuing')
    directory = backup / 'data-directory'
    if not directory.is_file() or directory.read_text().strip() != str(DATA):
        raise ToolError('Installation retry belongs to a different data directory')
    try:
        records = json.loads((backup / 'manifest.json').read_text())
        binary = [entry for entry in records if entry.get('name') == 'binary']
        if len(binary) != 1 or binary[0].get('path') != str(BINARY) or binary[0].get('exists') is not False:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ToolError('Installation retry is not a verified first-install rollback') from None


def execute(args):
    if os.geteuid() != 0: raise ToolError('Run this tool as root')
    expected = expected_enrollment_node(args)
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        configure_data_directory(getattr(args, 'data_dir', None))
        if args.command == 'rollback': return restore(resolve_backup(args.backup), args.automatic)
        cfg = config()
        cp = validate_url(args.control_plane or cfg.get('VPN_CONTROL_PLANE', DEFAULT_CP), args.allow_http_test)
        configure_download_origin(cp)
        if args.command == 'status':
            print(json.dumps(self_status(cp), ensure_ascii=False, indent=2)); return
        selected = planned_runtime_core(getattr(args, 'core', None) or cfg.get('VPN_RUNTIME_CORE'))
        require_runtime_compatible(VERSION, selected)
        require_runtime_data_traversal(selected)
        preflight(cp)
        local_identity = state()
        registered = bool(local_identity.get('agent_token'))
        if expected and registered and local_identity.get('node_id') != expected:
            raise ToolError('This server belongs to a different node; enrollment was refused before lifecycle changes')
        if getattr(args, 'require_bootstrap', False):
            if args.command != 'install':
                raise ToolError('--require-bootstrap is valid only with install')
            if registered and expected is None:
                raise ToolError('This server is already registered; fresh node enrollment was refused before any lifecycle changes')
        if args.command in ('upgrade', 'repair') and not registered: raise ToolError('Node is not registered; use install')
        if registered:
            observed = self_status(cp).get('agent_version') or ''
            try: newer = tuple(map(int, observed.split('.'))) > tuple(map(int, VERSION.split('.')))
            except ValueError: raise ToolError('Installed agent version is not recognized; nothing changed') from None
            if newer: raise ToolError('A newer agent is installed; download its matching tool or use explicit rollback')
        inspected = runtime_server_preflight(cp, selected, registered, getattr(args, 'bootstrap_token_file', None))
        if expected and not registered and (inspected is None or inspected[1] != expected):
            raise ToolError('Bootstrap does not belong to the selected website node; enrollment was refused before lifecycle changes')
        if expected and registered:
            # self_status authenticates the retained credential and verifies the
            # Control Plane response against the local identity before this gate.
            if BINARY.exists() and digest(BINARY) == SHA256 and ready(self_status(cp)):
                print('ALREADY_CURRENT_AND_HEALTHY version=' + VERSION); return
            require_initial_install_retry()
        elif registered and args.command != 'repair' and BINARY.exists() and digest(BINARY) == SHA256:
            if ready(self_status(cp)):
                print('ALREADY_CURRENT_AND_HEALTHY version=' + VERSION); return
            raise ToolError('Current version is installed but the node is not healthy; use status or repair')
        with tempfile.TemporaryDirectory(prefix='vpn-node-tool-') as temp:
            artifact = Path(temp) / 'agent'
            local_artifact = getattr(args, 'artifact_file', None)
            if local_artifact: download(artifact, local_artifact)
            else: download(artifact)
            if selected['core']=='openvpn':prepare_openvpn_package(Path(temp))
            if selected['core']=='wireguard':prepare_wireguard_packages(Path(temp))
            runtime_artifact=getattr(args,'runtime_artifact_file',None)
            if runtime_artifact and selected['core']!='pptp':raise ToolError('Local runtime artifact is supported only for PPTP')
            if selected['core']=='pptp':prepare_pptp_package(Path(temp),runtime_artifact)
            backup = snapshot(); arm_guard(backup)
            try:
                run(['systemctl', 'stop', '--job-mode=replace-irreversibly', SERVICE], check=UNIT.exists())
                if selected['core'] == 'hysteria2' and HYSTERIA_UNIT.exists(): run(['systemctl', 'stop', HYSTERIA_SERVICE])
                if selected['core']=='openvpn' and OPENVPN_UNIT.exists():run(['systemctl','stop','vpn-platform-openvpn.service'])
                if selected['core']=='pptp' and PPTP_UNIT.exists():run(['systemctl','stop','vpn-platform-pptp.service'])
                with node_ownership() as descriptor:
                    install_files(cp, artifact, selected['core'])
                    if selected['core'] in ('hysteria2','openvpn','wireguard','pptp'):
                        run([str(BINARY), 'provision-runtime', '--core', selected['core'], '--data-dir', str(DATA), '--ownership-fd', str(descriptor)], timeout=100, pass_fds=(descriptor,))
                    if not registered: register(cp, args.bootstrap_token_file, inspected)
                previous_health = self_status(cp).get('health_checked_at')
                run(['systemctl', 'daemon-reload']); run(['systemctl', 'enable', SERVICE]); run(['systemctl', 'restart', SERVICE])
                result = wait_ready(cp, VERSION, previous_health, True)
                atomic(backup / 'committed', 'complete\n')
                run(['systemctl', 'stop', guard_name(backup) + '.timer'])
                print('NODE_READY version=' + VERSION + ' identity=VERIFIED backup=' + backup.name)
            except Exception:
                restore(backup)
                raise

def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description='VPN Platform node install / upgrade / repair / rollback')
    parser.add_argument('command', choices=('install', 'upgrade', 'repair', 'rollback', 'status'), nargs='?', default='install')
    parser.add_argument('--control-plane')
    parser.add_argument('--data-dir', help='Protected Hysteria data directory; Xray requires /var/lib/vpn-platform and existing nodes cannot move')
    parser.add_argument('--artifact-file', help='Use a local agent binary; the release SHA-256 pin is still mandatory')
    parser.add_argument('--runtime-artifact-file', help='Local PPTP package; the reviewed release digest remains mandatory')
    parser.add_argument('--core', choices=('xray', 'hysteria2', 'openvpn', 'wireguard', 'pptp'), help='Core for a fresh node; existing nodes cannot migrate')
    parser.add_argument('--bootstrap-token-file', help='Owner-only file; credentials are never placed on the command line')
    parser.add_argument('--require-bootstrap', action='store_true', help='Require bootstrap enrollment; bound first-install retries also require --expected-node-id')
    parser.add_argument('--expected-node-id', help='Bind website enrollment and first-install retry to this node identity')
    parser.add_argument('--backup', help='Backup ID from this tool; defaults to the latest')
    parser.add_argument('--automatic', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--allow-http-test', action='store_true', help=argparse.SUPPRESS)
    try: execute(parser.parse_args())
    except ToolError as e: print('ERROR: ' + str(e), file=sys.stderr); return 1
    except KeyboardInterrupt: print('Interrupted; rollback guard remains active for unfinished changes', file=sys.stderr); return 130
    except Exception: print('ERROR: operation failed; inspect the local backup and service status', file=sys.stderr); return 1
    return 0

if __name__ == '__main__': sys.exit(main())
