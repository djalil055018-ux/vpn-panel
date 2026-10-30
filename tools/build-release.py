#!/usr/bin/env python3
"""Build the public Linux distribution from the source snapshots in this repository."""
import argparse
import ast
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
VERSION = '0.1.155'
CP_VERSION = '0.1.150'
WEB_VERSION = '0.12.71'
AGENTS = ('0.2.39', '0.2.42', '0.2.43')
UPSTREAM_FILES = {
    'artifacts/cores/amneziawg/3.1.20260828-pauk.1/linux-amd64.tar.gz': '1fc10912a24cc14178f3937552bd8c6a9d6489d8462f0884053a9ea3091e886a',
    'artifacts/pptp/1.14.0-platform.1/linux-amd64/pptp-accel-1.14.0-platform.1-linux-amd64.tar.gz': 'd6960405b74030750e7b835e3dafef76e26f1d2748a4d347578204fabcdd08a6',
    'artifacts/openvpn/2.6.19-0ubuntu0.24.04.4/linux-amd64/openvpn.deb': 'd288c3789e825b140258da3e2c40bdb8f07820b8e69ca6480b619b83af8f108a',
    'install/vpn-agent-updater-v0.1.0.py': '485a34aca4630548f2930f24a0f7ae73cf910611749bcd649a0126597cdb7fde',
    'install/install-vpn-agent-updater-v0.1.0.py': '6298b66dc56255cfad6530307db50a9d320c74e0da511b39c119fffa6505d370',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding='utf-8', newline='\n')


def bundle(directory, target):
    with target.open('wb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode='w') as archive:
                for path in sorted(directory.rglob('*')):
                    if not path.is_file():
                        continue
                    assert not path.is_symlink()
                    entry = archive.gettarinfo(str(path), arcname=path.relative_to(directory).as_posix())
                    entry.uid = entry.gid = entry.mtime = 0
                    entry.uname = entry.gname = ''
                    # Windows does not retain POSIX executable flags.
                    entry.mode = 0o755 if '/bin/' in '/' + entry.name or entry.name.startswith('artifacts/node-agent/') else 0o644
                    with path.open('rb') as stream:
                        archive.addfile(entry, stream)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    parser.add_argument('--runtime-dir', type=Path, required=True, help='Directory with the pinned upstream files listed in UPSTREAM_FILES')
    parser.add_argument('--work-dir', type=Path, required=True, help='A new directory for temporary output')
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    work = args.work_dir.resolve()
    assert not work.exists(), 'Use a new build directory'
    work.mkdir(parents=True)
    args.output.mkdir(parents=True, exist_ok=True)
    stage = work / 'bundle'
    payload = stage / 'payload'
    payload.mkdir(parents=True)
    public = work / 'public'
    public.mkdir()
    for rel, expected in UPSTREAM_FILES.items():
        source = args.runtime_dir / rel
        assert source.is_file() and sha(source) == expected, 'Upstream runtime checksum mismatch: ' + rel
        target = public / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    env = {**os.environ, 'GOOS': 'linux', 'GOARCH': 'amd64', 'CGO_ENABLED': '0', 'GOTOOLCHAIN': 'local', 'GOMAXPROCS': '2'}
    (work / 'tmp').mkdir()
    env.update(GOTMPDIR=str(work / 'tmp'), TMP=str(work / 'tmp'), TEMP=str(work / 'tmp'))
    previous = json.loads((ROOT / 'node-assets.json').read_text(encoding='utf-8'))
    replacements = {}
    rows = {}
    for version in AGENTS:
        rel = 'artifacts/node-agent/' + version + '/linux-amd64/vpn-node-agent'
        target = public / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        command = [args.go, 'build', '-trimpath', '-buildvcs=false', '-ldflags=-s -w -buildid=', '-o', str(target), './cmd/node-agent']
        result = subprocess.run(command, cwd=ROOT / 'native-agents' / version, env=env, capture_output=True, timeout=600)
        (work / ('agent-' + version + '.log')).write_bytes(result.stdout + result.stderr)
        assert result.returncode == 0, 'Node agent build failed: ' + version
        digest = sha(target)
        replacements[previous[rel]['sha256']] = digest
        rows[rel] = {'sha256': digest, 'bytes': target.stat().st_size}
        print('Built node agent ' + version, flush=True)
    # Update the generated binary pins before computing each node-tool checksum.
    for base in (ROOT / 'control-plane', ROOT / 'native-agents'):
        for path in base.rglob('*.py'):
            text = path.read_text(encoding='utf-8')
            for old, new in replacements.items():
                text = text.replace(old, new)
            write(path, text)
    for version in AGENTS:
        rel = 'install/vpn-node-tool-v' + version + '.py'
        target = public / rel
        source = ROOT / 'control-plane/scripts' / ('vpn-node-tool-v' + version + '.py')
        assert source.is_file()
        shutil.copyfile(source, target)
        ast.parse(target.read_text(encoding='utf-8'))
        digest = sha(target)
        replacements[previous[rel]['sha256']] = digest
        rows[rel] = {'sha256': digest, 'bytes': target.stat().st_size}
    runtime_ts = ROOT / 'web/src/lib/node-runtime.ts'
    text = runtime_ts.read_text(encoding='utf-8')
    for old, new in replacements.items():
        assert old in text, 'The frontend asset pin is missing'
        text = text.replace(old, new)
    write(runtime_ts, text)
    for rel in UPSTREAM_FILES:
        path = public / rel
        rows[rel] = {'sha256': sha(path), 'bytes': path.stat().st_size}
    write(ROOT / 'node-assets.json', json.dumps(rows, indent=2) + '\n')
    ignored = shutil.ignore_patterns('__pycache__', '*.pyc', 'node_modules', '.next', '.env', '.env.local')
    shutil.copytree(ROOT / 'control-plane', payload / 'source', ignore=ignored)
    shutil.copytree(ROOT / 'web', payload / 'web', ignore=ignored)
    shutil.copytree(ROOT / 'control-plane/deploy/systemd', payload / 'systemd')
    spec = importlib.util.spec_from_file_location('lifecycle', ROOT / 'control-plane/scripts/platform-lifecycle.py')
    lifecycle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lifecycle)
    built = []
    for name in lifecycle.BINARIES + lifecycle.OPTIONAL_BINARIES:
        target = payload / 'bin' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run([args.go, 'build', '-trimpath', '-buildvcs=false', '-ldflags=-s -w -buildid=', '-o', str(target), './cmd/' + name],
                                cwd=ROOT / 'control-plane', env=env, capture_output=True, timeout=600)
        (work / (name + '.log')).write_bytes(result.stdout + result.stderr)
        assert result.returncode == 0, 'Control plane build failed: ' + name
        built.append(name)
        print('Built ' + name, flush=True)
    files = {p.relative_to(stage).as_posix(): {'sha256': sha(p), 'size_bytes': p.stat().st_size}
             for p in sorted(payload.rglob('*')) if p.is_file()}
    manifest = {'format': 1, 'product': 'vpn-platform-control-plane', 'version': CP_VERSION, 'schema_version': 77,
                'tool_version': lifecycle.TOOL_VERSION, 'built_at': '2026-10-30T00:00:00+00:00', 'platform': 'linux-amd64',
                'schema_policy': 'additive_forward_only', 'binaries': built, 'files': files,
                'web_version': WEB_VERSION, 'distribution_version': VERSION}
    write(stage / 'manifest.json', json.dumps(manifest, indent=2) + '\n')
    core = args.output / 'vpn-panel-control-plane-linux-amd64.tgz'
    bundle(stage, core)
    checked = work / 'verified'
    checked.mkdir()
    assert lifecycle.extract_bundle(core, checked) == manifest
    node_assets = args.output / 'vpn-panel-node-assets.tgz'
    bundle(public, node_assets)
    # Also expose the two immutable runtime URLs referenced in desired state.
    standalone = {
        'amneziawg-3.1.20260828-pauk.1-linux-amd64.tar.gz': 'artifacts/cores/amneziawg/3.1.20260828-pauk.1/linux-amd64.tar.gz',
        'pptp-accel-1.14.0-platform.1-linux-amd64.tar.gz': 'artifacts/pptp/1.14.0-platform.1/linux-amd64/pptp-accel-1.14.0-platform.1-linux-amd64.tar.gz',
    }
    for filename, source in standalone.items():
        shutil.copyfile(public / source, args.output / filename)
    metadata = {'distribution': VERSION, 'control_plane': CP_VERSION, 'web': WEB_VERSION,
                'core_sha256': sha(core), 'node_assets_sha256': sha(node_assets), 'node_assets': rows,
                'core_manifest_sha256': sha(stage / 'manifest.json')}
    write(args.output / 'release.json', json.dumps(metadata, indent=2) + '\n')
    renderer_spec = importlib.util.spec_from_file_location('render_installer', ROOT / 'tools/render-installer.py')
    renderer = importlib.util.module_from_spec(renderer_spec)
    renderer_spec.loader.exec_module(renderer)
    renderer.render(args.output)
    write(args.output / 'SHA256SUMS.txt', ''.join(sha(path) + '  ' + path.name + '\n'
          for path in sorted(args.output.iterdir()) if path.is_file() and path.name != 'SHA256SUMS.txt'))
    print(json.dumps({'status': 'BUILD_AND_MANIFEST_VERIFICATION_PASS', 'files': len(files), **metadata}), flush=True)


if __name__ == '__main__':
    main()
