#!/usr/bin/env python3
"""Render the installation script with the exact hashes of an assembled release."""
import argparse
import json
from pathlib import Path
import re


def render(dist):
    root = Path(__file__).resolve().parents[1]
    release = json.loads((dist / 'release.json').read_text(encoding='utf-8'))
    assert release['distribution'] == '0.1.155'
    text = (root / 'tools/install.sh.in').read_text(encoding='utf-8')
    for key in ('core_sha256', 'node_assets_sha256'):
        assert re.fullmatch('[a-f0-9]{64}', release[key])
    text = text.replace('@CORE_SHA256@', release['core_sha256'])
    text = text.replace('@NODE_ASSETS_SHA256@', release['node_assets_sha256'])
    text = text.replace('@NODE_ASSET_MANIFEST@', json.dumps(release['node_assets'], separators=(',', ':')))
    assert not re.search('@[A-Z_]+@', text)
    (root / 'install.sh').write_text(text, encoding='utf-8', newline='\n')
    (dist / 'install.sh').write_text(text, encoding='utf-8', newline='\n')
    return root / 'install.sh'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dist', type=Path)
    print(render(parser.parse_args().dist))
