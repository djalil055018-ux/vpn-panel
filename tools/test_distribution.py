"""Linux regression tests for the shipped node-asset installer in an isolated directory."""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

DIST = Path(os.environ['VPN_PANEL_TEST_DIST']).resolve()
INSTALLER = (DIST / 'install.sh').read_text(encoding='utf-8')
CODE = INSTALLER.split("<<'PY_NODE_ASSETS'\n", 1)[1].split('\nPY_NODE_ASSETS', 1)[0]
RELEASE = json.loads((DIST / 'release.json').read_text(encoding='utf-8'))


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'Requires an isolated Linux root fixture')
class NodeAssetDistributionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='vpn-panel-public-test-', dir='/var/lib')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.base.chmod(0o755)
        self.public = self.base / 'public'

    def execute(self, archive=None):
        code = CODE.replace("Path('/var/www/vpn-platform-public')", 'Path(' + repr(str(self.public)) + ')')
        old = os.umask(0o077)
        try:
            with patch.object(sys, 'argv', ['node-assets', str(archive or DIST / 'vpn-panel-node-assets.tgz')]):
                exec(compile(code, '<shipped-node-assets-installer>', 'exec'), {})
        finally:
            os.umask(old)

    def test_exact_release_and_resume_with_private_umask(self):
        self.execute()
        self.execute()
        for directory in [self.public, *[p for p in self.public.rglob('*') if p.is_dir()]]:
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
        for rel, expected in RELEASE['node_assets'].items():
            path = self.public / rel
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected['sha256'])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)

    def test_symlink_root_is_rejected(self):
        target = self.base / 'unmanaged'
        target.mkdir()
        self.public.symlink_to(target, target_is_directory=True)
        with self.assertRaises(SystemExit):
            self.execute()
        self.assertFalse(any(target.iterdir()))

    def test_new_parent_is_traversable_under_private_umask(self):
        self.public = self.base / 'new-parent/public'
        self.execute()
        self.assertEqual(stat.S_IMODE(self.public.parent.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(self.public.stat().st_mode), 0o755)

    def test_modified_existing_asset_is_not_overwritten(self):
        self.execute()
        path = self.public / 'install/vpn-node-tool-v0.2.39.py'
        path.write_bytes(b'unmanaged data')
        with self.assertRaises(SystemExit):
            self.execute()
        self.assertEqual(path.read_bytes(), b'unmanaged data')

    def test_incomplete_or_traversing_archive_is_rejected(self):
        for name in ('install/unexpected.py', '../escape'):
            target = self.base / 'invalid.tgz'
            with tarfile.open(target, 'w:gz') as archive:
                entry = tarfile.TarInfo(name)
                raw = b'not a release'
                entry.size = len(raw)
                archive.addfile(entry, io.BytesIO(raw))
            with self.assertRaises(SystemExit):
                self.execute(target)
            self.assertFalse((self.base / 'escape').exists())


if __name__ == '__main__':
    unittest.main()
