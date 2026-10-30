"""Root-only Linux fixture; never touches a live node or calls services."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('tool', Path(__file__).with_name('vpn-node-tool.py'))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'isolated Linux root fixture required')
class CascadeInstallerFloorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pauk-cascade-installer-')
        self.old = tool.DATA
        tool.DATA = Path(self.tmp.name)
        tool.DATA.chmod(0o700)
        self.path = tool.DATA / 'runtime-selection.json'
        self.write('0.2.34')

    def tearDown(self):
        tool.DATA = self.old
        self.tmp.cleanup()

    def write(self, minimum):
        self.path.write_text(json.dumps({'format': 1, 'core': 'xray', 'minimum_agent': minimum}))
        self.path.chmod(0o600)

    def test_floor_survives_absent_cascade_configuration(self):
        # A cascade may be removed; the disk selection remains the downgrade fence.
        before = self.path.read_bytes()
        selected = tool.runtime_selection()
        self.assertEqual(selected['minimum_agent'], '0.2.34')
        for version in ('0.2.23', '0.2.31', '0.2.32', '0.2.33'):
            with self.subTest(version=version), self.assertRaises(tool.ToolError):
                tool.require_runtime_compatible(version)
        for version in ('0.2.34', '0.2.35'):
            tool.require_runtime_compatible(version)
        self.assertEqual(before, self.path.read_bytes())

    def test_access_fence_cannot_lower_cascade_floor(self):
        (tool.DATA / 'xray').mkdir()
        (tool.DATA / 'xray/access-fence.json').write_text('{}')
        self.assertEqual(tool.required_runtime_minimum(tool.runtime_selection()), '0.2.34')
        with self.assertRaises(tool.ToolError):
            tool.require_runtime_compatible('0.2.33')

    def test_known_previous_selections_remain_accepted(self):
        for minimum in ('0.2.23', '0.2.31'):
            with self.subTest(minimum=minimum):
                self.write(minimum)
                self.assertEqual(tool.runtime_selection()['minimum_agent'], minimum)
                tool.require_runtime_compatible('0.2.34')

    def test_unknown_or_malformed_floor_refused_without_rewrite(self):
        for minimum in ('0.2.35', '0.2.034', '0.2.34-extra', '', None):
            with self.subTest(minimum=minimum):
                self.write(minimum)
                before = self.path.read_bytes()
                with self.assertRaises(tool.ToolError):
                    tool.runtime_selection()
                self.assertEqual(before, self.path.read_bytes())

    def test_cascade_selection_keeps_file_protections(self):
        self.path.chmod(0o644)
        with self.assertRaises(tool.ToolError):
            tool.runtime_selection()
        self.path.chmod(0o600)
        target = tool.DATA / 'protected-selection.json'
        self.path.rename(target)
        self.path.symlink_to(target)
        with self.assertRaises(tool.ToolError):
            tool.runtime_selection()


if __name__ == '__main__':
    unittest.main(verbosity=2)
