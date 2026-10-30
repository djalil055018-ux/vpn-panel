import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('updater',Path(__file__).with_name('vpn-agent-updater.py'))
updater=importlib.util.module_from_spec(spec);spec.loader.exec_module(updater)

def assignment():
    return {'job_id':'11111111-1111-4111-8111-111111111111','run_id':'22222222-2222-4222-8222-222222222222','node_id':'33333333-3333-4333-8333-333333333333','claim_id':'44444444-4444-4444-8444-444444444444','from_version':'0.2.27','can_execute':True,'release':{'version':'0.2.30','binary_sha256':'a'*64,'installer_sha256':'b'*64}}

class FakeClient:
    node_id=assignment()['node_id']
    def __init__(self):self.reports=[];self.data=Path('/unused')
    def api(self,path,data=None):
        if '/report' in path:self.reports.append(data);return None
        raise AssertionError('unexpected API call')

class UpdaterTest(unittest.TestCase):
    def test_assignment_scope_and_version(self):
        value=assignment()
        with self.assertRaises(updater.UpdateError):updater.validate_assignment(value,assignment()['job_id'])
        value['release']['version']='0.2.30; touch /tmp/injected'
        with self.assertRaises(updater.UpdateError):updater.validate_assignment(value,FakeClient.node_id)
        value=assignment();value['release']['binary_sha256']='0'*63
        with self.assertRaises(updater.UpdateError):updater.validate_assignment(value,FakeClient.node_id)

    def test_installer_release_must_match(self):
        release=assignment()['release']
        updater.installer_identity(('VERSION="0.2.30"\nSHA256="'+'a'*64+'"\n').encode(),release)
        with self.assertRaises(updater.UpdateError):updater.installer_identity(b'VERSION="0.2.31"\nSHA256="wrong"',release)
        with self.assertRaises(updater.UpdateError):updater.installer_identity(b'VERSION=do_something()\n',release)

    def directory(self,root,value):
        directory=root/(value['job_id']+'-'+value['claim_id']);directory.mkdir()
        updater.atomic(directory/'assignment.json',updater.validate_assignment(value,FakeClient.node_id))
        return directory

    def test_saved_receipt_replays_without_install(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(updater,'protected'),patch.object(updater.subprocess,'run') as install:
            root=Path(tmp);value=assignment();directory=self.directory(root,value)
            receipt={'status':'succeeded','binary_sha256':'a'*64,'code':'ready'};updater.atomic(directory/'result.json',receipt)
            client=FakeClient()
            with patch.object(updater,'ROOT',root):updater.execute(client,value)
            install.assert_not_called();self.assertEqual(client.reports,[{'claim_id':value['claim_id'],**receipt}])
            self.assertTrue((directory/'reported.json').exists())

    def test_interrupted_installer_keeps_slot_until_guard_finishes(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(updater,'protected'),patch.object(updater.subprocess,'run') as install:
            root=Path(tmp);value=assignment();directory=self.directory(root,value)
            updater.atomic(directory/'started.json',{'at':time.time()});client=FakeClient()
            with patch.object(updater,'ROOT',root):updater.execute(client,value)
            self.assertEqual(client.reports,[]);install.assert_not_called()
            updater.atomic(directory/'started.json',{'at':time.time()-500})
            with patch.object(updater,'ROOT',root),patch.object(updater,'pending_rollback',return_value=True):updater.execute(client,value)
            self.assertEqual(client.reports,[]);install.assert_not_called()
            with patch.object(updater,'ROOT',root),patch.object(updater,'pending_rollback',return_value=False),patch.object(updater,'healthy',return_value=False):updater.execute(client,value)
            self.assertEqual(client.reports[0]['code'],'interrupted');install.assert_not_called()

    def test_committed_installer_recovers_receipt_without_repeat(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(updater,'protected'),patch.object(updater.subprocess,'run') as install:
            root=Path(tmp);value=assignment();directory=self.directory(root,value)
            updater.atomic(directory/'started.json',{'at':time.time()-500});client=FakeClient()
            with patch.object(updater,'ROOT',root),patch.object(updater,'pending_rollback',return_value=False),patch.object(updater,'healthy',return_value=True):updater.execute(client,value)
            self.assertEqual(client.reports[0]['status'],'succeeded');install.assert_not_called()

    def test_paused_or_revoked_assignment_never_executes(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(updater,'protected'),patch.object(updater.subprocess,'run') as install:
            value=assignment();value['can_execute']=False;client=FakeClient()
            with patch.object(updater,'ROOT',Path(tmp)):updater.execute(client,value)
            self.assertEqual(client.reports[0]['status'],'failed');install.assert_not_called()

    def test_timeout_or_failure_does_not_release_next_node(self):
        for outcome in ['timeout','failure']:
            with self.subTest(outcome=outcome),tempfile.TemporaryDirectory() as tmp,patch.object(updater,'protected'):
                root=Path(tmp);value=assignment();client=FakeClient()
                client.api=lambda *args: {'healthy':True,'health_fresh':True,'desired_generation':1,'applied_generation':1,'agent_version':'0.2.27'}
                client.claim=lambda:value
                client.download=lambda path,target,*args:target.write_text('VERSION="0.2.30"\nSHA256="'+'a'*64+'"\n')
                error=updater.subprocess.TimeoutExpired('installer',300) if outcome=='timeout' else None
                completed=updater.subprocess.CompletedProcess([],1)
                with patch.object(updater,'ROOT',root),patch.object(updater,'pending_rollback',return_value=False),patch.object(updater.subprocess,'run',side_effect=error,return_value=completed),patch.object(updater,'report') as report:
                    updater.execute(client,value)
                directory=root/(value['job_id']+'-'+value['claim_id'])
                self.assertTrue((directory/'started.json').exists())
                self.assertFalse((directory/'result.json').exists())
                report.assert_not_called()

if __name__=='__main__':unittest.main()
