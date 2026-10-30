import importlib.util,io,json,tarfile,tempfile,unittest
from unittest.mock import patch
from pathlib import Path
spec=importlib.util.spec_from_file_location('drill',Path(__file__).with_name('platform-restore-drill.py'))
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
class DrillTests(unittest.TestCase):
 def test_database_count_matches_node_api_visible_set(self):
  self.assertIn("FROM nodes WHERE status<>'retired'",d.RESTORED_COUNTS_SQL)
 def test_database_target_changes_only_to_unique_disposable_name(self):
  name='vpn_restore_drill_0123456789abcdef'
  self.assertEqual(d.clone_dsn('postgres://user:p%40ss@127.0.0.1:5432/live?sslmode=disable',name),'postgres://user:p%40ss@127.0.0.1:5432/'+name+'?sslmode=disable')
  for url in ['postgres://u:p@remote/live','postgres://u:p@localhost/live?dbname=live','postgres://u:p@localhost/live?host=remote','postgres://u:p@localhost/live?options=-c%20dbname=live','postgres://u:p@localhost/live?sslmode=disable&sslmode=require']:
   with self.assertRaises(d.DrillError):d.clone_dsn(url,name)
  with self.assertRaises(d.DrillError):d.clone_dsn('postgres://u:p@localhost/live','live')
 def test_selected_archive_links_and_traversal_are_never_extracted(self):
  for name,kind in [('opt/vpn-platform/web/src/escape',tarfile.SYMTYPE),('../escape',tarfile.REGTYPE)]:
   with tempfile.TemporaryDirectory() as temp:
    root=Path(temp);archive=root/'archive.tgz';out=root/'out';out.mkdir()
    with tarfile.open(archive,'w:gz') as tar:
     item=tarfile.TarInfo(name);item.type=kind;item.linkname='/etc/passwd';tar.addfile(item,io.BytesIO())
    with self.assertRaises(d.DrillError):d.extract_selected(archive,out)
    self.assertFalse((root/'escape').exists())
 def test_missing_build_configuration_fails_before_database_creation(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);archive=root/'archive.tgz';out=root/'out';out.mkdir()
   with tarfile.open(archive,'w:gz') as tar:
    item=tarfile.TarInfo('etc/vpn-platform/control-plane.env');data=b'DATABASE_URL=test';item.size=len(data);tar.addfile(item,io.BytesIO(data))
   with self.assertRaises(d.DrillError):d.extract_selected(archive,out)
 def test_environment_is_parsed_without_shell_execution(self):
  self.assertEqual(d.env_values(b"VALUE='$(printf private)'\nEMPTY=\n"),{'VALUE':'$(printf private)','EMPTY':''})
 def test_mfa_verifier_is_required_for_new_backups_and_explicit_for_legacy(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp)
   self.assertEqual(d.verify_mfa(root,{},'0.1.84'),{'status':'not_supported_by_archived_release'})
   with self.assertRaises(d.DrillError):d.verify_mfa(root,{},'0.1.85')
   verifier=root/d.MFA_VERIFIER;verifier.parent.mkdir(parents=True);verifier.write_bytes(b'test')
   valid={'status':'verified','enabled_accounts':2,'pending_enrollments':1,'key_configured':True}
   with patch.object(d,'run',return_value=json.dumps({**valid,'unexpected':'not returned'}).encode()) as runner:
    self.assertEqual(d.verify_mfa(root,{'DATABASE_URL':'clone'},'0.1.85'),valid)
    runner.assert_called_once_with([str(verifier)],env={'DATABASE_URL':'clone'},timeout=40)
   for result in [{**valid,'enabled_accounts':True},{**valid,'pending_enrollments':-1},{**valid,'status':'failed'}]:
    with patch.object(d,'run',return_value=json.dumps(result).encode()):
     with self.assertRaises(d.DrillError):d.verify_mfa(root,{},'0.1.85')
   with patch.object(d,'run',side_effect=RuntimeError('sensitive raw error')):
    with self.assertRaisesRegex(d.DrillError,'^restored MFA verification failed$'):d.verify_mfa(root,{},'0.1.85')
if __name__=='__main__':unittest.main()
