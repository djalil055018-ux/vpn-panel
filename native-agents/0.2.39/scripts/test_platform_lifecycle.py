import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('lifecycle',Path(__file__).with_name('platform-lifecycle.py'))
l=importlib.util.module_from_spec(spec);spec.loader.exec_module(l)

class LifecycleTests(unittest.TestCase):
 def test_bootstrap_never_resets_existing_owner(self):
  fixture='CONTROL_PLANE_ADMIN_TOKEN=test-root\nWEB_ADMIN_USER=old-user\nWEB_ADMIN_PASSWORD_HASH=test-hash\n'
  response=io.BytesIO(json.dumps({'accounts':[{'enabled':True,'role':'owner'}]}).encode())
  with patch.object(Path,'read_text',return_value=fixture),patch.object(l,'urlopen',return_value=response) as request:
   l.ensure_administrator_owner()
  self.assertEqual(request.call_count,1)
  self.assertEqual(request.call_args.args[0].get_method(),'GET')
 def test_bootstrap_empty_table_then_requires_active_owner(self):
  fixture='CONTROL_PLANE_ADMIN_TOKEN=test-root\nWEB_ADMIN_USER=first-owner\nWEB_ADMIN_PASSWORD_HASH=test-hash\n'
  responses=[io.BytesIO(json.dumps(v).encode()) for v in [{'accounts':[]},{'initialized':True},{'accounts':[{'enabled':True,'role':'owner'}]}]]
  with patch.object(Path,'read_text',return_value=fixture),patch.object(l,'urlopen',side_effect=responses) as request:
   l.ensure_administrator_owner()
  self.assertEqual(request.call_count,3)
  body=json.loads(request.call_args_list[1].args[0].data)
  self.assertEqual(body,{'username':'first-owner','password_hash':'test-hash'})
 def test_bootstrap_missing_owner_fails_without_secret_detail(self):
  fixture='CONTROL_PLANE_ADMIN_TOKEN=never-print-this\n'
  response=io.BytesIO(json.dumps({'accounts':[{'enabled':False,'role':'owner'}]}).encode())
  with patch.object(Path,'read_text',return_value=fixture),patch.object(l,'urlopen',return_value=response):
   with self.assertRaises(l.LifecycleError) as caught:l.ensure_administrator_owner()
  self.assertNotIn('never-print-this',str(caught.exception))
 def setUp(self):
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);self.root=Path(temporary.name)
 def bundle_tree(self):
  root=self.root/'release';payload=root/'payload';(payload/'bin').mkdir(parents=True)
  for name in l.BINARIES:(payload/'bin'/name).write_bytes(name.encode())
  files={p.relative_to(root).as_posix():{'sha256':l.sha256(p),'size_bytes':p.stat().st_size} for p in payload.rglob('*') if p.is_file()}
  l.atomic_json(root/'manifest.json',{'format':1,'product':'vpn-platform-control-plane','version':'1.2.3','schema_version':4,'tool_version':'test','platform':'linux-amd64','schema_policy':'additive_forward_only','binaries':list(l.BINARIES),'files':files})
  return root
 def make_bundle(self):
  root=self.bundle_tree();bundle=self.root/'release.tgz';l.deterministic_bundle(root,bundle);return bundle
 def test_verified_bundle_is_extracted_and_identified(self):
  bundle=self.make_bundle();target=self.root/'extract';target.mkdir()
  manifest=l.extract_bundle(bundle,target)
  self.assertEqual(manifest['version'],'1.2.3');self.assertEqual(manifest['schema_version'],4)
 def test_payload_change_is_rejected(self):
  root=self.bundle_tree();(root/'payload/bin/control-plane').write_bytes(b'changed')
  bundle=self.root/'changed.tgz';l.deterministic_bundle(root,bundle);target=self.root/'extract';target.mkdir()
  with self.assertRaises(l.LifecycleError):l.extract_bundle(bundle,target)
 def test_extra_file_not_in_manifest_is_rejected(self):
  root=self.bundle_tree();(root/'payload/unlisted').write_text('x')
  bundle=self.root/'extra.tgz';l.deterministic_bundle(root,bundle);target=self.root/'extract';target.mkdir()
  with self.assertRaises(l.LifecycleError):l.extract_bundle(bundle,target)
 def test_traversal_and_links_are_rejected_without_extraction(self):
  for kind in ('traversal','symlink'):
   bundle=self.root/(kind+'.tgz')
   with tarfile.open(bundle,'w:gz') as archive:
    info=tarfile.TarInfo('../outside' if kind=='traversal' else 'payload/link')
    if kind=='symlink':info.type=tarfile.SYMTYPE;info.linkname='/etc/shadow';archive.addfile(info)
    else:info.size=1;archive.addfile(info,io.BytesIO(b'x'))
   target=self.root/('extract-'+kind);target.mkdir()
   with self.assertRaises(l.LifecycleError):l.extract_bundle(bundle,target)
   self.assertFalse((self.root/'outside').exists())
 def test_migrations_are_forward_only_and_exact(self):
  stage=self.root/'stage';migrations=stage/'payload/source/migrations';migrations.mkdir(parents=True)
  for number in range(1,5):(migrations/(f'{number:06d}_test.sql')).write_text(f'-- {number}')
  applied=[]
  with patch.object(l,'run') as run:l.apply_migrations(stage,2,4,applied.append)
  self.assertEqual(run.call_count,2)
  self.assertEqual(run.call_args_list[0].kwargs['input'],b'-- 3')
  self.assertEqual(applied,[3,4])
  with self.assertRaises(l.LifecycleError):l.apply_migrations(stage,5,4)
 def test_missing_next_migration_is_rejected_before_database_call(self):
  stage=self.root/'stage';migrations=stage/'payload/source/migrations';migrations.mkdir(parents=True)
  (migrations/'000004_test.sql').write_text('-- 4')
  with patch.object(l,'run') as run:
   with self.assertRaises(l.LifecycleError):l.apply_migrations(stage,2,4)
   run.assert_not_called()
 def test_adopt_records_only_safe_release_metadata(self):
  bundle=self.make_bundle();state=self.root/'state.json';lock=self.root/'lock'
  with patch.object(l,'STATE',state),patch.object(l,'LOCK',lock),patch.object(l,'require_root'),patch.object(l,'validate_host'),patch.object(l,'health',return_value={'status':'ok','version':'1.2.3'}):
   l.adopt(SimpleNamespace(bundle=str(bundle),sha256=l.sha256(bundle),schema=4,replace=False))
  value=json.loads(state.read_text());self.assertEqual(value['version'],'1.2.3');self.assertEqual(value['schema_version'],4)
  self.assertNotIn('token',state.read_text().lower())
 def test_adopt_rejects_running_version_or_schema_mismatch(self):
  bundle=self.make_bundle()
  with patch.object(l,'STATE',self.root/'state'),patch.object(l,'require_root'),patch.object(l,'validate_host'),patch.object(l,'health',return_value={'version':'1.2.2'}):
   with self.assertRaises(l.LifecycleError):l.adopt(SimpleNamespace(bundle=str(bundle),sha256=l.sha256(bundle),schema=4,replace=False))
  with patch.object(l,'STATE',self.root/'state2'),patch.object(l,'require_root'),patch.object(l,'validate_host'),patch.object(l,'health',return_value={'version':'1.2.3'}):
   with self.assertRaises(l.LifecycleError):l.adopt(SimpleNamespace(bundle=str(bundle),sha256=l.sha256(bundle),schema=3,replace=False))
 def test_external_digest_is_required_for_mutating_commands(self):
  bundle=self.make_bundle()
  self.assertEqual(l.require_digest(bundle,l.sha256(bundle)),l.sha256(bundle))
  with self.assertRaises(l.LifecycleError):l.require_digest(bundle,'0'*64)
  with self.assertRaises(l.LifecycleError):l.require_digest(bundle,'invalid')
 def test_rollback_id_must_be_exact(self):
  for value in ('','../escape','20260101T000000Z-1234567g','20260101T000000Z-12345678/other'):
   with self.assertRaises(l.LifecycleError):l.rollback_value(value)
 def test_automatic_guard_does_not_rollback_committed_release(self):
  identifier='20260101T000000Z-12345678';backup=self.root/identifier;backup.mkdir()
  archive=backup/'application.tgz';archive.write_bytes(b'archive');(backup/'committed').touch()
  l.atomic_json(backup/'manifest.json',{'id':identifier,'application_sha256':l.sha256(archive)})
  with patch.object(l,'BACKUPS',self.root),patch.object(l,'restore_tar') as restore:
   l.rollback_value(identifier,automatic=True)
  restore.assert_not_called()

 def test_runtime_rollback_refuses_hysteria_before_stopping_services(self):
  with patch.object(l,'database_boolean',side_effect=[True,True]),patch.object(l,'run') as run:
   with self.assertRaises(l.LifecycleError):l.prepare_runtime_rollback({'version':'0.1.85'})
   run.assert_not_called()

 def test_runtime_rollback_closes_creation_race_and_restarts_current_cp(self):
  with patch.object(l,'database_boolean',side_effect=[True,False,True]),patch.object(l,'unit_active',return_value=True),patch.object(l,'run') as run:
   with self.assertRaises(l.LifecycleError):l.prepare_runtime_rollback({'version':'0.1.85'})
  self.assertEqual([call.args[0] for call in run.call_args_list],[['systemctl','stop','vpn-platform-control-plane.service'],['systemctl','start','vpn-platform-control-plane.service']])

 def test_runtime_rollback_database_failure_keeps_current_release_available(self):
  with patch.object(l,'database_boolean',side_effect=[True,False,l.LifecycleError('unavailable')]),patch.object(l,'unit_active',return_value=True),patch.object(l,'run') as run:
   with self.assertRaises(l.LifecycleError):l.prepare_runtime_rollback({'version':'0.1.85'})
  self.assertEqual(run.call_args.args[0],['systemctl','start','vpn-platform-control-plane.service'])

 def test_runtime_rollback_legacy_schema_and_compatible_release_are_allowed(self):
  with patch.object(l,'database_boolean',return_value=False) as query,patch.object(l,'run') as run:
   l.prepare_runtime_rollback({'version':'0.1.85'})
   self.assertEqual(query.call_count,1);run.assert_not_called()
  with patch.object(l,'database_boolean') as query:
   l.prepare_runtime_rollback({'version':'0.1.88'});query.assert_not_called()
   with self.assertRaises(l.LifecycleError):l.prepare_runtime_rollback(None)

 def test_runtime_rollback_quiesces_cp_only_for_old_reader_new_schema(self):
  with patch.object(l,'database_boolean',side_effect=[True,False,False]) as query,patch.object(l,'unit_active',return_value=True),patch.object(l,'run') as run:
   l.prepare_runtime_rollback({'version':'0.1.85'})
   self.assertEqual(query.call_count,3)
   self.assertEqual(run.call_args.args[0],['systemctl','stop','vpn-platform-control-plane.service'])

 def test_runtime_rollback_also_cancels_an_inactive_units_pending_restart(self):
  with patch.object(l,'database_boolean',side_effect=[True,False,False]),patch.object(l,'unit_active',return_value=False),patch.object(l,'run') as run:
   l.prepare_runtime_rollback({'version':'0.1.85'})
   self.assertEqual(run.call_args.args[0],['systemctl','stop','vpn-platform-control-plane.service'])

 def test_runtime_rollback_gate_precedes_web_stop_or_archive_extraction(self):
  identifier='20260101T000000Z-12345678';backup=self.root/identifier;backup.mkdir()
  archive=backup/'application.tgz';archive.write_bytes(b'archive')
  l.atomic_json(backup/'manifest.json',{'id':identifier,'application_sha256':l.sha256(archive),'previous_state':{'version':'0.1.85'}})
  with patch.object(l,'BACKUPS',self.root),patch.object(l,'prepare_runtime_rollback',side_effect=l.LifecycleError('incompatible')),patch.object(l.subprocess,'run') as run,patch.object(l,'restore_tar') as restore:
   with self.assertRaises(l.LifecycleError):l.rollback_value(identifier)
   run.assert_not_called();restore.assert_not_called()

 def test_database_boolean_refuses_empty_or_ambiguous_output(self):
  for raw in (b'',b'NULL',b't\nf',b'yes'):
   with patch.object(l,'run',return_value=SimpleNamespace(stdout=raw)):
    with self.assertRaises(l.LifecycleError):l.database_boolean('SELECT true;')
  with patch.object(l,'run',return_value=SimpleNamespace(stdout=b't\n')):
   self.assertTrue(l.database_boolean('SELECT true;'))
 def test_release_source_version_and_contiguous_migrations(self):
  source=self.root/'source';(source/'cmd/control-plane').mkdir(parents=True);(source/'migrations').mkdir()
  (source/'cmd/control-plane/main.go').write_text('map[string]string{"version": "2.3.4"}')
  for number in (1,2,3):(source/'migrations'/f'{number:06d}_x.sql').write_text('')
  self.assertEqual(l.release_version_from_source(source),'2.3.4');self.assertEqual(l.migration_number(source),3)
  (source/'migrations/000002_x.sql').unlink()
  with self.assertRaises(l.LifecycleError):l.migration_number(source)
 def test_release_source_version_from_health_version_constant(self):
  source=self.root/'source';control=source/'cmd/control-plane';control.mkdir(parents=True)
  (control/'main.go').write_text('package main\nvar health = map[string]string{"version": controlPlaneVersion}\n')
  (control/'imported_subscription_frontend.go').write_text('package main\nconst controlPlaneVersion = "0.1.128"\n')
  self.assertEqual(l.release_version_from_source(source),'0.1.128')
 def test_versions_compare_numerically_and_epoch_is_reproducible(self):
  self.assertGreater(l.version_tuple('1.10.0'),l.version_tuple('1.9.9'))
  with patch.dict('os.environ',{'SOURCE_DATE_EPOCH':'0'}):self.assertEqual(l.build_time(),'1970-01-01T00:00:00+00:00')
  with patch.dict('os.environ',{'SOURCE_DATE_EPOCH':'invalid'}):
   with self.assertRaises(l.LifecycleError):l.build_time()
 @unittest.skipUnless(os.name=='posix','POSIX permission semantics')
 def test_install_payload_makes_service_directories_traversable(self):
  stage=self.root/'stage';live=self.root/'live';units=self.root/'units';tool=self.root/'tool.py'
  (live/'web/node_modules').mkdir(parents=True);(live/'web/.next').mkdir(parents=True)
  for name in l.BINARIES:(stage/'payload/bin').mkdir(parents=True,exist_ok=True);(stage/'payload/bin'/name).write_text('binary')
  for name in l.SOURCE_ENTRIES:
   path=stage/'payload/source'/name
   if Path(name).suffix:path.parent.mkdir(parents=True,exist_ok=True);path.write_text('source')
   else:path.mkdir(parents=True,exist_ok=True)
  (stage/'payload/source/scripts/platform-lifecycle.py').write_text('tool')
  for name in l.WEB_ENTRIES+(l.WEB_RUNTIME,):
   path=stage/'payload/web'/name
   if Path(name).suffix:path.parent.mkdir(parents=True,exist_ok=True);path.write_text('web')
   else:path.mkdir(parents=True,exist_ok=True)
  (stage/'payload/web'/l.WEB_RUNTIME/'server.js').write_text('server')
  (stage/'payload/web'/l.WEB_RUNTIME/'.next').mkdir();(stage/'payload/web'/l.WEB_RUNTIME/'.next/BUILD_ID').write_text('runtime-build')
  for name in ('.next','node_modules'):
   path=stage/'payload/web'/name;path.mkdir();(path/'build-only').write_text('not for production')
  (stage/'payload/systemd').mkdir(parents=True)
  with patch.object(l,'LIVE',live),patch.object(l,'UNITS',units),patch.object(l,'TOOL',tool),patch.object(l,'install_units'),patch('shutil.chown'):
   l.install_payload(stage)
  self.assertEqual(live.stat().st_mode&0o777,0o755);self.assertEqual((live/'bin').stat().st_mode&0o777,0o755);self.assertEqual((live/'web').stat().st_mode&0o777,0o755)
  self.assertTrue((live/'web'/l.WEB_RUNTIME).is_dir())
  self.assertEqual((live/'web'/l.WEB_RUNTIME/'.next/BUILD_ID').read_text(),'runtime-build')
  self.assertFalse((live/'web'/'node_modules').exists())
  self.assertFalse((live/'web'/'.next').exists())

 def test_build_web_packages_standalone_server_with_public_and_static_assets(self):
  stage=self.root/'stage';web=stage/'payload/web';web.mkdir(parents=True)
  (web/'package-lock.json').write_text('{}')
  def build(*args,**kwargs):
   if args[0][0]=='npm' and args[0][1]=='run':
    standalone=web/'.next/standalone';(standalone/'.next').mkdir(parents=True)
    (standalone/'server.js').write_text('server')
    (web/'.next/static').mkdir(parents=True);(web/'.next/static/chunk.js').write_text('static')
    (web/'public').mkdir();(web/'public/logo.svg').write_text('public')
  with patch.object(l,'run',side_effect=build):l.build_web(stage)
  runtime=web/l.WEB_RUNTIME
  self.assertEqual((runtime/'server.js').read_text(),'server')
  self.assertEqual((runtime/'.next/static/chunk.js').read_text(),'static')
  self.assertEqual((runtime/'public/logo.svg').read_text(),'public')

 def test_install_units_adds_only_lifecycle_dropin_and_preserves_existing_files(self):
  stage=self.root/'stage';units=self.root/'units';source=stage/'payload/systemd/vpn-platform-web.service.d/zz-pauk-standalone.conf'
  source.parent.mkdir(parents=True);source.write_text(l.MANAGED_UNIT_DROPIN_MARKER+'\n[Service]\nExecStart=\n')
  existing=units/'vpn-platform-web.service.d/99-local.conf';existing.parent.mkdir(parents=True);existing.write_text('[Service]\nEnvironment=LOCAL_SETTING=preserve\n')
  with patch.object(l,'UNITS',units),patch.object(l,'run') as run:l.install_units(stage)
  self.assertEqual((existing).read_text(),'[Service]\nEnvironment=LOCAL_SETTING=preserve\n')
  self.assertEqual((units/'vpn-platform-web.service.d/zz-pauk-standalone.conf').read_text(),source.read_text())
  run.assert_called_once_with(['systemctl','daemon-reload'])

 def test_install_units_refuses_unmanaged_dropin_collision(self):
  stage=self.root/'stage';units=self.root/'units';source=stage/'payload/systemd/vpn-platform-web.service.d/zz-pauk-standalone.conf'
  source.parent.mkdir(parents=True);source.write_text(l.MANAGED_UNIT_DROPIN_MARKER+'\n[Service]\n')
  target=units/'vpn-platform-web.service.d/zz-pauk-standalone.conf';target.parent.mkdir(parents=True);target.write_text('[Service]\nEnvironment=LOCAL_SETTING=preserve\n')
  with patch.object(l,'UNITS',units),patch.object(l,'run') as run:
   with self.assertRaises(l.LifecycleError):l.install_units(stage)
   run.assert_not_called()
  self.assertIn('LOCAL_SETTING',target.read_text())

 def test_restore_managed_dropin_removes_only_its_own_file_or_restores_previous(self):
  units=self.root/'units';directory=units/'vpn-platform-web.service.d';directory.mkdir(parents=True)
  managed=directory/'zz-pauk-standalone.conf';managed.write_text(l.MANAGED_UNIT_DROPIN_MARKER+'\nnew\n')
  neighbor=directory/'99-local.conf';neighbor.write_text('preserve')
  restored=self.root/'restored';old=restored/'etc/systemd/system/vpn-platform-web.service.d/zz-pauk-standalone.conf'
  with patch.object(l,'UNITS',units):l.restore_managed_unit_dropins(restored)
  self.assertFalse(managed.exists());self.assertEqual(neighbor.read_text(),'preserve')
  managed.write_text(l.MANAGED_UNIT_DROPIN_MARKER+'\nnew\n');old.parent.mkdir(parents=True);old.write_text(l.MANAGED_UNIT_DROPIN_MARKER+'\nold\n')
  with patch.object(l,'UNITS',units):l.restore_managed_unit_dropins(restored)
  self.assertEqual(managed.read_text(),old.read_text());self.assertEqual(neighbor.read_text(),'preserve')

 def test_restore_standalone_snapshot_removes_stale_legacy_and_standalone_files(self):
  live=self.root/'live';restored=self.root/'restored';web=live/'web';archived=restored/'opt/vpn-platform/web'
  (web/'standalone').mkdir(parents=True);(web/'standalone/server.js').write_text('new');(web/'standalone/.next').mkdir();(web/'standalone/.next/BUILD_ID').write_text('new-build')
  (web/'node_modules').mkdir();(web/'.next').mkdir()
  (archived/'standalone').mkdir(parents=True);(archived/'standalone/server.js').write_text('old');(archived/'standalone/.next').mkdir();(archived/'standalone/.next/BUILD_ID').write_text('old-build')
  with patch.object(l,'LIVE',live),patch.object(l,'run') as run,patch('shutil.chown'):
   l.restore_web_snapshot(restored)
  self.assertEqual((web/'standalone/server.js').read_text(),'old')
  self.assertEqual((web/'standalone/.next/BUILD_ID').read_text(),'old-build')
  self.assertFalse((web/'node_modules').exists());self.assertFalse((web/'.next').exists())
  run.assert_not_called()

if __name__=='__main__':unittest.main()
