import contextlib
import calendar
import importlib.util
import io
import fcntl
import os
import json
from pathlib import Path
import tempfile
import tarfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('tool', Path(__file__).with_name('vpn-node-tool.py'))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)

class NodeToolTests(unittest.TestCase):
    def setUp(self):
        # Each test uses its own explicit fixture origin, independent of any deployment.
        origin = patch.object(t, 'DEFAULT_CP', 'https://control.example.test')
        origin.start(); self.addCleanup(origin.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        root.chmod(0o755)
        for name, relative in {'BINARY':'bin/agent','ENV':'etc/agent.env','DATA':'data','XRAY_DATA':'data',
            'STATE':'data/agent/state.json','UNIT':'etc/agent.service','HYSTERIA_UNIT':'etc/hysteria.service','XRAY_UNIT':'etc/xray.service',
            'WIREGUARD_DROPIN':'etc/wireguard.conf','OPENVPN_UNIT':'etc/openvpn.service','OPENVPN_NETWORK_UNIT':'etc/openvpn-network.service','OPENVPN_DROPIN':'etc/openvpn.conf','BACKUPS':'backups',
            'PPTP_UNIT':'etc/pptp.service','PPTP_NETWORK_UNIT':'etc/pptp-network.service','PPTP_DROPIN':'etc/pptp.conf',
            'MAINTENANCE':'data/maintenance','LOCK':'lock'}.items():
            p = patch.object(t, name, root / relative); p.start(); self.addCleanup(p.stop)
        self.commands = []
        self.server_preflight = t.runtime_server_preflight
        p = patch.object(t, 'build_opener', side_effect=t.ToolError('Network disabled in unit tests'));p.start();self.addCleanup(p.stop)
        p = patch.object(t, 'wait_ready', return_value={'node_id':'fixture-node'});p.start();self.addCleanup(p.stop)
        p = patch.object(t, 'runtime_server_preflight', return_value=None)
        p.start(); self.addCleanup(p.stop)
        def fake_command(args, **kwargs):
            self.commands.append(args)
            output=''
            if args[0]=='systemd-run':
                self.guard_calendar=next((v.removeprefix('--on-calendar=') for v in args if v.startswith('--on-calendar=')),'')
            elif args[:2]==['systemctl','show'] and '--property=NextElapseUSecRealtime' in args:
                output=self.guard_calendar
            elif args[0]=='date':
                output=str(calendar.timegm(time.strptime(args[3],'%Y-%m-%d %H:%M:%S UTC')))
            return SimpleNamespace(stdout=output,stderr='',returncode=0)
        p = patch.object(t, 'run', side_effect=fake_command)
        self.fake_command=fake_command
        p.start(); self.addCleanup(p.stop)
        self.output = io.StringIO()
        p = contextlib.redirect_stdout(self.output); p.__enter__(); self.addCleanup(p.__exit__,None,None,None)

    def identity(self):
        t.atomic(t.STATE, json.dumps({'node_id':'00000000-0000-4000-8000-000000000001',
            'tenant_id':'00000000-0000-4000-8000-000000000002','agent_token':'test-private-credential',
            'applied_generation':17}))

    def test_native_wireguard_selection_and_downgrade_guard(self):
        self.assertEqual(t.planned_runtime_core('wireguard'),{'format':1,'core':'wireguard','minimum_agent':'0.2.28'})
        t.atomic(t.DATA/'runtime-selection.json',json.dumps({'format':1,'core':'wireguard','minimum_agent':'0.2.28'}))
        with self.assertRaises(t.ToolError):t.require_runtime_compatible('0.2.27')
        t.require_runtime_compatible('0.2.28')
        with self.assertRaises(t.ToolError):t.planned_runtime_core('xray')

    def test_native_wireguard_installs_poststop_and_preserves_state_backup(self):
        artifact=Path(self.temp.name)/'candidate';artifact.write_bytes(b'test candidate')
        t.atomic(t.DATA/'wireguard/checkpoint.json','{"test":"fence"}')
        t.install_files('https://example.test',artifact,'wireguard')
        text=t.WIREGUARD_DROPIN.read_text()
        self.assertIn('ExecStopPost=/usr/local/bin/vpn-node-agent wireguard-runtime-stop --data-dir=',text)
        self.assertIn('TimeoutStopSec=30',text)
        self.assertEqual(text.splitlines()[0],'[Service]')
        self.assertEqual(len(text.splitlines()),5)
        self.assertIn('ExecStartPre=/usr/local/bin/vpn-node-agent provision-runtime --core wireguard --data-dir=',text)
        backup=t.snapshot()
        manifest=json.loads((backup/'manifest.json').read_text())
        self.assertTrue(any(e['name']=='wireguard-dropin' and e['exists'] for e in manifest))
        with tarfile.open(backup/'state-and-keys.tgz') as archive:self.assertIn('wireguard/checkpoint.json',archive.getnames())
    def test_openvpn_fresh_selection_and_downgrade_guard(self):
        self.assertEqual(t.planned_runtime_core('openvpn'),{'format':1,'core':'openvpn','minimum_agent':'0.2.27'})
        t.atomic(t.DATA/'runtime-selection.json',json.dumps({'format':1,'core':'openvpn','minimum_agent':'0.2.27'}))
        with self.assertRaises(t.ToolError):t.require_runtime_compatible('0.2.26')
        t.require_runtime_compatible('0.2.27')
        with self.assertRaises(t.ToolError):t.planned_runtime_core('xray')

    def test_xray_access_fence_prevents_agent_downgrade(self):
        t.atomic(t.DATA/'xray/access-fence.json','{}')
        with self.assertRaises(t.ToolError):t.require_runtime_compatible('0.2.26')
        t.require_runtime_compatible('0.2.27')

    def test_imported_xray_floor_rejects_rollback_before_service_stop(self):
        t.atomic(t.BINARY,b'prior-agent',0o755);t.atomic(t.UNIT,'old-unit');self.identity()
        with patch.object(t,'installed_binary_version',return_value='0.2.30'):backup=t.snapshot()
        t.atomic(t.DATA/'runtime-selection.json',json.dumps({'format':1,'core':'xray','minimum_agent':'0.2.31'}))
        t.atomic(t.BINARY,b'new-agent',0o755)
        for fence in [False,True]:
            if fence:t.atomic(t.DATA/'xray/access-fence.json','{}')
            with self.assertRaises(t.ToolError):t.require_runtime_compatible('0.2.30')
            t.require_runtime_compatible('0.2.31')
            with self.assertRaises(t.ToolError):t.restore(backup)
            self.assertEqual(self.commands,[])
            self.assertEqual(t.BINARY.read_bytes(),b'new-agent')
            self.assertEqual(t.runtime_selection()['minimum_agent'],'0.2.31')

    def test_rollback_restores_executable_but_preserves_new_identity_and_keys(self):
        t.atomic(t.BINARY,b'old',0o755); t.atomic(t.ENV,'VPN_CONTROL_PLANE=https://old.example\n'); t.atomic(t.UNIT,'old unit')
        self.identity(); backup=t.snapshot()
        t.atomic(t.BINARY,b'new',0o755); t.atomic(t.ENV,'new'); t.atomic(t.UNIT,'new')
        current=t.state(); current['applied_generation']=18; t.atomic(t.STATE,json.dumps(current))
        sequence=t.STATE.parent/'traffic-sequence';t.atomic(sequence,'900\n')
        queue=t.STATE.parent/'traffic-outbox/0000000000000900.json';t.atomic(queue,'pending-record')
        key=t.DATA/'certificates/current/private.key'; t.atomic(key,'new-certificate-key')
        t.restore(backup)
        self.assertEqual(t.BINARY.read_bytes(),b'old')
        self.assertEqual(t.state()['applied_generation'],18)
        self.assertEqual(sequence.read_text(),'900\n')
        self.assertEqual(queue.read_text(),'pending-record')
        self.assertEqual(key.read_text(),'new-certificate-key')
        self.assertEqual(t.ENV.stat().st_mode & 0o777,0o600)
        self.assertNotIn('test-private-credential',self.output.getvalue())

    def test_first_install_failure_preserves_consumed_registration(self):
        backup=t.snapshot(); self.identity()
        t.atomic(t.ENV,'VPN_CONTROL_PLANE=https://cp.example\n'); t.atomic(t.BINARY,b'new'); t.atomic(t.UNIT,'new')
        t.restore(backup)
        self.assertTrue(t.STATE.exists()); self.assertTrue(t.ENV.exists()); self.assertFalse(t.BINARY.exists())
        self.assertIn(['systemctl','disable',t.SERVICE],self.commands)

    def test_corrupt_backup_is_rejected_before_service_stop(self):
        t.atomic(t.BINARY,b'old'); backup=t.snapshot(); t.atomic(backup/'binary',b'corrupt')
        with self.assertRaises(t.ToolError):t.restore(backup)
        self.assertEqual(self.commands,[])

    def test_manifest_retargeting_and_incomplete_manifest_rejected(self):
        backup=t.snapshot(); records=json.loads((backup/'manifest.json').read_text())
        records[0]['path']=str(t.ENV); t.atomic(backup/'manifest.json',json.dumps(records))
        with self.assertRaises(t.ToolError):t.restore(backup)
        t.atomic(backup/'manifest.json','[]')
        with self.assertRaises(t.ToolError):t.restore(backup)
        self.assertEqual(self.commands,[])

    def test_committed_backup_guard_does_nothing(self):
        backup=t.snapshot(); t.atomic(backup/'committed','yes'); t.restore(backup,True)
        self.assertEqual(self.commands,[])

    def test_backup_path_escape_rejected(self):
        with self.assertRaises(t.ToolError):t.resolve_backup('../elsewhere')

    def test_ready_rejects_stale_health_drift_and_wrong_version(self):
        value=dict(registered=True,online=True,agent_version=t.VERSION,health_fresh=True,
            desired_generation=3,applied_generation=3,healthy=True)
        self.assertTrue(t.ready(value))
        self.assertFalse(t.ready(value,previous_health='old',require_new_health=True))
        self.assertFalse(t.ready(value|{'health_checked_at':'old'},previous_health='old',require_new_health=True))
        self.assertTrue(t.ready(value|{'health_checked_at':'new'},previous_health='old',require_new_health=True))
        for change in ({'health_fresh':False},{'applied_generation':2},{'agent_version':'0.2.12'},{'healthy':False}):
            self.assertFalse(t.ready(value|change))

    def test_control_plane_origin_rejects_credential_and_insecure_urls(self):
        for url in ('https://user:secret@example.com','https://example.com/?secret=x','http://example.com','https://example.com/path'):
            with self.assertRaises(t.ToolError):t.validate_url(url)
        self.assertEqual(t.validate_url('https://example.com/'),'https://example.com')

    def test_self_status_scopes_identity_and_filters_secrets(self):
        self.identity(); reply=t.state()|{'online':True}
        with patch.object(t,'request',return_value=reply):
            self.assertNotIn('agent_token',t.self_status('https://example.com'))
        with patch.object(t,'request',return_value=reply|{'node_id':'different'}):
            with self.assertRaises(t.ToolError):t.self_status('https://example.com')

    def test_old_tool_cannot_downgrade_a_newer_agent(self):
        self.identity()
        args=SimpleNamespace(command='upgrade',control_plane=None,allow_http_test=False)
        with patch.object(t.os,'geteuid',return_value=0), patch.object(t,'preflight'), patch.object(t,'self_status',return_value={'agent_version':'99.0.0'}), patch.object(t,'download') as download:
            with self.assertRaises(t.ToolError):t.execute(args)
            download.assert_not_called()

    def test_ordered_samples_require_compatible_control_plane(self):
        with patch.object(t.os,'geteuid',return_value=0), patch.object(t.os,'uname',return_value=SimpleNamespace(machine='x86_64')), patch.object(t.shutil,'which',return_value='/usr/bin/program'), patch.object(Path,'read_text',return_value='ID=ubuntu\nVERSION_ID="24.04"\n'):
            with patch.object(t,'request',return_value={'service':'vpn-platform-control-plane','version':'0.1.82'}):
                with self.assertRaises(t.ToolError):t.preflight('https://example.com')
            with patch.object(t,'request',return_value={'service':'vpn-platform-control-plane','version':'0.1.83'}):
                t.preflight('https://example.com')

    def select_hysteria(self):
        t.atomic(t.DATA/'runtime-selection.json',json.dumps({'format':1,'core':'hysteria2','minimum_agent':'0.2.24'}))

    def test_hysteria_blocks_old_tool_before_download_or_service_changes(self):
        self.identity();self.select_hysteria()
        args=SimpleNamespace(command='upgrade',control_plane=None,allow_http_test=False)
        with patch.object(t,'VERSION','0.2.24'),patch.object(t,'download') as download,patch.object(t,'preflight') as preflight:
            with self.assertRaises(t.ToolError):t.execute(args)
            download.assert_not_called();preflight.assert_not_called()
        self.assertEqual(self.commands,[])

    def test_hysteria_operational_floor_preserves_legacy_marker(self):
        self.identity()
        self.select_hysteria()
        selection=t.runtime_selection()
        self.assertEqual(selection['minimum_agent'],'0.2.24')
        with self.assertRaises(t.ToolError):
            t.require_runtime_compatible('0.2.24',selection)
        t.require_runtime_compatible('0.2.25',selection)

    def test_hysteria_rollback_rejects_old_and_unversioned_binary_before_stop(self):
        for known in (True,False):
            with self.subTest(known=known):
                t.atomic(t.BINARY,b'old-binary')
                with patch.object(t,'VERSION','0.2.24'),patch.object(t,'SHA256',t.digest(t.BINARY) if known else 'unknown'):
                    backup=t.snapshot()
                    self.select_hysteria()
                    with self.assertRaises(t.ToolError):t.restore(backup)
                    self.assertEqual(self.commands,[])
                    self.assertEqual(t.BINARY.read_bytes(),b'old-binary')
                (t.DATA/'runtime-selection.json').unlink()

    def test_compatible_rollback_preserves_hysteria_selection_and_new_revocations(self):
        t.atomic(t.BINARY,b'compatible-old-binary');t.atomic(t.UNIT,'old unit');self.identity();self.select_hysteria()
        t.atomic(t.HYSTERIA_UNIT,'old managed Hysteria unit',0o644)
        policy=t.DATA/'hysteria2/control/access.json';t.atomic(policy,'original-policy')
        with patch.object(t,'VERSION','0.2.25'),patch.object(t,'SHA256',t.digest(t.BINARY)):
            backup=t.snapshot()
            with tarfile.open(backup/'state-and-keys.tgz') as archive:
                self.assertIn('runtime-selection.json',archive.getnames())
                self.assertIn('hysteria2/control/access.json',archive.getnames())
            t.atomic(t.BINARY,b'new-binary');t.atomic(policy,'new-revoked-policy');t.atomic(t.HYSTERIA_UNIT,'new managed Hysteria unit',0o644)
            t.restore(backup)
        self.assertEqual(t.BINARY.read_bytes(),b'compatible-old-binary')
        self.assertEqual(policy.read_text(),'new-revoked-policy')
        self.assertEqual(t.HYSTERIA_UNIT.read_text(),'old managed Hysteria unit')
        self.assertIn(['systemctl','stop',t.HYSTERIA_SERVICE],self.commands)
        self.assertEqual(t.runtime_selection()['core'],'hysteria2')
        release=json.loads((t.DATA/'agent/binary-release.json').read_text())
        self.assertEqual(release['version'],'0.2.25');self.assertEqual(release['sha256'],t.digest(t.BINARY))

    def test_missing_or_weakened_runtime_selection_does_not_default_to_xray(self):
        t.atomic(t.DATA/'hysteria2/control/access.json','current-policy')
        with self.assertRaises(t.ToolError):t.require_runtime_compatible('0.2.24')
        t.atomic(t.DATA/'runtime-selection.json',json.dumps({'format':1,'core':'hysteria2','minimum_agent':'0.0.1'}))
        with self.assertRaises(t.ToolError):t.require_runtime_compatible('0.2.24')

    def test_release_record_is_bound_to_binary_hash(self):
        t.atomic(t.DATA/'agent/binary-release.json',json.dumps({'version':'0.2.24','sha256':'verified-fixture-hash'}))
        self.assertEqual(t.installed_binary_version('verified-fixture-hash'),'0.2.24')
        self.assertIsNone(t.installed_binary_version('different-hash'))

    def test_legacy_three_entry_backup_remains_usable_only_for_xray(self):
        backup=t.snapshot();records=json.loads((backup/'manifest.json').read_text())
        t.atomic(backup/'manifest.json',json.dumps([entry for entry in records if entry['name'] in {'binary','environment','unit'}]))
        self.select_hysteria()
        with self.assertRaises(t.ToolError):t.restore(backup)
        self.assertEqual(self.commands,[])
        (t.DATA/'runtime-selection.json').unlink();t.restore(backup)

    def test_conflicting_core_files_and_orphaned_artifact_require_repair(self):
        self.select_hysteria();t.atomic(t.DATA/'xray/config.json','unrelated core')
        with self.assertRaises(t.ToolError):t.runtime_selection()
        (t.DATA/'xray/config.json').unlink();(t.DATA/'xray').rmdir();(t.DATA/'runtime-selection.json').unlink()
        t.atomic(t.DATA/'cores/hysteria2/2.12.2/hysteria','fixture binary')
        with self.assertRaises(t.ToolError):t.runtime_selection()

    def test_boolean_format_is_not_a_valid_selection_version(self):
        t.atomic(t.DATA/'runtime-selection.json',json.dumps({'format':True,'core':'xray','minimum_agent':'0.2.23'}))
        with self.assertRaises(t.ToolError):t.runtime_selection()

    def test_fresh_hysteria_selection_does_not_migrate_registered_or_installed_nodes(self):
        self.assertEqual(t.planned_runtime_core('hysteria2')['core'],'hysteria2')
        for path in (t.BINARY,t.UNIT,t.DATA/'xray/config.json',t.DATA/'cores/xray/current'):
            t.atomic(path,'existing')
            with self.assertRaises(t.ToolError):t.planned_runtime_core('hysteria2')
            path.unlink()
            # Empty Xray directories are themselves retained identity evidence.
            for directory in (t.DATA/'xray',t.DATA/'cores/xray'):
                if directory.exists():directory.rmdir()
        self.identity()
        with self.assertRaises(t.ToolError):t.planned_runtime_core('hysteria2')
        self.select_hysteria()
        self.assertEqual(t.planned_runtime_core()['core'],'hysteria2')
        with self.assertRaises(t.ToolError):t.planned_runtime_core('xray')

    def test_node_ownership_refuses_another_agent_and_unsafe_lock(self):
        t.DATA.mkdir(mode=0o700)
        with t.node_ownership():
            with self.assertRaises(t.ToolError):
                with t.node_ownership():self.fail('ownership bypassed')
        with t.node_ownership():pass
        path=t.DATA/'agent-lifecycle.lock'
        path.chmod(0o644)
        with self.assertRaises(t.ToolError):
            with t.node_ownership():self.fail('unsafe ownership accepted')
        path.unlink();path.symlink_to(t.DATA/'elsewhere')
        with self.assertRaises(t.ToolError):
            with t.node_ownership():self.fail('symlink ownership accepted')

    def test_guarded_fresh_hysteria_install_provisions_under_inherited_lock(self):
        args=SimpleNamespace(command='install',control_plane=None,allow_http_test=False,core='hysteria2',bootstrap_token_file=None)
        def command(argv,**kwargs):
            result=self.fake_command(argv,**kwargs)
            if len(argv)>1 and argv[1]=='provision-runtime':
                self.assertTrue(any(row[0]=='systemd-run' for row in self.commands))
                self.assertIn(['systemctl','stop','--job-mode=replace-irreversibly',t.SERVICE],self.commands)
                descriptor=int(argv[-1]);self.assertEqual(kwargs['pass_fds'],(descriptor,))
                self.assertEqual(os.fstat(descriptor).st_ino,(t.DATA/'agent-lifecycle.lock').stat().st_ino)
                with self.assertRaises(t.ToolError):
                    with t.node_ownership():self.fail('installer lock not held across provisioning')
                self.select_hysteria();t.atomic(t.HYSTERIA_UNIT,'managed Hysteria unit',0o644)
            return result
        with patch.object(t,'VERSION','0.2.25'),patch.object(t,'preflight'),patch.object(t,'self_status',return_value={}),patch.object(t,'download',side_effect=lambda path:path.write_bytes(b'fixture-agent')),patch.object(t,'run',side_effect=command),patch.object(t,'register',side_effect=lambda *args:self.identity()),patch.object(t,'wait_ready',return_value={'node_id':'fixture-node'}):
            t.execute(args)
        self.assertEqual(t.config()['VPN_RUNTIME_CORE'],'hysteria2')
        self.assertTrue((t.resolve_backup()/'committed').exists())
        with t.node_ownership():pass
        self.assertNotIn('test-private-credential',self.output.getvalue())

    def test_partial_hysteria_provision_failure_rolls_back_files_but_preserves_selection(self):
        args=SimpleNamespace(command='install',control_plane=None,allow_http_test=False,core='hysteria2',bootstrap_token_file=None)
        def command(argv,**kwargs):
            result=self.fake_command(argv,**kwargs)
            if len(argv)>1 and argv[1]=='provision-runtime':
                self.select_hysteria();t.atomic(t.HYSTERIA_UNIT,'partial unit',0o644)
                raise t.ToolError('injected provisioning failure')
            return result
        with patch.object(t,'VERSION','0.2.25'),patch.object(t,'preflight'),patch.object(t,'download',side_effect=lambda path:path.write_bytes(b'fixture-agent')),patch.object(t,'run',side_effect=command),patch.object(t,'register') as register:
            with self.assertRaises(t.ToolError):t.execute(args)
            register.assert_not_called()
        self.assertTrue((t.resolve_backup()/'rolled-back').exists())
        self.assertFalse(t.BINARY.exists());self.assertFalse(t.HYSTERIA_UNIT.exists())
        self.assertEqual(t.runtime_selection()['core'],'hysteria2')

    def test_rollback_does_not_replace_files_owned_by_a_competing_agent(self):
        t.atomic(t.BINARY,b'original');backup=t.snapshot();t.atomic(t.BINARY,b'current')
        with t.node_ownership():
            with self.assertRaises(t.ToolError):t.restore(backup)
        self.assertEqual(t.BINARY.read_bytes(),b'current')

    def test_unrelated_data_directory_rejected_before_backup_download_or_stop(self):
        t.DATA.mkdir(mode=0o700)
        args=SimpleNamespace(command='install',control_plane=None,allow_http_test=False,core='hysteria2',bootstrap_token_file=None)
        for kind in ('writable','other_owner','symlink'):
            with self.subTest(kind=kind):
                if kind=='writable':t.DATA.chmod(0o777)
                elif kind=='other_owner':os.chown(t.DATA,65534,65534)
                else:t.DATA.rmdir();t.DATA.symlink_to(self.temp.name,target_is_directory=True)
                try:
                    with patch.object(t,'download') as download,patch.object(t,'snapshot') as snapshot:
                        with self.assertRaises(t.ToolError):t.execute(args)
                        download.assert_not_called();snapshot.assert_not_called()
                    self.assertEqual(self.commands,[])
                finally:
                    if kind=='symlink':t.DATA.unlink();t.DATA.mkdir(mode=0o700)
                    else:os.chown(t.DATA,0,0);t.DATA.chmod(0o700)

    def test_custom_data_path_is_saved_and_forwarded_to_rollback_guard(self):
        custom=t.DATA.parent/'custom-node'
        t.configure_data_directory(str(custom))
        self.assertEqual(t.STATE,custom/'agent/state.json')
        backup=t.snapshot()
        def guard_command(args,**kwargs):
            self.commands.append(args)
            return SimpleNamespace(stdout='synthetic deadline' if args[0]=='systemctl' else '1790000300' if args[0]=='date' else '')
        with patch.object(t.time,'time',return_value=1790000000),patch.object(t,'run',side_effect=guard_command):t.arm_guard(backup)
        self.assertEqual((backup/'data-directory').read_text().strip(),str(custom))
        self.assertEqual(next(command for command in self.commands if command[0]=='systemd-run')[-2:],['--data-dir',str(custom)])
        artifact=custom/'candidate';artifact.write_bytes(b'fixture-agent')
        t.install_files('https://fixture.example',artifact,'hysteria2')
        self.assertEqual(t.config()['VPN_AGENT_DATA'],str(custom))
        with self.assertRaises(t.ToolError):t.configure_data_directory(str(custom.parent/'elsewhere'))
        t.configure_data_directory()
        self.assertEqual(t.DATA,custom)

    def test_custom_path_cannot_retarget_a_backup(self):
        backup=t.snapshot()
        elsewhere=t.DATA.parent/'elsewhere';elsewhere.mkdir(mode=0o700)
        t.configure_data_directory(str(elsewhere))
        with self.assertRaises(t.ToolError):t.restore(backup)
        self.assertEqual(self.commands,[])

    def test_noncanonical_or_symlink_custom_paths_are_rejected_without_creation(self):
        for value in ('/','relative','/opt/../etc','/opt/test\nUser=root','/opt/%n','/opt/white space'):
            with self.assertRaises(t.ToolError):t.configure_data_directory(value)
        target=t.DATA.parent/'actual';target.mkdir(mode=0o700)
        link=t.DATA.parent/'alias';link.symlink_to(target,target_is_directory=True)
        with self.assertRaises(t.ToolError):t.configure_data_directory(str(link/'node'))
        self.assertFalse((target/'node').exists())

    def test_local_artifact_uses_release_pin_without_network(self):
        source=t.DATA.parent/'agent-artifact';source.write_bytes(b'verified fixture');source.chmod(0o555)
        target=t.DATA.parent/'downloaded'
        with patch.object(t,'SHA256',t.digest(source)),patch.object(t.HTTP,'open') as network:
            t.download(target,source)
            network.assert_not_called()
        self.assertEqual(target.read_bytes(),source.read_bytes())
        with patch.object(t.HTTP,'open') as network:
            with self.assertRaises(t.ToolError):t.download(target,source)
            network.assert_not_called()

    def test_local_artifact_rejects_symlink_writable_and_nonregular_sources(self):
        source=t.DATA.parent/'agent-artifact';source.write_bytes(b'fixture');source.chmod(0o777)
        target=t.DATA.parent/'downloaded'
        with self.assertRaises(t.ToolError):t.download(target,source)
        source.chmod(0o555);link=t.DATA.parent/'alias';link.symlink_to(source)
        with self.assertRaises(t.ToolError):t.download(target,link)
        fifo=t.DATA.parent/'fifo';os.mkfifo(fifo,0o600)
        with self.assertRaises(t.ToolError):t.download(target,fifo)

    def test_hysteria_private_ancestor_rejected_before_backup_or_download(self):
        args=SimpleNamespace(command='install',control_plane=None,allow_http_test=False,core='hysteria2',bootstrap_token_file=None)
        root=Path(self.temp.name)
        root.chmod(0o700)
        with patch.object(t,'download') as download,patch.object(t,'snapshot') as snapshot:
            with self.assertRaises(t.ToolError):t.execute(args)
            download.assert_not_called();snapshot.assert_not_called()
        self.assertEqual(self.commands,[])
        self.assertEqual(root.stat().st_mode & 0o777,0o700)
        # A root-owned ancestor readable only by the explicitly managed group
        # is valid; no supplementary-group or root-group assumption is made.
        root.chmod(0o750);os.chown(root,0,65000)
        try:
            with patch.object(t.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=65000)):
                t.require_runtime_data_traversal({'core':'hysteria2'})
        finally:os.chown(root,0,0);root.chmod(0o755)
        with patch.object(t,'DATA',root/'missing'/'data'):
            with self.assertRaises(t.ToolError):t.require_runtime_data_traversal({'core':'hysteria2'})
        self.assertFalse((root/'missing').exists())

    def test_xray_custom_data_directory_rejected_before_network_or_mutation(self):
        args=SimpleNamespace(command='install',control_plane=None,allow_http_test=False,core='xray',bootstrap_token_file=None)
        with patch.object(t,'XRAY_DATA',Path('/var/lib/vpn-platform')),patch.object(t,'preflight') as preflight,patch.object(t,'download') as download,patch.object(t,'snapshot') as snapshot:
            with self.assertRaisesRegex(t.ToolError,'Xray requires'):t.execute(args)
            preflight.assert_not_called();download.assert_not_called();snapshot.assert_not_called()
        self.assertEqual(self.commands,[]);self.assertFalse(t.DATA.exists())
        t.require_runtime_data_traversal({'core':'xray'})

    def test_hysteria_readiness_requires_matching_server_selection(self):
        self.select_hysteria()
        value={'registered':True,'online':True,'agent_version':t.VERSION,'health_fresh':True,'desired_generation':0,'applied_generation':0,'healthy':False}
        self.assertFalse(t.ready(value))
        self.assertFalse(t.ready(value|{'runtime_core':'xray'}))
        self.assertTrue(t.ready(value|{'runtime_core':'hysteria2'}))

    def capabilities(self):
        return {'format':1,'runtime_selection':True,'bootstrap_inspection':True,'traffic_address_availability':True,
            'runtimes':{'hysteria2':{'minimum_agent':'0.2.25','provisioning':True},'xray':{'minimum_agent':'0.2.23','provisioning':True}}}

    def test_hysteria_capability_rejection_precedes_download_backup_and_stop(self):
        args=SimpleNamespace(command='install',control_plane=None,allow_http_test=False,core='hysteria2',bootstrap_token_file=None)
        capabilities=self.capabilities()
        invalid=[None,{},capabilities|{'format':True},capabilities|{'runtime_selection':False},capabilities|{'traffic_address_availability':False},capabilities|{'runtimes':{'hysteria2':{'minimum_agent':'.'.join(map(str,(*t.release_version(t.VERSION)[:2],t.release_version(t.VERSION)[2]+1))),'provisioning':True}}}]
        for reply in invalid:
            with patch.object(t,'runtime_server_preflight',side_effect=self.server_preflight),patch.object(t,'preflight'),patch.object(t,'request',return_value=reply),patch.object(t,'download') as download,patch.object(t,'snapshot') as snapshot,patch.object(t,'read_bootstrap_credential') as credential:
                with self.assertRaises(t.ToolError):t.execute(args)
                download.assert_not_called();snapshot.assert_not_called();credential.assert_not_called()
            self.assertEqual(self.commands,[]);self.assertFalse(t.DATA.exists())

    def test_bootstrap_mismatch_precedes_provision_and_inspection_is_reused(self):
        source=Path(self.temp.name)/'bootstrap';source.write_text('fixture-bootstrap-first');source.chmod(0o600)
        node_id='99999999-9999-4999-8999-999999999999'
        args=SimpleNamespace(command='install',control_plane=None,allow_http_test=False,core='hysteria2',bootstrap_token_file=source)
        with patch.object(t,'runtime_server_preflight',side_effect=self.server_preflight),patch.object(t,'preflight'),patch.object(t,'request',side_effect=[self.capabilities(),{'node_id':node_id,'runtime_core':'xray'}]),patch.object(t,'download') as download,patch.object(t,'snapshot') as snapshot:
            with self.assertRaises(t.ToolError):t.execute(args)
            download.assert_not_called();snapshot.assert_not_called()
        self.assertEqual(self.commands,[]);self.assertFalse(t.DATA.exists())
        with patch.object(t,'request',side_effect=[self.capabilities(),{'node_id':node_id,'runtime_core':'hysteria2'}]):
            proof=self.server_preflight('https://fixture.example',{'core':'hysteria2'},False,source)
        source.write_text('fixture-bootstrap-replaced')
        self.select_hysteria()
        reply={'node_id':node_id,'tenant_id':'11111111-1111-4111-8111-111111111111','runtime_core':'hysteria2','agent_token':'fixture-permanent'}
        with patch.object(t,'request',return_value=reply) as request:
            t.register('https://fixture.example',source,proof)
            self.assertEqual(request.call_args.args[3],'fixture-bootstrap-first')
        self.assertEqual(t.state()['node_id'],node_id)
        self.assertNotIn('fixture-bootstrap',self.output.getvalue())

    def test_registered_core_mismatch_blocks_repair_and_legacy_xray_can_proceed(self):
        with patch.object(t,'request',return_value=self.capabilities()),patch.object(t,'self_status',return_value={'runtime_core':'xray'}),patch.object(t,'read_bootstrap_credential') as credential:
            with self.assertRaises(t.ToolError):self.server_preflight('https://fixture.example',{'core':'hysteria2'},True)
            credential.assert_not_called()
        with patch.object(t,'request',return_value=None),patch.object(t,'read_bootstrap_credential') as credential:
            self.assertIsNone(self.server_preflight('https://fixture.example',{'core':'xray'},False))
            credential.assert_not_called()

    def test_capability_legacy_fallback_only_for_http_404(self):
        for status in (401,403,404,503):
            with patch.object(t.HTTP,'open',side_effect=t.HTTPError('https://fixture.example',status,'fixture',{},None)):
                if status==404:self.assertIsNone(t.request('https://fixture.example','/api/v1/agent/capabilities',missing_ok=True))
                else:
                    with self.assertRaises(t.ToolError):t.request('https://fixture.example','/api/v1/agent/capabilities',missing_ok=True)

    def test_bootstrap_file_rejects_symlink_public_fifo_and_control_characters(self):
        source=Path(self.temp.name)/'bootstrap';source.write_text('fixture');source.chmod(0o644)
        with self.assertRaises(t.ToolError):t.read_bootstrap_credential(source)
        source.chmod(0o600);link=Path(self.temp.name)/'alias';link.symlink_to(source)
        with self.assertRaises(t.ToolError):t.read_bootstrap_credential(link)
        fifo=Path(self.temp.name)/'fifo';os.mkfifo(fifo,0o600)
        with self.assertRaises(t.ToolError):t.read_bootstrap_credential(fifo)
        source.write_text('fixture\nheader')
        with self.assertRaises(t.ToolError):t.read_bootstrap_credential(source)

class NativePeerUpdateCompatibilityTests(unittest.TestCase):
    def test_pending_native_update_refuses_older_agent(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_data=t.DATA
            try:
                t.DATA=Path(tmp)
                (t.DATA/'wireguard').mkdir()
                t.atomic(t.DATA/'wireguard/interface-update.json','{}')
                selected={'format':1,'core':'wireguard','minimum_agent':'0.2.28'}
                with self.assertRaises(t.ToolError):t.require_runtime_compatible('0.2.28',selected)
                t.require_runtime_compatible('0.2.29',selected)
            finally:t.DATA=old_data

if __name__=='__main__':unittest.main()
