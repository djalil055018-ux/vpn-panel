import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('backup',Path(__file__).with_name('platform-backup.py'))
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)

class BackupTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        for name,relative in [('ROOT','backups'),('STATUS','status')]:
            p=patch.object(b,name,self.root/relative);p.start();self.addCleanup(p.stop)
        self.source=self.root/'source';self.source.mkdir();(self.source/'secret').write_text('test-secret-not-for-output')
        p=patch.object(b,'archive_paths',return_value=[self.source]);p.start();self.addCleanup(p.stop)

    def test_node_backup_integrity_and_safe_status(self):
        value=b.create('node',7);self.assertEqual(value['status'],'verified')
        path=b.ROOT/'node'/value['id'];self.assertEqual(path.stat().st_mode&0o777,0o700)
        status=(b.STATUS/'node-backup.json').read_text();self.assertNotIn('test-secret',status);self.assertNotIn(str(self.source),status)
        (path/'configuration.tgz').write_bytes(b'corrupt')
        with self.assertRaises(b.BackupError):b.verify(path)

    def test_manifest_cannot_redirect_verification_to_other_files(self):
        value=b.create('node',7);path=b.ROOT/'node'/value['id']
        value['files']['../../outside']={'sha256':'x'};b.atomic(path/'manifest.json',value)
        with self.assertRaises(b.BackupError):b.verify(path)

    def test_retention_preserves_unmanaged_and_unverified_directories(self):
        a=b.create('node',7);b.create('node',7)
        unmanaged=b.ROOT/'node'/'manual-backup';unmanaged.mkdir()
        incomplete=b.ROOT/'node'/'20000101T000000Z-00000000';incomplete.mkdir();b.atomic(incomplete/'manifest.json',{'id':incomplete.name,'role':'node','status':'created'})
        b.retain('node',1)
        self.assertTrue(unmanaged.exists());self.assertTrue(incomplete.exists())
        verified=[p for p in (b.ROOT/'node').iterdir() if (p/'manifest.json').exists() and json.loads((p/'manifest.json').read_text()).get('status')=='verified']
        self.assertEqual(len(verified),1)

    def test_failed_restore_drops_only_its_new_verification_database(self):
        dump=self.root/'database.dump';dump.write_bytes(b'test');calls=[]
        def docker(command,*args,**kwargs):
            calls.append((command,args))
            if command.startswith('pg_restore'):raise b.BackupError('simulated restore failure')
        with patch.object(b,'docker',side_effect=docker):
            with self.assertRaises(b.BackupError):b.verify_database(dump)
        self.assertTrue(calls[-1][0].startswith('dropdb'))
        self.assertEqual(calls[0][1][0],calls[-1][1][0]);self.assertRegex(calls[-1][1][0],b.VERIFY_DB)

    def test_failed_database_creation_never_drops_any_database(self):
        with patch.object(b,'docker',side_effect=b.BackupError('createdb failed')) as docker:
            with self.assertRaises(b.BackupError):b.verify_database(self.root/'absent')
            self.assertEqual(docker.call_count,1)

    def test_tar_traversal_is_rejected_without_extraction(self):
        path=self.root/'unsafe.tgz'
        with tarfile.open(path,'w:gz') as archive:
            member=tarfile.TarInfo('../outside');member.size=1;archive.addfile(member,io.BytesIO(b'x'))
        with self.assertRaises(b.BackupError):b.verify_archive(path)

if __name__=='__main__':unittest.main()
