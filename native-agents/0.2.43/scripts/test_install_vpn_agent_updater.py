import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('installer',Path(__file__).with_name('install-vpn-agent-updater.py'))
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)
FIXTURE='''VERSION='0.1.0'
def version(v):return tuple(map(int,v.split('.')))
class Client:
 node_id='synthetic-node'
 def api(self,path):
  if path=='/healthz':return {'service':'vpn-platform-control-plane','version':CP_VERSION}
  return {'node_id':self.node_id}
'''

class InstallerTest(unittest.TestCase):
 def setup_paths(self,tmp,cp='0.1.102'):
  root=Path(tmp);source=root/'fixture.py';source.write_text('CP_VERSION='+repr(cp)+'\n'+FIXTURE)
  target=root/'libexec/updater.py';units=root/'units';units.mkdir()
  return source,target,units,hashlib.sha256(source.read_bytes()).hexdigest()
 def test_requires_new_cp_before_any_installation(self):
  with tempfile.TemporaryDirectory() as tmp:
   source,target,units,digest=self.setup_paths(tmp,'0.1.99')
   with patch.object(installer,'protected'),patch.object(installer.os,'geteuid',return_value=0),patch.object(installer,'SHA256',digest),patch.object(installer,'TARGET',target),patch.object(installer,'UNITS',units),patch.object(installer,'command') as command:
    with self.assertRaisesRegex(RuntimeError,'102'):installer.install(source,True)
    command.assert_not_called();self.assertFalse(target.exists());self.assertEqual(list(units.iterdir()),[])
 def test_exact_replay_and_unknown_units_preserved(self):
  with tempfile.TemporaryDirectory() as tmp:
   source,target,units,digest=self.setup_paths(tmp)
   calls=[]
   def command(*args):
    calls.append(args)
    return 'active' if args[:2]==('systemctl','is-active') else 'inactive' if args[:2]==('systemctl','show') else ''
   with patch.object(installer,'protected'),patch.object(installer.os,'geteuid',return_value=0),patch.object(installer,'SHA256',digest),patch.object(installer,'TARGET',target),patch.object(installer,'UNITS',units),patch.object(installer,'command',side_effect=command):
    installer.install(source,True);original=target.stat().st_mtime_ns
    installer.install(source,True);self.assertEqual(target.stat().st_mtime_ns,original)
    self.assertEqual(target.read_bytes(),source.read_bytes())
    service=units/installer.SERVICE;service.write_text('operator customisation')
    count=len(calls)
    with self.assertRaisesRegex(RuntimeError,'differs'):installer.install(source,True)
    self.assertEqual(service.read_text(),'operator customisation');self.assertEqual(len(calls),count+1)
 def test_checksum_mismatch_cannot_import_or_write(self):
  with tempfile.TemporaryDirectory() as tmp:
   source,target,units,_=self.setup_paths(tmp)
   with patch.object(installer,'protected'),patch.object(installer.os,'geteuid',return_value=0),patch.object(installer,'TARGET',target),patch.object(installer,'UNITS',units),patch.object(installer,'command') as command:
    with self.assertRaisesRegex(RuntimeError,'checksum'):installer.install(source,True)
    command.assert_not_called();self.assertFalse(target.exists())

if __name__=='__main__':unittest.main()
