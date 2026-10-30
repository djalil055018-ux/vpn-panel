import importlib.util
from pathlib import Path
from unittest import TestCase,main
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('recovery',Path(__file__).with_name('admin-mfa-recover.py'))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class MFARecoveryTests(TestCase):
 def test_nonroot_unconfirmed_and_invalid_names_never_touch_database(self):
  with patch.object(r,'sql') as sql:
   for user,confirm,uid in [('owner',True,1000),('owner',False,0),("owner';DELETE",True,0)]:
    with patch.object(r.os,'geteuid',return_value=uid,create=True):
     with self.assertRaises(r.RecoveryError):r.recover(user,confirm)
   sql.assert_not_called()
 def test_backup_failure_prevents_reset(self):
  with patch.object(r.os,'geteuid',return_value=0,create=True),patch.object(r,'sql',return_value='00000000-0000-4000-8000-000000000001|true') as sql,patch.object(r,'verified_backup',side_effect=r.RecoveryError('failed')):
   with self.assertRaises(r.RecoveryError):r.recover('owner',True)
   self.assertEqual(sql.call_count,1)
 def test_reset_is_after_backup_and_scoped_transaction_with_audit(self):
  events=[]
  def sql(statement,**variables):
   events.append('read' if statement.startswith('SELECT id') else 'reset')
   if events[-1]=='read':return '00000000-0000-4000-8000-000000000001|true'
   self.assertTrue(statement.startswith('BEGIN;'));self.assertIn('COMMIT;',statement)
   self.assertIn('admin_mfa.emergency_reset',statement);self.assertIn('WHERE id=:',statement)
   self.assertEqual(variables['account_id'],'00000000-0000-4000-8000-000000000001')
  def backup():events.append('backup');return '20260910T000000Z-01234567'
  with patch.object(r.os,'geteuid',return_value=0,create=True),patch.object(r,'sql',side_effect=sql),patch.object(r,'verified_backup',side_effect=backup):
   result=r.recover('owner',True)
  self.assertEqual(events,['read','backup','reset']);self.assertEqual(result['status'],'mfa_reset')

if __name__=='__main__':main()
