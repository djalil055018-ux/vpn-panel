#!/usr/bin/env python3
"""Preview or stage a reviewed Remnawave inventory; never activates clients."""
import argparse,hashlib,importlib.util,ipaddress,json,os,pathlib,re,stat,sys,time
from urllib.request import Request,build_opener,HTTPRedirectHandler
from urllib.parse import urlsplit
from urllib.error import HTTPError

class ImportError(Exception):pass
class NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):raise ImportError('Target redirect refused')
def private_file(path,maximum):
 try:
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  with os.fdopen(fd,'rb') as f:
   info=os.fstat(f.fileno())
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077 or not 0<info.st_size<=maximum:raise ValueError()
   data=f.read(maximum+1)
   if len(data)!=info.st_size:raise ValueError()
   return data
 except Exception:raise ImportError('Input must be an owner-only regular file without symlinks and within its size bound') from None
def target_origin(value,allow_http):
 p=urlsplit(value)
 valid_http=False
 if allow_http and p.scheme=='http':
  try:valid_http=ipaddress.ip_address(p.hostname).is_private
  except ValueError:valid_http=p.hostname=='localhost'
 if not p.hostname or (p.scheme!='https' and not valid_http) or p.username or p.password or p.path not in ('','/') or p.query or p.fragment:raise ImportError('Target must be a canonical HTTPS origin')
 return value.rstrip('/')
def call(target,token,path,raw,headers=None):
 request=Request(target+path,data=raw,method='POST',headers={'Authorization':'Bearer '+token,'Content-Type':'application/json','Accept':'application/json',**(headers or {})})
 try:
  with build_opener(NoRedirect()).open(request,timeout=60) as response:
   data=response.read(1024*1024+1)
   if len(data)>1024*1024:raise ImportError('Target response exceeded its bound')
   return json.loads(data)
 except HTTPError as e:raise ImportError('Target rejected request with HTTP '+str(e.code)+'; no response body or credentials logged') from None
 except ImportError:raise
 except Exception:raise ImportError('Target request failed; retrying exact held staging bytes is idempotent') from None
def save_new(path,value):
 parent=path.parent.resolve();info=parent.stat()
 if info.st_uid!=os.geteuid() or info.st_mode&0o077:raise ImportError('Receipt directory must be owner-only')
 raw=json.dumps(value,ensure_ascii=False,indent=2).encode()+b'\n'
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=['preview','stage','delta-preview']);p.add_argument('--target',required=True);p.add_argument('--token-file',required=True,type=pathlib.Path);p.add_argument('--inventory',required=True,type=pathlib.Path);p.add_argument('--tenant',required=True);p.add_argument('--import-id');p.add_argument('--output',required=True,type=pathlib.Path);p.add_argument('--reviewed-sha256');p.add_argument('--allow-http-test',action='store_true');args=p.parse_args()
 os.umask(0o077);target=target_origin(args.target,args.allow_http_test)
 if not re.fullmatch(r'[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',args.tenant):raise ImportError('Invalid target tenant identity')
 if args.output.exists():raise ImportError('Receipt already exists; choose a new output file')
 raw=private_file(args.inventory,64*1024*1024);digest=hashlib.sha256(raw).hexdigest();token=private_file(args.token_file,8192).decode().strip()
 if not token or any(ord(c)<33 or ord(c)>126 for c in token):raise ImportError('Invalid target credential file')
 # The exact server parser is authoritative; this preliminary request is read-only.
 preview=call(target,token,'/api/v1/remnawave/preview',raw)
 if preview.get('report',{}).get('sha256')!=digest or not preview.get('stage_ready') or preview.get('cutover_ready') is not False:raise ImportError('Unexpected target preview contract')
 result={'operation':args.operation,'target':target,'tenant_id':args.tenant,'inventory_sha256':digest,'at':time.time(),'preview':preview,'source_modified':False,'clients_activated':False}
 if args.operation=='stage':
  if args.reviewed_sha256!=digest:raise ImportError('Provide the exact SHA-256 from the reviewed preview')
  value=call(target,token,'/api/v1/tenants/'+args.tenant+'/remnawave-imports',raw,{'X-Reviewed-Inventory-SHA256':digest,'X-Remnawave-Mode':'stage-held'})
  item=value.get('import',{})
  if item.get('state')!='held' or item.get('tenant_id')!=args.tenant or item.get('report',{}).get('sha256')!=digest or value.get('cutover_ready') is not False:raise ImportError('Unexpected staging receipt; inspect target before further action')
  result['staging']=value
 if args.operation=='delta-preview':
  if not args.import_id or not re.fullmatch(r'[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',args.import_id):raise ImportError('Delta preview requires an existing import identity')
  value=call(target,token,'/api/v1/remnawave/imports/'+args.import_id+'/delta-preview',raw,{'X-Remnawave-Tenant-ID':args.tenant})
  if value.get('delta',{}).get('after_sha256')!=digest or value.get('target_modified') is not False or value.get('cutover_ready') is not False:raise ImportError('Unexpected read-only delta preview contract')
  result['delta']=value;result['import_id']=args.import_id
 save_new(args.output,result)
 print(json.dumps({'status':{'preview':'PREVIEW_READY','stage':'STAGED_HELD','delta-preview':'DELTA_REVIEW_READY'}[args.operation],'sha256':digest,'users':preview['report']['users'],'cutover_ready':False,'receipt':str(args.output)}))
if __name__=='__main__':
 try:main()
 except ImportError as e:print('ERROR: '+str(e),file=sys.stderr);raise SystemExit(1)
 except Exception:print('ERROR: import tool failed; inspect target receipt before retry',file=sys.stderr);raise SystemExit(1)
