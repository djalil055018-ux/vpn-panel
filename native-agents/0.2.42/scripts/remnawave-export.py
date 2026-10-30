#!/usr/bin/env python3
"""Read-only Remnawave 3.4.3 inventory. No source mutation endpoints exist here."""
import argparse,datetime,hashlib,json,os,pathlib,re,stat,sys,tempfile,time
from urllib.parse import urlsplit,urlencode
from urllib.request import Request,build_opener,HTTPRedirectHandler
from urllib.error import HTTPError

class ExportError(Exception):pass
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ExportError('Source redirect refused; use its canonical HTTPS origin')

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def identity(user):
    value=user.get('id')
    if type(value) is not int or not 0<value<=9007199254740991:raise ExportError('Unsupported source user identity; expected Remnawave 3.4.3 numeric IDs')
    return value
def stable_user(user):
    # Traffic and online timestamps change while users connect. Every other
    # source field must be identical between the two read-only inventory passes.
    return {k:v for k,v in user.items() if k!='userTraffic'}

def stable_nodes(value):
    if not isinstance(value,list) or any(not isinstance(row,dict) for row in value):raise ExportError('Unsupported node collection')
    # Reviewed 3.4.3 NodesSchema: these values describe observations, not access
    # configuration. All other fields, including unknown fields, must be stable.
    telemetry={'isConnected','isConnecting','lastStatusChange','lastStatusMessage','trafficUsedBytes','updatedAt','system','xrayUptime','usersOnline'}
    rows=[{k:v for k,v in row.items() if k not in telemetry} for row in value]
    return sorted(canonical(row) for row in rows)

def device_identity(row):
    if not isinstance(row,dict) or type(row.get('userId')) is not int or row['userId']<=0 or not isinstance(row.get('hwid'),str) or not row['hwid'] or len(row['hwid'])>2048:raise ExportError('Invalid HWID device identity')
    return row['userId'],row['hwid']

def stable_devices(rows):
    # IP and observation time may change while the same device requests its
    # subscription; device registration and platform information must not.
    return sorted(canonical({k:v for k,v in row.items() if k not in ('requestIp','updatedAt')}) for row in rows)

class Source:
    def __init__(self,origin,token,opener=None):
        parsed=urlsplit(origin)
        if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ('','/') or parsed.query or parsed.fragment:
            raise ExportError('Source must be an HTTPS origin without credentials, path or query')
        if not token or len(token)>8192 or any(ord(c)<33 or ord(c)>126 for c in token):raise ExportError('Invalid API credential')
        self.origin=origin.rstrip('/');self.token=token;self.opener=opener or build_opener(NoRedirect());self.calls=0
    def get(self,path,query=None):
        if not path.startswith('/api/') or '?' in path or '#' in path:raise ExportError('Invalid source API path')
        address=self.origin+path+('?' + urlencode(query) if query else '')
        req=Request(address,headers={'Authorization':'Bearer '+self.token,'Accept':'application/json'},method='GET')
        start=time.monotonic()
        try:
            with self.opener.open(req,timeout=20) as response:
                if response.status!=200:raise ExportError('Source did not return HTTP200')
                content=bytearray()
                while True:
                    part=response.read(65536)
                    if not part:break
                    content.extend(part)
                    if len(content)>32*1024*1024 or time.monotonic()-start>60:raise ExportError('Source response exceeded its size or time limit')
            value=json.loads(content)
        except ExportError:raise
        except HTTPError as e:raise ExportError('Source GET failed with HTTP '+str(e.code)+' at '+path) from None
        except Exception:raise ExportError('Source GET or JSON decoding failed at '+path) from None
        self.calls+=1
        if not isinstance(value,dict) or 'response' not in value:raise ExportError('Unsupported source response at '+path)
        return value['response']
    def users(self,maximum):
        users=[];seen=set();cursor=None;last_id=0
        while True:
            query={'size':250}
            if cursor is not None:query['cursor']=cursor
            value=self.get('/api/users/stream',query)
            if not isinstance(value,dict) or not isinstance(value.get('users'),list) or type(value.get('hasMore')) is not bool:raise ExportError('Unsupported users stream response')
            rows=value['users']
            for user in rows:
                if not isinstance(user,dict):raise ExportError('Invalid source user')
                key=identity(user)
                if key in seen or key<=last_id:raise ExportError('User stream repeated or reordered an identity')
                seen.add(key);last_id=key;users.append(user)
                if len(users)>maximum:raise ExportError('User count exceeded configured maximum')
            if not value['hasMore']:
                if value.get('nextCursor') is not None:raise ExportError('Final user cursor was inconsistent')
                return users
            next_cursor=value.get('nextCursor')
            if not rows or not isinstance(next_cursor,str) or not re.fullmatch(r'[1-9][0-9]{0,15}',next_cursor) or int(next_cursor)!=last_id:
                raise ExportError('User cursor failed to advance')
            cursor=next_cursor
    def devices(self,maximum):
        rows=[];total=None;seen=set()
        while total is None or len(rows)<total:
            value=self.get('/api/hwid/devices',{'start':len(rows),'size':250})
            if not isinstance(value,dict) or type(value.get('total')) is not int or not isinstance(value.get('devices'),list):raise ExportError('Unsupported HWID response')
            if total is not None and total!=value['total']:raise ExportError('HWID count changed during export')
            total=value['total']
            if not 0<=total<=maximum:raise ExportError('HWID count exceeds the export bound')
            page=value['devices']
            if not page and len(rows)<total:raise ExportError('HWID pagination stopped early')
            for row in page:
                marker=device_identity(row)
                if marker in seen:raise ExportError('HWID pagination repeated a record')
                seen.add(marker);rows.append(row)
            if len(rows)>total:raise ExportError('HWID pagination exceeded the declared total')
        return rows

def capture(source,maximum=100000):
    started=datetime.datetime.now(datetime.timezone.utc).isoformat()
    metadata=source.get('/api/system/metadata')
    if not isinstance(metadata,dict) or metadata.get('version')!='3.4.3':raise ExportError('Source version differs from reviewed Remnawave 3.4.3; inspect its API contract before export')
    first=source.users(maximum)
    collections={}
    for name,path in [('internal_squads','internal-squads'),('external_squads','external-squads'),('hosts','hosts'),('nodes','nodes'),('config_profiles','config-profiles')]:
        collections[name]=source.get('/api/'+path)
    devices=source.devices(maximum*20)
    second=source.users(maximum)
    expected=source.get('/api/users',{'start':0,'size':1})
    if not isinstance(expected,dict) or expected.get('total')!=len(second):raise ExportError('Source total does not match the complete user stream')
    if len(first)!=len(second) or any(canonical(stable_user(a))!=canonical(stable_user(b)) for a,b in zip(first,second)):
        raise ExportError('User eligibility or identity changed during export; repeat after source edits settle')
    for name,path in [('internal_squads','internal-squads'),('external_squads','external-squads'),('hosts','hosts'),('config_profiles','config-profiles')]:
        if canonical(collections[name])!=canonical(source.get('/api/'+path)):raise ExportError('Source access configuration changed during export')
    later_nodes=source.get('/api/nodes')
    if stable_nodes(collections['nodes'])!=stable_nodes(later_nodes):raise ExportError('Source node access configuration changed during export')
    collections['nodes']=later_nodes
    later_devices=source.devices(maximum*20)
    if stable_devices(devices)!=stable_devices(later_devices):raise ExportError('Registered HWID devices changed during export')
    devices=later_devices
    user_ids={identity(u) for u in second}
    if any(device_identity(row)[0] not in user_ids for row in devices):raise ExportError('Device inventory contains a user outside the captured user stream')
    ended=datetime.datetime.now(datetime.timezone.utc).isoformat()
    return {'format':1,'kind':'remnawave_inventory','contract_version':'3.4.3','contract_commit':'f8ad8ad3410252215ca7b2e429d157bd275ec564','source_origin':source.origin,'started_at':started,'captured_at':ended,'source_metadata':metadata,'users':second,'devices':devices,**collections,'verification':{'source_total':len(second),'unique_user_ids':len({identity(u) for u in second}),'stable_user_passes':2,'stable_access_configuration_passes':2,'stable_node_configuration_passes':2,'stable_device_registration_passes':2,'api_get_calls':source.calls,'atomic_database_snapshot':False}}

def private_token(path):
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077 or not 0<info.st_size<=8193:raise ValueError()
            return stream.read(8194).decode().strip()
    except Exception:raise ExportError('API token file must be a small, owner-only regular file without symlinks') from None

def save_new(path,value):
    parent=path.parent.resolve();info=parent.stat()
    if info.st_uid!=os.geteuid() or info.st_mode&0o077:raise ExportError('Export directory must be owner-only; inventory includes client credentials')
    raw=canonical(value)+b'\n'
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True);parser.add_argument('--token-file',required=True)
    parser.add_argument('--output',required=True,type=pathlib.Path);parser.add_argument('--max-users',type=int,default=100000)
    args=parser.parse_args()
    if not 1<=args.max_users<=100000:raise ExportError('max-users must be between 1 and 100000')
    os.umask(0o077)
    value=capture(Source(args.source,private_token(args.token_file)),args.max_users)
    digest=save_new(args.output,value)
    print(json.dumps({'status':'EXPORTED_READ_ONLY','users':len(value['users']),'devices':len(value['devices']),'sha256':digest,'api_get_calls':value['verification']['api_get_calls']}))
if __name__=='__main__':
    try:main()
    except ExportError as error:print('ERROR: '+str(error),file=sys.stderr);raise SystemExit(1)
    except Exception:print('ERROR: export failed; source was not modified',file=sys.stderr);raise SystemExit(1)
