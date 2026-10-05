"""Bounded GitHub publisher. Used only by package-update.py on a trusted release host."""
import os
from pathlib import Path
import re
import struct
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from update_release_provenance import (ABIS, digest, encode, exact, parse, regular,
                                     sign, uint, verify_signature, runtime_manifest)

MAGIC=b'D2KCP001'
MAX_CHECKPOINTS=4096
MAX_PAGES=64


def index(data):
    d=parse(data,65536)
    exact(d,('schema','channel','sequence','issued_at','expires_at','release_id','manifest_sha256'))
    if uint(d['schema'])!=1 or d['channel']!='stable' or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,63}',d['release_id']) or d['release_id']=='d2k-channel-stable' or not re.fullmatch('[0-9a-f]{64}',d['manifest_sha256']):
        raise ValueError('checkpoint index format')
    uint(d['sequence'],True); uint(d['issued_at'],True,(1<<63)-1); uint(d['expires_at'],True,(1<<63)-1)
    if d['expires_at']-d['issued_at'] != 604800: raise ValueError('index expiry policy')
    return d


def checkpoint(doc,sig):
    if len(doc)>65536 or len(sig)!=64: raise ValueError('checkpoint bounds')
    d=index(doc)
    return 'checkpoint-'+str(d['sequence'])+'-'+digest(doc)+'.bin', MAGIC+struct.pack('>I',len(doc))+doc+sig


def authenticated_checkpoint(name,blob,public):
    if len(blob)<77 or len(blob)>65612 or blob[:8]!=MAGIC: raise ValueError('checkpoint frame')
    size=struct.unpack('>I',blob[8:12])[0]
    if not size or size>65536 or len(blob)!=12+size+64: raise ValueError('checkpoint length')
    doc,sig=blob[12:12+size],blob[-64:]
    verify_signature(doc,sig,public)  # Authentication BEFORE parsing enclosed index.
    d=index(doc)
    if checkpoint(doc,sig)[0]!=name: raise ValueError('checkpoint filename binding')
    d['_document']=doc; d['_signature']=sig
    return d


def recover(store,public):
    records={}; count=0
    for asset in store.list():
        name=asset['name']
        if name.startswith('checkpoint-'):
            count+=1
            if count>MAX_CHECKPOINTS: raise ValueError('checkpoint listing limit; refuse sequence allocation')
            if asset['state']!='uploaded' or not 77<=asset['size']<=65612:
                raise ValueError('incomplete/ambiguous checkpoint; operator investigation required')
            d=authenticated_checkpoint(name,store.read(name,65612),public)
            old=records.get(d['sequence'])
            if old and old['_document']!=d['_document']: raise ValueError('conflicting signed sequence')
            records[d['sequence']]=d
    # Stable pair is also sequence proof, even if checkpoint retention is incomplete.
    doc=sig=None
    try:doc=store.read('stable.json',65536)
    except FileNotFoundError:pass
    try:sig=store.read('stable.json.sig',64)
    except FileNotFoundError:pass
    if (doc is None)!=(sig is None) and not records:raise ValueError('partial stable pair without authenticated sequence provenance')
    if doc is not None and sig is not None:
        try: verify_signature(doc,sig,public)
        except ValueError:
            if not records: raise ValueError('broken stable pair without authenticated sequence provenance')
        else:
            d=index(doc); d['_document']=doc; d['_signature']=sig
            old=records.get(d['sequence'])
            if old and old['_document']!=doc: raise ValueError('conflicting stable/checkpoint sequence')
            records[d['sequence']]=d
    return records[max(records)] if records else None


class MemoryStore:
    """Offline API fixture with immutable upload names and observable mutation order."""
    def __init__(self): self.assets={}; self.events=[]
    def list(self): return [{'name':n,'state':'uploaded','size':len(b)} for n,b in self.assets.items()]
    def read(self,name,bound=1<<30):
        if name not in self.assets: raise FileNotFoundError(name)
        b=self.assets[name]
        if len(b)>bound: raise ValueError('asset too large')
        return b
    def upload(self,name,data):
        if name in self.assets: raise ValueError('immutable asset name already exists')
        self.assets[name]=data; self.events.append(('upload',name))
    def delete(self,name):
        if name not in ('stable.json.sig','stable.json'): raise ValueError('immutable asset deletion refused')
        if name in self.assets:
            del self.assets[name]; self.events.append(('delete',name))


class Publisher:
    def __init__(self,store,public,signer,verify_runtime):
        self.store,self.public,self.signer,self.verify_runtime=store,public,signer,verify_runtime
    def refresh(self,manifest,now,dry_run=False):
        md=parse(manifest); release=md['release_id']; sha=digest(manifest)
        if not self.verify_runtime(release,sha): raise ValueError('runtime is incomplete/hash mismatch')
        highest=recover(self.store,self.public)
        pending=highest and highest['expires_at']>now and highest['issued_at']<=now and highest['release_id']==release and highest['manifest_sha256']==sha
        # A coherent already published pair is a completed publication: daily refresh allocates newer.
        coherent=False
        if pending:
            try: coherent=self.store.read('stable.json')==highest['_document'] and self.store.read('stable.json.sig')==highest['_signature']
            except FileNotFoundError: pass
        if pending and not coherent:
            doc,sig=highest['_document'],highest['_signature']
        else:
            seq=uint((highest['sequence'] if highest else 0)+1,True)
            uint(now,True,(1<<63)-1-604800)
            doc=encode({'schema':1,'channel':'stable','sequence':seq,'issued_at':now,
                        'expires_at':now+604800,'release_id':release,'manifest_sha256':sha},65536)
            sig=self.signer(doc); verify_signature(doc,sig,self.public)
        name,blob=checkpoint(doc,sig)
        if dry_run: return {'checkpoint':name,'sequence':index(doc)['sequence'],'mutations':False}
        existing={a['name'] for a in self.store.list()}
        if name not in existing:
            self.store.upload(name,blob)  # Single immutable, completely authenticated recovery record.
        if self.store.read(name,65612)!=blob: raise ValueError('checkpoint upload verification')
        # Re-list and authenticate just before mutable replacement: racing allocation fails closed.
        selected=recover(self.store,self.public)
        if selected['_document']!=doc: raise ValueError('racing publisher allocation')
        for n,b in (('stable.json.sig',sig),('stable.json',doc)):
            try: same=self.store.read(n)==b
            except FileNotFoundError: same=False
            if not same:
                self.store.delete(n); self.store.upload(n,b)
                if self.store.read(n,len(b))!=b: raise ValueError('channel upload verification')
        verify_signature(self.store.read('stable.json',65536),self.store.read('stable.json.sig',64),self.public)
        return {'sequence':index(doc)['sequence'],'checkpoint':name,'mutations':True}


class GitHubStore:
    """One release's bounded REST assets. Only stable filenames may be replaced."""
    def __init__(self,repository,release,token):
        if not re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repository): raise ValueError('repository syntax')
        self.repository,self.release,self.token=repository,release,token
        self.base='https://api.github.com/repos/'+repository
    def request(self,url,method='GET',data=None,raw=False,bound=1048576):
        u=urlsplit(url)
        if u.scheme!='https' or u.hostname not in ('api.github.com','uploads.github.com'):
            raise ValueError('unexpected GitHub API host')
        headers={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28',
                 'Authorization':'Bearer '+self.token,'Content-Type':'application/octet-stream' if raw else 'application/json'}
        with urlopen(Request(url,data=data,method=method,headers=headers),timeout=60) as response:
            body=response.read(bound+1)
            if len(body)>bound: raise ValueError('API response limit')
        return body if raw or not body else parse(body,bound)
    def list(self):
        result=[]; names=set()
        for page in range(1,MAX_PAGES+1):
            part=self.request(self.base+'/releases/'+str(self.release['id'])+'/assets?per_page=100&page='+str(page))
            if not isinstance(part,list) or len(part)>100: raise ValueError('API asset listing shape')
            for a in part:
                if a['name'] in names: raise ValueError('ambiguous asset filename')
                names.add(a['name']); result.append(a)
            if len(part)<100: return result
        raise ValueError('API pagination bound; refuse sequence allocation')
    def asset(self,name):
        found=[a for a in self.list() if a['name']==name]
        if not found: raise FileNotFoundError(name)
        if len(found)!=1 or found[0]['state']!='uploaded': raise ValueError('incomplete/ambiguous asset')
        return found[0]
    def read(self,name,bound=1<<30):
        a=self.asset(name)
        if a['size']>bound: raise ValueError('asset size limit')
        # Public download URL verification: credentials never forwarded to CDN.
        return public_download(a['browser_download_url'],bound)
    def upload(self,name,data):
        if any(a['name']==name for a in self.list()): raise ValueError('immutable asset name already exists')
        url=self.release['upload_url'].split('{',1)[0]+'?name='+quote(name,safe='')
        a=self.request(url,'POST',data,True)
        # request(raw=True) returns bytes; decode the bounded upload JSON response.
        a=parse(a)
        if a['state']!='uploaded' or a['name']!=name or a['size']!=len(data): raise ValueError('incomplete upload; refuse channel publication')
    def delete(self,name):
        if name not in ('stable.json.sig','stable.json'): raise ValueError('immutable deletion refused')
        try: a=self.asset(name)
        except FileNotFoundError: return
        self.request(self.base+'/releases/assets/'+str(a['id']),'DELETE')


def public_download(url,bound):
    # Standard certificate/name validation; constrain every redirect before following it.
    from urllib.request import HTTPRedirectHandler, build_opener
    allowed={'github.com','release-assets.githubusercontent.com','objects.githubusercontent.com'}
    def check(value):
        u=urlsplit(value)
        if u.scheme!='https' or u.hostname not in allowed or u.username or u.password or u.port not in (None,443): raise ValueError('download host policy')
    class Redirect(HTTPRedirectHandler):
        def redirect_request(self,req,fp,code,msg,headers,newurl):
            check(newurl)
            return super().redirect_request(req,fp,code,msg,headers,newurl)
    check(url)
    with build_opener(Redirect()).open(url,timeout=60) as response:
        if response.status!=200: raise ValueError('download HTTP status')
        b=response.read(bound+1)
        if len(b)>bound: raise ValueError('download bound')
        return b


def fetch_current(args):
    """Authenticated daily-refresh input; no mutable assets or sequence allocation."""
    from update_release_provenance import atomic
    if not args.public_key or not args.repository or not args.out:raise ValueError('fetch-current requires repository/public-key/out')
    public=regular(args.public_key,32);token=os.environ.get('GH_TOKEN','')
    api=GitHubStore(args.repository,{},token)
    channel=api.request(api.base+'/releases/tags/d2k-channel-stable')
    highest=recover(GitHubStore(args.repository,channel,token),public)
    if not highest:raise ValueError('no authenticated sequence provenance')
    runtime=api.request(api.base+'/releases/tags/'+quote(highest['release_id'],safe=''))
    if runtime['draft']:raise ValueError('runtime is not public')
    rs=GitHubStore(args.repository,runtime,token)
    doc=rs.read('manifest.json',1048576);sig=rs.read('manifest.json.sig',64)
    verify_signature(doc,sig,public)
    md=runtime_manifest(doc)
    if digest(doc)!=highest['manifest_sha256'] or md['release_id']!=highest['release_id'] or {p['abi'] for p in md['packages']}!=set(ABIS) or len(md['packages'])!=9:raise ValueError('recovery runtime binding')
    out=Path(args.out)
    for p in md['packages']:
        if not re.fullmatch('d2k-runtime-('+('|'.join(ABIS))+')'+r'\.tar',p['artifact']):raise ValueError('runtime artifact name')
        uint(p['size'],True);data=rs.read(p['artifact'],p['size'])
        if len(data)!=p['size'] or digest(data)!=p['sha256']:raise ValueError('runtime artifact integrity')
        atomic(out/p['artifact'],data)
    atomic(out/'manifest.json',doc);atomic(out/'manifest.json.sig',sig)
    return out


def publish_cli(args):
    if not args.out or not args.public_key or not args.signing_key or not args.repository:
        raise ValueError('publish requires out/public-key/signing-key/repository')
    out=Path(args.out); manifest=regular(out/'manifest.json')
    public=regular(args.public_key,32); signature=regular(out/'manifest.json.sig',64)
    verify_signature(manifest,signature,public)
    md=runtime_manifest(manifest)
    if {p['abi'] for p in md['packages']}!=set(ABIS) or len(md['packages'])!=9: raise ValueError('full nine ABI manifest required')
    local={p['artifact']:p for p in md['packages']}
    for n,p in local.items():
        if digest(regular(out/n))!=p['sha256'] or (out/n).stat().st_size!=p['size']: raise ValueError('local package hash/size')
    import importlib.util
    spec=importlib.util.spec_from_file_location('d2ku_trusted_package',Path(__file__).with_name('package-update.py'))
    trusted=importlib.util.module_from_spec(spec);spec.loader.exec_module(trusted)
    for p in md['packages']:trusted.verified_tar(regular(out/p['artifact']),p['files'])
    if args.release or args.dry_run:
        for abi in ABIS:
            bdoc=regular(out/('bootstrap-'+abi+'.json'));bsig=regular(out/('bootstrap-'+abi+'.json.sig'),64)
            verify_signature(bdoc,bsig,public)
            bd=trusted.bootstrap_manifest(bdoc,abi,Path(__file__).resolve().parents[1])
            blob=regular(out/bd['artifact'],bd['size'])
            if len(blob)!=bd['size'] or digest(blob)!=bd['sha256']:raise ValueError('bootstrap artifact integrity')
            files=trusted.verified_tar(blob,bd['files']);trusted.public_config(files['update.conf'],abi)
            if digest(files['update.conf'])!=bd['public_config_sha256'] or bd['commit']!=md['commit'] or bd['built_at']!=md['built_at']:raise ValueError('bootstrap public config/source binding')
    if args.dry_run:
        # Dry-run uses the same state machine and fixture signing; zero network calls/mutations.
        store=MemoryStore()
        return Publisher(store,public,lambda d:sign(d,args.signing_key),lambda r,h:r==md['release_id'] and h==digest(manifest)).refresh(manifest,args.issued_at or int(__import__('time').time()),True)
    if os.environ.get('D2K_PROTECTED_SIGNING')!='1': raise ValueError('protected signing environment is required')
    token=os.environ.get('GH_TOKEN')
    if not token: raise ValueError('GitHub token unavailable')
    api=GitHubStore(args.repository,{},token)
    def get(tag):
        try: return api.request(api.base+'/releases/tags/'+quote(tag,safe=''))
        except HTTPError as e:
            if e.code==404: return None
            raise
    runtime=get(md['release_id'])
    if args.release:
        if args.release!=md['release_id'] or runtime is not None: raise ValueError('immutable release ID reuse refused')
        runtime=api.request(api.base+'/releases','POST',encode({'tag_name':md['release_id'],'target_commitish':md['commit'],'name':md['release_id'],'draft':True,'prerelease':False}))
        runtime_store=GitHubStore(args.repository,runtime,token)
        for n in sorted(local): runtime_store.upload(n,regular(out/n))
        # Separate signed bootstrap assets are also required before runtime becomes public.
        for abi in ABIS:
            doc=regular(out/('bootstrap-'+abi+'.json')); sig=regular(out/('bootstrap-'+abi+'.json.sig'),64)
            verify_signature(doc,sig,public)
            bd=parse(doc); archive=regular(out/bd['artifact'])
            if digest(archive)!=bd['sha256'] or len(archive)!=bd['size']: raise ValueError('bootstrap package mismatch')
            for n,b in ((bd['artifact'],archive),('bootstrap-'+abi+'.json',doc),('bootstrap-'+abi+'.json.sig',sig)): runtime_store.upload(n,b)
        runtime_store.upload('manifest.json',manifest); runtime_store.upload('manifest.json.sig',signature)
        runtime=api.request(api.base+'/releases/'+str(runtime['id']),'PATCH',encode({'draft':False}))
    if not runtime or runtime['draft']: raise ValueError('runtime release missing/incomplete')
    def verify_runtime(release,sha):
        rel=get(release)
        if not rel or rel['draft']: return False
        rs=GitHubStore(args.repository,rel,token)
        doc=rs.read('manifest.json',1048576); sig=rs.read('manifest.json.sig',64)
        verify_signature(doc,sig,public)
        d=runtime_manifest(doc)
        if digest(doc)!=sha or d['release_id']!=release or {p['abi'] for p in d['packages']}!=set(ABIS): return False
        for p in d['packages']:
            b=rs.read(p['artifact'],p['size'])
            if len(b)!=p['size'] or digest(b)!=p['sha256']: return False
        return True
    channel=get('d2k-channel-stable')
    if not channel:
        channel=api.request(api.base+'/releases','POST',encode({'tag_name':'d2k-channel-stable','target_commitish':md['commit'],'name':'D2K stable channel','draft':False,'prerelease':False,'make_latest':'false'}))
    return Publisher(GitHubStore(args.repository,channel,token),public,lambda d:sign(d,args.signing_key),verify_runtime).refresh(manifest,args.issued_at or int(__import__('time').time()))
