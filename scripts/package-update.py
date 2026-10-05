#!/usr/bin/env python3
"""One trusted-checkout CLI for offline packaging, bootstrap staging and publication."""
import argparse
import io
import os
from pathlib import Path
import re
import sys
import tarfile
import time
sys.path.insert(0, str(Path(__file__).resolve().parent))
from update_release_provenance import (ABIS, atomic, clean_source, description, digest, encode,
    exact, parse, regular, sign, uint, validate_build, verified_source, verify_signature, runtime_manifest)


def release_id(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', value) or value == 'd2k-channel-stable':
        raise ValueError('invalid/reserved runtime release ID')
    return value


def safe_path(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 240 or not value.isascii():
        raise ValueError('path bound')
    if any(not re.fullmatch(r'[A-Za-z0-9._-]+', p) or p in ('.','..') for p in value.split('/')):
        raise ValueError('unsafe path')
    return value


def inventory(root, kind):
    entries = []
    for line in (Path(root)/'update/runtime-files.txt').read_text().splitlines():
        if not line or line.startswith('#'): continue
        fields = line.split()
        if len(fields) != 4 or fields[0] not in ('runtime','bootstrap'):
            raise ValueError('invalid inventory')
        if fields[0] != kind: continue
        _, source, dest, mode = fields
        safe_path(dest)
        if mode not in ('0644','0755'): raise ValueError('inventory mode')
        entries.append((source,dest,int(mode,8)))
    if len(entries) != {'runtime':26,'bootstrap':15}[kind] or len({e[1] for e in entries}) != len(entries):
        raise ValueError('inventory count/duplicates')
    return sorted(entries, key=lambda e: e[1])


def public_config(data, abi):
    if not data or len(data) > 16384 or b'\x00' in data:
        raise ValueError('public configuration bound')
    lines = data.decode('ascii').splitlines()
    if not lines or lines.pop(0) != 'D2KU-CONFIG-1': raise ValueError('config magic')
    scalar, hosts, keys = {}, [], []
    for line in lines:
        if '=' not in line: raise ValueError('config record')
        k, v = line.split('=',1)
        if k == 'host':
            if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?',v) or v in hosts:
                raise ValueError('config host')
            hosts.append(v)
        elif k == 'key':
            p = v.split(' ')
            if len(p) != 3 or not re.fullmatch('[0-9a-f]{64}',p[0]) or not p[1].isdigit() or not p[2].isdigit() or not 0 <= int(p[1]) < int(p[2]) <= (1<<63)-1 or p[0] in [x[0] for x in keys]:
                raise ValueError('config key/interval')
            keys.append(p)
        elif k in ('feed','ca','abi','build') and k not in scalar: scalar[k]=v
        else: raise ValueError('unknown/duplicate config record')
    if set(scalar) != {'feed','ca','abi','build'} or scalar['abi'] != abi or not scalar['build'].isdigit() or int(scalar['build']) <= 0:
        raise ValueError('config scalar fields')
    from urllib.parse import urlsplit
    u=urlsplit(scalar['feed'])
    if u.scheme != 'https' or not u.hostname or u.username or u.password or u.query or u.fragment or (u.port is not None and not 1<=u.port<=65535):
        raise ValueError('config HTTPS feed')
    if not scalar['ca'].startswith('/') or any(c.isspace() for c in scalar['ca']) or not 1 <= len(hosts) <= 8 or not 1 <= len(keys) <= 8:
        raise ValueError('config CA/trust bounds')
    if u.hostname not in hosts: raise ValueError('feed host not provisioned')
    return scalar


def archive_bytes(files, built_at):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for path, data, mode in sorted(files):
            info=tarfile.TarInfo(safe_path(path))
            info.size=len(data); info.mode=mode; info.mtime=built_at
            info.uid=info.gid=0; info.uname=info.gname=''
            tar.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def package(args):
    root=Path(args.root).resolve(); build=Path(args.build_dir or root/'builds').resolve()
    commit=clean_source(root); release=release_id(args.release)
    epoch=uint(args.built_at,True,(1<<63)-1)
    if not isinstance(args.version,str) or not 1<=len(args.version.encode())<=64: raise ValueError('version bound')
    if epoch > int(time.time()): raise ValueError('future build time')
    receipt=validate_build(root,build,args.arch,release,epoch)
    kind='bootstrap' if args.bootstrap else 'runtime'
    # The inventory itself must be from this exact commit.
    verified_source(root,'update/runtime-files.txt')
    files=[]
    for source,dest,mode in inventory(root,kind):
        if source.startswith('build:'):
            name=source[6:].format(abi=args.arch)
            data=regular(build/name)
            if description(build/name) != receipt['binaries'][name]: raise ValueError('binary changed during packaging')
        elif source.startswith('public:'):
            if not args.public_config: raise ValueError('--public-config is required')
            data=regular(args.public_config,16384)
            st=Path(args.public_config).lstat()
            if st.st_uid!=os.getuid() or st.st_mode & 0o022:raise ValueError('public config owner/mode')
            public_config(data,args.arch)
        else: data=verified_source(root,source)
        files.append((dest,data,mode))
    artifact=('d2k-bootstrap-' if args.bootstrap else 'd2k-runtime-')+args.arch+'.tar'
    blob=archive_bytes(files,epoch)
    entry={'abi':args.arch,'artifact':artifact,'size':len(blob),'sha256':digest(blob),
           'files':[{'path':p,'size':len(d),'mode':m,'sha256':digest(d)} for p,d,m in files]}
    out=Path(args.out)
    if args.bootstrap:
        obj={'format':'d2k-bootstrap-v1','schema':1,'bootstrap_id':'bootstrap-'+release,
             'commit':commit,'built_at':epoch,'abi':args.arch,'boot_protocol':1,
             'artifact':artifact,'size':len(blob),'sha256':digest(blob),
             'public_config_sha256':digest(next(d for p,d,m in files if p=='update.conf')),
             'files':entry['files']}
        name='bootstrap-'+args.arch+'.json'
    else:
        obj={'schema':1,'release_id':release,'version':args.version,'commit':commit,
             'built_at':epoch,'notes':regular(args.notes_file,16384).decode() if args.notes_file else '',
             'min_updater':1,'wire':13,'state':1,'packages':[entry]}
        if getattr(args,'signing_keys_file',None):
            keys=parse(regular(args.signing_keys_file,16384),16384)
            if not isinstance(keys,list) or not 1<=len(keys)<=8:raise ValueError('key transition bound')
            seen=set()
            for key in keys:
                exact(key,('public_key','not_before','not_after'))
                if not re.fullmatch('[0-9a-f]{64}',key['public_key']) or key['public_key'] in seen:raise ValueError('transition key')
                uint(key['not_before'],False,(1<<63)-1);uint(key['not_after'],True,(1<<63)-1)
                if key['not_before']>=key['not_after']:raise ValueError('transition validity')
                seen.add(key['public_key'])
            obj['signing_keys']=keys
        name='draft-'+args.arch+'.json'
    # Each immutable output refuses reuse, even for identical bytes.
    atomic(out/artifact,blob)
    atomic(out/name,encode(obj))
    clean_source(root)
    return out/name


def finalize(args):
    root=Path(args.root).resolve(); commit=clean_source(root); out=Path(args.out)
    docs=[]
    for abi in ABIS:
        d=parse(regular(out/('draft-'+abi+'.json')))
        validate_build(root,Path(args.build_dir or root/'builds'),abi,args.release,d['built_at'])
        if d['commit'] != commit or d['release_id'] != release_id(args.release) or len(d['packages']) != 1 or d['packages'][0]['abi'] != abi:
            raise ValueError('mixed aggregation provenance')
        p=d['packages'][0]
        exact(p,('abi','artifact','size','sha256','files'))
        expected=[]
        for source,dest,mode in inventory(root,'runtime'):
            data=regular(Path(args.build_dir or root/'builds')/source[6:].format(abi=abi)) if source.startswith('build:') else verified_source(root,source)
            expected.append({'path':dest,'size':len(data),'mode':mode,'sha256':digest(data)})
        if p['files']!=expected:raise ValueError('draft inventory differs from clean built source')
        verified_tar(regular(out/p['artifact']),expected)
        if description(out/p['artifact']) != {k:p[k] for k in ('size','sha256')}:
            raise ValueError('artifact changed')
        docs.append(d)
    base={k:v for k,v in docs[0].items() if k!='packages'}
    if any({k:v for k,v in d.items() if k!='packages'} != base for d in docs):
        raise ValueError('common metadata mismatch')
    base['packages']=[d['packages'][0] for d in docs]
    if sum(len(p['files']) for p in base['packages']) > 512: raise ValueError('manifest file bound')
    runtime_manifest(encode(base))
    atomic(out/'manifest.json',encode(base))
    return out/'manifest.json'


def bootstrap_manifest(data, abi, root):
    d=parse(data)
    exact(d,('format','schema','bootstrap_id','commit','built_at','abi','boot_protocol',
             'artifact','size','sha256','public_config_sha256','files'))
    if d['format']!='d2k-bootstrap-v1' or uint(d['schema'])!=1 or d['abi']!=abi or uint(d['boot_protocol'])!=1:
        raise ValueError('bootstrap format/ABI/protocol')
    release_id(d['bootstrap_id']); uint(d['built_at'],True,(1<<63)-1); uint(d['size'],True)
    safe_path(d['artifact'])
    if any(not re.fullmatch('[0-9a-f]{'+str(n)+'}',d[k]) for k,n in (('commit',40),('sha256',64),('public_config_sha256',64))):
        raise ValueError('bootstrap digest syntax')
    expected={p:m for s,p,m in inventory(root,'bootstrap')}
    if not isinstance(d['files'],list) or len(d['files'])!=len(expected): raise ValueError('bootstrap inventory bound')
    seen=set()
    for f in d['files']:
        exact(f,('path','size','mode','sha256')); safe_path(f['path']); uint(f['size'])
        if f['path'] in seen or f['path'] not in expected or type(f['mode']) is not int or f['mode']!=expected[f['path']] or not re.fullmatch('[0-9a-f]{64}',f['sha256']):
            raise ValueError('bootstrap file allowlist/mode/hash')
        seen.add(f['path'])
    return d


def verified_tar(blob, files):
    """Fully inspect bounded strict ustar before creating any staging entry."""
    expected={f['path']:f for f in files}; found={}; at=0
    while at+512 <= len(blob):
        h=blob[at:at+512]; at+=512
        if h==bytes(512):
            if len(blob)-at < 512 or any(blob[at:]): raise ValueError('tar end/padding')
            if set(found)!=set(expected): raise ValueError('tar missing member')
            return found
        if h[257:265] != b'ustar\x0000' or h[156:157] not in (b'0',b'\0') or any(h[157:257]) or any(h[500:512]):
            raise ValueError('nonregular/nonustar header')
        def octal(s):
            if not re.fullmatch(b'[0-7]+[\x00 ]*',s.lstrip(b' ')): raise ValueError('tar octal')
            return int(s.rstrip(b'\0 '),8)
        ch=octal(h[148:156]); check=bytearray(h); check[148:156]=b' '*8
        if sum(check)!=ch: raise ValueError('tar checksum')
        def name(s):
            a,sep,tail=s.partition(b'\0')
            if any(tail): raise ValueError('tar nonzero name suffix')
            return a.decode('ascii')
        p=name(h[:100]); prefix=name(h[345:500]); p=prefix+'/'+p if prefix else p
        safe_path(p); size=octal(h[124:136]); mode=octal(h[100:108])
        if p not in expected or p in found or size!=expected[p]['size'] or mode!=expected[p]['mode']:
            raise ValueError('tar unexpected member/size/mode')
        end=at+size; padded=(end+511)//512*512
        if padded>len(blob) or any(blob[end:padded]): raise ValueError('tar payload/padding')
        data=blob[at:end]
        if digest(data)!=expected[p]['sha256']: raise ValueError('tar file hash')
        found[p]=data; at=padded
    raise ValueError('truncated tar')


def verify_bootstrap(args):
    data=regular(args.verify_bootstrap,1048576)
    verify_signature(data,regular(args.signature,64),regular(args.public_key,32))
    d=bootstrap_manifest(data,args.arch,Path(__file__).resolve().parents[1])
    blob=regular(args.archive,d['size'])
    if len(blob)!=d['size'] or digest(blob)!=d['sha256']: raise ValueError('bootstrap archive hash/size')
    files=verified_tar(blob,d['files'])
    if digest(files['update.conf'])!=d['public_config_sha256']: raise ValueError('public config binding')
    public_config(files['update.conf'],args.arch)
    stage=Path(args.stage)
    s=stage.lstat()
    if not stage.is_dir() or stage.is_symlink() or s.st_uid!=os.getuid() or s.st_mode & 0o077 or any(stage.iterdir()):
        raise ValueError('stage must be owned private empty directory')
    # Exact allowlist above is flat, no member can replace a trusted tool or execute.
    for f in d['files']:
        atomic(stage/f['path'],files[f['path']]); os.chmod(stage/f['path'],f['mode'])
        fd=os.open(stage/f['path'],os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    fd=os.open(stage,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)
    return stage


def channel_document(manifest, sequence, issued):
    d=parse(manifest); release_id(d['release_id']); uint(sequence,True)
    uint(issued,True,(1<<63)-1-604800)
    return encode({'schema':1,'channel':'stable','sequence':sequence,'issued_at':issued,
                   'expires_at':issued+604800,'release_id':d['release_id'],
                   'manifest_sha256':digest(manifest)},65536)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',default=str(Path(__file__).resolve().parents[1])); p.add_argument('--build-dir')
    p.add_argument('--arch',choices=ABIS); p.add_argument('--release'); p.add_argument('--out')
    p.add_argument('--signing-keys-file'); p.add_argument('--version',default='0.1.0'); p.add_argument('--notes-file')
    p.add_argument('--built-at',type=int,default=int(os.environ.get('SOURCE_DATE_EPOCH','0')))
    p.add_argument('--finalize',action='store_true'); p.add_argument('--bootstrap',action='store_true'); p.add_argument('--public-config')
    p.add_argument('--verify-bootstrap'); p.add_argument('--signature'); p.add_argument('--archive'); p.add_argument('--public-key'); p.add_argument('--stage')
    p.add_argument('--channel',action='store_true'); p.add_argument('--manifest'); p.add_argument('--sequence',type=int); p.add_argument('--issued-at',type=int)
    p.add_argument('--fetch-current',action='store_true'); p.add_argument('--publish',action='store_true'); p.add_argument('--dry-run',action='store_true'); p.add_argument('--repository'); p.add_argument('--signing-key')
    a=p.parse_args()
    if a.verify_bootstrap:
        if not all((a.signature,a.archive,a.public_key,a.arch,a.stage)): p.error('verification requires signature/archive/public-key/arch/stage')
        result=verify_bootstrap(a)
    elif a.fetch_current:
        from update_release_publish import fetch_current
        result=fetch_current(a)
    elif a.publish:
        from update_release_publish import publish_cli
        result=publish_cli(a)
    elif a.channel:
        if not all((a.manifest,a.sequence,a.issued_at,a.out)): p.error('channel requires manifest/sequence/issued-at/out')
        result=Path(a.out)/'stable.json'; atomic(result,channel_document(regular(a.manifest),a.sequence,a.issued_at))
    elif a.finalize:
        if not all((a.release,a.out)): p.error('finalize requires release/out')
        result=finalize(a)
    else:
        if not all((a.release,a.out,a.arch,a.built_at)): p.error('package requires release/out/arch/built-at')
        result=package(a)
    print(result)


if __name__=='__main__':
    try: main()
    except (ValueError,OSError,KeyError) as e:
        print('release refused: '+str(e),file=sys.stderr); sys.exit(1)
