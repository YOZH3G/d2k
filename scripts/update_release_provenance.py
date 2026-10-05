"""Trusted build/operator helpers, never installed in a router runtime."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

OPENSSL_TOOL = os.environ.get('D2K_OPENSSL', '/opt/homebrew/opt/openssl@3/bin/openssl' if Path('/opt/homebrew/opt/openssl@3/bin/openssl').exists() else 'openssl')

ABIS = ('arm64', 'arm', 'mipsel', 'mips', 'mips64el', 'amd64', 'x86', 'ppc64', 'riscv64')
OPENSSL = 'f4dc4d58b48d346a8270183f89acf826d459b0ca'
CURL = '01346829096c61b372692f6dc43ffa778c6caccd'
CURL_SHA = 'f7ef3ae8a22e521f289803fe93543eb64c329b58aa73a9e224dfd915a2a5f4f7'
TARGETS = {
 'arm64': ('aarch64-linux-musl', ''), 'arm': ('arm-linux-musleabi', '-mcpu=generic+v7a'),
 'mipsel': ('mipsel-linux-musleabi', '-mcpu=mips32+soft_float'),
 'mips': ('mips-linux-musleabi', '-mcpu=mips32+soft_float'),
 'mips64el': ('mips64el-linux-muslabi64', '-mcpu=mips64 -fPIC'),
 'amd64': ('x86_64-linux-musl', '-mcpu=x86_64'), 'x86': ('x86-linux-musl', '-mcpu=i686'),
 'ppc64': ('powerpc64-linux-musl', ''), 'riscv64': ('riscv64-linux-musl', '')}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular(path, bound=None):
    p = Path(path)
    s = p.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or (bound and s.st_size > bound):
        raise ValueError('not a bounded single-link regular file: ' + str(p))
    return p.read_bytes()


def description(path):
    b = regular(path)
    return {'size': len(b), 'sha256': digest(b)}


def pairs(items):
    out = {}
    for k, v in items:
        if k in out:
            raise ValueError('duplicate JSON key')
        out[k] = v
    return out


def parse(data, bound=1048576):
    if not data or len(data) > bound or b'\x00' in data:
        raise ValueError('JSON bound/encoding')
    # Bound depth before the host JSON parser can recurse. Braces inside strings
    # are bytes of data and never contribute to nesting.
    depth=0; quoted=False; escape=False
    for c in data:
        if quoted:
            if escape:escape=False
            elif c==92:escape=True
            elif c==34:quoted=False
        elif c==34:quoted=True
        elif c in (123,91):
            depth+=1
            if depth>16:raise ValueError('JSON nesting bound')
        elif c in (125,93):depth-=1
    obj=json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                   parse_constant=lambda _: (_ for _ in ()).throw(ValueError('noninteger JSON')))
    pending=[obj];tokens=0
    while pending:
        v=pending.pop();tokens+=1
        if isinstance(v,dict):tokens+=len(v);pending.extend(v.values())
        elif isinstance(v,list):pending.extend(v)
        if tokens>16384:raise ValueError('JSON token bound')
    return obj


def encode(obj, bound=1048576):
    data = (json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if len(data) > bound:
        raise ValueError('document too large')
    return data


def exact(obj, keys):
    if not isinstance(obj, dict) or set(obj) != set(keys):
        raise ValueError('unknown/missing fields')


def uint(value, positive=False, limit=(1 << 64)-1):
    if type(value) is not int or value < int(positive) or value > limit:
        raise ValueError('integer outside bound')
    return value


def runtime_manifest(data):
    d=parse(data)
    required={'schema','release_id','version','commit','built_at','notes','min_updater','wire','state','packages'}
    if not isinstance(d,dict) or set(d) not in (required,required|{'signing_keys'}):raise ValueError('manifest fields')
    if uint(d['schema'])!=1 or uint(d['wire'],True)!=13 or uint(d['state'],True)!=1 or uint(d['min_updater'],True)!=1:raise ValueError('manifest protocol')
    if not isinstance(d['release_id'],str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,63}',d['release_id']) or d['release_id']=='d2k-channel-stable':raise ValueError('manifest ID')
    if not isinstance(d['commit'],str) or not re.fullmatch('[0-9a-f]{40}',d['commit']):raise ValueError('manifest commit')
    for key,minimum,maximum in (('version',1,64),('notes',0,16384)):
        if not isinstance(d[key],str) or not minimum<=len(d[key].encode('utf-8'))<=maximum:raise ValueError('manifest text bound')
    uint(d['built_at'],True,(1<<63)-1)
    if not isinstance(d['packages'],list) or len(d['packages'])!=9:raise ValueError('nine ABI manifest required')
    expected={}
    inventory=Path(__file__).resolve().parents[1]/'update/runtime-files.txt'
    for line in inventory.read_text().splitlines():
        if line.startswith('runtime '):
            _,source,path,mode=line.split();expected[path]=int(mode,8)
    abis=set();files=0
    for p in d['packages']:
        exact(p,('abi','artifact','size','sha256','files'))
        if p['abi'] not in ABIS or p['abi'] in abis or p['artifact']!='d2k-runtime-'+p['abi']+'.tar':raise ValueError('manifest ABI/artifact')
        abis.add(p['abi']);uint(p['size'],True)
        if not re.fullmatch('[0-9a-f]{64}',p['sha256']):raise ValueError('artifact hash')
        if not isinstance(p['files'],list) or len(p['files'])!=len(expected):raise ValueError('runtime file inventory')
        paths=set();payload=0
        for f in p['files']:
            exact(f,('path','size','mode','sha256'))
            if f['path'] in paths or f['path'] not in expected or type(f['mode']) is not int or f['mode']!=expected[f['path']] or not re.fullmatch('[0-9a-f]{64}',f['sha256']):raise ValueError('runtime file allowlist/mode/hash')
            paths.add(f['path']);payload+=uint(f['size'])
        if payload>p['size']:raise ValueError('payload exceeds artifact')
        files+=len(paths)
    if files>512:raise ValueError('manifest file bound')
    if 'signing_keys' in d:
        keys=d['signing_keys'];seen=set()
        if not isinstance(keys,list) or not 1<=len(keys)<=8:raise ValueError('transition key bound')
        for k in keys:
            exact(k,('public_key','not_before','not_after'))
            if not re.fullmatch('[0-9a-f]{64}',k['public_key']) or k['public_key'] in seen:raise ValueError('transition key')
            seen.add(k['public_key']);uint(k['not_before'],False,(1<<63)-1);uint(k['not_after'],True,(1<<63)-1)
            if k['not_before']>=k['not_after']:raise ValueError('transition validity')
    return d


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args]).decode().strip()


def clean_source(root):
    root = Path(root).resolve()
    if git(root, 'rev-parse', '--show-toplevel') != str(root):
        raise ValueError('--root must be checkout root')
    dirty = git(root, 'status', '--porcelain', '--untracked-files=all')
    if dirty:
        raise ValueError('dirty source checkout: ' + ' '.join(dirty.splitlines()[:10]))
    commit = git(root, 'rev-parse', 'HEAD')
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('invalid commit')
    return commit


def verified_source(root, relative):
    p = Path(root) / relative
    b = regular(p)
    expected = subprocess.check_output(['git', '-C', str(root), 'show', 'HEAD:' + relative])
    if b != expected:
        raise ValueError('resource differs from source commit: ' + relative)
    return b


def atomic(path, data, replace=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.d2ku-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if replace:
            os.replace(tmp, path)
        else:
            os.link(tmp, path)  # O_EXCL equivalent; never clobber an immutable release.
            os.unlink(tmp)
        d = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def verify_signature(document, signature, public_key):
    if len(signature) != 64 or len(public_key) != 32:
        raise ValueError('Ed25519 raw signature/key length')
    # Build/operator OpenSSL only. No JSON is inspected until this returns.
    with tempfile.TemporaryDirectory(prefix='d2ku-verify-') as td:
        d = Path(td)
        (d/'key.der').write_bytes(bytes.fromhex('302a300506032b6570032100') + public_key)
        (d/'doc').write_bytes(document)
        (d/'sig').write_bytes(signature)
        p = subprocess.run([OPENSSL_TOOL, 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER',
                            '-inkey', str(d/'key.der'), '-rawin', '-in', str(d/'doc'),
                            '-sigfile', str(d/'sig')], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.returncode:
            raise ValueError('untrusted signature')


def sign(document, private_key):
    # Key path belongs to an externally configured protected environment.
    with tempfile.TemporaryDirectory(prefix='d2ku-sign-') as td:
        p = Path(td)/'document'
        p.write_bytes(document)
        sig = subprocess.check_output([OPENSSL_TOOL, 'pkeyutl', '-sign', '-rawin',
                                       '-inkey', str(private_key), '-in', str(p)], stderr=subprocess.PIPE)
        if len(sig) != 64:
            raise ValueError('not an Ed25519 signing key')
        return sig


def validate_dependencies(path, abi):
    data = parse(regular(path))
    if data['openssl_revision'] != OPENSSL or data['curl_revision'] != CURL:
        raise ValueError('pinned dependency revision mismatch')
    if data['curl_archive']['sha256'] != CURL_SHA:
        raise ValueError('pinned curl archive mismatch')
    archive = data['curl_archive']
    if description(archive['path']) != {k: archive[k] for k in ('size', 'sha256')}:
        raise ValueError('curl source archive modified')
    b = data['abis'][abi]['build']
    if (b['target'], b['target_flags']) != TARGETS[abi] or b['abi'] != abi:
        raise ValueError('dependency target/flags mismatch')
    if not b['openssl_source_clean_after'] or any(c['exit'] != 0 for c in b['commands']):
        raise ValueError('dependency failed/dirty')
    source = b['environment']['OPENSSL_SRC_DIR']
    if clean_source(source) != OPENSSL or git(source, 'rev-parse', 'HEAD^{tree}') != data['openssl_tree']:
        raise ValueError('OpenSSL source provenance changed')
    compiler = b['compiler']
    if description(compiler['path']) != {k: compiler[k] for k in ('size', 'sha256')}:
        raise ValueError('compiler modified')
    if subprocess.check_output([compiler['path'], 'version']).decode().strip() != compiler['version']:
        raise ValueError('compiler version mismatch')
    # Original dependency scripts are retained in a clean historical checkout.
    sr = Path(data['scripts']['build-target.sh']['path']).parents[1]
    if clean_source(sr) != data['source_revision']:
        raise ValueError('dependency build checkout changed')
    for name, rec in data['scripts'].items():
        if description(rec['path']) != {k: rec[k] for k in ('size', 'sha256')} or git(sr, 'rev-parse', 'HEAD:scripts/'+name) != rec['git_blob']:
            raise ValueError('dependency script provenance mismatch')
    for rec in b['outputs'].values():
        if description(rec['path']) != {k: rec[k] for k in ('size', 'sha256')}:
            raise ValueError('dependency output modified')
    q = data['abis'][abi]['qemu']
    if q['status'] != 'PASS' or any(t['exit'] != 0 for t in q['tests']):
        raise ValueError('dependency QEMU gate missing')
    return b


def validate_build(root, build, abi, release, built_at, require_gates=True, check_dependencies=True):
    commit = clean_source(root)
    receipt = parse(regular(Path(build)/('provenance-'+abi+'.json')))
    if any(receipt[k] != v for k, v in {'format':'d2k-build-v1', 'commit':commit,
            'release_id':release, 'abi':abi, 'built_at':built_at}.items()):
        raise ValueError('mixed source/release/build provenance')
    if receipt['tree'] != git(root, 'rev-parse', 'HEAD^{tree}'):
        raise ValueError('source tree mismatch')
    if check_dependencies:
        deps = validate_dependencies(receipt['dependency_receipt'], abi)
        if receipt['dependency_sha256'] != description(receipt['dependency_receipt'])['sha256']:
            raise ValueError('dependency receipt changed')
        if receipt['compiler'] != deps['compiler'] or tuple(receipt['target']) != TARGETS[abi]:
            raise ValueError('runtime compiler/flags mismatch')
    for name, desc in receipt['binaries'].items():
        if description(Path(build)/name) != desc:
            raise ValueError('runtime bytes changed: '+name)
    expected = {n+'-linux-'+abi for n in ('d2kd','d2kc','d2kpanel','d2ktg','d2k-update','d2k-update-boot','d2k-service-adapter')}
    if set(receipt['binaries']) != expected:
        raise ValueError('missing build output')
    if require_gates:
        gates = parse(regular(Path(build)/('gates-'+abi+'.json')))
        exact(gates, ('format','commit','release_id','abi','binaries','tests'))
        if any(gates[k] != receipt[k] for k in ('commit','release_id','abi','binaries')) or gates['format'] != 'd2k-linux-gates-v1':
            raise ValueError('gate provenance mismatch')
        needed = {'static','release-id','startup','crypto','quicwire','plan-parse','openssl-link-smoke','tg-session','tg-tls','update-manifest','update-package','update-schedule'}
        if abi in ('mips','mipsel'): needed |= {'4Kc','controller-handshake'}
        if abi == 'x86': needed.add('pentium2')
        if set(gates['tests']) != needed or any(v != 0 for v in gates['tests'].values()):
            raise ValueError('incomplete Linux runtime gates')
    return receipt


def record_build(root, build, abi, release, built_at, deps):
    commit = clean_source(root)
    d = validate_dependencies(deps, abi)
    binaries = {n+'-linux-'+abi: description(Path(build)/(n+'-linux-'+abi)) for n in
                ('d2kd','d2kc','d2kpanel','d2ktg','d2k-update','d2k-update-boot','d2k-service-adapter')}
    receipt = {'format':'d2k-build-v1','commit':commit,'tree':git(root,'rev-parse','HEAD^{tree}'),
               'release_id':release,'built_at':built_at,'abi':abi,'target':list(TARGETS[abi]),
               'compiler':d['compiler'],'dependency_receipt':str(Path(deps).resolve()),
               'dependency_sha256':description(deps)['sha256'],'binaries':binaries,
               'build_script_blobs':{n:git(root,'rev-parse','HEAD:scripts/'+n) for n in ('build-router.sh','build-openssl-tg.sh','build-target.sh')},
               'build_command':['sh','scripts/build-router.sh'],
               'flags_policy':'committed build-router.sh and component Makefiles; RELEASE_ID/SOURCE_DATE_EPOCH explicit; static musl'}
    atomic(Path(build)/('provenance-'+abi+'.json'), encode(receipt))


def prepare_dependencies(root, destination, arches, zig, zig_mips64el):
    """Fresh Linux CI/operator build, including real dependency QEMU gates."""
    import shutil
    import time
    root=Path(root).resolve();commit=clean_source(root)
    dest=Path(destination).resolve()
    dest.mkdir(mode=0o700,parents=True,exist_ok=False)
    source=dest/'openssl-source'
    subprocess.run(['git','init',str(source)],check=True,stdout=subprocess.DEVNULL)
    subprocess.run(['git','-C',str(source),'fetch','--depth','1','https://github.com/openssl/openssl.git',OPENSSL],check=True)
    subprocess.run(['git','-C',str(source),'checkout','--detach',OPENSSL],check=True)
    data={'format':'d2k-static-dependencies-v1','source_revision':commit,'source_tree':git(root,'rev-parse','HEAD^{tree}'),
          'openssl_revision':OPENSSL,'openssl_tree':git(source,'rev-parse','HEAD^{tree}'),'curl_revision':CURL,
          'scripts':{n:dict(description(root/'scripts'/n),path=str(root/'scripts'/n),git_blob=git(root,'rev-parse','HEAD:scripts/'+n)) for n in ('build-target.sh','build-openssl-tg.sh','build-update-deps.sh')},'abis':{}}
    for abi in arches:
        compiler=Path(shutil.which(zig_mips64el if abi=='mips64el' else zig)).resolve()
        c=dict(description(compiler),path=str(compiler),version=subprocess.check_output([str(compiler),'version']).decode().strip())
        env=dict(os.environ,ARCH=abi,JOBS='2',ZIG=str(compiler),ZIG_MIPS64EL=str(compiler),
                 OPENSSL_SRC_DIR=str(source),OPENSSL_OBJ_DIR=str(dest/'objects'/abi),
                 OPENSSL_PREFIX=str(dest/'prefix'/('openssl-'+abi)),UPDATE_DEPS_DIR=str(dest/'curl-source'),
                 UPDATE_DEPS_PREFIX=str(dest/'prefix'/('curl-'+abi)),OUT=str(dest/'intermediate'),
                 TEST_OUT=str(dest/'smoke'),RELEASE_ID='dependency-smoke')
        commands=[]
        for name in ('build-openssl-tg.sh','build-update-deps.sh'):
            log=dest/(abi+'-'+name+'.log');argv=['sh',str(root/'scripts'/name)]
            with log.open('wb') as f: result=subprocess.run(argv,env=env,stdout=f,stderr=subprocess.STDOUT)
            commands.append({'argv':argv,'log':str(log),'exit':result.returncode})
            if result.returncode: raise ValueError('dependency build failed: '+str(log))
        ssl=Path(env['OPENSSL_PREFIX'])/'lib'
        if not (ssl/'libssl.a').exists(): ssl=ssl.parent/'lib64'
        outputs={'libssl.a':ssl/'libssl.a','libcrypto.a':ssl/'libcrypto.a','libcurl.a':Path(env['UPDATE_DEPS_PREFIX'])/'lib/libcurl.a',
                 'openssl-smoke':dest/'smoke'/('openssl-link-smoke-'+abi),'curl-smoke':Path(env['UPDATE_DEPS_PREFIX'])/'curl-link-smoke'}
        qcpu={'arm64':'aarch64','arm':'arm','mipsel':'mipsel','mips':'mips','mips64el':'mips64el','amd64':'x86_64','x86':'i386','ppc64':'ppc64','riscv64':'riscv64'}[abi]
        tests=[]
        variants=[[]]+([['-cpu','4Kc']] if abi in ('mips','mipsel') else [['-cpu','pentium2']] if abi=='x86' else [])
        for kind in ('openssl-smoke','curl-smoke'):
            binary=outputs[kind]
            for flag in ('-l','-d'):
                text=subprocess.check_output(['readelf',flag,str(binary)])
                if b'INTERP' in text or b'NEEDED' in text: raise ValueError('nonstatic dependency smoke')
            for variant in variants:
                argv=['timeout','120','qemu-'+qcpu,*variant,str(binary)]
                log=dest/(abi+'-'+kind+('-'+variant[-1] if variant else '')+'.log')
                with log.open('wb') as f: result=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT)
                tests.append({'argv':argv,'exit':result.returncode,'binary_sha256':description(binary)['sha256']})
                if result.returncode: raise ValueError('dependency QEMU failed: '+str(log))
        data['abis'][abi]={'build':{'abi':abi,'target':TARGETS[abi][0],'target_flags':TARGETS[abi][1],
             'compiler':c,'environment':{k:env[k] for k in ('OPENSSL_SRC_DIR','OPENSSL_PREFIX','UPDATE_DEPS_PREFIX')},
             'commands':commands,'openssl_source_clean_after':clean_source(source)==OPENSSL,
             'outputs':{n:dict(description(v),path=str(v)) for n,v in outputs.items()}},'qemu':{'status':'PASS','tests':tests}}
    data['curl_archive']=dict(description(dest/'curl-source/curl-8.22.0.tar.xz'),path=str(dest/'curl-source/curl-8.22.0.tar.xz'))
    atomic(dest/'DEPENDENCY-PROVENANCE.json',encode(data))
    return dest/'DEPENDENCY-PROVENANCE.json'


def main():
    import argparse
    import shlex
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',required=True); p.add_argument('--build-dir',required=True)
    p.add_argument('--abi',choices=ABIS); p.add_argument('--release'); p.add_argument('--built-at',type=int)
    p.add_argument('--dependencies'); p.add_argument('--deps-env',action='store_true')
    p.add_argument('--record',action='store_true'); p.add_argument('--gates',action='store_true')
    p.add_argument('--prepare-dependencies',action='store_true');p.add_argument('--arches',default=' '.join(ABIS))
    p.add_argument('--zig',default='zig');p.add_argument('--zig-mips64el',default=os.environ.get('ZIG_MIPS64EL','zig'))
    a=p.parse_args()
    if a.prepare_dependencies:
        arches=a.arches.split()
        if not arches or len(set(arches))!=len(arches) or any(x not in ABIS for x in arches):p.error('invalid ABI list')
        print(prepare_dependencies(a.root,a.build_dir,arches,a.zig,a.zig_mips64el));return
    if not a.abi:p.error('--abi required')
    if a.deps_env:
        b=validate_dependencies(a.dependencies,a.abi)
        lib=b['outputs']['libssl.a']['path']; curl=b['outputs']['libcurl.a']['path']
        for k,v in {'OPENSSL_PREFIX':str(Path(lib).parents[1]),'UPDATE_DEPS_PREFIX':str(Path(curl).parents[1]),
                    'OPENSSL_SRC_DIR':b['environment']['OPENSSL_SRC_DIR'],'BUILD_ZIG':b['compiler']['path'],
                    'D2K_REUSE_VALIDATED_DEPS':'1','DEPENDENCY_CURL_SMOKE':b['outputs']['curl-smoke']['path']}.items():
            print('export '+k+'='+shlex.quote(v))
    elif a.record:
        record_build(a.root,a.build_dir,a.abi,a.release,a.built_at,a.dependencies)
    elif a.gates:
        r=validate_build(a.root,a.build_dir,a.abi,a.release,a.built_at,False,False)
        tests={'static','release-id','startup','crypto','quicwire','plan-parse','openssl-link-smoke','tg-session','tg-tls','update-manifest','update-package','update-schedule'}
        if a.abi in ('mips','mipsel'): tests|={'4Kc','controller-handshake'}
        if a.abi=='x86': tests.add('pentium2')
        # Caller invokes only after all set -e checks in check-router-builds.sh.
        atomic(Path(a.build_dir)/('gates-'+a.abi+'.json'),encode({'format':'d2k-linux-gates-v1',
            'commit':r['commit'],'release_id':r['release_id'],'abi':a.abi,'binaries':r['binaries'],
            'tests':{t:0 for t in sorted(tests)}}))
    else: p.error('select deps-env/record/gates')


if __name__=='__main__':
    try: main()
    except (ValueError,OSError,KeyError) as e:
        raise SystemExit('provenance refused: '+str(e))
