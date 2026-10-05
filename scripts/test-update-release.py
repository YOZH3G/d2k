#!/usr/bin/env python3
"""Offline release-tool regression tests; never contact GitHub or use real keys."""
import importlib.util
import pathlib
import sys
import shutil
import argparse
import json
import tempfile
import subprocess
from unittest.mock import patch
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from update_release_provenance import digest, encode, parse, clean_source, sign, verify_signature, atomic, OPENSSL_TOOL

def load_tool():
    spec = importlib.util.spec_from_file_location('release_tool', ROOT / 'scripts/package-update.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def fixture_key(root):
    key = root / 'fixture.pem'
    subprocess.run([OPENSSL_TOOL,'genpkey','-algorithm','ED25519','-out',str(key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    der = subprocess.check_output([OPENSSL_TOOL,'pkey','-in',str(key),'-pubout','-outform','DER'],stderr=subprocess.DEVNULL)
    return key, der[-32:]


class ReleaseTests(unittest.TestCase):
    def test_explicit_inventory_and_reserved_channel(self):
        module = load_tool()
        self.assertEqual(len(module.inventory(ROOT, 'runtime')), 26)
        self.assertEqual(len(module.inventory(ROOT, 'bootstrap')), 15)
        self.assertEqual(len(module.ABIS), 9)
        with self.assertRaises(ValueError):
            module.release_id('d2k-channel-stable')

    def test_dirty_rejected_and_immutable_output(self):
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td)
            subprocess.run(['git','init','-q',str(d)],check=True)
            (d/'source').write_text('clean')
            subprocess.run(['git','-C',str(d),'add','source'],check=True)
            subprocess.run(['git','-C',str(d),'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture'],check=True)
            self.assertEqual(len(clean_source(d)),40)
            (d/'source').write_text('dirty')
            with self.assertRaises(ValueError): clean_source(d)
            atomic(d/'immutable',b'one')
            with self.assertRaises(FileExistsError): atomic(d/'immutable',b'two')
            self.assertEqual((d/'immutable').read_bytes(),b'one')

    def test_signature_before_parse(self):
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td); key, public = fixture_key(d)
            doc = b'{"schema":1}\n'; sig = sign(doc,key)
            verify_signature(doc,sig,public)
            for bad, signature in ((b'not JSON',sig),(doc,bytes(64)),(doc,sig[:-1])):
                with self.assertRaises(ValueError): verify_signature(bad,signature,public)
            with self.assertRaises(ValueError): parse(b'{"x":1,"x":2}')

    def test_deterministic_exact_tar_and_secret_absence(self):
        m = load_tool()
        files = [('panel/index.html',b'public',420),('d2kc',b'fixture binary',493)]
        first = m.archive_bytes(files,100)
        self.assertEqual(first,m.archive_bytes(list(reversed(files)),100))
        meta = [{'path':p,'size':len(b),'mode':mode,'sha256':digest(b)} for p,b,mode in files]
        self.assertEqual(m.verified_tar(first,meta),{p:b for p,b,mode in files})
        self.assertNotIn(b'personal-secret',first)
        for altered in (first[:512],first[:512]+b'X'+first[513:]):
            with self.assertRaises(ValueError): m.verified_tar(altered,meta)
        unknown = m.archive_bytes(files+[('secret',b'private',420)],100)
        with self.assertRaises(ValueError): m.verified_tar(unknown,meta)

    def test_publisher_checkpoint_recovery(self):
        from update_release_publish import checkpoint, recover, MemoryStore, Publisher
        m=load_tool()
        with tempfile.TemporaryDirectory() as td:
            key,public=fixture_key(pathlib.Path(td))
            manifest=encode({'release_id':'fixture-A'})
            doc=m.channel_document(manifest,9,100)
            sig=sign(doc,key)
            name,blob=checkpoint(doc,sig)
            store=MemoryStore()
            store.upload(name,blob)
            self.assertEqual(recover(store,public)['sequence'],9)
            store.upload('stable.json',b'broken')
            self.assertEqual(recover(store,public)['sequence'],9)
            pub=Publisher(store,public,lambda d:sign(d,key),lambda r,h: True)
            pub.refresh(manifest,200)
            self.assertEqual(parse(store.read('stable.json'))['sequence'],9)
            self.assertEqual(store.events[-1],('upload','stable.json'))
            verify_signature(store.read('stable.json'),store.read('stable.json.sig'),public)
            pub.refresh(manifest,800000)
            self.assertEqual(parse(store.read('stable.json'))['sequence'],10)
            before=list(store.events)
            pub.refresh(manifest,900000,dry_run=True)
            self.assertEqual(store.events,before)

    def test_real_package_fixture_and_all_abi_finalization(self):
        m=load_tool()
        with tempfile.TemporaryDirectory() as td:
            base=pathlib.Path(td); root=base/'checkout'; root.mkdir(); build=base/'build';build.mkdir()
            for kind in ('runtime','bootstrap'):
                for source,dest,mode in m.inventory(ROOT,kind):
                    if ':' in source: continue
                    target=root/source;target.parent.mkdir(parents=True,exist_ok=True)
                    shutil.copyfile(ROOT/source,target)
            (root/'update').mkdir(exist_ok=True);shutil.copyfile(ROOT/'update/runtime-files.txt',root/'update/runtime-files.txt')
            (root/'.gitignore').write_text('personal/\n')
            subprocess.run(['git','init','-q',str(root)],check=True)
            subprocess.run(['git','-C',str(root),'add','.'],check=True)
            subprocess.run(['git','-C',str(root),'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','release fixture'],check=True)
            commit=clean_source(root)
            (root/'personal').mkdir();(root/'personal/token').write_text('personal-secret-sentinel')
            def receipt(abi):
                names={source[6:].format(abi=abi) for kind in ('runtime','bootstrap') for source,dest,mode in m.inventory(root,kind) if source.startswith('build:')}
                return {'binaries':{name:{'size':len((build/name).read_bytes()),'sha256':digest((build/name).read_bytes())} for name in names}}
            args=argparse.Namespace(root=str(root),build_dir=str(build),release='fixture-A',built_at=100,
                bootstrap=False,public_config=None,version='fixture',notes_file=None,out=str(base/'out'),arch='arm64')
            for abi in m.ABIS:
                for source,dest,mode in m.inventory(root,'runtime')+m.inventory(root,'bootstrap'):
                    if source.startswith('build:'): (build/source[6:].format(abi=abi)).write_bytes(('UNIT FIXTURE '+abi+' '+args.release).encode())
                args.arch=abi
                with patch.object(m,'validate_build',return_value=receipt(abi)): m.package(args)
            with patch.object(m,'validate_build'):
                manifest=parse(m.finalize(args).read_bytes())
            self.assertEqual(manifest['commit'],commit)
            self.assertEqual(sum(len(p['files']) for p in manifest['packages']),234)
            for pkg in manifest['packages']:
                blob=(base/'out'/pkg['artifact']).read_bytes()
                self.assertNotIn(b'personal-secret-sentinel',blob)
                self.assertEqual(len(m.verified_tar(blob,pkg['files'])),26)
            with patch.object(m,'validate_build',return_value=receipt('arm64')):
                args.arch='arm64'
                with self.assertRaises(FileExistsError): m.package(args)
                (root/'files/S99d2k').write_text('foreign dirt')
                with self.assertRaises(ValueError): m.package(args)

    def test_bootstrap_no_execution_before_complete_verification(self):
        m=load_tool()
        with tempfile.TemporaryDirectory() as td:
            d=pathlib.Path(td);key,public=fixture_key(d);(d/'public').write_bytes(public)
            config=('D2KU-CONFIG-1\nfeed=https://github.com/necronicle/d2k/releases/download\nca=/etc/ssl/certs/ca-certificates.crt\nabi=arm64\nbuild=100\nhost=github.com\nkey='+public.hex()+' 1 9999999999\n').encode()
            sentinel=d/'EXECUTED'
            files=[(p,config if p=='update.conf' else ('#!/bin/sh\ntouch '+str(sentinel)+'\n').encode(),mode) for source,p,mode in m.inventory(ROOT,'bootstrap')]
            blob=m.archive_bytes(files,100)
            obj={'format':'d2k-bootstrap-v1','schema':1,'bootstrap_id':'bootstrap-fixture','commit':'a'*40,'built_at':100,'abi':'arm64','boot_protocol':1,'artifact':'bootstrap.tar','size':len(blob),'sha256':digest(blob),'public_config_sha256':digest(config),'files':[{'path':p,'size':len(b),'mode':mode,'sha256':digest(b)} for p,b,mode in files]}
            doc=encode(obj);(d/'doc').write_bytes(doc);(d/'sig').write_bytes(sign(doc,key));(d/'tar').write_bytes(blob)
            stage=d/'stage';stage.mkdir(mode=0o700)
            a=argparse.Namespace(verify_bootstrap=str(d/'doc'),signature=str(d/'sig'),public_key=str(d/'public'),archive=str(d/'tar'),arch='arm64',stage=str(stage))
            (d/'doc').write_bytes(b'not JSON')
            with patch.object(m,'bootstrap_manifest',side_effect=AssertionError('parsed before verification')):
                with self.assertRaises(ValueError):m.verify_bootstrap(a)
            (d/'doc').write_bytes(doc);(d/'tar').write_bytes(blob[:-1]+b'X')
            with self.assertRaises(ValueError):m.verify_bootstrap(a)
            self.assertEqual(list(stage.iterdir()),[])
            bad=m.archive_bytes(files+[('unexpected',b'x',420)],100)
            obj['size']=len(bad);obj['sha256']=digest(bad);bad_doc=encode(obj)
            (d/'doc').write_bytes(bad_doc);(d/'sig').write_bytes(sign(bad_doc,key));(d/'tar').write_bytes(bad)
            with self.assertRaises(ValueError):m.verify_bootstrap(a)
            self.assertEqual(list(stage.iterdir()),[]);self.assertFalse(sentinel.exists())
            (d/'doc').write_bytes(doc);(d/'sig').write_bytes(sign(doc,key));(d/'tar').write_bytes(blob)
            m.verify_bootstrap(a)
            self.assertEqual(len(list(stage.iterdir())),15);self.assertFalse(sentinel.exists())

    def test_publisher_every_interruption_resume_and_bounds(self):
        from update_release_publish import MemoryStore, Publisher, recover, checkpoint, MAX_CHECKPOINTS
        m=load_tool()
        with tempfile.TemporaryDirectory() as td:
            key,public=fixture_key(pathlib.Path(td));manifest=encode({'release_id':'fixture-B'})
            signer=lambda b:sign(b,key)
            for stop in range(1,7):
                class CrashStore(MemoryStore):
                    def __init__(self):super().__init__();self.calls=0;self.active=True
                    def upload(self,n,b):
                        self.calls+=1
                        if self.active and self.calls==stop: raise OSError('fixture interruption before upload')
                        super().upload(n,b)
                    def delete(self,n):
                        self.calls+=1
                        if self.active and self.calls==stop: raise OSError('fixture interruption before delete')
                        super().delete(n)
                st=CrashStore();st.assets={'stable.json':b'bad','stable.json.sig':b'bad'}
                initial=m.channel_document(manifest,7,100);n,b=checkpoint(initial,signer(initial));st.assets[n]=b
                pub=Publisher(st,public,signer,lambda r,h:True)
                try:pub.refresh(manifest,800000)
                except OSError:pass
                st.active=False;pub.refresh(manifest,800001)
                verify_signature(st.read('stable.json'),st.read('stable.json.sig'),public)
                self.assertGreaterEqual(parse(st.read('stable.json'))['sequence'],8)
                self.assertGreaterEqual(recover(st,public)['sequence'],8)
            st=MemoryStore();doc=m.channel_document(manifest,(1<<64)-1,100);n,b=checkpoint(doc,signer(doc));st.upload(n,b)
            with self.assertRaises(ValueError):Publisher(st,public,signer,lambda r,h:True).refresh(manifest,800000)
            st=MemoryStore();doc=m.channel_document(manifest,5,100);n,b=checkpoint(doc,signer(doc));st.upload(n,b[:-1])
            with self.assertRaises(ValueError):recover(st,public)
            st=MemoryStore();doc=m.channel_document(manifest,5,100);n,b=checkpoint(doc,signer(doc));st.upload(n,b)
            other=m.channel_document(manifest,5,101);n,b=checkpoint(other,signer(other));st.upload(n,b)
            with self.assertRaises(ValueError):recover(st,public)
            st=MemoryStore()
            with self.assertRaises(ValueError):Publisher(st,public,signer,lambda r,h:False).refresh(manifest,100)
            self.assertEqual(st.events,[])

    def test_provenance_mixed_commit_release_and_missing_binary(self):
        import update_release_provenance as prov
        with tempfile.TemporaryDirectory() as td:
            d=pathlib.Path(td);root=d/'source';root.mkdir();build=d/'build';build.mkdir()
            subprocess.run(['git','init','-q',str(root)],check=True)
            (root/'source').write_text('fixture')
            subprocess.run(['git','-C',str(root),'add','.'],check=True)
            subprocess.run(['git','-C',str(root),'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture'],check=True)
            compiler={'path':'UNIT-ONLY','version':'UNIT','size':1,'sha256':'a'*64}
            rec={'format':'d2k-build-v1','commit':clean_source(root),'tree':prov.git(root,'rev-parse','HEAD^{tree}'),
                 'abi':'arm64','release_id':'fixture-A','built_at':100,'dependency_receipt':str(d/'deps'),
                 'dependency_sha256':digest(b'fixture'),'compiler':compiler,'target':list(prov.TARGETS['arm64']),
                 'binaries':{}}
            (d/'deps').write_bytes(b'fixture')
            path=build/'provenance-arm64.json'
            for field,value in (('commit','b'*40),('release_id','fixture-B'),('built_at',101),('tree','c'*40)):
                bad=dict(rec);bad[field]=value;path.write_bytes(encode(bad))
                with self.assertRaises(ValueError):prov.validate_build(root,build,'arm64','fixture-A',100)
            path.write_bytes(encode(rec))
            with patch.object(prov,'validate_dependencies',return_value={'compiler':compiler}):
                with self.assertRaisesRegex(ValueError,'missing build output'):prov.validate_build(root,build,'arm64','fixture-A',100)
                rec['binaries']={'d2kc-linux-arm64':{'size':3,'sha256':digest(b'new')}};path.write_bytes(encode(rec))
                with self.assertRaises(FileNotFoundError):prov.validate_build(root,build,'arm64','fixture-A',100)
                (build/'d2kc-linux-arm64').write_bytes(b'old')
                with self.assertRaisesRegex(ValueError,'runtime bytes changed'):prov.validate_build(root,build,'arm64','fixture-A',100)

    def test_json_and_public_config_bounds(self):
        m=load_tool()
        for document in (b'{"x":NaN}',b'['*17+b'0'+b']'*17,b'{"x":1,"x":2}',b'{"x":1}x',b'\xff'):
            with self.assertRaises(ValueError):parse(document)
        base=b'D2KU-CONFIG-1\nfeed=https://github.com/f\nca=/etc/ssl/certs/ca-certificates.crt\nabi=arm64\nbuild=100\nhost=github.com\nkey='+b'a'*64+b' 1 9999999999\n'
        m.public_config(base,'arm64')
        for config in (base+b'abi=arm64\n',base+b'password=secret\n',base.replace(b'https:',b'http:'),base.replace(b'abi=arm64',b'abi=x86'),base+b'key='+b'a'*64+b' 1 9999999999\n'):
            with self.assertRaises(ValueError):m.public_config(config,'arm64')

    def test_api_pagination_bound_and_racing_allocation(self):
        import update_release_publish as pub
        m=load_tool()
        class Pages(pub.GitHubStore):
            def __init__(self):super().__init__('fixture/repo',{'id':1},'FIXTURE');self.pages=[]
            def request(self,url,*args,**kwargs):
                page=int(url.split('page=')[-1]);self.pages.append(page)
                return [{'name':str(page)+'-'+str(i)} for i in range(100)]
        pages=Pages()
        with self.assertRaisesRegex(ValueError,'pagination bound'):pages.list()
        self.assertEqual(pages.pages,list(range(1,pub.MAX_PAGES+1)))
        with tempfile.TemporaryDirectory() as td:
            key,public=fixture_key(pathlib.Path(td));manifest=encode({'release_id':'fixture-race'})
            signer=lambda d:sign(d,key)
            class Race(pub.MemoryStore):
                def upload(self,n,b):
                    super().upload(n,b)
                    if n.startswith('checkpoint-'):
                        doc=m.channel_document(manifest,2,100)
                        other,data=pub.checkpoint(doc,signer(doc))
                        self.assets[other]=data
            st=Race()
            with self.assertRaisesRegex(ValueError,'racing publisher'):pub.Publisher(st,public,signer,lambda r,h:True).refresh(manifest,100)
            self.assertNotIn('stable.json',st.assets)
            partial=pub.MemoryStore();partial.assets['stable.json.sig']=bytes(64)
            with self.assertRaises(ValueError):pub.recover(partial,public)
            st=pub.MemoryStore()
            for seq in (1,2):
                doc=m.channel_document(manifest,seq,100);n,b=pub.checkpoint(doc,signer(doc));st.upload(n,b)
            with patch.object(pub,'MAX_CHECKPOINTS',1):
                with self.assertRaisesRegex(ValueError,'listing limit'):pub.recover(st,public)


if __name__ == '__main__':
    unittest.main()
