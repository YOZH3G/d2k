#!/usr/bin/env python3
"""Private loopback HTTPS and ephemeral TEST signing key. No remote traffic."""
import hashlib,http.server,json,os,pathlib,ssl,subprocess,sys,tempfile,threading,time
with tempfile.TemporaryDirectory(prefix='d2ku-feed-') as tmp:
    root=pathlib.Path(tmp);(root/'boot').mkdir();(root/'r2').mkdir();(root/'d2k-channel-stable').mkdir()
    def openssl(*args):
        return subprocess.run([os.environ.get('OPENSSL', '/opt/homebrew/opt/openssl@3/bin/openssl' if pathlib.Path('/opt/homebrew/opt/openssl@3/bin/openssl').exists() else 'openssl'),*map(str,args)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout
    key=root/'TEST-key.pem';cert=root/'TEST-cert.pem'
    openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-subj','/CN=localhost','-days','1','-addext','subjectAltName=DNS:localhost')
    signing=root/'TEST-signing.pem';openssl('genpkey','-algorithm','ED25519','-out',signing)
    pub=openssl('pkey','-in',signing,'-pubout','-outform','DER')[-32:].hex()
    now=int(time.time())
    manifest=dict(schema=1,release_id='r2',version='fixture-version',commit='a'*40,built_at=now-60,notes='Signed fixture',min_updater=1,wire=13,state=1,packages=[dict(abi='arm64',artifact='arm64.tar',size=4,sha256=hashlib.sha256(b'data').hexdigest(),files=[dict(path='d2kc',size=4,mode=493,sha256=hashlib.sha256(b'data').hexdigest())])])
    def signed(path,obj):
        data=json.dumps(obj,separators=(',',':')).encode();path.write_bytes(data)
        openssl('pkeyutl','-sign','-inkey',signing,'-rawin','-in',path,'-out',str(path)+'.sig')
        return data
    manifest['signing_keys']=[dict(public_key='02'+'00'*31,not_before=now-10,not_after=now+7000)]
    data=signed(root/'r2/manifest.json',manifest);(root/'r2/arm64.tar').write_bytes(b'data')
    signed(root/'d2k-channel-stable/stable.json',dict(schema=1,channel='stable',sequence=2,issued_at=now-30,expires_at=now+3600,release_id='r2',manifest_sha256=hashlib.sha256(data).hexdigest()))
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self,*a,**kw):super().__init__(*a,directory=tmp,**kw)
        def log_message(self,*a):pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key);server.socket=ctx.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    (root/'boot/update.conf').write_text(f'D2KU-CONFIG-1\nfeed=https://localhost:{server.server_port}\nhost=localhost\nca={cert}\nabi=arm64\nbuild={now-60}\nkey={pub} {now-100} {now+7200}\n');os.chmod(root/'boot/update.conf',0o600)
    try:subprocess.run([sys.argv[1],tmp],check=True)
    finally:server.shutdown()
