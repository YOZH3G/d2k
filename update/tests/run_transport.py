#!/usr/bin/env python3
"""Private localhost TLS fixture; no router or remote service access."""
import http.server, os, ssl, subprocess, sys, tempfile, threading
with tempfile.TemporaryDirectory(prefix='d2ku-tls-') as root:
    def openssl(*args):
        subprocess.run(['openssl', *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ca, cakey = root+'/ca.pem', root+'/ca.key'
    openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',cakey,'-out',ca,'-subj','/CN=D2KU TEST CA','-days','1')
    key, csr, cert = root+'/server.key', root+'/server.csr', root+'/server.pem'
    openssl('req','-newkey','rsa:2048','-nodes','-keyout',key,'-out',csr,'-subj','/CN=localhost')
    ext = root+'/ext'
    with open(ext,'w') as f: f.write('subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')
    openssl('x509','-req','-in',csr,'-CA',ca,'-CAkey',cakey,'-CAcreateserial','-out',cert,'-days','1','-extfile',ext)
    badkey, badcert = root+'/bad.key', root+'/bad.pem'
    openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',badkey,'-out',badcert,'-subj','/CN=localhost','-days','1','-addext','subjectAltName=DNS:localhost')
    wrongcsr, wrongcert = root+'/wrong.csr', root+'/wrong.pem'
    openssl('req','-new','-key',key,'-out',wrongcsr,'-subj','/CN=wrong.test')
    with open(ext,'w') as f: f.write('subjectAltName=DNS:wrong.test\nextendedKeyUsage=serverAuth\n')
    openssl('x509','-req','-in',wrongcsr,'-CA',ca,'-CAkey',cakey,'-CAcreateserial','-out',wrongcert,'-days','1','-extfile',ext)
    bad_port = wrong_port = good_port = 0
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_GET(self):
            path = self.path
            targets = {'/redirect-http':'http://localhost:1/ok','/redirect-host':f'https://127.0.0.1:{good_port}/ok', '/bad-tls':f'https://localhost:{bad_port}/ok','/wrong-name':f'https://localhost:{wrong_port}/ok','/redirect-good':'/ok','/loop':'/loop','/creds':'https://u:p@localhost:1/ok','/redirect-five':'/r4','/r4':'/r3','/r3':'/r2','/r2':'/r1','/r1':'/ok'}
            if path in targets:
                self.send_response(302); self.send_header('Location',targets[path]); self.send_header('Content-Length','20'); self.end_headers(); self.wfile.write(b'ignored redirectbody'); return
            if path=='/error':
                self.send_response(404); self.end_headers(); self.wfile.write(b'err'); return
            self.send_response(200)
            if path=='/compressed': self.send_header('Content-Encoding','gzip')
            if path=='/chunked': self.send_header('Transfer-Encoding','chunked')
            else: self.send_header('Content-Length','4' if path=='/large' else '3')
            self.end_headers(); self.wfile.write(b'4\r\nabcd\r\n0\r\n\r\n' if path=='/chunked' else b'abcd' if path=='/large' else b'abc')
    def server(cert,key):
        s=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert,key); s.socket=ctx.wrap_socket(s.socket,server_side=True)
        threading.Thread(target=s.serve_forever,daemon=True).start(); return s
    bad=server(badcert,badkey); bad_port=bad.server_port; wrong=server(wrongcert,key); wrong_port=wrong.server_port; good=server(cert,key); good_port=good.server_port
    try: subprocess.run([sys.argv[1],f'https://localhost:{good.server_port}',ca,root],check=True)
    finally: good.shutdown(); bad.shutdown(); wrong.shutdown()
