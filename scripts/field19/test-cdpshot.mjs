import {createServer} from 'node:http';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {strict as assert} from 'node:assert';
const sockets=new Set();
const server=createServer((req,res)=>{
 res.setHeader('Content-Type','application/json');
 res.end(JSON.stringify([{type:'page',url:'https://fixture.invalid/',webSocketDebuggerUrl:`ws://127.0.0.1:${server.address().port}/ws`}]));
});
server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});
server.on('upgrade',(req,s)=>{
 const accept=createHash('sha1').update(req.headers['sec-websocket-key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
 s.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
 // Accepted connection, but renderer never replies to the CDP command.
});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const child=spawn(process.execPath,[new URL('./cdpshot.mjs',import.meta.url).pathname,String(server.address().port),'/tmp/d2k-cdpshot-never-written.png'],{env:{...process.env,D2K_CDP_TIMEOUT_MS:'200'}});
let stderr='',killed=false;child.stderr.on('data',b=>stderr+=b);
const timer=setTimeout(()=>{killed=true;child.kill('SIGKILL');},1500);
const code=await new Promise(r=>child.on('exit',r));clearTimeout(timer);
for(const s of sockets)s.destroy();await new Promise(r=>server.close(r));
assert.equal(killed,false,'CDP observer hung on an unresponsive renderer');
assert.notEqual(code,0);assert.match(stderr,/тайм-аут CDP/);
console.log('CDP unresponsive renderer: bounded failure passed');
