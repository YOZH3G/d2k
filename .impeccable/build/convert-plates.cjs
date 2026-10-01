const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawn} = require('node:child_process');
const profile = fs.mkdtempSync(path.join(os.tmpdir(),'d2k-design-chrome-'));
const chrome = spawn('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
 ['--headless','--no-first-run','--remote-debugging-port=0','--user-data-dir='+profile,'about:blank'],
 {stdio:'ignore'});
let ws;
async function main(){
 let port;
 for(let i=0;i<100;i++){
  try{port=fs.readFileSync(path.join(profile,'DevToolsActivePort'),'utf8').split('\n')[0];break;}catch{}
  await new Promise(r=>setTimeout(r,100));
 }
 if(!port)throw Error('Headless Chrome did not expose debugging port');
 const tab=await(await fetch('http://127.0.0.1:'+port+'/json/new?http://127.0.0.1:55940/',{method:'PUT'})).json();
 ws=new WebSocket(tab.webSocketDebuggerUrl);
 await new Promise((r,j)=>{ws.onopen=r;ws.onerror=j});
 let id=0;const pending=new Map();
 ws.onmessage=e=>{const x=JSON.parse(e.data);if(x.id){const p=pending.get(x.id);pending.delete(x.id);x.error?p.reject(x.error):p.resolve(x.result)}};
 const call=(method,params={})=>new Promise((resolve,reject)=>{pending.set(++id,{resolve,reject});ws.send(JSON.stringify({id,method,params}))});
 await call('Page.enable');
 await call('Page.navigate',{url:'http://127.0.0.1:55940/'});
 await new Promise(r=>setTimeout(r,400));
 for(const [source,dest,width] of [
  ['/assets/plates/ground.png','internal/web/assets/ground.webp',600],
  ['/assets/plates/rack-art.png','internal/web/assets/rack.webp',1440],
  ['/assets/plates/family-art.png','internal/web/assets/family-rack.webp',1440],
  ['/assets/plates/layers/left.png','internal/web/assets/slide-left.webp',1440],
  ['/assets/plates/layers/center.png','internal/web/assets/slide-center.webp',1440],
  ['/assets/plates/layers/right.png','internal/web/assets/slide-right.webp',1440],
  ['/assets/plates/layers/holder.png','internal/web/assets/slide-holder.webp',1440]
 ]){
  const expression='(async()=>{const im=new Image();im.src='+JSON.stringify(source)+';await im.decode();const c=document.createElement("canvas");c.width='+width+';c.height=Math.round(im.height*c.width/im.width);c.getContext("2d").drawImage(im,0,0,c.width,c.height);return c.toDataURL("image/webp",.83).split(",")[1]})()';
  const result=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});
  if(result.exceptionDetails)throw Error(JSON.stringify(result.exceptionDetails));
  fs.writeFileSync(dest,Buffer.from(result.result.value,'base64'));
  console.log(dest,fs.statSync(dest).size,'bytes');
 }
}
main().catch(e=>{console.error(e);process.exitCode=1}).finally(()=>{if(ws)ws.close();chrome.kill()});
