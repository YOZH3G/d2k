// Observe only a dedicated field Chrome instance, with bounded CDP calls.
import {mkdirSync,writeFileSync,readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
const [port,out,input,waitArg='45']=process.argv.slice(2);
mkdirSync(out,{recursive:true});
const watchdog=setTimeout(()=>{console.error('CDP observation deadline expired');process.exit(1);},(Number(waitArg)+120)*1000);
watchdog.unref();
const urls=JSON.parse(readFileSync(input,'utf8'));
async function rpc(url,event=()=>{}) {
 const ws=new WebSocket(url); let seq=0; const pending=new Map();
 await new Promise((ok,bad)=>{ws.onopen=ok;ws.onerror=bad;});
 ws.onmessage=e=>{const m=JSON.parse(e.data);if(m.id&&pending.has(m.id)){const [ok,bad,t]=pending.get(m.id);clearTimeout(t);pending.delete(m.id);m.error?bad(Error(JSON.stringify(m.error))):ok(m.result);}else event(m);};
 return {close:()=>ws.close(),call:(method,params={})=>new Promise((ok,bad)=>{const id=++seq;const t=setTimeout(()=>{pending.delete(id);bad(Error(`${method} timeout`));},10000);pending.set(id,[ok,bad,t]);ws.send(JSON.stringify({id,method,params}));})};
}
let version;
for(let i=0;i<50;i++){try{version=await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();break;}catch(e){if(i===49)throw e;await new Promise(r=>setTimeout(r,200));}}
writeFileSync(`${out}/observer.json`,JSON.stringify({browser:version.Browser,protocol:version['Protocol-Version'],wait_s:Number(waitArg),cache_disabled:true,navigation_count:1},null,2));
const browser=await rpc(version.webSocketDebuggerUrl);
const runs=await Promise.all(urls.map(async(url,index)=>{
 const {targetId}=await browser.call('Target.createTarget',{url:'about:blank'});
 const tabs=await (await fetch(`http://127.0.0.1:${port}/json`)).json();
 const tab=tabs.find(t=>t.id===targetId);const requests=new Map();const errors=[];
 const page=await rpc(tab.webSocketDebuggerUrl,m=>{
  const p=m.params||{};const id=p.requestId;
  if(m.method==='Network.requestWillBeSent'){
   const prior=requests.get(id);if(prior&&p.redirectResponse){prior.redirect=p.redirectResponse.status;requests.set(id+':'+p.timestamp,prior);}
   requests.set(id,{url:p.request.url,method:p.request.method,type:p.type,start:p.timestamp,requestHeaders:Object.fromEntries(Object.entries(p.request.headers||{}).filter(([k])=>/^(accept|user-agent)$/i.test(k)))});
  }
  const r=requests.get(id);if(!r)return;
  if(m.method==='Network.responseReceived'){const q=p.response;Object.assign(r,{status:q.status,protocol:q.protocol,mime:q.mimeType,ip:q.remoteIPAddress,fromCache:q.fromDiskCache||q.fromServiceWorker,headers:Object.fromEntries(Object.entries(q.headers).filter(([k])=>/^(content-length|content-encoding|content-type|location|etag)$/i.test(k)))});}
  if(m.method==='Network.dataReceived'){r.dataBytes=(r.dataBytes||0)+p.dataLength;r.encodedBytes=(r.encodedBytes||0)+p.encodedDataLength;}
  if(m.method==='Network.loadingFinished'){r.finished=true;r.end=p.timestamp;r.transfer=p.encodedDataLength;}
  if(m.method==='Network.loadingFailed'){r.error=p.errorText;r.canceled=p.canceled;r.end=p.timestamp;}
 });
 await page.call('Network.enable');await page.call('Network.setCacheDisabled',{cacheDisabled:true});await page.call('Page.enable');
 try {await page.call('Page.navigate',{url});} catch(e) {errors.push(String(e));} return {page,requests,errors,index,url,targetId};
}));
await new Promise(r=>setTimeout(r,Number(waitArg)*1000));
await Promise.all(runs.map(async r=>{
 for(const [requestId,q] of r.requests){
  if(q.finished && q.type==='Image' && q.url.startsWith('https://cdnb.enimerosi.com/')){
   try {const v=await r.page.call('Network.getResponseBody',{requestId});const body=Buffer.from(v.body,v.base64Encoded?'base64':'utf8');q.bodyBytes=body.length;q.bodySha256=createHash('sha256').update(body).digest('hex');}
   catch(e){q.bodyObserverError=String(e);}
  }
 }
 let dom=null;try{const v=await r.page.call('Runtime.evaluate',{expression:'JSON.stringify({url:location.href,title:document.title,ready:document.readyState,text:(document.body?.innerText||" ").trim().length,styles:[...document.styleSheets].map(s=>s.href).filter(Boolean),images:[...document.images].filter(i=>!i.complete||!i.naturalWidth).map(i=>i.src)})',returnByValue:true});dom=JSON.parse(v.result.value);}catch(e){r.errors.push(String(e));}
 try{const shot=await r.page.call('Page.captureScreenshot',{format:'png'});writeFileSync(`${out}/${r.index+1}.png`,Buffer.from(shot.data,'base64'));}catch(e){r.errors.push(String(e));}
 writeFileSync(`${out}/${r.index+1}.json`,JSON.stringify({url:r.url,dom,observerErrors:r.errors,requests:[...r.requests.values()]},null,2));
 console.log(JSON.stringify({url:r.url,dom,errors:r.errors,failed:[...r.requests.values()].filter(q=>q.error).map(q=>({url:q.url,error:q.error,type:q.type}))}));
 await browser.call('Target.closeTarget',{targetId:r.targetId});r.page.close();
}));
await browser.call('Browser.close').catch(()=>{});browser.close();clearTimeout(watchdog);
