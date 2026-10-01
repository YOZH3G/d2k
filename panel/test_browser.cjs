"use strict";
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawn}=require('node:child_process');
const profile=fs.mkdtempSync(path.join(os.tmpdir(),'d2k-browser-'));
const chrome=spawn('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
 ['--headless','--no-first-run','--hide-scrollbars','--remote-debugging-port=0','--user-data-dir='+profile,'about:blank'],{stdio:'ignore'});
let ws;
async function main(){
 let port;
 for(let i=0;i<100;i++){try{port=fs.readFileSync(path.join(profile,'DevToolsActivePort'),'utf8').split('\n')[0];break}catch{}await new Promise(r=>setTimeout(r,100))}
 if(!port)throw Error('Headless browser unavailable');
 const tab=await(await fetch('http://127.0.0.1:'+port+'/json/new?about:blank',{method:'PUT'})).json();
 ws=new WebSocket(tab.webSocketDebuggerUrl);await new Promise((r,j)=>{ws.onopen=r;ws.onerror=j});
 let id=0;const pending=new Map(),exceptions=[];
 ws.onmessage=e=>{const x=JSON.parse(e.data);if(x.id){const p=pending.get(x.id);pending.delete(x.id);x.error?p.reject(x.error):p.resolve(x.result)}
 else if(x.method==='Page.javascriptDialogOpening')call('Page.handleJavaScriptDialog',{accept:true});
 else if(x.method==='Runtime.exceptionThrown')exceptions.push(x.params.exceptionDetails)};
 const call=(method,params={})=>new Promise((resolve,reject)=>{pending.set(++id,{resolve,reject});ws.send(JSON.stringify({id,method,params}))});
 const evaluate=async(expression)=>{const r=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value};
 await call('Page.enable');await call('Runtime.enable');
 const out=path.resolve(__dirname,'../.impeccable/review');fs.mkdirSync(out,{recursive:true});
 for(const [name,width,height] of [['desktop',1536,1024],['mobile',390,844]]){
  await call('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
  await call('Page.navigate',{url:'http://127.0.0.1:55941/'});
  await new Promise(r=>setTimeout(r,600));
  await evaluate('document.fonts.ready');
  const metrics=await evaluate('({width:innerWidth,scroll:document.documentElement.scrollWidth,fonts:document.fonts.check("700 24px Slide"),cards:document.querySelectorAll("[data-slide-key]").length,controls:[...document.querySelectorAll("[data-control]")].map(x=>({action:x.dataset.control,disabled:x.disabled,rect:x.getBoundingClientRect().toJSON()}))})');
  console.log(name,JSON.stringify(metrics));
  if(metrics.scroll>width)console.log('overflow',await evaluate('[...document.body.querySelectorAll("*")].filter(x=>{const r=x.getBoundingClientRect();return r.width&&r.right>innerWidth}).map(x=>({tag:x.tagName,class:x.className,right:x.getBoundingClientRect().right})).slice(0,25)'));
  assert.equal(metrics.cards,3);assert.ok(metrics.fonts);assert.ok(metrics.scroll<=width,'Page must not overflow horizontally');
  if(name==='desktop'){
   const domainSpacing=await evaluate('[...document.querySelectorAll("[data-slot=left] .search-target,.family-header h3")].map(x=>({name:x.textContent,spacing:parseFloat(getComputedStyle(x).letterSpacing)||0}))');
   for(const domain of domainSpacing)assert.ok(domain.spacing>=0,'Domain punctuation must retain uncompressed tracking: '+domain.name);
  }
  for(const control of metrics.controls){
   assert.ok(control.rect.left>=0 && control.rect.right<=width,'Control must be fully visible: '+control.action);
   assert.ok(control.rect.height>=44,'Control must retain a 44px touch target: '+control.action);
  }
  if(!process.env.D2K_SKIP_CAPTURE){
   const image=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});
   fs.writeFileSync(path.join(out,'integrated-'+name+'.png'),Buffer.from(image.data,'base64'));
   if(name==='desktop')fs.writeFileSync(path.join(out,'hero-repro.png'),Buffer.from(image.data,'base64'));
  }
 }
 await evaluate('document.querySelector("[data-select-slide]").click()');
 assert.equal(await evaluate('document.querySelector("[data-select-slide]").getAttribute("aria-pressed")'),'true');
 await new Promise(r=>setTimeout(r,550));
 await evaluate('window.controlBeforePoll=document.querySelector("[data-control=restart]");window.controlBeforePoll.focus()');
 await evaluate('document.dispatchEvent(new Event("DOMContentLoaded"))');
 await new Promise(r=>setTimeout(r,300));
 assert.equal(await evaluate('document.querySelector("[data-select-slide]").getAttribute("aria-pressed")'),'true','Selection must survive polling');
 assert.equal(await evaluate('window.controlBeforePoll===document.querySelector("[data-control=restart]")'),true,
   'A poll must not replace a service button while the user may be pressing it');
 assert.equal(await evaluate('document.activeElement===window.controlBeforePoll'),true,
   'Keyboard focus must remain on the same service button');
 assert.equal(await evaluate('document.getAnimations().length'),0,'Unchanged poll must not replay effects');
 await evaluate('document.querySelector("[data-control=telegram-disable]").click()');
 await new Promise(r=>setTimeout(r,300));
 assert.equal(await evaluate('!!document.querySelector("[data-control=telegram-enable]")'),true);
 await evaluate('document.querySelector("[data-control=stop]").click()');
 await new Promise(r=>setTimeout(r,300));
 assert.equal(await evaluate('document.querySelector("#rail-state").textContent'),'D2K не на связи');
 await evaluate('document.querySelector("[data-control=start]").click()');
 await new Promise(r=>setTimeout(r,300));
 assert.equal(await evaluate('document.querySelector("#rail-state").textContent'),'D2K на связи');
 await evaluate('document.querySelector("[data-control=telegram-enable]").click()');
 await new Promise(r=>setTimeout(r,300));
 assert.equal(await evaluate('!!document.querySelector("[data-control=telegram-disable]")'),true);
 const changePhase=async(target,phase)=>{
   const response=await fetch('http://127.0.0.1:55941/__test/phase?'+new URLSearchParams({target,phase}),{method:'POST'});
   assert.equal(response.status,200);
   await evaluate('document.dispatchEvent(new Event("DOMContentLoaded"))');
   await new Promise(r=>setTimeout(r,90));
 };
 await call('Emulation.setDeviceMetricsOverride',{width:1536,height:1024,deviceScaleFactor:1,mobile:false});
 await evaluate('scrollTo(0,0)');
 await changePhase('googlevideo.com','проверяем выведенный план');
 assert.ok(await evaluate('document.getAnimations().length>0'),'A changed stage must produce feedback');
 await new Promise(r=>setTimeout(r,700));
 await changePhase('googlevideo.com','подтверждено, смотрим живой трафик');
 assert.equal(await evaluate('document.querySelectorAll("body > [aria-hidden=true][data-slide-key]").length'),1,
   'Confirmed slide must travel to its matching visible family');
 await new Promise(r=>setTimeout(r,800));
 assert.equal(await evaluate('document.querySelectorAll("body > [aria-hidden=true][data-slide-key]").length'),0,
   'The transfer must release its temporary DOM and animation');
 await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});
 await changePhase('googlevideo.com','проверяем выведенный план');
 assert.equal(await evaluate('document.getAnimations().some(a=>a.effect.getKeyframes().some(k=>k.transform))'),false,
   'Reduced motion must not translate or scale slides');
 await changePhase('googlevideo.com','подтверждено, смотрим живой трафик');
 assert.equal(await evaluate('document.querySelectorAll("body > [aria-hidden=true][data-slide-key]").length'),0);
 await call('Network.enable');
 await call('Network.setBlockedURLs',{urls:['http://127.0.0.1:55941/api/status']});
 await evaluate('document.querySelector("[data-control=restart]").click()');
 await new Promise(r=>setTimeout(r,300));
 assert.equal(await evaluate('window.controlBeforePoll===document.querySelector("[data-control=restart]")'),true,
   'Losing the API must not remove the service strip');
 assert.equal(await evaluate('[...document.querySelectorAll("[data-control]")].every(b=>b.disabled)'),true,
   'An old action promise must not re-enable its button after the status API failed');
 await call('Network.setBlockedURLs',{urls:[]});
 await evaluate('document.dispatchEvent(new Event("DOMContentLoaded"))');
 await new Promise(r=>setTimeout(r,300));
 assert.equal(await evaluate('[...document.querySelectorAll("[data-control]")].every(b=>!b.disabled)'),true,
   'Recovered API must restore enabled controls from fresh permission flags');
 assert.deepEqual(exceptions,[]);
 // The presentation must hold at the content breakpoints, not just two goldens.
 await call('Emulation.setEmulatedMedia',{features:[]});
 const fixture=await(await fetch('http://127.0.0.1:55941/api/status')).json();
 await evaluate('window.originalFetch=window.fetch');
 for(const [name,width,height] of [['narrow',320,740],['tablet',768,1024],['laptop',1280,800],['wide',1920,1080]]){
  await call('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
  await evaluate('scrollTo(0,0)');
  const state=await evaluate('({overflow:document.documentElement.scrollWidth>innerWidth,controls:[...document.querySelectorAll("[data-control]")].filter(x=>{const r=x.getBoundingClientRect();return r.left<0||r.right>innerWidth||r.top<0||r.bottom>innerHeight||r.height<44}).map(x=>x.dataset.control)})');
  console.log('layout',name,state);
  assert.equal(state.overflow,false,name+' horizontal overflow');
  assert.deepEqual(state.controls,[],name+' inaccessible controls');
  assert.equal(await evaluate('(()=>{const r=document.querySelector("[data-selected=true]").getBoundingClientRect();return r.top<document.querySelector("#controls").getBoundingClientRect().top&&r.width>0})()'),true,name+' must show the selected slide before the fixed service strip');
  if(width<=1100){
   assert.equal(await evaluate('(()=>{const h=document.querySelector(".page-heading").getBoundingClientRect(),s=document.querySelector("[data-selected=true]").getBoundingClientRect();return h.bottom<=s.top})()'),true,name+' heading must not overlap the selected slide');
  }
  if(width<=700){
   assert.equal(await evaluate('[...document.querySelectorAll("[data-slide-step]")].every(x=>{const r=x.getBoundingClientRect();return r.top>=0&&r.bottom<=document.querySelector("#controls").getBoundingClientRect().top&&r.height>=44})'),true,name+' slide navigation must stay above the service dock');
  }
  if(!process.env.D2K_SKIP_CAPTURE && name==='tablet'){
   const shot=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});
   fs.writeFileSync(path.join(out,'integrated-tablet.png'),Buffer.from(shot.data,'base64'));
  }
 }
 const scenarios=[
  ['empty',p=>{p.knowledge.searches=[];p.knowledge.groups=[];p.knowledge.boxes=[];}],
  ['stopped',p=>{p.snapshot.engine_running=false;p.snapshot.controller_running=false;p.knowledge.linked=false;}],
  ['many',p=>{p.knowledge.searches=Array.from({length:18},(_,i)=>({...p.knowledge.searches[i%3],target:'long-client-'+i+'.service.example.com'}));p.knowledge.groups=Array.from({length:8},(_,i)=>({...p.knowledge.groups[i%3],suffix:'family-'+i+'.example.com'}));}]
 ];
 for(const [name,mutate] of scenarios){
  const payload=structuredClone(fixture);mutate(payload);
  await evaluate('window.fetch=(url,options)=>url==="/api/status"?Promise.resolve({ok:true,json:async()=>('+JSON.stringify(payload)+')}):window.originalFetch(url,options);document.dispatchEvent(new Event("DOMContentLoaded"))');
  await new Promise(r=>setTimeout(r,120));
  const state=await evaluate('({overflow:document.documentElement.scrollWidth>innerWidth,visible:[...document.querySelectorAll("[data-slide-key]")].filter(x=>getComputedStyle(x).display!=="none").length,title:document.querySelector("#rail-state").textContent})');
  console.log('scenario',name,state);assert.equal(state.overflow,false);
  if(name==='empty'){
   assert.equal(state.visible,0);
   assert.equal(await evaluate('(()=>{const a=document.querySelector(".page-heading h1").getBoundingClientRect(),b=document.querySelector("#searches .empty-state").getBoundingClientRect();return a.right<=b.left||b.right<=a.left||a.bottom<=b.top||b.bottom<=a.top})()'),true,
     'An empty search must not cover the Slidoscope heading');
  }
  if(name==='stopped')assert.match(state.title,/не на связи/);
  if(name==='many'){
   assert.equal(state.visible,3);
   for(let i=0;i<18;i++)await evaluate('document.querySelectorAll("[data-slide-step]")[1].click()');
   assert.equal(await evaluate('document.querySelectorAll("[data-selected=true]").length'),1);
  }
 }
 await evaluate('window.fetch=window.originalFetch;document.dispatchEvent(new Event("DOMContentLoaded"))');
 assert.deepEqual(exceptions,[]);
 const cPanel=await require('./browser-c-fixture.cjs')(fixture);
 try {
  await call('Emulation.setDeviceMetricsOverride',{width:1536,height:1024,deviceScaleFactor:1,mobile:false});
  await call('Page.navigate',{url:cPanel.url});
  await new Promise(r=>setTimeout(r,500));
  await evaluate('document.fonts.ready');
  assert.equal(await evaluate('document.querySelectorAll("[data-slide-key]").length'),3,'C API must populate the actual renderer');
  assert.equal(await evaluate('document.querySelector("#rail-state").getAttribute("data-connected")'),'true');
  assert.equal(await evaluate('document.fonts.check("700 24px Slide")'),true,'C CSP must load the bundled font');
  const assetResults=await evaluate(`Promise.all([
    "ground.webp", "rack.webp", "family-rack.webp", "slide-left.webp",
    "slide-center.webp", "slide-right.webp", "slide-holder.webp"
  ].map(async name=>{
    const response=await fetch("/assets/"+name);
    const blob=await response.blob();
    const bitmap=await createImageBitmap(blob);
    const result={name,status:response.status,type:blob.type,width:bitmap.width,height:bitmap.height};
    bitmap.close();
    return result;
  }))`);
  for(const asset of assetResults){
    assert.equal(asset.status,200,'C server must serve the installed material: '+asset.name);
    assert.equal(asset.type,'image/webp','Material must carry its correct MIME: '+asset.name);
    assert.ok(asset.width>0&&asset.height>0,'Material must decode, not merely exist: '+asset.name);
  }
  for(const [action,command] of [['stop','engine-stop'],['start','engine-start'],['restart','engine-restart'],['reapply','reapply'],['telegram-disable','telegram-disable'],['telegram-enable','telegram-enable']]){
   await evaluate('document.querySelector("[data-control='+action+']").click()');
   await cPanel.waitFor(command);
   await new Promise(r=>setTimeout(r,100));
   await evaluate('document.dispatchEvent(new Event("DOMContentLoaded"))');
   await new Promise(r=>setTimeout(r,150));
   const status=await(await fetch(cPanel.url+'api/status')).json();
   if(action==='stop'){assert.equal(status.snapshot.engine_running,false);assert.equal(status.snapshot.telegram_enabled,true);}
   if(action==='telegram-disable'){assert.equal(status.snapshot.telegram_enabled,false);assert.equal(status.snapshot.engine_running,true);}
  }
  assert.deepEqual(exceptions,[]);
  console.log('C integration: browser -> real HTTP/CSP/API -> isolated service fixture, all six commands verified.');
 } finally {await cPanel.close();}
 console.log('Browser: live renderer, selection persistence, quiet polling and independent controls OK (simulated services).');
}
main().catch(e=>{console.error(e);process.exitCode=1}).finally(()=>{if(ws)ws.close();chrome.kill()});
