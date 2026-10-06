"use strict";
// Браузер → настоящий C-сервер панели (HTTP, CSP, API) → изолированная запись команд службы.
// Ни роутера, ни /opt: всё во временном каталоге.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawn}=require('node:child_process');
const profile=fs.mkdtempSync(path.join(os.tmpdir(),'d2k-browser-'));
const chrome=spawn('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
 ['--headless','--no-first-run','--hide-scrollbars','--remote-debugging-port=0','--user-data-dir='+profile,'about:blank'],{stdio:'ignore'});
const now=Date.now(),iso=s=>new Date(now-s*1000).toISOString();
const fixture={knowledge:{
 searches:[
  {target:'rutracker.org',family:4,transport:6,ip:'104.21.32.39',port:443,phase:'распознаём поведение',since:iso(40),attempts:0,probes:5,candidate:'',source:'',question:'принимает ли ответ на усечённое приветствие'},
  {target:'video.example',family:6,transport:17,ip:'2001:db8::5',port:443,phase:'проверяем готовое узнанной коробки',since:iso(200),attempts:1,probes:3,candidate:'план поставлен',source:'готовый план узнанной коробки'},
  {target:'queued.example',family:4,transport:6,ip:'192.0.2.7',port:443,phase:'ожидает безопасного слота замера',since:iso(20),attempts:0,probes:0,candidate:'',source:''}
 ],
 groups:[{suffix:'example.com',transport:6,family:4,shape:1,evidence_count:3,plan_id:'plan-a',probe_path:'/',ech_origin:'',active:true,
  evidence:['a.example.com','b.example.com','c.example.com'],exceptions:[{name:'skip.example.com'}]}],
 boxes:[{id:'box-a',created:iso(3600),updated:iso(60),signals:[{kind:'silent',human:'ответа на приветствие не было',seen:3}],
  plans:[{id:'plan-a',proto:'tls',successes:4,enabled:true,human:'',text:'d2k-plan 1 1\nproto tcp tls\nsplit payload_start +1\norder reverse\n'}],
  bindings:[
   {target:'<img src=x onerror=alert(1)>',family:4,transport:6,shape:1,kind:'name',level:2,level_name:'сервер ответил',successes:1,confirmed:iso(90),enabled:true,recheck:false},
   {target:'a.example.com',family:4,transport:6,shape:1,kind:'name',level:3,level_name:'обмен прошёл',successes:2,confirmed:iso(120),enabled:true,recheck:false},
   {target:'a.example.com',family:6,transport:6,shape:1,kind:'name',level:3,level_name:'обмен прошёл',successes:1,confirmed:iso(130),enabled:true,recheck:true},
   {target:'skip.example.com',family:4,transport:6,shape:1,kind:'name',level:3,level_name:'обмен прошёл',successes:1,confirmed:iso(140),enabled:true,recheck:false}
  ]}],
 measurements:{active:1,limit:4,queued:0,cores:2,free_pct:80},targets:4,confirms:7,probes_used:30,client_unfit:0}};
let ws;
async function main(){
 let port;
 for(let i=0;i<100;i++){try{port=fs.readFileSync(path.join(profile,'DevToolsActivePort'),'utf8').split('\n')[0];break}catch{}await new Promise(r=>setTimeout(r,100))}
 if(!port)throw Error('Headless browser unavailable');
 const tab=await(await fetch('http://127.0.0.1:'+port+'/json/new?about:blank',{method:'PUT'})).json();
 ws=new WebSocket(tab.webSocketDebuggerUrl);await new Promise((r,j)=>{ws.onopen=r;ws.onerror=j});
 let id=0;const pending=new Map(),exceptions=[],dialogs=[];
 ws.onmessage=e=>{const x=JSON.parse(e.data);if(x.id){const p=pending.get(x.id);pending.delete(x.id);x.error?p.reject(x.error):p.resolve(x.result)}
 else if(x.method==='Page.javascriptDialogOpening'){dialogs.push(x.params.message);call('Page.handleJavaScriptDialog',{accept:true})}
 else if(x.method==='Runtime.exceptionThrown')exceptions.push(x.params.exceptionDetails)};
 const call=(method,params={})=>new Promise((resolve,reject)=>{pending.set(++id,{resolve,reject});ws.send(JSON.stringify({id,method,params}))});
 const evaluate=async(expression)=>{const r=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value};
 const wait=ms=>new Promise(r=>setTimeout(r,ms));
 const until=async(expr,msg)=>{for(let i=0;i<160;i++){if(await evaluate(expr))return;await wait(50)}throw Error(msg)};
 await call('Page.enable');await call('Runtime.enable');
 const out=process.env.D2K_CAPTURE_DIR;
 const panel=await require('./browser-c-fixture.cjs')(fixture);
 try{
  await call('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false});
  await call('Page.navigate',{url:panel.url});
  await until('document.querySelectorAll(".search").length===2','C API must populate the live searches');
  await evaluate('document.fonts.ready');
  assert.equal(await evaluate('document.fonts.check("700 24px Onest")'),true,'C CSP must load the bundled text face');
  assert.match(await evaluate('document.querySelector("#now-title").textContent'),/Идёт 3 поиска/);
  assert.equal(await evaluate('document.querySelectorAll(".queue-list li").length'),1,'queued searches are listed compactly');
  assert.match(await evaluate('document.querySelector("#engine-state").textContent.trim()'),/^Движок работает, идёт подборрежим: применение$/,
    'panel process uptime must not be shown as engine uptime');

  // Данные из сети — только текст.
  assert.equal(await evaluate('document.body.textContent.includes("<img src=x onerror=alert(1)>")'),true,'network names are shown literally');
  assert.equal(await evaluate('[...document.images].some(i=>i.getAttribute("src")==="x")'),false,'network names never become elements');
  assert.deepEqual(dialogs,[]);

  // Семейство сворачивает покрытые имена, но не исключения и не другой IP-контекст.
  const rows=await evaluate('[...document.querySelectorAll(".bindings tbody tr")].map(r=>r.querySelector(".t").textContent+"|"+r.querySelector(".n").textContent)');
  assert.ok(rows.includes('skip.example.com|TLS 1.3 · IPv4'),'family exception stays visible');
  assert.ok(rows.includes('a.example.com|TLS 1.3 · IPv6'),'IPv6 context stays visible');
  assert.ok(!rows.includes('a.example.com|TLS 1.3 · IPv4'),'covered IPv4 name is folded into the family');
  assert.match(await evaluate('document.querySelector(".covered summary").textContent'),/1 цель покрыта/);

  // Коробки свёрнуты по умолчанию; туннель нарисован в своём состоянии.
  assert.deepEqual(await evaluate('[...document.querySelectorAll(".crate")].map(c=>c.open)'),[false],'boxes start collapsed');
  assert.match(await evaluate('document.querySelector(".crate-label").textContent'),/4цели · 1 план/);
  assert.equal(await evaluate('document.querySelector("#telegram-body").dataset.state'),'connected');
  assert.equal(await evaluate('!!document.querySelector("#telegram-body .tun")'),true,'tunnel drawing is present');

  // Туннель: одна сцена на все состояния, переходы идут на ней же; каждое состояние читается.
  await evaluate('document.querySelector("#telegram").scrollIntoView({block:"center"})');
  const shots=process.env.D2K_TUNNEL_SHOTS;
  if(shots)fs.mkdirSync(shots,{recursive:true});
  const tunnelShot=async name=>{if(!shots)return;
   const b=await evaluate('(()=>{const r=document.querySelector("#telegram-body").getBoundingClientRect();return {x:r.x+scrollX,y:r.y+scrollY,width:r.width,height:r.height}})()');
   const s=await call('Page.captureScreenshot',{format:'png',clip:{...b,scale:2}});fs.writeFileSync(path.join(shots,name+'.png'),Buffer.from(s.data,'base64'))};
  const tunnelState=async st=>{panel.telegram(st);await until('document.querySelector("#telegram-body").dataset.state==="'+st+'"','tunnel must reach '+st)};
  const visiblePkts='[...document.querySelectorAll("#telegram-body .pkt")].filter(p=>+gsap.getProperty(p,"opacity")>0.5)';
  await evaluate('window.tunScene=document.querySelector("#telegram-body .tun")');
  assert.equal(await evaluate('document.querySelector("#telegram-body").dataset.motion'),'live','tunnel runs its scene');
  await until(visiblePkts+'.length>=2','connected tunnel carries live traffic');
  const widths=new Set();
  for(let i=0;i<24;i++){(await evaluate(visiblePkts+'.map(p=>Math.round(p.width.baseVal.value))')).forEach(w=>widths.add(w));await wait(150)}
  assert.ok(widths.size>=4,'packets vary in size: '+[...widths]);
  await tunnelShot('1-connected');
  await tunnelState('stopped');
  await wait(650);await tunnelShot('2-connected-to-stopped');
  await until('getComputedStyle(document.querySelector(".gate-post")).opacity==="1"&&!gsap.getProperty(document.querySelector(".gate-post"),"y")','the gate settles down');
  await until(visiblePkts+'.length===0','traffic drains when the tunnel stops');
  await wait(400);await tunnelShot('3-stopped');
  await tunnelState('connecting');
  await until('+gsap.getProperty(document.querySelector(".tun-probe"),"opacity")>0.5','connecting tunnel sends a call');
  await wait(300);await tunnelShot('4-connecting');
  assert.equal(await evaluate(visiblePkts+'.length'),0,'no traffic before the relay answers');
  await tunnelState('connected');
  await wait(1050);await tunnelShot('5-handshake-relay-answers');
  await wait(1300);await tunnelShot('6-handshake-tunnel-opens');
  await until(visiblePkts+'.length>=1','traffic starts after the handshake');
  await wait(1500);await tunnelShot('7-connected-flow');
  await tunnelState('not_configured');
  await wait(2200);await tunnelShot('8-not-configured');
  assert.notEqual(await evaluate('getComputedStyle(document.querySelector(".tun-wall")).strokeDasharray'),'none','sketch is dotted again after transitions');
  assert.equal(await evaluate('window.tunScene===document.querySelector("#telegram-body .tun")'),true,'state changes animate the same drawing');
  await tunnelState('connected');

  // GSAP загружен с роутера под CSP; коробка открывается сценой и закрывается обратно.
  assert.equal(await evaluate('typeof gsap==="object"&&typeof Flip==="function"&&document.documentElement.classList.contains("has-gsap")'),true,'GSAP must load from the panel itself');
  await evaluate('document.querySelector(".crate-lid").click()');
  await until('document.querySelector(".crate").open&&!gsap.isTweening(document.querySelector(".crate-body"))','crate opens through its timeline');
  await wait(400);
  assert.equal(await evaluate('getComputedStyle(document.querySelector(".crate-body")).height!=="0px"'),true,'opened crate shows its contents');
  await evaluate('document.querySelector(".crate-lid").click()');
  await until('!document.querySelector(".crate").open','crate closes after its reverse timeline');
  assert.equal(await evaluate('document.querySelector(".crate-body").getAttribute("style")||""'),'','animation leaves no inline styles behind');

  // Бирка семейства ведёт к коробке с её планом: прокрутка и раскрытие.
  assert.equal(await evaluate('document.querySelectorAll(".ftag-wrap").length'),1,'family is drawn as a tag');
  await evaluate('document.querySelector(".ftag-box").click()');
  await until('document.querySelector(".crate").open&&!gsap.isTweening(window)','family tag link opens its box');
  await evaluate('document.querySelector(".crate-lid").click()');
  await until('!document.querySelector(".crate").open','box closes again');
  assert.equal(await evaluate('!!document.querySelector(".index-marker")&&getComputedStyle(document.querySelector(".index-marker")).display'),'block','navigation marker is present');
  assert.match(await evaluate('document.title'),/^(● )?D2K — Движок работает, идёт подбор$/,'title carries the engine state and no theme name');
  assert.equal(await evaluate('document.body.textContent.includes("Ведомость")'),false,'the theme name is not shown in the interface');

  // Опрос не сбрасывает раскрытые подробности, фокус и фильтр.
  await evaluate('document.querySelector(".plan").open=true');
  await evaluate('document.querySelector("[data-control=restart]").focus();window.restartBefore=document.querySelector("[data-control=restart]")');
  const polls='performance.getEntriesByType("resource").filter(e=>new URL(e.name).pathname==="/api/status").length';
  const before=await evaluate(polls);
  await until(polls+'>='+(before+2),'panel must keep polling');
  assert.equal(await evaluate('document.querySelector(".plan").open'),true,'open plan survives polling');
  assert.equal(await evaluate('document.activeElement===window.restartBefore'),true,'focused control is not replaced by a poll');
  await evaluate('(()=>{const i=document.querySelector("#filter");i.value="skip";i.dispatchEvent(new Event("input"))})()');
  assert.match(await evaluate('document.querySelector("#filter-count").textContent'),/1 цель/);
  assert.equal(await evaluate('document.querySelector(".crate").open'),true,'a box with filter matches opens itself');
  await evaluate('(()=>{const i=document.querySelector("#filter");i.value="";i.dispatchEvent(new Event("input"))})()');

  // Шкала фаз совпадает с этапом оригинала.
  assert.equal(await evaluate('document.querySelector(".search .track-step[data-state=now]").textContent'),'Распознаём');

  // Карточка этапа «Распознаём»: последний вопрос и счётчик зондов, без устаревшего источника.
  assert.equal(await evaluate('document.querySelector(".search .search-question").textContent'),'Вопрос коробке: принимает ли ответ на усечённое приветствие');
  assert.equal(await evaluate('document.querySelector(".search .search-question").hidden'),false);
  assert.match(await evaluate('document.querySelector(".search").textContent'),/5 зондов/);
  assert.doesNotMatch(await evaluate('document.querySelector(".search").textContent'),/выведен из замера/);
  assert.equal(await evaluate('[...document.querySelectorAll(".search")].filter(x=>!x.querySelector(".search-question").hidden).length'),1,'question only on the classifier card');

  // Раскладка на ширинах содержимого.
  for(const [name,width,height] of [['narrow',320,740],['phone',390,844],['tablet',768,1024],['laptop',1280,800],['wide',1920,1080]]){
   await call('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:width<600});
   await evaluate('scrollTo(0,0)');await wait(120);
   const state=await evaluate('({overflow:document.documentElement.scrollWidth>innerWidth,bad:[...document.querySelectorAll("#engine-actions [data-control]")].filter(x=>{const r=x.getBoundingClientRect();return r.left<0||r.right>innerWidth||r.top<0||r.height<44||r.width<44}).map(x=>x.dataset.control)})');
   console.log('layout',name,JSON.stringify(state));
   if(state.overflow)console.log('overflow by',await evaluate('[...document.body.querySelectorAll("*")].filter(x=>{const r=x.getBoundingClientRect();return r.width&&r.right>innerWidth+1}).map(x=>x.tagName+"."+(x.getAttribute("class")||"")+" right="+Math.round(x.getBoundingClientRect().right)+" style="+(x.getAttribute("style")||"")).slice(0,8)'));
   assert.equal(state.overflow,false,name+' horizontal overflow');
   assert.deepEqual(state.bad,[],name+' engine controls must be visible 44px targets in the masthead');
   if(out){const s=await call('Page.captureScreenshot',{format:'png'});fs.writeFileSync(path.join(out,'panel-'+name+'.png'),Buffer.from(s.data,'base64'))}
  }
  await call('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false});

  // Остановка требует подтверждения; все шесть команд доходят до службы.
  await evaluate('document.querySelector("[data-control=stop]").click()');
  assert.equal(await evaluate('document.querySelector("[data-control=stop]").textContent'),'Остановить движок?','stop needs an explicit second press');
  await evaluate('document.querySelector("[data-control=cancel]").click()');
  for(const [action,command,presses] of [['stop','engine-stop',2],['start','engine-start',1],['restart','engine-restart',1],['reapply','reapply',1],['telegram-disable','telegram-disable',1],['telegram-enable','telegram-enable',1]]){
   await until('!!document.querySelector("[data-control='+action+']:not([disabled])")',action+' control must become available');
   for(let i=0;i<presses;i++)await evaluate('document.querySelector("[data-control='+action+']").click()');
   await panel.waitFor(command);
   if(action==='stop'){
    await until('/остановлен/.test(document.querySelector("#now-title").textContent)','stopped engine must be stated');
    const s=await(await fetch(panel.url+'api/status')).json();
    assert.equal(s.snapshot.telegram_enabled,true,'stopping the engine leaves the tunnel alone');
   }
   if(action==='telegram-disable'){
    await until('document.querySelector("#telegram-body").dataset.state==="stopped"','tunnel drawing must show the stopped state');
    await until('!!document.querySelector("[data-control=telegram-enable]")','tunnel must offer enabling after disable');
    const s=await(await fetch(panel.url+'api/status')).json();
    assert.equal(s.snapshot.engine_running,true,'the tunnel toggle leaves the engine alone');
   }
  }

  // Потеря API: последний снимок приглушён и честно подписан.
  await call('Network.enable');
  await call('Network.setBlockedURLs',{urls:[panel.url+'api/status']});
  await wait(11500);
  assert.equal(await evaluate('document.body.dataset.stale'),'true','lost API must mark the snapshot stale');
  assert.match(await evaluate('document.querySelector("#notice").textContent'),/Нет ответа от панели/);
  await call('Network.setBlockedURLs',{urls:[]});
  await until('document.body.dataset.stale==="false"','recovered API must clear the stale mark');
  // «Уменьшить движение»: без сцен, но всё работает.
  await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});
  await call('Page.reload');
  await until('document.querySelectorAll(".search").length===2','reduced-motion page renders');
  await evaluate('document.querySelector(".crate-lid").click()');
  assert.equal(await evaluate('document.querySelector(".crate").open'),true,'reduced motion opens the crate natively at once');
  assert.equal(await evaluate('gsap.globalTimeline.getChildren(true,true,false).filter(t=>t.isActive()).length'),0,'reduced motion runs no tweens');
  assert.equal(await evaluate('document.querySelector("#telegram-body").dataset.motion'),'still','reduced motion shows a still tunnel frame');
  assert.equal(await evaluate('getComputedStyle(document.querySelector(".tun-still-flow")).display'),'inline','the still frame still shows traffic');
  if(process.env.D2K_TUNNEL_SHOTS){await evaluate('document.querySelector("#telegram").scrollIntoView({block:"center"})');await wait(200);
   const b=await evaluate('(()=>{const r=document.querySelector("#telegram-body").getBoundingClientRect();return {x:r.x+scrollX,y:r.y+scrollY,width:r.width,height:r.height}})()');
   const s=await call('Page.captureScreenshot',{format:'png',clip:{...b,scale:2}});fs.writeFileSync(path.join(process.env.D2K_TUNNEL_SHOTS,'9-reduced-motion-connected.png'),Buffer.from(s.data,'base64'))}
  await call('Emulation.setEmulatedMedia',{features:[]});
  assert.deepEqual(exceptions,[]);
  console.log('Browser + C panel: rendering, honesty, polling, layout and all six commands passed.');
 }finally{await panel.close()}
}
main().catch(e=>{console.error(e);process.exitCode=1}).finally(()=>{if(ws)ws.close();chrome.kill()});
