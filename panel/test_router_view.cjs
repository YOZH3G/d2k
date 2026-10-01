"use strict";
// Read-only field view: GET requests and local viewport changes only.
// Never invoke /api/control or mutate the household service state.
const assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {spawn}=require("node:child_process");
const base=process.argv[2]||"http://192.168.1.1:8090/";
const profile=fs.mkdtempSync(path.join(os.tmpdir(),"d2k-router-view-"));
const chrome=spawn("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
 ["--headless","--no-first-run","--hide-scrollbars","--remote-debugging-port=0","--user-data-dir="+profile,"about:blank"],{stdio:"ignore"});
let ws;
async function main(){
 let port;
 for(let i=0;i<100;i++){
  try{port=fs.readFileSync(path.join(profile,"DevToolsActivePort"),"utf8").split("\n")[0];break;}catch{}
  await new Promise(r=>setTimeout(r,100));
 }
 assert.ok(port,"Headless browser must start");
 const tab=await(await fetch("http://127.0.0.1:"+port+"/json/new?about:blank",{method:"PUT"})).json();
 ws=new WebSocket(tab.webSocketDebuggerUrl);
 await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject;});
 let id=0;const pending=new Map(),exceptions=[],failedRequests=[];
 ws.onmessage=e=>{
  const x=JSON.parse(e.data);
  if(x.id){const p=pending.get(x.id);pending.delete(x.id);x.error?p.reject(x.error):p.resolve(x.result);}
  else if(x.method==="Runtime.exceptionThrown")exceptions.push(x.params.exceptionDetails);
  else if(x.method==="Network.responseReceived"&&x.params.response.status>=400)failedRequests.push(x.params.response.url);
  else if(x.method==="Network.requestWillBeSent")assert.equal(x.params.request.method,"GET","Field view must never issue a service command");
 };
 const call=(method,params={})=>new Promise((resolve,reject)=>{pending.set(++id,{resolve,reject});ws.send(JSON.stringify({id,method,params}));});
 const evaluate=async expression=>{
  const result=await call("Runtime.evaluate",{expression,awaitPromise:true,returnByValue:true});
  assert.equal(result.exceptionDetails,undefined,"Browser expression must succeed");
  return result.result.value;
 };
 await call("Page.enable");await call("Runtime.enable");await call("Network.enable");
 const out=path.resolve(__dirname,"../.impeccable/review");fs.mkdirSync(out,{recursive:true});
 for(const [name,width,height] of [["desktop",1536,1024],["common",1440,1000],["tablet",768,1024],["mobile",390,844]]){
  await call("Emulation.setDeviceMetricsOverride",{width,height,deviceScaleFactor:1,mobile:false});
  await call("Page.navigate",{url:base});
  await new Promise(r=>setTimeout(r,800));await evaluate("document.fonts.ready");
  const state=await evaluate(`({
    connected:document.querySelector("#rail-state").dataset.connected,
    overflow:document.documentElement.scrollWidth>innerWidth,
    font:document.fonts.check("700 24px Slide"),
    cards:document.querySelectorAll("[data-slide-key]").length,
    controls:[...document.querySelectorAll("[data-control]")].map(x=>{
      const r=x.getBoundingClientRect();
      return {action:x.dataset.control,disabled:x.disabled,visible:r.left>=0&&r.right<=innerWidth&&r.top>=0&&r.bottom<=innerHeight&&r.height>=44};
    }),
    selectedVisible:(()=>{const s=document.querySelector("[data-selected=true]");if(!s)return null;const r=s.getBoundingClientRect();return r.top<document.querySelector("#controls").getBoundingClientRect().top;})()
  })`);
  console.log(name,JSON.stringify(state));
  assert.equal(state.connected,"true","Panel must be linked to the real router API");
  assert.equal(state.overflow,false,"Real data must not overflow horizontally");
  assert.equal(state.font,true,"Router must serve its offline font");
  assert.ok(state.controls.length>=5,"Independent engine and Telegram controls must be rendered");
  for(const control of state.controls){assert.ok(control.visible,control.action+" must be accessible");assert.equal(control.disabled,false,control.action+" must use actual API permissions");}
  if(state.cards)assert.equal(state.selectedVisible,true,"A live selected slide must appear above the fixed dock");
  assert.equal(await evaluate('(()=>{const e=document.querySelector("#searches .empty-state");if(!e)return true;const a=document.querySelector(".page-heading h1").getBoundingClientRect(),b=e.getBoundingClientRect();return a.right<=b.left||b.right<=a.left||a.bottom<=b.top||b.bottom<=a.top})()'),true,
   "Empty live state must not cover the page heading");
  const shot=await call("Page.captureScreenshot",{format:"png",captureBeyondViewport:false});
  fs.writeFileSync(path.join(out,"router-"+name+".png"),Buffer.from(shot.data,"base64"));
 }
 assert.deepEqual(exceptions,[],"Real API render must produce no browser exceptions");
 assert.deepEqual(failedRequests,[],"All router resources must resolve without 4xx/5xx responses");
 console.log("Router view: four viewports, real API, offline materials and available controls verified; no commands issued.");
}
main().catch(error=>{console.error(error);process.exitCode=1;}).finally(()=>{if(ws)ws.close();chrome.kill();});
