"use strict";
// Real updater JSON contract + panel DOM/action lifecycle; no router access.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { App } = require('../internal/web/assets/panel.js');
const ids = ['updates-body','nav-updates','update-current','update-state','update-reason','update-checked','update-release','update-version','update-notes','update-notes-text','update-progress','update-progress-text','update-check','update-install','update-warning','update-auto','update-schedule','update-result','update-action'];
function fixture() {
  const nodes = Object.fromEntries(ids.map(id => [id, {textContent:'',hidden:false,disabled:false,checked:false,style:{},attrs:{},listeners:{},setAttribute(k,v){this.attrs[k]=v;},removeAttribute(k){delete this.attrs[k];},addEventListener(k,v){this.listeners[k]=v;}}]));
  const requests=[];
  const document={hidden:false,getElementById:id=>nodes[id]};
  const window={crypto:require('node:crypto').webcrypto,setTimeout,clearTimeout,fetch:async (url,opts={})=>{requests.push({url,...opts,body:opts.body&&JSON.parse(opts.body)});return {ok:true,status:202,json:async()=>status()};}};
  return {app:new App(document,window),nodes,requests,window,document};
}
function status(over={}) { return {state:'available',operation_id:'check-one',phase:2,busy:false,received_bytes:0,total_bytes:0,current:{release_id:'installed'},previous:null,available:{release_id:'shown',manifest_sha256:'a'.repeat(64),version:'1.2.3',notes:'<img src=x onerror=alert(1)>',compatible:true},check:{cached:true,fresh:true,result:0,last_success_utc:1791150000},last_result:0,last_error:'',settings:{enabled:true,window_start:180,window_end:300,timezone:'Europe/Volgograd',selected_date:20261006,selected_minute:203},...over}; }
async function main(){
 const {app,nodes,requests,window,document}=fixture();
 assert.equal(typeof app.renderUpdates,'function','actual panel needs update section renderer');
 app.initUpdates();app.renderUpdates(status());
 app.status={engine:'untouched'};
 assert.equal(nodes['update-notes-text'].textContent,'<img src=x onerror=alert(1)>');
 await app.checkUpdates(false);await app.checkUpdates(true);
 assert.deepEqual(requests.slice(0,2).map(x=>[x.url,x.body.force]),[['/api/update/check',false],['/api/update/check',true]]);
 assert.notEqual(requests[0].body.operation_id,requests[1].body.operation_id);
 app.renderUpdates(status());await nodes['update-install'].listeners.click();
 const install=requests.find(r=>r.url.endsWith('/install'));
 assert.equal(install.body.release_id,'shown');assert.equal(install.body.manifest_sha256,'a'.repeat(64));assert.ok(install.body.operation_id);
 await app.pollUpdates();assert.deepEqual(app.status,{engine:'untouched'});assert.equal(requests.filter(r=>r.url.endsWith('/install')).length,1,'reconnection must only read status');
 app.renderUpdates(status({available:{...status().available,compatible:false}}));assert.equal(nodes['update-install'].disabled,true);assert.match(nodes['update-warning'].textContent,/ABI/);
 for (const check of [{fresh:false,result:0},{fresh:true,result:8}]){app.renderUpdates(status({state:'current',available:null,check}));assert.doesNotMatch(nodes['update-state'].textContent,/последняя доступная/);}
 app.renderUpdates(status({state:'error',phase:3,last_result:8,last_error:'network transfer failed'}));assert.match(nodes['update-state'].textContent,/установить/);assert.match(nodes['update-reason'].textContent,/по сети/);
 app.renderUpdates(status({state:'error',last_result:9,last_error:'Нет доверенного времени'}));assert.match(nodes['update-reason'].textContent,/времени/);
 app.renderUpdates(status({quarantine:{active:true,applies_to_available:true,manifest_sha256:'a'.repeat(64),reason:'health failed'}}));assert.match(nodes['update-install'].textContent,/Повторить/);assert.match(nodes['update-reason'].textContent,/health failed/);
 app.renderUpdates(status({quarantine:{active:true,applies_to_available:false,manifest_sha256:'b'.repeat(64),reason:'other release'}}));assert.equal(nodes['update-install'].textContent,'Установить сейчас');
 app.renderUpdates(status({last_installation:{operation_id:'old-install',release_id:'old-release',result:10,phase:12,completed_utc:1791150100,reason:'health failed'}}));assert.match(nodes['update-result'].textContent,/old-release/);assert.match(nodes['update-result'].textContent,/health failed/);assert.doesNotMatch(nodes['update-result'].textContent,/время завершения не сохранено/);
 app.renderUpdates(status({phase:12,last_result:10,state:'error'}));assert.match(nodes['update-state'].textContent,/Восстановлена/);assert.match(nodes['update-install'].textContent,/Повторить/);
 for (let phase=3;phase<=9;phase++){app.renderUpdates(status({phase,busy:true}));assert.equal(nodes['update-install'].disabled,true);assert.equal(nodes['update-progress'].hidden,true,'no progress without real total bytes');}
 app.renderUpdates(status({phase:3,busy:true,received_bytes:25,total_bytes:100}));assert.equal(nodes['update-progress'].value,25);
 nodes['update-auto'].checked=false;await nodes['update-auto'].listeners.change();assert.equal(requests.at(-1).body.enabled,false);
 document.hidden=true;await app.pollUpdates();assert.equal(requests.at(-1).url,'/api/update/settings');document.hidden=false;
 window.fetch=async()=>{throw Error('connection lost');};app.renderUpdates(status({state:'current',available:null}));await app.pollUpdates();assert.doesNotMatch(nodes['update-state'].textContent,/последняя доступная/);
 assert.match(fs.readFileSync(require('node:path').join(__dirname,'../internal/web/assets/index.html'),'utf8'),/id="updates"[\s\S]*id="diagnostics"/);
 console.log('panel updates: selections, freshness, phases, notes, actions and reconnect passed');
}
main().catch(e=>{console.error(e);process.exitCode=1;});
