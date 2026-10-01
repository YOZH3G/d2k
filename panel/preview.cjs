"use strict";
// Local presentation/test server. No router access and no real service commands.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const assets = path.resolve(__dirname, '../internal/web/assets');
const payload = {
  snapshot: { preview:true, mode:'apply', engine_running:true, controller_running:true, live_fresh:true,
    catalog_available:true, controls_enabled:true, control_state:'idle',
    telegram_enabled:true, telegram_configured:true, telegram_status:'connected',
    version:'local-design-preview', stages:[], absent:[], taken:'2026-10-01T12:30:00Z' },
  knowledge: {linked:true, targets:3, confirms:8, probes_used:12,
    searches:[
      {target:'rutracker.org',shape:2,proto:'tls12',family:4,transport:6,phase:'распознаём поведение',since:'2026-10-01T12:29:00Z',attempts:0,probes:1},
      {target:'meduza.io',shape:1,proto:'tls13',family:4,transport:6,phase:'проверяем выведенный план',since:'2026-10-01T12:29:00Z',attempts:2,probes:4},
      {target:'googlevideo.com',shape:3,proto:'quic',family:4,transport:17,phase:'подтверждено, смотрим живой трафик',since:'2026-10-01T12:29:00Z',attempts:1,probes:3}
    ],
    groups:[
      {suffix:'googlevideo.com',active:true,shape:3,family:4,transport:17,evidence_count:3,plan_id:'demo-quic',evidence:['demo.googlevideo.com']},
      {suffix:'cdninstagram.com',active:true,shape:1,family:4,transport:6,evidence_count:2,plan_id:'demo-tls13'},
      {suffix:'youtube.com',active:true,shape:2,family:6,transport:6,evidence_count:3,plan_id:'demo-tls12'}
    ], boxes:[]
  }
};
const actions = [];
const server=http.createServer((req,res)=>{
  const url=new URL(req.url,'http://localhost');
  if(url.pathname==='/api/status'){res.setHeader('Content-Type','application/json');return res.end(JSON.stringify(payload));}
  if(url.pathname.startsWith('/api/control/') && req.method==='POST'){
    const action=url.pathname.slice('/api/control/'.length);actions.push(action);
    if(action==='stop')payload.snapshot.engine_running=false;
    if(action==='start'||action==='restart')payload.snapshot.engine_running=true;
    if(action==='telegram-disable'){payload.snapshot.telegram_enabled=false;payload.snapshot.telegram_status='stopped';}
    if(action==='telegram-enable'){payload.snapshot.telegram_enabled=true;payload.snapshot.telegram_status='connected';}
    res.setHeader('Content-Type','application/json');return res.end(JSON.stringify({ok:true,message:'Команда выполнена на демонстрационном стенде.'}));
  }
  if(url.pathname==='/__test/actions'){res.setHeader('Content-Type','application/json');return res.end(JSON.stringify(actions));}
  if(url.pathname==='/__test/phase' && req.method==='POST'){
    const target=payload.knowledge.searches.find(x=>x.target===url.searchParams.get('target'));
    if(!target){res.writeHead(404);return res.end();}
    target.phase=url.searchParams.get('phase');
    res.setHeader('Content-Type','application/json');return res.end('{"ok":true}');
  }
  let relative=url.pathname==='/'?'index.html':url.pathname.replace(/^\/assets\//,'');
  if(relative==='oswald.ttf')relative='fonts/'+relative;
  const file=path.resolve(assets,relative);
  if(!file.startsWith(assets+path.sep)){res.writeHead(403);return res.end();}
  fs.readFile(file,(error,data)=>{
    if(error){res.writeHead(404);return res.end();}
    const types={'.html':'text/html; charset=utf-8','.css':'text/css','.js':'text/javascript','.ttf':'font/ttf','.webp':'image/webp'};
    res.setHeader('Content-Type',types[path.extname(file)]||'application/octet-stream');
    if(relative==='index.html')data=data.toString().replace('Автоматический подбор обходов','Демонстрационные данные — локальный стенд');
    res.end(data);
  });
});
server.listen(Number(process.env.D2K_PREVIEW_PORT)||55941,'127.0.0.1',()=>console.log('Preview (simulated API only): http://127.0.0.1:55941'));
