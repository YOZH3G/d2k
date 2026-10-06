"use strict";
const assert = require('node:assert/strict');
const ui = require('../internal/web/assets/panel.js');
const flush = async () => { await new Promise(r => setImmediate(r)); await new Promise(r => setImmediate(r)); };
async function main() {
  const originalNow = Date.now; let now = 100000, calls = [], reply;
  Date.now = () => now;
  const win = { setTimeout: () => 1, clearTimeout() {}, fetch: async url => {
    calls.push(url); return { ok: true, json: async () => structuredClone(reply) };
  }};
  const app = new ui.App({}, win);
  app.render = function () { this.m = ui.model(this.status, this.received, now); };
  app.renderNotice = () => {};
  const full = () => ({ catalog_revision:'0123456789abcdef', catalog_unchanged:false,
    snapshot:{engine_running:true,controller_running:true,live_fresh:true,mode:'apply',control_state:'idle'},
    knowledge:{linked:true,boxes:[{id:'box'}],groups:[{suffix:'example.test'}],searches:[],probes_used:1} });
  try {
    reply = full(); app.poll(); await flush();
    assert.equal(calls[0], '/api/status');
    now += 2000; app.poll(true); await flush();
    assert.equal(calls.length, 1, 'idle panel should skip the two-second tick');
    now += 4000;
    reply = { ...full(), catalog_unchanged:true, knowledge:{linked:true,boxes:null,groups:null,searches:[],probes_used:2} };
    app.poll(true); await flush();
    assert.match(calls[1], /catalog_revision=0123456789abcdef/);
    assert.equal(app.status.knowledge.boxes[0].id, 'box');
    assert.equal(app.status.knowledge.groups[0].suffix, 'example.test');
    assert.equal(app.status.knowledge.probes_used, 2, 'fresh counters must survive cache merge');
    now += 2000; app.pending = 'restart'; app.poll(true); await flush();
    assert.equal(calls.length, 3, 'controls retain fast polling'); app.pending = null;
    reply = { ...full(), catalog_revision:'fedcba9876543210', catalog_unchanged:false,
      knowledge:{linked:true,boxes:[],groups:[],searches:[{target:'x',phase:'распознаём поведение'}]} };
    app.poll(); await flush();
    assert.equal(app.status.knowledge.boxes.length, 0, 'changed catalog can remove entries');
    now += 2000; app.poll(true); await flush();
    assert.equal(calls.length, 5, 'active searches retain two-second polling');
    reply = { ...full(), catalog_revision:'mismatched', catalog_unchanged:true };
    app.poll(); await flush(); assert.equal(app.failed, true, 'unmatched delta is rejected');
    reply = full(); app.poll(); await flush();
    assert.equal(calls.at(-1), '/api/status', 'bad delta forces a complete refresh');
    delete reply.catalog_revision; delete reply.catalog_unchanged;
    app.poll(); await flush(); assert.equal(app.failed, false, 'older servers remain supported');
    app.poll(); await flush(); assert.equal(calls.at(-1), '/api/status');
    console.log('status client: idle/active intervals, catalog merge, removals and fallback PASS');
  } finally { Date.now = originalNow; }
}
main().catch(err => { console.error(err); process.exitCode = 1; });
