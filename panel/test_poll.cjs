const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

async function main() {
  let ready, visibility, tick, calls = 0, aborted = 0;
  const timers = new Map(); let next = 0;
  const app = { replaceChildren() {}, appendChild() {}, setAttribute() {} };
  const element = () => ({ appendChild() {}, setAttribute() {} });
  const window = {
    AbortController,
    document: {
      hidden: false, getElementById: id => id === 'app' ? app : null,
      createElement: element,
      addEventListener(name, fn) {
        if (name === 'DOMContentLoaded') ready = fn;
        if (name === 'visibilitychange') visibility = fn;
      },
    },
    addEventListener() {},
    setTimeout(fn, ms) { timers.set(++next, { fn, ms }); return next; },
    clearTimeout(id) { timers.delete(id); },
    setInterval(fn) { tick = fn; },
    fetch(url, options) {
      calls++;
      return new Promise((resolve, reject) => {
        if (options.signal) options.signal.addEventListener('abort', () => {
          aborted++; reject(new Error('aborted'));
        });
      });
    },
  };
  const context = { window, module: { exports: {} } };
  vm.runInNewContext(fs.readFileSync('../internal/web/assets/panel.js', 'utf8'), context);
  ready();
  for (let i = 0; i < 12; i++) {
    if (tick) tick();
    context.module.exports.refresh();
  }
  assert.equal(calls, 1, 'a pending status request must prevent another request');
  const deadline = [...timers.values()].find(t => t.ms === 10000);
  assert.ok(deadline, 'a hung status request needs a finite deadline');
  deadline.fn();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(aborted, 1, 'deadline must abort the request');
  window.document.hidden = true;
  if (visibility) visibility();
  await context.module.exports.refresh();
  assert.equal(calls, 1, 'a hidden page must not poll');
  window.document.hidden = false;
  visibility();
  assert.equal(calls, 2, 'returning to the panel resumes polling');
  console.log('panel polling: overlap, timeout and visibility passed');
}
main().catch(e => { console.error(e); process.exitCode = 1; });
