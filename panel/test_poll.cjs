"use strict";
// Опрос: один запрос за раз, конечный срок, скрытая вкладка не опрашивает.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

async function main() {
  let visibility, calls = 0, aborted = 0;
  const intervals = [], timers = new Map(); let next = 0;
  const stub = () => ({
    get ownerDocument() { return document; },
    addEventListener() {}, setAttribute() {}, removeAttribute() {}, replaceChildren() {}, appendChild() {},
    querySelector: () => stub(), querySelectorAll: () => [], contains: () => false, children: [], style: { setProperty() {} },
  });
  const document = {
    hidden: false, readyState: 'complete', body: stub(),
    getElementById: () => stub(), createElement: () => stub(), createTextNode: () => stub(),
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener(name, fn) { if (name === 'visibilitychange') visibility = fn; },
  };
  const window = {
    document, AbortController,
    setTimeout(fn, ms) { timers.set(++next, { fn, ms }); return next; },
    clearTimeout(id) { timers.delete(id); },
    setInterval(fn, ms) { intervals.push({ fn, ms }); },
    fetch(url, options) {
      calls++;
      return new Promise((resolve, reject) => {
        options.signal.addEventListener('abort', () => { aborted++; reject(new Error('aborted')); });
      });
    },
  };
  vm.runInNewContext(fs.readFileSync('../internal/web/assets/panel.js', 'utf8'), { window, AbortController, Date, JSON, Math, Object, String, Number, Array, Error, Promise });
  assert.equal(calls, 1, 'the panel polls immediately on load');
  const poll = intervals.find(i => i.ms === 2000);
  assert.ok(poll, 'the panel polls on an interval');
  for (let i = 0; i < 12; i++) poll.fn();
  assert.equal(calls, 1, 'a pending status request must prevent another request');
  const deadline = [...timers.values()].find(t => t.ms === 5000);
  assert.ok(deadline, 'a hung status request needs a finite deadline');
  deadline.fn();
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(aborted, 1, 'deadline must abort the request');
  document.hidden = true;
  poll.fn();
  assert.equal(calls, 1, 'a hidden page must not poll');
  document.hidden = false;
  visibility();
  assert.equal(calls, 2, 'returning to the panel resumes polling at once');
  console.log('panel polling: overlap, timeout and visibility passed');
}
main().catch(e => { console.error(e); process.exitCode = 1; });
