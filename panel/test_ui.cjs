const assert = require('node:assert/strict');
const fs = require('node:fs');
const { render } = require('../internal/web/assets/panel.js');

class TextNode {
  constructor(text) { this.textContent = String(text); }
}

class Element {
  constructor(tagName) {
    this.tagName = tagName;
    this.children = [];
    this.attributes = {};
    this.className = '';
    this._text = '';
    this.usedInnerHTML = false;
    this.listeners = {};
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map((child) => child.textContent).join(''); }
  set innerHTML(value) { this.usedInnerHTML = true; this._text = String(value); this.children = []; }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this._text = ''; this.children = children; }
  setAttribute(key, value) { this.attributes[key] = String(value); if (key === 'id') this.id = String(value); }
  getAttribute(key) { return this.attributes[key] || null; }
  contains(target) { return this === target || this.children.some((child) => child.contains && child.contains(target)); }
  focus() { document.activeElement = this; }
  addEventListener(type, callback) { this.listeners[type] = callback; }
  dispatch(type, target) { if (this.listeners[type]) this.listeners[type]({ target }); }
  querySelectorAll(selector) {
    const nodes = this.walk().slice(1);
    if (selector === '.box-item') return nodes.filter((node) => node.className.split(/\s+/).includes('box-item'));
    if (selector === 'details[data-ui-key]') return nodes.filter((node) => node.tagName === 'details' && node.attributes['data-ui-key']);
    if (selector === '[data-ui-key]') return nodes.filter((node) => node.attributes['data-ui-key']);
    return [];
  }
  walk() { return [this, ...this.children.flatMap((child) => child.walk ? child.walk() : [])]; }
}

const document = {
  activeElement: null,
  createElement: (tag) => new Element(tag),
  createTextNode: (text) => new TextNode(text),
};

const root = new Element('main');
render(root, {
  snapshot: {
    version: 'test', commit: 'abcdef0123456789', built: 'now', dirty: false,
    mode: 'apply', config_path: '/tmp/config', config_exists: true,
    state_dir: '/tmp/state', state_dir_note: 'каталог доступен',
    queue_num: 2000, panel_listen: '127.0.0.1:8090',
    telegram_enabled: true, telegram_configured: true, telegram_status: 'connected',
    unknown_keys: ['FUTURE_OPTION'], stages: [], absent: [], taken: 'now',
  },
  knowledge: {
    linked: true, link_note: '', catalog_at: '/tmp/state/catalog.json',
    boxes: [{
      id: 'box-a', signals: [], plans: [{ proto: 'tls13', enabled: true, text: '--split' }],
      bindings: [{
        target: '<img src=x onerror=alert(1)>', enabled: true, level: 2,
        level_name: 'сервер ответил', successes: 1,
      }],
    },
      { id: 'box-b', signals: [], plans: [], bindings: [{ target: 'youtube.com', enabled: true }] }],
    searches: [], targets: 1, confirms: 1, probes_used: 1, client_unfit: 0,
  },
}, document);

assert.match(root.textContent, /FUTURE_OPTION/,
  'panel must disclose configuration keys this build does not understand');
assert.match(root.textContent, /каталог доступен/,
  'panel must report the state-directory condition rather than hiding it');
assert.match(root.textContent, /<img src=x onerror=alert\(1\)>/,
  'network-provided names must be shown literally');
assert.equal(root.walk().some((node) => node.tagName === 'img' &&
  node.attributes.src === 'x'), false,
  'network-provided target text must never become an image element');
assert.equal(root.walk().some((node) => node.usedInnerHTML), false,
  'renderer must not parse catalog data as HTML');
assert.match(root.textContent, /Подбор сейчас/,
  'the overview must call out current work in plain language');
assert.match(root.textContent, /D2K на связи/,
  'the first screen must describe the connection in everyday language');
assert.match(root.textContent, /Если что-то заблокировано, D2K подберёт обход/,
  'the first screen must explain what D2K does without protocol jargon');
assert.equal(root.walk().some((node) => node.tagName === 'details' &&
  node.className === 'diagnostics' && !node.open), true,
  'technical diagnostics must be available but collapsed by default');
assert.match(root.textContent, /Изученные коробки/,
  'new UI must include the learned-box directory');
assert.match(root.textContent, /Как устроена работа D2K/,
  'technical runtime details must remain available in diagnostics');
assert.match(root.textContent, /Управление D2K/,
  'panel must expose real service controls rather than remain read-only');
assert.deepEqual(root.walk().filter((node) => node.attributes['data-control'])
  .map((node) => node.attributes['data-control']), ['telegram-disable', 'start', 'stop', 'restart', 'reapply'],
  'the UI must expose the Telegram toggle and the existing fixed engine actions');
assert.match(root.textContent, /Telegram-туннель/);
assert.match(root.textContent, /Работает/);
assert.match(root.textContent, /1 результат/,
  'the overview must expose saved knowledge counts from the real API');
assert.match(root.textContent, /сервер ответил/,
  'box detail must preserve the exact evidence level instead of claiming success');

const filter = root.walk().find((node) => node.id === 'box-filter');
filter.value = 'box-a';
filter.focus();
root.dispatch('input', filter);
const diagnostics = root.walk().find((node) => node.tagName === 'details' && node.className === 'diagnostics');
diagnostics.open = true;
const planDetail = root.walk().find((node) => node.tagName === 'details' && node.attributes['data-ui-key'] === 'plan:box-a:0');
planDetail.open = true;
render(root, {
  snapshot: { mode: 'observe', catalog_available: true, controls_enabled: true,
    stages: [], absent: [], taken: 'now' },
  knowledge: {
    linked: true, boxes: [
      { id: 'box-a', signals: [], plans: [{ proto: 'tls13', enabled: true, text: '--split' }], bindings: [] },
      { id: 'box-b', signals: [], plans: [], bindings: [{ target: 'youtube.com', enabled: true }] },
    ], searches: [], targets: 1, confirms: 1,
  },
}, document);
const engineControls = root.walk().filter((node) => {
  const action = node.attributes && node.attributes['data-control'];
  return action && action !== 'telegram-enable' && action !== 'telegram-disable';
});
assert.equal(engineControls.every((button) => button.disabled === false), true,
  'same-origin panel controls must render enabled when the API says control is available');
assert.match(root.textContent, /только с того же адреса панели/,
  'the panel must explain that controls are restricted to its same origin');
assert.equal(root.walk().find((node) => node.id === 'box-filter').value, 'box-a',
  'box filter text must survive periodic refreshes');
assert.equal(root.walk().find((node) => node.tagName === 'details' && node.attributes['data-ui-key'] === 'plan:box-a:0').open, true,
  'expanded strategy details must survive periodic refreshes');
assert.equal(root.walk().find((node) => node.tagName === 'details' && node.className === 'diagnostics').open, true,
  'expanded diagnostics must stay open during periodic refreshes');
assert.equal(root.walk().find((node) => node.className === 'box-item' && node.textContent.includes('youtube.com')).hidden, true,
  'the active box filter must be reapplied after refresh');
assert.equal(document.activeElement.id, 'box-filter',
  'polling must preserve search-field focus');

const searching = new Element('main');
render(searching, {
  snapshot: { mode: 'apply', stages: [], absent: [], taken: 'now' },
  knowledge: {
    linked: true, searches: [{ target: 'video.example', phase: 'проверяем готовое',
      since: '2026-09-28T10:00:00Z', attempts: 2, probes: 1,
      candidate: 'quic5 copies=6', source: 'готовый план узнанной коробки' }],
    boxes: [], targets: 0, confirms: 0, probes_used: 1, client_unfit: 0,
  },
}, document);
assert.match(searching.textContent, /video\.example/,
  'the live-search view must identify its actual target');
assert.match(searching.textContent, /готовый план узнанной коробки/,
  'the live-search view must show whether it is reusing an existing box');
assert.match(searching.textContent, /quic5 copies=6/,
  'the live-search view must show the current candidate without inventing a result');

const disconnected = new Element('main');
render(disconnected, {
  snapshot: { mode: 'apply', live_fresh: false, engine_running: false, controller_running: false, stages: [], absent: [], taken: 'now' },
  knowledge: { linked: true, link_note: '', searches: [], boxes: [],
    targets: 0, confirms: 0, probes_used: 0, client_unfit: 0 },
}, document);
assert.match(disconnected.textContent, /D2K пока не подключён/,
  'a stopped engine must not be presented as observing live traffic');
assert.match(disconnected.textContent, /D2K остановлен/,
  'the panel must explain why stale live knowledge is disconnected');
assert.doesNotMatch(disconnected.textContent, /Контроллер подключён|D2K наблюдает поток|D2K подключён/,
  'cached linked=true data must not override the stopped runtime');
assert.match(disconnected.textContent, /нет свежих данных/,
  'a disconnected engine must mark session counters unavailable');
assert.doesNotMatch(disconnected.textContent, /0 поисков|0 подтверждений/,
  'missing live readings must not be presented as zero');

const unavailableCatalog = new Element('main');
render(unavailableCatalog, {
  snapshot: { mode: 'observe', catalog_available: false, controls_enabled: false,
    stages: [], absent: [], taken: 'now' },
  knowledge: { linked: false, link_note: 'live json отсутствует', searches: [], boxes: [],
    targets: 0, confirms: 0, probes_used: 0, client_unfit: 0 },
}, document);
assert.match(unavailableCatalog.textContent, /Сохранённые результаты сейчас недоступны/,
  'an unavailable catalog must be distinguished from a genuinely empty one');
assert.doesNotMatch(unavailableCatalog.textContent, /0 целей|0 коробок|0 коробки/,
  'unavailable catalog counts must not be represented as zeros');
const dual = new Element('main');
const dualState = {
  snapshot: { mode: 'apply', stages: [], absent: [], taken: 'now' },
  knowledge: { linked: true, searches: [
    { target: 'dual.example', family: 4, transport: 6 },
    { target: 'dual.example', family: 6, transport: 6 },
    { target: 'dual.example', family: 6, transport: 17 },
  ], boxes: [{ id: 'dual-box', bindings: [
    { target: 'dual.example', kind: 'name', family: 4, transport: 6, enabled: true },
    { target: 'dual.example', kind: 'name', family: 6, transport: 6, enabled: true },
  ] }], targets: 2, confirms: 0, probes_used: 0 },
};
render(dual, dualState, document);
assert.match(dual.textContent, /IPv4/, 'panel identifies IPv4 context');
assert.match(dual.textContent, /IPv6/, 'panel identifies IPv6 context');
const dualDetails = dual.walk().filter(x => x.className === 'search-detail');
assert.equal(new Set(dualDetails.map(x => x.getAttribute('data-ui-key'))).size, 3,
  'same domain across families/transports has independent disclosure state');
const dualCopies = dual.walk().filter(x => x.className === 'copy-button');
assert.equal(new Set(dualCopies.map(x => x.getAttribute('data-ui-key'))).size, 2,
  'copy focus distinguishes IPv4 and IPv6 bindings');
dualDetails[0].open = true;
render(dual, dualState, document);
const restored = dual.walk().filter(x => x.className === 'search-detail');
assert.equal(restored[0].open, true);
assert.equal(restored[1].open, false, 'opening IPv4 details must not open IPv6 details after refresh');
const families = new Element('main');
const familyState = {
  snapshot: { engine_running: true, controller_running: true, live_fresh: true, controls_enabled: true },
  knowledge: { linked: true, groups: [{ suffix: 'googlevideo.com', family: 4, transport: 6, shape: 1,
    plan_id: 'plan-own', evidence_count: 3, active: true, evidence: ['rr-a.googlevideo.com'],
    exceptions: [{ name: '<img src=x onerror=alert(1)>', reason: 'Напрямую работает' }] }],
    boxes: [{ id: 'one', bindings: [
      { target: 'rr-a.googlevideo.com', transport: 6, family: 4, shape: 1, plan_id: 'plan-own', enabled: true },
      { target: 'meet.google.com', transport: 6, family: 4, shape: 1, plan_id: 'plan-other', enabled: true },
    ] }], searches: [], targets: 2 },
};
render(families, familyState, document);
assert.match(families.textContent, /Сохранённые семейства/);
assert.match(families.textContent, /Новые адреса используют найденное решение/);
assert.match(families.textContent, /TLS 1\.3/);
assert.equal(families.walk().filter(x => x.className === 'family-item').length, 1);
assert.equal(families.walk().filter(x => x.className === 'target-name').length, 1,
  'learned evidence is disclosed with its family, not duplicated as individual CDN rows');
assert.match(families.textContent, /meet.google.com/, 'independent exact service stays visible');
assert.match(families.textContent, /<img src=x onerror=alert\(1\)>/);
assert.equal(families.walk().some(x => x.usedInnerHTML), false, 'group data is never HTML');
assert.equal(families.walk().filter(x => x.attributes['data-control']).length, 5,
  'adding families preserves existing service actions');
const coveredState = JSON.parse(JSON.stringify(familyState));
const coveredGroup = coveredState.knowledge.groups[0];
coveredGroup.exceptions.push({ name: 'excluded.googlevideo.com', reason: 'failed' });
const baseBinding = { kind: 'name', transport: 6, family: 4, shape: 1, enabled: true };
coveredState.knowledge.boxes[0].bindings = [
  { ...baseBinding, target: 'rr1---sn-n8v7kne7.googlevideo.com' },
  { ...baseBinding, target: 'nested.new.googlevideo.com' },
  { ...baseBinding, target: 'excluded.googlevideo.com' },
  { ...baseBinding, target: 'notgooglevideo.com' },
  { ...baseBinding, target: 'googlevideo.com.evil.example' },
  { ...baseBinding, target: 'v6.googlevideo.com', family: 6 },
  { ...baseBinding, target: 'legacy.googlevideo.com', shape: 2 },
  { ...baseBinding, target: 'quic.googlevideo.com', transport: 17, shape: 3 },
];
render(families, coveredState, document);
assert.deepEqual(families.walk().filter(x => x.className === 'target-name').map(x => x.textContent),
  ['excluded.googlevideo.com', 'notgooglevideo.com', 'googlevideo.com.evil.example',
    'v6.googlevideo.com', 'legacy.googlevideo.com', 'quic.googlevideo.com'],
  'covered non-evidence hosts disappear, exceptions and other protocol contexts remain');
coveredGroup.active = false;
render(families, coveredState, document);
assert.equal(families.walk().filter(x => x.className === 'target-name').length, 8,
  'inactive family must not hide individual hosts');
render(families, { snapshot: {}, knowledge: { groups: { invalid: true }, boxes: [] } }, document);
assert.equal(families.walk().filter(x => x.className === 'family-item').length, 0,
  'invalid/old group snapshots render safely');
console.log('C panel DOM renderer: all checks passed');

const busy = new Element('main');
render(busy, {
  snapshot: { controls_enabled: true, telegram_configured: true, control_state: 'running' },
  knowledge: {},
}, document);
assert.ok(busy.walk().filter(x => x.attributes['data-control']).every(x => x.disabled),
  'a running server-side command must remain locked after the POST has returned');
assert.match(busy.textContent, /Выполняется команда/);
render(busy, { snapshot: { controls_enabled: true, control_state: 'timeout' }, knowledge: {} }, document);
assert.match(busy.textContent, /не завершилась вовремя/);
assert.equal(busy.walk().find(x => x.attributes['data-control'] === 'stop').disabled, false,
  'a timed-out command must release the controls');
