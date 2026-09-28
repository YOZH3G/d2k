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
assert.equal(root.walk().some((node) => node.tagName === 'img' &&
  node.className === 'mascot' && node.attributes.src === '/assets/mascot-d2k.png' && node.attributes.alt), true,
  'the D2K mascot must be visibly included in the first screen');
assert.match(fs.readFileSync(require.resolve('../internal/web/assets/index.html'), 'utf8'),
  /<img[^>]+src="\/assets\/logo-d2k\.png"[^>]*>/,
  'the D2K header must use the generated brand mark beside the live text wordmark');
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
console.log('C panel DOM renderer: all checks passed');
