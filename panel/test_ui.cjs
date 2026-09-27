const assert = require('node:assert/strict');
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
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map((child) => child.textContent).join(''); }
  set innerHTML(value) { this.usedInnerHTML = true; this._text = String(value); this.children = []; }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this._text = ''; this.children = children; }
  setAttribute(key, value) { this.attributes[key] = String(value); }
  walk() { return [this, ...this.children.flatMap((child) => child.walk ? child.walk() : [])]; }
}

const document = {
  createElement: (tag) => new Element(tag),
  createTextNode: (text) => new TextNode(text),
};

const root = new Element('main');
render(root, {
  snapshot: {
    version: 'test', commit: 'abcdef0123456789', built: 'now', dirty: false,
    mode: 'observe', config_path: '/tmp/config', config_exists: true,
    state_dir: '/tmp/state', state_dir_note: 'каталог доступен',
    queue_num: 2000, panel_listen: '127.0.0.1:8090',
    unknown_keys: ['FUTURE_OPTION'], stages: [], absent: [], taken: 'now',
  },
  knowledge: {
    linked: true, link_note: '', catalog_at: '/tmp/state/catalog.json',
    boxes: [{
      id: 'box-a', signals: [], plans: [],
      bindings: [{
        target: '<img src=x onerror=alert(1)>', enabled: true, level: 2,
        level_name: 'сервер ответил', successes: 1,
      }],
    }],
    searches: [], targets: 1, confirms: 1, probes_used: 1, client_unfit: 0,
  },
}, document);

assert.match(root.textContent, /FUTURE_OPTION/,
  'panel must disclose configuration keys this build does not understand');
assert.match(root.textContent, /каталог доступен/,
  'panel must report the state-directory condition rather than hiding it');
assert.match(root.textContent, /<img src=x onerror=alert\(1\)>/,
  'network-provided names must be shown literally');
assert.equal(root.walk().some((node) => node.tagName === 'img'), false,
  'network-provided target text must never become markup');
assert.equal(root.walk().some((node) => node.usedInnerHTML), false,
  'renderer must not parse catalog data as HTML');
console.log('C panel DOM renderer: all checks passed');
