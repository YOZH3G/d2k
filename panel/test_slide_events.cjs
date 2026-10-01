"use strict";
const assert = require("node:assert/strict");
const { slideEvents } = require("../internal/web/assets/panel.js");

const initial = [{ key: 'a:tls13', stage: 'measure' }];
assert.deepEqual(slideEvents(null, initial), [], 'Initial status must not impersonate a new measurement');
assert.deepEqual(slideEvents(initial, initial), [], 'An unchanged polling response must not replay motion');
assert.deepEqual(slideEvents(initial, [{ key: 'a:tls13', stage: 'verify' }]),
  [{ key: 'a:tls13', kind: 'advance' }]);
assert.deepEqual(slideEvents(initial, []), [], 'Disappearing work is not proof of success');
assert.deepEqual(slideEvents(initial, [{ key: 'a:tls12', stage: 'measure' }]),
  [{ key: 'a:tls12', kind: 'arrive' }], 'Different TLS contexts cannot inherit animation state');
assert.deepEqual(slideEvents(initial, [{ key: 'a:tls13', stage: 'confirmed' }]),
  [{ key: 'a:tls13', kind: 'confirm' }]);
assert.deepEqual(slideEvents([{ key: 'a:tls13', stage: 'confirmed' }],
  [{ key: 'a:tls13', stage: 'confirmed' }]), [], 'Confirmation must animate only once');
console.log('slide event semantics: OK');
