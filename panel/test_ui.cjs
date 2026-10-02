"use strict";
// Смысловые правила панели без браузера: что можно утверждать по снимку.
const assert = require('node:assert/strict');
const ui = require('../internal/web/assets/panel.js');

const snap = (over) => ({ engine_running: true, controller_running: true, live_fresh: true, mode: 'apply', ...over });

// Нет связи с датапатом — это отсутствие измерения, а не «ноль поисков».
{
  const m = ui.model({ snapshot: snap(), knowledge: { linked: false, link_note: 'движок не отдаёт состояние', searches: [{ target: 'x' }] } });
  assert.equal(m.linked, false);
  assert.deepEqual(m.searches, [], 'unlinked snapshot must not show searches as measured');
  assert.match(m.headline.join(''), /Нет связи/);
  assert.match(m.lede, /не «ноль поисков»/);
  assert.match(m.lede, /движок не отдаёт состояние/);
}
// Остановленный движок не выдаётся за работающий, даже если в снимке остались поиски.
{
  const m = ui.model({ snapshot: snap({ engine_running: false }), knowledge: { linked: false, searches: [] } });
  assert.match(m.headline.join(''), /остановлен/);
  assert.equal(m.lamp, 'bad');
}
// MODE=off объясняется словами конфигурации.
{
  const m = ui.model({ snapshot: snap({ engine_running: false, mode: 'off' }), knowledge: {} });
  assert.match(m.lede, /MODE=off/);
}
// Работающий трафик без блокировок — «поисков нет», без утверждения, что интернет работает.
{
  const m = ui.model({ snapshot: snap(), knowledge: { linked: true, searches: [] } });
  assert.equal(m.hunting, 0);
  assert.doesNotMatch(m.lede + m.headline.join(''), /интернет работает|всё работает|сайты доступны/i);
}
// Подтверждённая задача, которая лишь наблюдает трафик, не считается идущим поиском.
{
  const m = ui.model({ snapshot: snap(), knowledge: { linked: true, searches: [
    { target: 'a', phase: 'распознаём поведение' },
    { target: 'b', phase: 'подтверждено, смотрим живой трафик' },
  ] } });
  assert.equal(m.hunting, 1);
  assert.match(m.headline.join(''), /1 поиск$/);
}
// Устаревший снимок отмечается, а не выдаётся за текущий.
{
  const m = ui.model({ snapshot: snap({ live_fresh: false }), knowledge: { linked: true } });
  assert.equal(m.lamp, 'warn');
  assert.match(m.state, /устарел/);
}
// Мусор вместо массивов не роняет модель.
{
  const m = ui.model({ snapshot: {}, knowledge: { linked: true, groups: { invalid: true }, boxes: 'x', searches: null } });
  assert.deepEqual(m.groups, []);
  assert.deepEqual(m.boxes, []);
  assert.deepEqual(ui.model(null).searches, []);
}

// uptime_seconds — время работы процесса панели, не движка: рядом с состоянием движка его нет.
{
  const m = ui.model({ snapshot: snap({ uptime_seconds: 10 }), knowledge: { linked: true } });
  assert.doesNotMatch(m.stateDetail, /10 с/, 'panel uptime must not be shown as engine uptime');
  assert.match(m.stateDetail, /режим: применение/);
  assert.equal(m.panelUptime, 10);
}
// Поиски в очереди замера отделены от идущих замеров.
{
  const m = ui.model({ snapshot: snap(), knowledge: { linked: true, searches: [
    { target: 'a', phase: 'распознаём поведение' },
    { target: 'b', phase: 'ожидает безопасного слота замера' },
    { target: 'c', phase: 'ожидает безопасного слота замера' },
  ] } });
  assert.equal(m.hunting, 3);
  assert.deepEqual(m.running.map(s => s.target), ['a']);
  assert.deepEqual(m.queued.map(s => s.target), ['b', 'c']);
  assert.match(m.lede, /2 ждут/);
}

// Шкала фаз: этапы оригинала распознаются целиком, голос — своей шкалой, неизвестное — без шкалы.
assert.equal(ui.trackFor('распознаём поведение').at, 2);
assert.equal(ui.trackFor('проверяем готовое узнанной коробки').at, 5);
assert.equal(ui.trackFor('проверяем выведенный план').at, 5);
assert.equal(ui.trackFor('подтверждено, смотрим живой трафик').at, 6);
assert.equal(ui.trackFor('приём голоса стоит, ждём разговора').voice, true);
assert.equal(ui.trackFor('новый этап из будущей сборки'), null);

// Протоколы и семейства адресов не сливаются.
assert.equal(ui.shapeLabel(1, 6), 'TLS 1.3');
assert.equal(ui.shapeLabel(2, 6), 'TLS 1.2');
assert.equal(ui.shapeLabel(3, 17), 'QUIC');
assert.equal(ui.shapeLabel(6, 6), 'TLS 1.3 + ECH');
assert.equal(ui.shapeLabel(0, 17), 'UDP', 'unknown shape must not be guessed as QUIC');
assert.equal(ui.shapeLabel(undefined, undefined), 'протокол не указан');

// Покрытие семейством: только активное семейство, тот же протокол/IP/путь, не исключение, только имена.
{
  const g = { suffix: 'example.com', active: true, transport: 6, family: 4, shape: 1, probe_path: '/', ech_origin: '',
    exceptions: [{ name: 'skip.example.com' }] };
  const b = (over) => ({ target: 'a.example.com', kind: 'name', transport: 6, family: 4, shape: 1, ...over });
  assert.equal(ui.coveredBy(b(), [g]), g);
  assert.equal(ui.coveredBy(b({ target: 'example.com.' }), [g]), g, 'trailing dot and apex match');
  assert.equal(ui.coveredBy(b({ target: 'notexample.com' }), [g]), null, 'suffix must match on a label boundary');
  assert.equal(ui.coveredBy(b({ target: 'skip.example.com' }), [g]), null, 'exceptions stay visible');
  assert.equal(ui.coveredBy(b({ family: 6 }), [g]), null, 'IPv6 is a different context');
  assert.equal(ui.coveredBy(b({ shape: 2 }), [g]), null, 'TLS 1.2 is a different context');
  assert.equal(ui.coveredBy(b({ transport: 17, shape: 3 }), [g]), null, 'QUIC is a different context');
  assert.equal(ui.coveredBy(b({ kind: 'addr', target: '1.2.3.4' }), [g]), null, 'addresses are never folded into names');
  assert.equal(ui.coveredBy(b(), [{ ...g, active: false }]), null, 'inactive family must not hide hosts');
  assert.equal(ui.coveredBy(b({ probe_path: '/x' }), [g]), null);
}

// Выжимка плана не показывает полезную нагрузку.
{
  const gist = ui.planGist('d2k-plan 1 1\nid 00\nproto tcp tls\npayload 1 0f0f0f0f\nsplit payload_start +1\norder reverse\n');
  assert.equal(gist, 'split payload_start +1 · order reverse');
}

assert.equal(ui.plural(1, 'поиск', 'поиска', 'поисков'), 'поиск');
assert.equal(ui.plural(3, 'поиск', 'поиска', 'поисков'), 'поиска');
assert.equal(ui.plural(11, 'поиск', 'поиска', 'поисков'), 'поисков');
assert.equal(ui.plural(22, 'поиск', 'поиска', 'поисков'), 'поиска');
assert.equal(ui.duration(3725000), '1 ч 2 мин');

console.log('panel model: all checks passed');
