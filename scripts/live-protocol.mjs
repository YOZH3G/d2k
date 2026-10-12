/* live-protocol.mjs — ЖИВОЙ КРИТЕРИЙ: чем НАСТОЯЩИЙ браузер забрал страницу.
 *
 * Зачем он есть. До 12.10.2026 колонка live в таблицах всех полевых прогонов
 * стояла `unknown` в каждой строке: мы знали, что зонд подтвердил план, и не
 * знали, открылся ли сайт у пользователя и каким протоколом. Заголовок вкладки
 * этого не говорит — он приходит в первых килобайтах, — а curl не годится
 * вовсе: у него не браузерное приветствие, и коробка его не трогает там, где
 * трогает Chrome (замер 12.10: curl отдавал 200 по имени, которое Chrome в ту
 * же минуту не открывал).
 *
 * Что он даёт по каждому имени: статус документа, протокол (h3 / h2 /
 * http/1.1), АДРЕС сервера и заголовок alt-svc документа. Адрес печатается не
 * для красоты: 12.10 я вывел семейство адреса из предпочтений браузера вместо
 * того, чтобы его измерить, и построил на этом неверный полевой вывод
 * (docs/field/2026-10-12d — отзыв). Chrome выбирает адрес сам, и догадка здесь
 * обходится дорого.
 *
 * ALT-SVC — ОПРОВЕРГАТЕЛЬ, а не повод спрашивать. Он берётся из
 * `Network.responseReceived` → `response.headers` (проверено 12.10: по
 * www.cloudflare.com приходит `h3=":443"; ma=86400`, по www.google.com
 * `h3=":443"; ma=2592000,h3-29=...`, по flibusta.is заголовка нет вовсе).
 * Нет h3 — значит браузер по QUIC сюда не пойдёт, и записанный на это имя долг
 * по QUIC беспредметен (scripts/field-table.py --no-h3). Обратное НЕВЕРНО:
 * «h3 объявлен» не повод заводить поиск по QUIC — рабочий прямой трафик не
 * запускает подбор (§0 ТЗ).
 * Факт скоропортящийся и внешний: живёт ma секунд и может появиться позже;
 * приходит ВНУТРИ TLS, то есть его читает браузер или свой зонд, а датапат его
 * не видит; и может называть другой порт (`h3=":8443"`) — тогда QUIC не
 * беспредметен, он просто не на 443.
 *
 * НЕ headless: §«Поле и UI — только браузерами». Профиль временный, чтобы не
 * трогать профиль владельца.
 *
 * Запуск:
 *   "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
 *     --remote-debugging-port=9222 --user-data-dir=<временный> \
 *     --no-first-run --no-default-browser-check about:blank &
 *   node scripts/live-protocol.mjs nnmclub.to rutracker.org ...
 *
 * Полезные варианты того же запуска:
 *   --disable-features=EncryptedClientHello  — без ECH, то есть с настоящим
 *       именем в приветствии (с ECH D2K видит внешнее имя Cloudflare);
 *   --host-resolver-rules="MAP <имя> <литерал>" — принудительный адрес. ВНИМАНИЕ:
 *       это обходит DNS, значит отключает и ECH, и литерал надо сперва
 *       проверить на достижимость (у меня опыт с недостижимым литералом стоил
 *       целого неверного вывода).
 *   --disable-quic — отделить отказ h3 от отказа h2.
 *
 * Каждое имя открывается ДВА раза: alt-svc Chrome узнаёт только из ответа,
 * поэтому h3 выбирается со второго захода. */
const PORT = 9222;
const sites = process.argv.slice(2);

async function targets() {
    /* `localhost`, а не 127.0.0.1: 12.10 Chrome на этом маке открыл порт
       отладки ТОЛЬКО на [::1] (lsof: TCP [::1]:9222 LISTEN, curl на 127.0.0.1
       — отказ), и скрипт падал на fetch ещё до первого имени. Это про
       локальную петлю инструмента и ничего не говорит про поле. */
    const r = await fetch(`http://localhost:${PORT}/json/list`);
    return r.json();
}

function sock(url) {
    return new Promise((res, rej) => {
        const ws = new WebSocket(url);
        ws.onopen = () => res(ws);
        ws.onerror = (e) => rej(new Error('ws: ' + e.message));
    });
}

let id = 0;
function send(ws, method, params) {
    const my = ++id;
    ws.send(JSON.stringify({ id: my, method, params: params || {} }));
    return my;
}

/* Заголовки в CDP приходят как есть от сервера, регистр имени произвольный. */
function header(headers, name) {
    for (const k of Object.keys(headers || {}))
        if (k.toLowerCase() === name) return headers[k];
    return null;
}

async function visit(ws, url, waitMs) {
    const seen = new Map();   /* url -> protocol */
    let docProto = null, docStatus = null, loaded = false, err = null, docIp = null;
    let docAltSvc = null;
    const onMsg = (ev) => {
        const m = JSON.parse(ev.data);
        if (m.method === 'Network.responseReceived') {
            const p = m.params.response.protocol || '?';
            seen.set(m.params.response.url, p);
            if (m.params.type === 'Document' && docProto === null) {
                docProto = p; docStatus = m.params.response.status;
                /* СЕМЕЙСТВО АДРЕСА ИЗМЕРЯЕТСЯ, А НЕ ВЫВОДИТСЯ ИЗ ПРЕДПОЧТЕНИЙ
                   БРАУЗЕРА: Chrome выбирает его сам (Happy Eyeballs), и
                   догадка здесь однажды стоила мне неверного вывода. */
                docIp = m.params.response.remoteIPAddress || '?';
                /* ТОТ ЖЕ ПРИНЦИП ДЛЯ ALT-SVC: читается из ответа, не выводится
                   из имени. Пусто = заголовка в ЭТОМ ответе не было. */
                docAltSvc = header(m.params.response.headers, 'alt-svc');
            }
        } else if (m.method === 'Network.loadingFailed' && m.params.type === 'Document') {
            err = m.params.errorText;
        } else if (m.method === 'Page.loadEventFired') {
            loaded = true;
        }
    };
    ws.addEventListener('message', onMsg);
    send(ws, 'Page.navigate', { url });
    const t0 = Date.now();
    while (Date.now() - t0 < waitMs && !(loaded && docProto)) {
        await new Promise((r) => setTimeout(r, 200));
    }
    ws.removeEventListener('message', onMsg);
    const counts = {};
    for (const p of seen.values()) counts[p] = (counts[p] || 0) + 1;
    return { docProto, docStatus, err, loaded, counts, n: seen.size, docIp,
             docAltSvc, ms: Date.now() - t0 };
}

const list = await targets();
const page = list.find((t) => t.type === 'page');
if (!page) { console.error('страницы нет'); process.exit(1); }
const ws = await sock(page.webSocketDebuggerUrl);
send(ws, 'Network.enable');
send(ws, 'Page.enable');
await new Promise((r) => setTimeout(r, 300));

for (const s of sites) {
    const url = s.startsWith('http') ? s : 'https://' + s + '/';
    const a = await visit(ws, url, 35000);
    await new Promise((r) => setTimeout(r, 500));
    await new Promise((r) => setTimeout(r, 3000));
    const b = await visit(ws, url, 35000);
    const fam = (ip) => !ip ? '—' : (ip.includes(':') ? 'v6' : 'v4');
    const fmt = (v) => `${v.docProto || '—'}/${v.docStatus ?? (v.err || 'нет')}` +
        ` ${fam(v.docIp)} ${v.docIp || ''} зап.${v.n}` +
        ` [${Object.entries(v.counts).map(([k, n]) => k + '×' + n).join(' ')}]`;
    /* alt-svc печатается ОТДЕЛЬНОЙ строкой и по обоим заходам: «нет» в первом
       ответе и «есть» во втором — это разные вещи, а не шум. Пустое поле
       означает только «в этом ответе заголовка не было» — на момент чтения. */
    const alt = (v) => v.docAltSvc || (v.docProto ? 'НЕТ' : '—');
    const both = a.docAltSvc === b.docAltSvc ? alt(a) : `${alt(a)} → ${alt(b)}`;
    console.log(`${s.padEnd(22)} 1-й: ${fmt(a)}\n${' '.repeat(22)} 2-й: ${fmt(b)}` +
        `\n${' '.repeat(22)} alt-svc: ${both}`);
}
ws.close();
