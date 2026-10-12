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
 * http/1.1) и АДРЕС сервера. Адрес печатается не для красоты: 12.10 я вывел
 * семейство адреса из предпочтений браузера вместо того, чтобы его измерить, и
 * построил на этом неверный полевой вывод (docs/field/2026-10-12d — отзыв).
 * Chrome выбирает адрес сам, и догадка здесь обходится дорого.
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
    const r = await fetch(`http://127.0.0.1:${PORT}/json/list`);
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

async function visit(ws, url, waitMs) {
    const seen = new Map();   /* url -> protocol */
    let docProto = null, docStatus = null, loaded = false, err = null, docIp = null;
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
             ms: Date.now() - t0 };
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
    console.log(`${s.padEnd(22)} 1-й: ${fmt(a)}\n${' '.repeat(22)} 2-й: ${fmt(b)}`);
}
ws.close();
