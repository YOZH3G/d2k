// cdpshot.mjs <port> <out.png> : снимок страницы Chrome прогона через протокол
// отладки (CDP). Снимается содержимое НАШЕЙ вкладки, а не область экрана:
// чужое окно в снимок попасть не может, и право «Универсальный доступ» для
// osascript не нужно (поле 16.10.2026: его отзыв оборвал контроль на 14-м
// сайте). Печатает одну строку: url, заголовок, длина видимого текста.
import { writeFileSync } from "node:fs";

const [port, out] = process.argv.slice(2);
// Bound the observer, not the site's network measurements. A hung renderer
// must produce a failed observation instead of blocking all remaining sites.
const timeoutMs = Number(process.env.D2K_CDP_TIMEOUT_MS || 15000);
if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw Error("invalid CDP timeout");
const watchdog = setTimeout(() => {
  console.error(`тайм-аут CDP: ответ не получен за ${timeoutMs} мс`);
  process.exit(1);
}, timeoutMs);
watchdog.unref();
const tabs = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
const pages = tabs.filter((t) => t.type === "page");
const tab = pages.find((t) => t.url !== "about:blank") ?? pages[0];
if (!tab) { console.log("нет вкладки"); process.exit(2); }
const ws = new WebSocket(tab.webSocketDebuggerUrl);
let seq = 0;
const wait = new Map();
ws.onmessage = (e) => {
  const m = JSON.parse(e.data);
  if (m.id && wait.has(m.id)) { const {ok, bad} = wait.get(m.id); wait.delete(m.id); m.error ? bad(Error(JSON.stringify(m.error))) : ok(m); }
};
const call = (method, params = {}) => new Promise((ok, bad) => {
  const id = ++seq;
  wait.set(id, {ok, bad});
  ws.send(JSON.stringify({ id, method, params }));
});
await new Promise((ok) => { ws.onopen = ok; });
const ev = await call("Runtime.evaluate", {
  expression: "JSON.stringify([location.href, document.title, (document.body && document.body.innerText || '').trim().length])",
  returnByValue: true,
});
const [href, title, textLen] = JSON.parse(ev.result?.result?.value ?? '["?","?",0]');
const shot = await call("Page.captureScreenshot", { format: "png" });
if (shot.result?.data) writeFileSync(out, Buffer.from(shot.result.data, "base64"));
console.log(`${href} | «${title}» | текст ${textLen} симв.${shot.result?.data ? "" : " | снимок не получен"}`);
ws.close();
clearTimeout(watchdog);
