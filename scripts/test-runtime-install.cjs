#!/usr/bin/env node
// Full installer/uninstaller in a private filesystem with router boundaries
// replaced by local commands. No /opt, firewall, or router state is touched.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const tmp = fs.mkdtempSync('/tmp/runtime-install-test.');
function fixture(name, contents, mode = 0o755) {
  const target = path.join(tmp, 'source', name);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents, { mode });
}
try {
  fs.mkdirSync(path.join(tmp, 'bin'));
  for (const command of ['curl', 'ip', 'ipset', 'openssl']) {
    fs.writeFileSync(path.join(tmp, 'bin', command), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  }
  // iptables doubles: no d2k chains; filter OUTPUT holds RST-drop rules left
  // by a killed d2k process (owner PID gone), a foreign one and a live owner's.
  for (const command of ['iptables', 'ip6tables']) {
    fs.writeFileSync(path.join(tmp, 'bin', command), `#!/bin/sh
printf '${command} %s\\n' "$*" >> "$IPT_CALLS"
case "$*" in
  *"-S OUTPUT"*) [ "\${IPT_RST:-0}" = 1 ] || exit 0
    printf '%s\\n' '-P OUTPUT ACCEPT' \\
      '-A OUTPUT -p tcp -m tcp --sport 40750 --tcp-flags RST RST -m comment --comment d2k-rst:2147480001 -j DROP' \\
      '-A OUTPUT -p tcp -m tcp --sport 40751 --tcp-flags RST RST -m comment --comment other:2147480001 -j DROP' \\
      '-A OUTPUT -p tcp -m tcp --sport 40752 --tcp-flags RST RST -m comment --comment d2k-rst:${process.pid} -j DROP'
    exit 0 ;;
esac
exit 1
`, { mode: 0o755 });
  }
  fs.writeFileSync(path.join(tmp, 'bin/start-stop-daemon'), '#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n', { mode: 0o755 });
  fixture('scripts/architecture.sh', '#!/bin/sh\nprintf "amd64\\n"\n');
  for (const name of ['check-cpu.sh', 'select-panel-ip.sh']) fixture(`scripts/${name}`, '#!/bin/sh\nexit 0\n');
  fixture('builds/d2kpanel-linux-amd64', '#!/bin/sh\necho features=telegram-control\n');
  fixture('builds/d2ktg-linux-amd64', '#!/bin/sh\necho features=per-install-enrollment,instagram-ip-probe,meta-hosts-v3\n');
  fixture('builds/d2kd-linux-amd64', '#!/bin/sh\nexit 0\n');
  for (const name of ['d2kc']) fixture(`builds/${name}-linux-amd64`, '#!/bin/sh\nexit 2\n');
  fixture('files/S99d2k', '#!/bin/sh\n[ "$1" != status ] || echo "датапат: работает"\nexit 0\n');
  fixture('files/config', 'PANEL_LISTEN=192.168.1.1:8090\nTG_ENABLED=0\nTG_RELAY_URL=wss://example.test/ws\n');
  for (const name of ['d2k-fw-heal.sh', 'd2k-ppe-deoffload.sh', '001-d2k.sh', 'd2k-tg-firewall.sh', 'd2k-tg-watchdog.sh', 'd2k-instagram-dns-scheduler.sh']) fixture(`files/${name}`, '#!/bin/sh\nexit 0\n');
  fixture('files/d2k-instagram-dns.sh', '#!/bin/sh\nprintf "dns-%s\\n" "$1" >> "$CALLS"\n');
  fixture('files/d2k-log-maintenance.sh', fs.readFileSync(path.join(root, 'files/d2k-log-maintenance.sh')));
  for (const name of ['meta-ranges.txt', 'tg-roots.pem', 'fake/stun.bin', 'fake/quic_initial_dbankcloud_ru.bin']) fixture(`files/${name}`, 'fixture\n');
  for (const name of ['index.html', 'favicon.svg', 'panel.css', 'panel.js', 'gsap.js', 'fonts/onest.woff2', 'fonts/OFL-onest.txt', 'fonts/jbmono.woff2', 'fonts/OFL-jbmono.txt']) fixture(`internal/web/assets/${name}`, 'fixture\n');
  fs.mkdirSync(path.join(tmp, 'proc/net/netfilter'), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'proc/net/netfilter/nfnetlink_queue'), '');
  fs.writeFileSync(path.join(tmp, 'proc/net/ip_tables_targets'), 'NFQUEUE\n');
  fs.writeFileSync(path.join(tmp, 'proc/net/ip_tables_matches'), 'connbytes\n');
  fs.mkdirSync(path.join(tmp, 'opt/etc/ndm/netfilter.d'), { recursive: true });
  const runtime = path.join(tmp, 'runtime');
  for (const name of ['install', 'uninstall']) {
    const script = fs.readFileSync(path.join(root, `scripts/${name}.sh`), 'utf8')
      .replaceAll('/opt', path.join(tmp, 'opt'))
      .replaceAll('/proc', path.join(tmp, 'proc'))
      .replaceAll('/tmp/d2k', runtime);
    fs.writeFileSync(path.join(tmp, `${name}.sh`), script);
  }
  const iptCalls = path.join(tmp, 'ipt-calls');
  const env = { ...process.env, PATH: `${tmp}/bin:${process.env.PATH}`, D2K_LOCAL: `${tmp}/source`, CALLS: `${tmp}/calls`, IPT_CALLS: iptCalls, D2K_KEEP_STATE: '1' };
  function run(name, extraEnv = {}) {
    const result = spawnSync('/bin/sh', [path.join(tmp, `${name}.sh`)], { env: { ...env, ...extraEnv }, encoding: 'utf8', timeout: 10000 });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    return result.stdout;
  }
  const calls = () => { try { return fs.readFileSync(path.join(tmp, 'calls'), 'utf8'); } catch { return ''; } };
  // Upgrade from a release that shipped the port-80 proxy (task 51): its binary goes away.
  fs.mkdirSync(path.join(tmp, 'opt/sbin'), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'opt/sbin/d2khttp'), '#!/bin/sh\nexit 2\n', { mode: 0o755 });
  const installOut = run('install');
  assert(!fs.existsSync(path.join(tmp, 'opt/sbin/d2khttp')), 'upgrade must remove the old d2khttp proxy binary');
  // The first DNS refresh (15 names, possibly silent edges) must not hold the
  // installer: the service's scheduler runs it in the background with a log.
  assert(!calls().includes('dns-refresh'), 'installer must not run the DNS refresh synchronously');
  assert.match(installOut, /в фоне/, 'installer must say the DNS refresh runs in the background');
  // An upgrade keeps a success younger than a day (no release-day herd on
  // /resolve); an older or time-less mark is cleared, so the scheduler
  // refreshes right away.
  const dnsSuccess = path.join(tmp, 'opt/d2k/state/instagram-dns-last-success');
  const nowSec = Math.floor(Date.now() / 1000);
  fs.writeFileSync(dnsSuccess, `2026-10-02\n${nowSec - 3600}\n`);
  run('install');
  assert(fs.existsSync(dnsSuccess), 'upgrade must keep a DNS success mark younger than 24 h');
  fs.writeFileSync(dnsSuccess, `2026-10-01\n${nowSec - 90000}\n`);
  run('install');
  assert(!fs.existsSync(dnsSuccess), 'upgrade must clear a DNS success mark older than 24 h');
  fs.writeFileSync(dnsSuccess, `2026-10-02\n${nowSec + 7200}\n`);
  run('install');
  assert(!fs.existsSync(dnsSuccess), 'a success mark from the future is not trusted');
  fs.writeFileSync(dnsSuccess, '2026-10-02\n');
  run('install');
  assert(!fs.existsSync(dnsSuccess), 'upgrade must clear an old-format DNS success mark so the scheduler refreshes right away');
  assert(!calls().includes('dns-refresh'), 'upgrade must not run the DNS refresh synchronously');
  // A d2ktg without the 15-name certificate check would silently skip WhatsApp/fbcdn.
  const tgFixture = path.join(tmp, 'source/builds/d2ktg-linux-amd64');
  const tgCurrent = fs.readFileSync(tgFixture);
  fs.writeFileSync(tgFixture, '#!/bin/sh\necho features=per-install-enrollment,instagram-ip-probe,meta-hosts-v2\n');
  const stale = spawnSync('/bin/sh', [path.join(tmp, 'install.sh')], { env, encoding: 'utf8', timeout: 10000 });
  assert.notEqual(stale.status, 0, 'installer must reject a d2ktg without the Meta host list check');
  assert.match(stale.stdout + stale.stderr, /d2ktg устарел/);
  fs.writeFileSync(tgFixture, tgCurrent);
  run('install');
  const installed = path.join(tmp, 'opt/d2k/d2k-log-maintenance.sh');
  assert.deepEqual(fs.readFileSync(installed), fs.readFileSync(path.join(root, 'files/d2k-log-maintenance.sh')), 'installer must fetch and install helper');
  assert(fs.statSync(installed).mode & 0o111, 'installed helper must be executable');
  const ppe = path.join(tmp, 'opt/d2k/d2k-ppe-deoffload.sh');
  assert(fs.existsSync(ppe) && (fs.statSync(ppe).mode & 0o111), 'installer must install the PPE de-offload helper executable');
  // Uninstall without init must still remove its own tagged -j PPE rules.
  fs.writeFileSync(ppe, '#!/bin/sh\nd2k_ppe_remove() { printf "ppe-remove\\n" >> "$CALLS"; }\n');
  const state = path.join(tmp, 'opt/d2k/state/catalog.json'); fs.writeFileSync(state, '{"learned":true}');
  fs.writeFileSync(path.join(tmp, 'opt/d2k/run/d2k-log-maintenance.pid'), '123');
  // A background DNS refresh must not race the removal of its pins.
  fs.writeFileSync(path.join(tmp, 'opt/d2k/run/d2k-instagram-dns-scheduler.pid'), '999999');
  // Init may already be missing: uninstall still stops its owned helper.
  fs.unlinkSync(path.join(tmp, 'opt/etc/init.d/S99d2k'));
  fs.mkdirSync(runtime); fs.writeFileSync(path.join(runtime, 'live.json'), '{}');
  fs.writeFileSync(path.join(runtime, 'log-tail.ABCDEF'), 'stale');
  fs.writeFileSync(path.join(runtime, 'unrelated'), 'keep');
  const customRuntime = path.join(tmp, 'custom-runtime');
  fs.mkdirSync(customRuntime);
  fs.writeFileSync(path.join(customRuntime, 'live.json'), '{}');
  fs.writeFileSync(path.join(customRuntime, 'log-tail.QRSTUV'), 'stale');
  fs.writeFileSync(path.join(customRuntime, 'unrelated'), 'keep');
  fs.appendFileSync(path.join(tmp, 'opt/d2k/config'), `D2K_RUNTIME_DIR='${customRuntime}'\n`);
  // Init is gone: the fallback still restores the NAT accelerator setting it
  // saved, removes its own MASQUERADE and leftover RST-drop rules, and its /tmp files.
  const fastnat = path.join(tmp, 'proc/sys/net/netfilter/nf_conntrack_fastnat');
  fs.mkdirSync(path.dirname(fastnat), { recursive: true }); fs.writeFileSync(fastnat, '0\n');
  fs.writeFileSync(path.join(tmp, 'opt/d2k/run/fastnat.saved'), '1\n');
  const tmpLeft = [`${runtime}-fw-heal.last`, `${runtime}-instagram-dns-last-attempt`];
  for (const f of tmpLeft) fs.writeFileSync(f, '1');
  for (const d of [`${runtime}-fw-heal.lock`, `${runtime}-fw-operation.lock`]) { fs.mkdirSync(d); fs.writeFileSync(path.join(d, 'pid'), '2147480001'); }
  fs.rmSync(iptCalls, { force: true });
  run('uninstall', { IPT_RST: '1' });
  assert.equal(fs.readFileSync(fastnat, 'utf8').trim(), '1', 'uninstall fallback must restore the saved fastnat value');
  const ipt = fs.readFileSync(iptCalls, 'utf8');
  for (const tool of ['iptables', 'ip6tables']) {
    assert(ipt.includes(`${tool} -w -D OUTPUT -p tcp --sport 40750 --tcp-flags RST RST -m comment --comment d2k-rst:2147480001 -j DROP`), `${tool}: leftover d2k-rst rule of a dead owner not removed`);
    assert(!ipt.includes(`${tool} -w -D OUTPUT -p tcp --sport 40751`), `${tool}: foreign RST rule touched`);
    assert(!ipt.includes(`${tool} -w -D OUTPUT -p tcp --sport 40752`), `${tool}: RST rule of a live non-d2k process touched`);
  }
  assert(ipt.includes('iptables -t nat -D POSTROUTING -p udp -m mark --mark 0x2d -j MASQUERADE'), 'uninstall fallback must remove its own MASQUERADE');
  for (const f of tmpLeft) assert(!fs.existsSync(f), `uninstall left ${f}`);
  for (const d of [`${runtime}-fw-heal.lock`, `${runtime}-fw-operation.lock`]) assert(!fs.existsSync(d), `uninstall left stale lock ${d}`);
  assert(calls().includes('dns-remove'), 'uninstall must remove the owned DNS pins through the manifest helper');
  const sched = calls().indexOf('d2k-instagram-dns-scheduler.pid');
  assert(sched >= 0 && sched < calls().indexOf('dns-remove'), 'uninstall must stop the DNS scheduler before removing its pins');
  assert(!fs.existsSync(installed), 'uninstall must remove helper even when persistent state is kept');
  assert(!fs.existsSync(ppe), 'uninstall must remove the PPE de-offload helper');
  assert(fs.readFileSync(path.join(tmp, 'calls'), 'utf8').includes('ppe-remove'), 'uninstall must remove own PPE rules even without init');
  assert(!fs.existsSync(path.join(runtime, 'live.json')), 'uninstall must remove volatile live snapshot');
  assert(!fs.existsSync(path.join(runtime, 'log-tail.ABCDEF')), 'uninstall must remove owned abandoned stage');
  assert.equal(fs.readFileSync(path.join(runtime, 'unrelated'), 'utf8'), 'keep');
  assert(!fs.existsSync(path.join(customRuntime, 'live.json')), 'missing-init uninstall must remove configured custom snapshot');
  assert(!fs.existsSync(path.join(customRuntime, 'log-tail.QRSTUV')), 'missing-init uninstall must remove custom abandoned stage');
  assert.equal(fs.readFileSync(path.join(customRuntime, 'unrelated'), 'utf8'), 'keep');
  assert.equal(fs.readFileSync(state, 'utf8'), '{"learned":true}', 'keep-state must preserve catalog');
  assert(fs.readFileSync(path.join(tmp, 'calls'), 'utf8').includes('d2k-log-maintenance.pid'), 'uninstall fallback must stop owned helper');

  const config = path.join(tmp, 'opt/d2k/config');
  const protectedRuntime = path.join(tmp, 'protected-runtime'); fs.mkdirSync(protectedRuntime);
  fs.writeFileSync(path.join(protectedRuntime, 'live.json'), 'keep');
  const linkedRuntime = path.join(tmp, 'linked-runtime'); fs.symlinkSync(protectedRuntime, linkedRuntime);
  fs.mkdirSync(path.join(protectedRuntime, 'child'));
  for (const value of [linkedRuntime, `${protectedRuntime}/child/..`, `/tmp`, `$(touch ${tmp}/executed)`]) {
    fs.appendFileSync(config, `D2K_RUNTIME_DIR=${value}\n`);
    run('uninstall');
    assert.equal(fs.readFileSync(path.join(protectedRuntime, 'live.json'), 'utf8'), 'keep', 'unsafe custom runtime must be preserved');
    assert(!fs.existsSync(path.join(tmp, 'executed')), 'runtime cleanup must never evaluate configuration');
  }
  const envRuntime = path.join(tmp, 'env-runtime'); fs.mkdirSync(envRuntime);
  fs.writeFileSync(path.join(envRuntime, 'live.json'), '{}');
  run('uninstall', { D2K_RUNTIME_DIR: envRuntime });
  assert(!fs.existsSync(envRuntime), 'explicit valid environment runtime must be cleaned and removed when empty');
  console.log('local installer/helper and keep-state uninstall: PASS');
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
