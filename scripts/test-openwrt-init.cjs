#!/usr/bin/env node
// Isolated boot bridge behavior: no router, /opt, procd or firewall is touched.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const tmp = fs.mkdtempSync('/tmp/d2k-openwrt-test.');
try {
  const calls = path.join(tmp, 'calls');
  const init = path.join(tmp, 'S99d2k');
  const config = path.join(tmp, 'config');
  const hook = path.join(tmp, 'hook');
  const source = fs.readFileSync(path.join(__dirname, '../files/d2k-openwrt-init'), 'utf8');
  fs.writeFileSync(hook, source.replaceAll('/opt/etc/init.d/S99d2k', init)
    .replaceAll('/opt/d2k/config', config));
  const engine = '#!/bin/sh\nprintf "engine-%s\\n" "$1" >> "$CALLS"\n';
  const prelude = `extra_command() { :; }
procd_open_instance() { echo "instance-$1" >> "$CALLS"; }
procd_set_param() { printf '%s\\n' "$*" >> "$CALLS"; }
procd_close_instance() { :; }
procd_kill() { echo "kill-$1" >> "$CALLS"; }
. "$HOOK"
`;
  function run(body, env = {}) {
    const r = spawnSync('/bin/sh', ['-c', prelude + body], {
      env: { ...process.env, CALLS: calls, HOOK: hook, ...env }, encoding: 'utf8', timeout: 5000,
    });
    return r;
  }
  const log = () => fs.existsSync(calls) ? fs.readFileSync(calls, 'utf8') : '';
  function clear() { fs.rmSync(calls, { force: true }); }
  assert.equal(run('start_service').status, 0);
  assert.match(log(), /command \/bin\/sh \/etc\/rc.common \/etc\/init.d\/d2k boot_wait/);
  assert(!log().includes('engine-'), 'start registers a worker without blocking boot');
  assert(!log().includes('respawn'), 'boot bridge must leave daemon supervision to S99d2k');
  clear();
  // A deterministic late mount: sleep supplies the files on the first wait.
  assert.equal(run(`sleep() {
    printf '%s' "$ENGINE" > "$INIT"; chmod 755 "$INIT"
    : > "$CONFIG"
}
boot_wait`, { ENGINE: engine, INIT: init, CONFIG: config }).status, 0);
  assert.equal(log(), 'engine-start\n', 'flat install boots after delayed mount');
  clear();
  assert.equal(run('stop_service').status, 0);
  assert.equal(log(), 'kill-d2k\nengine-stop\n', 'cancel waiting worker before stopping engine');
  clear();
  assert.equal(run('detach').status, 0);
  assert.equal(log(), 'kill-d2k\n', 'uninstall detaches without stopping engine twice');
  clear();
  assert.equal(run('status_service').status, 0);
  assert.equal(log(), 'engine-status\n');
  fs.rmSync(init);
  clear();
  assert.equal(run('stop_service').status, 0, 'stop is safe before /opt appears');
  assert.equal(run('status_service').status, 1);
  // Waiter is cancellable even if Entware never appears.
  const cancelled = spawnSync('/bin/sh', ['-c', prelude + 'boot_wait'], {
    env: { ...process.env, CALLS: calls, HOOK: hook }, timeout: 100, encoding: 'utf8',
  });
  assert.equal(cancelled.error?.code, 'ETIMEDOUT');
  assert(!log().includes('engine-'));
  console.log('OpenWrt boot bridge: delayed mount, start, stop and cancellation: PASS');
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
