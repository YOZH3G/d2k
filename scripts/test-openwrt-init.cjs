#!/usr/bin/env node
// Isolated boot bridge behavior: no router, /opt, procd or firewall is touched.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const tmp = fs.mkdtempSync('/tmp/d2k-openwrt-test.');
// OpenWrt ash supports fd 1000; dash does not. Use ash when available.
const busybox = ['/bin/busybox', '/usr/bin/busybox'].find(p => fs.existsSync(p));
const shell = busybox || '/bin/bash';
const shellArgs = busybox ? ['ash', '-c'] : ['-c'];
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
procd_kill() { echo "kill-$1\${2:+/$2}" >> "$CALLS"; }
. "$HOOK"
`;
  function run(body, env = {}) {
    const r = spawnSync(shell, [...shellArgs, prelude + body], {
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
  assert.equal(run(`exec 1000>"$LOCK"
sleep() {
    [ ! -e /proc/self/fd/1000 ] || exit 70
    printf '%s' "$ENGINE" > "$INIT"; chmod 755 "$INIT"
    : > "$CONFIG"
}
boot_wait`, { ENGINE: engine, INIT: init, CONFIG: config, LOCK: path.join(tmp, 'wait-lock') }).status, 0);
  assert.equal(log(), 'engine-start\n', 'flat install boots after delayed mount');
  clear();
  // Simulate procd's preload and an inherited lock descriptor. A spawned
  // service must receive neither, or glibc fails and rc.common stays locked.
  fs.writeFileSync(init, '#!/bin/sh\n' +
    'printf "preload=%s\\n" "${LD_PRELOAD+set}" >> "$CALLS"\n' +
    'if [ -e /proc/self/fd/1000 ]; then echo lock=open; else echo lock=closed; fi >> "$CALLS"\n', { mode: 0o755 });
  const isolated = run('exec 1000>"$LOCK"\nboot_wait', { LD_PRELOAD: '', LOCK: path.join(tmp, 'lock') });
  assert.equal(isolated.status, 0, isolated.stderr);
  assert.equal(log(), 'preload=\nlock=closed\n', 'service must not inherit procd preload or fd 1000');
  fs.writeFileSync(init, engine, { mode: 0o755 });
  clear();
  assert.equal(run('stop_service').status, 0);
  assert.equal(log(), 'kill-d2k/boot\nengine-stop\n', 'cancel waiting worker before stopping engine');
  clear();
  // rc.common deletes the whole service AFTER stop_service returns. Deleting
  // the entire service inside stop_service made that second delete fail.
  const stopped = run(`present=1
procd_kill() {
    [ "$present" = 1 ] || { echo "Not found" >&2; return 1; }
    [ "\${2:-}" = boot ] || present=0
}
stop_service
procd_kill d2k`);
  assert.equal(stopped.status, 0);
  assert.equal(stopped.stderr, '', 'rc.common final deletion must not delete an already deleted service');
  clear();
  assert.equal(run('detach').status, 0);
  assert.equal(log(), 'kill-d2k\n', 'uninstall detaches without stopping engine twice');
  clear();
  const missing = run('procd_kill() { echo "Not found" >&2; return 1; }; detach');
  assert.equal(missing.status, 1, 'detach retains procd failure status');
  assert.equal(missing.stderr, '', 'missing one-shot instance must not print a ubus error');
  assert.equal(run('status_service').status, 0);
  assert.equal(log(), 'engine-status\n');
  fs.rmSync(init);
  clear();
  assert.equal(run('stop_service').status, 0, 'stop is safe before /opt appears');
  assert.equal(run('status_service').status, 1);
  // Waiter is cancellable even if Entware never appears.
  const cancelled = spawnSync(shell, [...shellArgs, prelude + 'boot_wait'], {
    env: { ...process.env, CALLS: calls, HOOK: hook }, timeout: 100, encoding: 'utf8',
  });
  assert.equal(cancelled.error?.code, 'ETIMEDOUT');
  assert(!log().includes('engine-'));
  console.log(`OpenWrt boot bridge (${busybox ? 'ash' : 'bash'}): delayed mount, procd isolation, stop and cancellation: PASS`);
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
