#!/usr/bin/env node
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const helper = path.resolve(__dirname, '../files/d2k-log-maintenance.sh');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'd2k-log-process-test.'));
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
(async () => {
  let worker;
  let sleeper;
  try {
    fs.mkdirSync(path.join(tmp, 'bin'));
    fs.writeFileSync(path.join(tmp, 'bin/sleep'), '#!/bin/sh\necho $$ > "$SLEEP_PID_FILE"\nexec /bin/sleep "$@"\n', { mode: 0o755 });
    worker = spawn('/bin/sh', [helper, 'run'], { env: {
      ...process.env, D2K_DIR: tmp, D2K_RUNTIME_DIR: path.join(tmp, 'runtime'),
      LOG_EVERY: '30', PATH: `${tmp}/bin:${process.env.PATH}`, SLEEP_PID_FILE: path.join(tmp, 'sleeper')
    }, stdio: 'ignore' });
    const exited = new Promise(resolve => worker.once('exit', resolve));
    for (let i = 0; i < 100 && !fs.existsSync(path.join(tmp, 'sleeper')); i++) await delay(20);
    assert(fs.existsSync(path.join(tmp, 'sleeper')), 'periodic worker must enter sleep');
    sleeper = Number(fs.readFileSync(path.join(tmp, 'sleeper'), 'utf8'));
    worker.kill('SIGTERM');
    await Promise.race([exited, delay(2000).then(() => { throw new Error('worker did not stop promptly'); })]);
    assert.throws(() => process.kill(sleeper, 0), { code: 'ESRCH' }, 'stopping log worker must kill and reap its sleeping child');
    console.log('log maintenance TERM kills and reaps sleep child: PASS');

    // Managed installation: tick goes through the service adapter, which waits
    // for the maintenance lock. During an update that lock is held by the very
    // transaction that is stopping this worker; a TERM deferred until the
    // adapter returns ends in SIGKILL and a failed managed stop.
    const managed = path.join(tmp, 'managed');
    fs.mkdirSync(path.join(managed, 'boot'), { recursive: true });
    fs.mkdirSync(path.join(managed, 'releases/r'), { recursive: true });
    fs.symlinkSync('releases/r', path.join(managed, 'current'));
    fs.writeFileSync(path.join(managed, 'boot/d2k-service-adapter'),
      '#!/bin/sh\necho $$ > "$ADAPTER_PID_FILE"\nexec /bin/sleep 30\n', { mode: 0o755 });
    fs.rmSync(path.join(tmp, 'sleeper'), { force: true });
    worker = spawn('/bin/sh', [helper, 'run'], { env: {
      ...process.env, D2K_DIR: managed, D2K_RUNTIME_DIR: path.join(tmp, 'runtime2'), D2K_MANAGED_INTERNAL: '',
      LOG_EVERY: '30', PATH: `${tmp}/bin:${process.env.PATH}`, SLEEP_PID_FILE: path.join(tmp, 'sleeper'),
      ADAPTER_PID_FILE: path.join(tmp, 'adapter')
    }, stdio: 'ignore' });
    const managedExit = new Promise(resolve => worker.once('exit', resolve));
    for (let i = 0; i < 100 && !fs.existsSync(path.join(tmp, 'adapter')); i++) await delay(20);
    assert(fs.existsSync(path.join(tmp, 'adapter')), 'managed tick must call the service adapter');
    const adapter = Number(fs.readFileSync(path.join(tmp, 'adapter'), 'utf8'));
    worker.kill('SIGTERM');
    await Promise.race([managedExit, delay(2000).then(() => { throw new Error('worker blocked on the adapter ignored TERM'); })]);
    assert.throws(() => process.kill(adapter, 0), { code: 'ESRCH' }, 'stopping log worker must end its waiting adapter call');
    console.log('log maintenance TERM while the adapter waits for maintenance: PASS');
  } finally {
    if (worker && worker.exitCode === null) worker.kill('SIGKILL');
    if (sleeper) { try { process.kill(sleeper, 'SIGKILL'); } catch {} }
    fs.rmSync(tmp, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
