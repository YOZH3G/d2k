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

  } finally {
    if (worker && worker.exitCode === null) worker.kill('SIGKILL');
    if (sleeper) { try { process.kill(sleeper, 'SIGKILL'); } catch {} }
    fs.rmSync(tmp, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
