const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');

const controller = process.env.D2K_TEST_BINARY || path.resolve(__dirname, '../core/d2kc');
const runner = process.env.D2K_TEST_RUNNER || '';
const runnerArgs = (process.env.D2K_TEST_RUNNER_ARGS || '').split(/\s+/).filter(Boolean);

let VALID = 0;

async function trial(version, legacy = false) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'd2k-greet-'));
  const socket = path.join(dir, 'ctl.sock');
  let peer, child, deadline;
  let prematureBytes = 0;
  const server = net.createServer(connection => {
    peer = connection;
    connection.on('error', () => {});
    connection.on('data', b => { prematureBytes += b.length; });
    if (version !== null) {
      const keySize = legacy ? 13 : 38;
      const frame = Buffer.alloc(6 + keySize + 6);
      frame.writeUInt32BE(keySize + 8, 0);
      frame.writeUInt16BE(0x000A, 4); // D2K_EV_PROTO (checked against the header below)
      if (!legacy) frame[6] = 4;
      frame.writeUInt16BE(version, 6 + keySize);
      frame.writeUInt32BE(8192, 8 + keySize);
      connection.write(frame);
    }
  });
  try {
    await new Promise(resolve => server.listen(socket, resolve));
    const args = ['--control', socket, '--catalog', path.join(dir, 'catalog.json')];
    child = runner
      ? spawn(runner, [...runnerArgs, controller, ...args])
      : spawn(controller, args);
    let output = '';
    child.stdout.on('data', b => { output += b; });
    child.stderr.on('data', b => { output += b; });
    const result = await new Promise(resolve => {
      deadline = setTimeout(() => {
        child.kill('SIGTERM');
        resolve({ timeout: true });
      }, 3500);
      child.on('close', code => resolve({ code }));
    });
    clearTimeout(deadline);
    if (version === VALID && !legacy) {
      assert.equal(result.timeout, true, `valid peer rejected: ${output}`);
      assert.match(output, /d2kc: запущен/, `controller stayed alive without completing startup: ${output}`);
    } else {
      assert.equal(result.timeout, undefined, `controller accepted missing/incompatible greeting: ${output}`);
      assert.equal(result.code, 1, output);
    }
    assert.equal(prematureBytes, 0, 'commands must not precede protocol validation');
  } finally {
    clearTimeout(deadline);
    if (child && child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
      await new Promise(resolve => child.once('close', resolve));
    }
    if (peer) peer.destroy();
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

(async () => {
  const headerPath = process.env.D2K_PROTOCOL_HEADER ||
    path.resolve(__dirname, '../datapath/include/d2k_ctl.h');
  const header = fs.readFileSync(headerPath, 'utf8');
  assert.match(header, /#define D2K_EV_PROTO\s+0x000A/);
  // Действующая версия — из заголовка, а не числом в тесте: тест с
  // зашитой «4» отвергал собственный датапат с версии 5.
  const m = header.match(/#define D2K_CTL_PROTO_VERSION\s+(\d+)/);
  assert.ok(m, 'D2K_CTL_PROTO_VERSION not found');
  VALID = Number(m[1]);
  await trial(null);
  await trial(VALID - 1);
  await trial(VALID - 1, true);
  await trial(VALID);
  console.log('controller refuses silent and incompatible datapaths before any command: pass');
})().catch(e => { console.error(e); process.exitCode = 1; });
