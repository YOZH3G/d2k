const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');

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
    child = spawn(path.resolve(__dirname, '../core/d2kc'),
      ['--control', socket, '--catalog', path.join(dir, 'catalog.json')]);
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
    if (version === 4 && !legacy) {
      assert.equal(result.timeout, true, `valid peer rejected: ${output}`);
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
  const header = fs.readFileSync(path.resolve(__dirname, '../datapath/include/d2k_ctl.h'), 'utf8');
  assert.match(header, /#define D2K_EV_PROTO\s+0x000A/);
  await trial(null);
  await trial(3);
  await trial(3, true);
  await trial(4);
  console.log('controller refuses silent and incompatible datapaths before any command: pass');
})().catch(e => { console.error(e); process.exitCode = 1; });
