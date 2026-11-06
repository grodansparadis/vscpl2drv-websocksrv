import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createCipheriv } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, rmdir, unlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const [app, driver] = process.argv.slice(2);
if (!app || !driver || typeof WebSocket === 'undefined') {
  throw new Error('Requires Node.js 22+: node test/test_auth.mjs <testapp> <driver-library> (from repository root)');
}

const defaultKey = '2DBB079A38985AF00EBEEFE22F9FFA0E';
const directory = await mkdtemp(join(tmpdir(), 'websocksrv-auth-'));
const configPath = join(directory, 'config.json');
const usersPath = join(directory, 'users.json');
const keyPath = join(directory, 'key.hex');
const users = JSON.parse(await readFile('debug/users.json', 'utf8'));
const admin = users.users.find(user => user.name === 'admin');
users.users.push({ ...admin, name: 'adminuser' });
users.users.push({ ...admin, name: 'administrator-with-a-long-name' });
await writeFile(usersPath, JSON.stringify(users));
const config = JSON.parse(await readFile('debug/linux/websocksrv.json', 'utf8'));
config['path-users'] = usersPath;
config.logging['file-enable-log'] = false;
let server;
let serverExit;
let output = '';

async function stopServer() {
  if (server && server.exitCode === null && server.signalCode === null) {
    server.kill('SIGINT');
    const timeout = setTimeout(() => server.kill('SIGKILL'), 5000);
    try {
      await serverExit;
    } finally {
      clearTimeout(timeout);
    }
  }
}

function launch() {
  output = '';
  server = spawn(resolve(app), ['--driver', resolve(driver), '--config', configPath]);
  server.stdout.on('data', data => { output = (output + data).slice(-10000); });
  server.stderr.on('data', data => { output = (output + data).slice(-10000); });
  serverExit = once(server, 'exit');
}

function connect(url) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    const timeout = setTimeout(() => {
      socket.close();
      reject(new Error('Timed out waiting for authentication challenge'));
    }, 3000);
    socket.addEventListener('error', () => {
      clearTimeout(timeout);
      reject(new Error('WebSocket connection failed'));
    }, { once: true });
    socket.addEventListener('message', event => {
      clearTimeout(timeout);
      resolve({ socket, challenge: event.data });
    }, { once: true });
  });
}

async function authenticate(protocol, key, user = 'admin', password = 'secret', malformed) {
  const { socket, challenge } = await connect(`${config.interface}/${protocol}`);
  try {
    const sid = protocol === 'ws1' ? challenge.split(';')[2] : JSON.parse(challenge).args[1];
    const credentials = Buffer.from(`${user}:${password}`);
    const plaintext = Buffer.alloc(Math.ceil(credentials.length / 16) * 16);
    credentials.copy(plaintext);
    const cipher = createCipheriv('aes-128-cbc', Buffer.from(key, 'hex'), Buffer.from(sid, 'hex'));
    cipher.setAutoPadding(false);
    let crypto = Buffer.concat([cipher.update(plaintext), cipher.final()]).toString('hex');
    let iv = sid;
    if (malformed === 'hex') crypto = 'Z'.repeat(32);
    if (malformed === 'partial') crypto = '00';
    if (malformed === 'oversize') crypto = '00'.repeat(2048);
    if (malformed === 'iv') iv = (sid[0] === '0' ? '1' : '0') + sid.slice(1);
    const response = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Authentication response timeout')), 3000);
      socket.addEventListener('message', event => {
        clearTimeout(timeout);
        resolve(event.data);
      }, { once: true });
    });
    socket.send(protocol === 'ws1' ? `C;AUTH;${iv};${crypto}` :
      JSON.stringify({ type: 'CMD', command: 'AUTH', args: { iv, crypto } }));
    const text = await response;
    return protocol === 'ws1' ? text.startsWith('+;AUTH1;') :
      JSON.parse(text).type === '+' && JSON.parse(text).command === 'AUTH';
  } finally {
    socket.close();
  }
}

try {
  for (const keyFile of [null, '00112233445566778899aabbccddeeff', '00112233445566778899aabbccddeeff' + 'ab'.repeat(16)]) {
    const portServer = createServer();
    portServer.listen(0, '127.0.0.1');
    await once(portServer, 'listening');
    const port = portServer.address().port;
    await new Promise(resolve => portServer.close(resolve));
    config.interface = `ws://127.0.0.1:${port}`;
    delete config['key-file'];
    if (keyFile) {
      await writeFile(keyPath, keyFile + '\n');
      config['key-file'] = keyPath;
    }
    await writeFile(configPath, JSON.stringify(config));
    launch();
    let ready = false;
    for (let attempt = 0; attempt < 40; ++attempt) {
      if (server.exitCode !== null) throw new Error(`Test server exited:\n${output}`);
      try {
        const { socket } = await connect(`${config.interface}/ws1`);
        socket.close();
        ready = true;
        break;
      } catch {
        await delay(100);
      }
    }
    assert.ok(ready, `Test server did not become ready:\n${output}`);
    const key = keyFile ? keyFile.slice(0, 32) : defaultKey;
    for (const protocol of ['ws1', 'ws2']) {
      for (const user of ['admin', 'adminuser', 'administrator-with-a-long-name']) {
        assert.equal(await authenticate(protocol, key, user), true, `${protocol}: ${user}`);
      }
      assert.equal(await authenticate(protocol, key, 'unknown-user'), false);
      assert.equal(await authenticate(protocol, key, 'admin', 'wrong-password'), false);
      assert.equal(await authenticate(protocol, 'ff'.repeat(16)), false);
      for (const malformed of ['hex', 'partial', 'oversize', 'iv']) {
        assert.equal(await authenticate(protocol, key, 'admin', 'secret', malformed), false);
      }
      console.log(`${protocol}: login, exact/multi-block credentials, and invalid-input tests passed (${keyFile ? keyFile.length / 2 + '-byte key file' : 'default key'})`);
    }
    await stopServer();
  }

  for (const invalidKey of ['', '00', 'zz'.repeat(16)]) {
    await writeFile(keyPath, invalidKey);
    config['key-file'] = keyPath;
    await writeFile(configPath, JSON.stringify(config));
    launch();
    const timeout = setTimeout(() => server.kill('SIGKILL'), 5000);
    const [code] = await serverExit;
    clearTimeout(timeout);
    assert.equal(code, 1, `Invalid key must fail startup:\n${output}`);
  }
  console.log('Invalid key files correctly prevent startup.');

  delete config['key-file'];
  await writeFile(configPath, JSON.stringify(config));
  for (const invalidUsers of [
    JSON.stringify({ users: [{ ...admin, password: 'DO_NOT_LOG_PASSWORD' }] }),
    '{"users":[{"name":"admin","password":"DO_NOT_LOG_PASSWORD',
  ]) {
    await writeFile(usersPath, invalidUsers);
    launch();
    const timeout = setTimeout(() => server.kill('SIGKILL'), 5000);
    const [code] = await serverExit;
    clearTimeout(timeout);
    assert.equal(code, 1, `Invalid user file must fail startup:\n${output}`);
    assert.ok(!output.includes('DO_NOT_LOG_PASSWORD'), 'User-file diagnostics leaked a credential');
  }
  console.log('Invalid user files prevent startup without exposing credential values.');
} finally {
  await stopServer();
  for (const file of [configPath, usersPath, keyPath]) await unlink(file);
  await rmdir(directory);
}
