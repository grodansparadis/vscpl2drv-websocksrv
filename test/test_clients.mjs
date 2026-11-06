import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rmdir, unlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const [app, driver, cWs1, cWs2] = process.argv.slice(2);
if (!app || !driver || !cWs1 || !cWs2 || typeof WebSocket === 'undefined') {
  throw new Error('Node.js 22+: node test/test_clients.mjs <testapp> <driver> <C-WS1-client> <C-WS2-client>');
}

function run(command, args, env, timeout = 25000) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env: { ...process.env, ...env } });
    let output = '';
    child.stdout.on('data', data => { output += data; });
    child.stderr.on('data', data => { output += data; });
    const timer = setTimeout(() => child.kill('SIGKILL'), timeout);
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('exit', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, output });
    });
  });
}

const directory = await mkdtemp(join(tmpdir(), 'websocksrv-clients-'));
const usersPath = join(directory, 'users.json');
const configPath = join(directory, 'config.json');
const users = JSON.parse(await readFile('debug/users.json', 'utf8'));
const admin = users.users.find(user => user.name === 'admin');
const names = ['admin', 'adminuser', 'administrator-with-a-long-name', 'adm\u00edn'];
for (const name of names.slice(1)) users.users.push({ ...admin, name });
await writeFile(usersPath, JSON.stringify(users));
const config = JSON.parse(await readFile('debug/linux/websocksrv.json', 'utf8'));
config['path-users'] = usersPath;
config.logging['file-enable-log'] = false;
const portServer = createServer();
portServer.listen(0, '127.0.0.1');
await once(portServer, 'listening');
const port = portServer.address().port;
await new Promise(resolve => portServer.close(resolve));
config.interface = `ws://127.0.0.1:${port}`;
await writeFile(configPath, JSON.stringify(config));

const server = spawn(resolve(app), ['--driver', resolve(driver), '--config', configPath]);
const serverExit = once(server, 'close');
let serverOutput = '';
server.stdout.on('data', data => { serverOutput += data; });
server.stderr.on('data', data => { serverOutput += data; });
const clients = [
  ['Python WS1', process.env.PYTHON || 'python3', ['test/test_ws1.py'], 'ws1'],
  ['Python WS2', process.env.PYTHON || 'python3', ['test/test_ws2.py'], 'ws2'],
  ['JavaScript WS1', process.execPath, ['test/test_ws1.js'], 'ws1'],
  ['JavaScript WS2', process.execPath, ['test/test_ws2.js'], 'ws2'],
  ['C WS1', resolve(cWs1), [], 'ws1'],
  ['C WS2', resolve(cWs2), [], 'ws2'],
];

async function stopServer() {
  if (server.exitCode === null && server.signalCode === null) {
    server.kill('SIGINT');
    const timer = setTimeout(() => server.kill('SIGKILL'), 5000);
    try {
      await serverExit;
    } finally {
      clearTimeout(timer);
    }
  } else {
    await serverExit;
  }
}

try {
  let ready = false;
  for (let attempt = 0; attempt < 50; ++attempt) {
    assert.equal(server.exitCode, null, `Server exited:\n${serverOutput}`);
    try {
      const response = await fetch(`http://127.0.0.1:${port}/ws1`);
      ready = response.status === 426;
      if (ready) break;
    } catch (error) {
      if (error.cause?.code !== 'ECONNREFUSED') throw error;
    }
    await delay(100);
  }
  assert.ok(ready, `Server did not become ready:\n${serverOutput}`);

  // Run different protocols concurrently to catch cross-protocol forwarding bugs.
  for (const username of names) {
    const results = await Promise.all(clients.map(async ([name, command, args, protocol]) => {
      const result = await run(command, args, {
        VSCP_WS_URL: `${config.interface}/${protocol}`,
        VSCP_USERNAME: username,
        VSCP_PASSWORD: 'secret',
        VSCP_KEY_HEX: '2DBB079A38985AF00EBEEFE22F9FFA0E',
        VSCP_TEST_SECONDS: '7',
        NO_PROXY: '127.0.0.1,localhost',
        no_proxy: '127.0.0.1,localhost',
      });
      return { name, ...result };
    }));
    for (const result of results) {
      assert.equal(result.code, 0, `${result.name} (${username}):\n${result.output}`);
      assert.match(result.output, /Authenticated|Authentication successful|authenticated/i);
      assert.match(result.output, /Event received|Event: (E;|\d)|Recv: E;|"type": "EVENT"/);
      assert.match(result.output, /CLOSE/);
      assert.doesNotMatch(result.output, /undefined|Error reply|Command rejected|Traceback/);
      console.log(`${result.name}: login, commands, bidirectional events, CLOSE passed (${username})`);
    }
  }

  for (const [label, password, key] of [
    ['wrong password', 'wrong-password', '2DBB079A38985AF00EBEEFE22F9FFA0E'],
    ['wrong key', 'secret', 'ff'.repeat(16)],
  ]) {
    const failures = await Promise.all(clients.map(async ([name, command, args, protocol]) => ({
      name,
      ...await run(command, args, {
        VSCP_WS_URL: `${config.interface}/${protocol}`,
        VSCP_USERNAME: 'admin',
        VSCP_PASSWORD: password,
        VSCP_KEY_HEX: key,
        VSCP_TEST_SECONDS: '7',
        NO_PROXY: '127.0.0.1,localhost',
        no_proxy: '127.0.0.1,localhost',
      }),
    })));
    for (const result of failures) {
      assert.equal(result.code, 1, `${result.name}: failed login must exit with error:\n${result.output}`);
      console.log(`${result.name}: ${label} rejected with nonzero exit status`);
    }
  }
  // Shutdown flushes buffered host logs; 'close' also waits for both output pipes.
  await stopServer();
  assert.ok((serverOutput.match(/Received event: class=30, type=5/g) || []).length === clients.length * names.length,
    `Server did not receive every client's demonstration event:\n${serverOutput}`);
} finally {
  await stopServer();
  await unlink(configPath);
  await unlink(usersPath);
  await rmdir(directory);
}
