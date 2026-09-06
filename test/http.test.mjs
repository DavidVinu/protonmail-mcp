// Contract for the HTTP entry point.
//
// This entry point is the only one meant to be reachable from a network, so
// these tests are mostly about the door rather than the tools. The tools are
// the same ones stdio uses and have their own contract in tools.test.mjs.
//
// The server is started as a real child process on an ephemeral port and
// queried over HTTP. himalaya is replaced by the same mock the tool contract
// uses, through HIMALAYA_BIN.

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import test from 'node:test';

import { HTTP, TEST_HOME, mock, tmp } from './helpers.mjs';

const TOKEN = 'contract-' + 'x'.repeat(40);
const WRONG = 'contract-' + 'y'.repeat(40);

const tokenFile = path.join(tmp, 'http-token');
fs.writeFileSync(tokenFile, TOKEN + '\n');
fs.chmodSync(tokenFile, 0o600);

const MOCK_LOG = path.join(tmp, 'http-log.jsonl');

let child;
let base;

/** Start the server and wait for its readiness line. */
function start(env = {}) {
  return new Promise((done, fail) => {
    const p = spawn(process.execPath, [HTTP], {
      env: {
        ...process.env,
        HOME: TEST_HOME,
        HIMALAYA_BIN: mock,
        PROTONMAIL_MCP_ATTACHMENT_DIR: path.join(tmp, 'http-attachments'),
        PROTONMAIL_MCP_TOKEN_FILE: tokenFile,
        PROTONMAIL_MCP_PORT: '0',
        MOCK_LOG,
        MOCK_STDOUT: '{"mailboxes":[]}',
        ...env,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stderr = '';
    const timer = setTimeout(() => fail(
      new Error('server never reported ready: ' + stderr)), 15000);
    p.stderr.on('data', (d) => {
      stderr += d;
      const m = /ready on http:\/\/([0-9.]+):(\d+)/.exec(stderr);
      if (m) { clearTimeout(timer); done({ p, base: `http://${m[1]}:${m[2]}` }); }
    });
    p.on('exit', (code) => {
      clearTimeout(timer);
      fail(new Error(`server exited with ${code}: ${stderr}`));
    });
  });
}

const INIT = {
  jsonrpc: '2.0', id: 1, method: 'initialize',
  params: {
    protocolVersion: '2024-11-05', capabilities: {},
    clientInfo: { name: 'contract', version: '0' },
  },
};

async function post(body, { token = TOKEN, path: p = '/mcp', session } = {}) {
  const headers = {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
  };
  if (token !== null) headers.authorization = `Bearer ${token}`;
  if (session) headers['mcp-session-id'] = session;
  const res = await fetch(base + p, {
    method: 'POST', headers, body: JSON.stringify(body),
  });
  const text = await res.text();
  return {
    status: res.status, text,
    session: res.headers.get('mcp-session-id'), headers: res.headers,
  };
}

/** GET, for the OAuth discovery paths. */
async function get(p, { token = null } = {}) {
  const headers = {};
  if (token !== null) headers.authorization = `Bearer ${token}`;
  const res = await fetch(base + p, { headers });
  return { status: res.status, headers: res.headers };
}

/** Pull the JSON-RPC payload out of a response, event-stream included. */
function payload(text, id) {
  for (const line of text.split('\n')) {
    const raw = line.startsWith('data:') ? line.slice(5).trim() : line.trim();
    if (!raw.startsWith('{')) continue;
    try {
      const d = JSON.parse(raw);
      if (d.id === id) return d;
    } catch { /* keep looking */ }
  }
  return null;
}

test.before(async () => {
  const started = await start();
  child = started.p;
  base = started.base;
});

// Without this the running server keeps the test run open: node waits for
// every child process to end, and this one deliberately keeps running until it
// is signalled.
test.after(() => { child?.kill('SIGTERM'); });

// ------------------------------------------------------------------ door ----

test('Without a token: 401, and nothing from the server', async () => {
  const r = await post(INIT, { token: null });
  assert.equal(r.status, 401);
  assert.ok(!r.text.includes('serverInfo'), 'nothing from the MCP server leaks');
});

test('With a wrong token: 401', async () => {
  const r = await post(INIT, { token: WRONG });
  assert.equal(r.status, 401);
});

test('A token that is only a prefix is not enough', async () => {
  const r = await post(INIT, { token: TOKEN.slice(0, 20) });
  assert.equal(r.status, 401);
});

test('With the right token the MCP server answers', async () => {
  const r = await post(INIT);
  assert.equal(r.status, 200);
  assert.ok(r.text.includes('protonmail'), r.text.slice(0, 200));
});

test('An unknown path is 404 even with a valid token', async () => {
  const r = await post(INIT, { path: '/admin' });
  assert.equal(r.status, 404);
});

// ----------------------------------------------------------------- OAuth ----

test('The server never claims to speak OAuth', async () => {
  // Measured 2026-09-06: with `WWW-Authenticate: Bearer` in the 401, Claude
  // takes the server for an OAuth server, attempts dynamic client
  // registration and fails ("Couldn't register with ... sign-in service").
  // This server uses a static token, so it must not send that header.
  const r = await post(INIT, { token: null });
  assert.equal(r.status, 401);
  assert.equal(r.headers.get('www-authenticate'), null,
    'no WWW-Authenticate, or the client starts an OAuth flow');
});

test('The OAuth discovery paths answer 404, not 401', async () => {
  // A 401 there means, to the client, "OAuth exists here, you are merely not
  // signed in". 404 means "there is no OAuth here", which is the truth.
  for (const p of [
    '/.well-known/oauth-protected-resource',
    '/.well-known/oauth-protected-resource/mcp',
    '/.well-known/oauth-authorization-server',
  ]) {
    const r = await get(p);
    assert.equal(r.status, 404, p);
    assert.equal(r.headers.get('www-authenticate'), null, p);
  }
});

test('The discovery paths give nothing away about the token', async () => {
  const without = await get('/.well-known/oauth-protected-resource');
  const with_ = await get('/.well-known/oauth-protected-resource', { token: TOKEN });
  assert.equal(without.status, with_.status,
    'same answer with and without a token, otherwise it is an oracle');
});

// ----------------------------------------------------------------- tools ----

test('The server offers the same twelve tools as stdio', async () => {
  const init = await post(INIT);
  assert.equal(init.status, 200);
  const session = init.session;
  assert.ok(session, 'the server issues a session id');

  await post({ jsonrpc: '2.0', method: 'notifications/initialized' }, { session });
  const list = await post(
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }, { session });
  const d = payload(list.text, 2);
  assert.ok(d, list.text.slice(0, 300));
  const names = d.result.tools.map((x) => x.name).sort();
  assert.deepEqual(names, [
    'attachment_download', 'attachment_list', 'envelope_list',
    'envelope_search', 'flag_add', 'flag_remove', 'mailbox_list',
    'message_compose', 'message_forward', 'message_move', 'message_read',
    'message_reply',
  ]);
  for (const forbidden of ['send', 'delete', 'delegate', 'forward_address']) {
    assert.ok(!names.some((n) => n.includes(forbidden)),
      `no tool may be named '${forbidden}'`);
  }
});

test('A tool call reaches himalaya with the expected argv', async () => {
  const init = await post(INIT);
  const session = init.session;
  await post({ jsonrpc: '2.0', method: 'notifications/initialized' }, { session });
  fs.rmSync(MOCK_LOG, { force: true });
  await post({
    jsonrpc: '2.0', id: 3, method: 'tools/call',
    params: { name: 'mailbox_list', arguments: {} },
  }, { session });
  const lines = fs.readFileSync(MOCK_LOG, 'utf8').trim().split('\n');
  assert.deepEqual(JSON.parse(lines[0]).argv, ['mailbox', 'list', '--json']);
});

test('An unknown session id answers 404, so the client re-initializes', async () => {
  // Sessions live in memory only, so every restart of this service throws all
  // of them away. 404 is what tells a client "this session is gone, start a
  // new one". Anything else and it keeps retrying a session that will never
  // come back: measured 2026-09-06, a working connector stayed broken across
  // a restart because the request fell through to a fresh, uninitialized
  // transport and got `Bad Request: Server not initialized` forever.
  const r = await post({
    jsonrpc: '2.0', id: 9, method: 'tools/call',
    params: { name: 'mailbox_list', arguments: {} },
  }, { session: '00000000-0000-0000-0000-000000000000' });
  assert.equal(r.status, 404, r.text.slice(0, 200));
  assert.ok(!r.text.includes('not initialized'), r.text.slice(0, 200));
});

test('A fresh initialize still works without a session id', async () => {
  // The counter-check: the 404 above must not block the normal path.
  const r = await post(INIT);
  assert.equal(r.status, 200);
  assert.ok(r.session, 'a new session id is issued');
});

// ------------------------------------------------------------- start-up ----

test('The server binds to the loopback only, never to 0.0.0.0', async () => {
  assert.ok(base.startsWith('http://127.0.0.1:'),
    `bound to ${base}; exposure is the job of a proxy you control, not of this process`);
});

test('Without a token file the server does not start at all', async () => {
  await assert.rejects(
    () => start({ PROTONMAIL_MCP_TOKEN_FILE: path.join(tmp, 'does-not-exist') }),
    /exited with/,
  );
});

test('A token file readable by others is refused', async () => {
  const open = path.join(tmp, 'token-open');
  fs.writeFileSync(open, TOKEN + '\n');
  fs.chmodSync(open, 0o644);
  await assert.rejects(
    () => start({ PROTONMAIL_MCP_TOKEN_FILE: open }), /exited with/);
});

test('A token that is too short is refused', async () => {
  const short = path.join(tmp, 'token-short');
  fs.writeFileSync(short, 'short\n');
  fs.chmodSync(short, 0o600);
  await assert.rejects(
    () => start({ PROTONMAIL_MCP_TOKEN_FILE: short }), /exited with/);
});
