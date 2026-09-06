// Shared harness for the tool contracts.
//
// The real server runs as a child process over stdio. himalaya is replaced by
// a mock: HIMALAYA_BIN points at a small script that appends its argv and its
// environment to a log file and then prints whatever the test asked for.
//
// Note what is NOT faked: the server itself, the MCP protocol, the argument
// schemas and both filters. Only the far end of the pipe is a stand-in.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
export const REPO = path.dirname(here);
export const STDIO = path.join(REPO, 'src/stdio.mjs');
export const HTTP = path.join(REPO, 'src/http.mjs');

const MOCK = `#!${process.execPath}
import fs from 'node:fs';
const argv = process.argv.slice(2);
fs.appendFileSync(process.env.MOCK_LOG,
  JSON.stringify({ argv, env: process.env }) + '\\n');
// The recipient check reads the original with 'read --raw'; that call gets its
// own output and its own exit code, so a test can make the check fail without
// making every other call fail too.
if (argv.includes('read') && argv.includes('--raw')) {
  process.stdout.write(process.env.MOCK_RAW ?? '');
  process.exit(Number(process.env.MOCK_RAW_CODE ?? '0'));
}
process.stdout.write(process.env.MOCK_STDOUT ?? '');
process.stderr.write(process.env.MOCK_STDERR ?? '');
process.exit(Number(process.env.MOCK_CODE ?? '0'));
`;

export const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'protonmail-mcp-test-'));
export const mock = path.join(tmp, 'himalaya-mock.mjs');
fs.writeFileSync(mock, MOCK);
fs.chmodSync(mock, 0o755);

// A home of its own. The recipient rule reads the account address from
// himalaya's configuration; a contract must not depend on whose machine it
// runs on, and the attachment directory stays isolated this way too.
export const TEST_HOME = path.join(tmp, 'home');
export const OWN_ADDRESS = 'me@example.org';
fs.mkdirSync(path.join(TEST_HOME, '.config/himalaya'), { recursive: true });
fs.writeFileSync(path.join(TEST_HOME, '.config/himalaya/config.toml'),
  `[accounts.probe]\ndefault = true\nemail = "${OWN_ADDRESS}"\n`);

/** A raw message addressed to the account's own address. */
export const TO_OWN = ['From: Alice <alice@example.org>', `To: <${OWN_ADDRESS}>`,
  '', 'Text', ''].join('\n');


process.on('exit', () => fs.rmSync(tmp, { recursive: true, force: true }));

/** Start the server, send requests, collect answers and observed argv. */
export function callServer(requests, { stdout = '', code = 0, env = {},
  raw = '', rawCode = 0, entry = STDIO } = {}) {
  const log = path.join(tmp, `log-${Math.random()}.jsonl`);
  const child = spawn(process.execPath, [entry], {
    env: {
      ...process.env,
      HOME: TEST_HOME,
      HIMALAYA_BIN: mock,
      PROTONMAIL_MCP_ATTACHMENT_DIR: path.join(tmp, 'attachments'),
      MOCK_LOG: log,
      MOCK_STDOUT: stdout,
      MOCK_CODE: String(code),
      MOCK_RAW: raw,
      MOCK_RAW_CODE: String(rawCode),
      ...env,
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const lines = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {
      protocolVersion: '2024-11-05', capabilities: {},
      clientInfo: { name: 'contract', version: '0' } } },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    ...requests,
  ];
  child.stdin.write(lines.map((l) => JSON.stringify(l)).join('\n') + '\n');
  child.stdin.end();

  return new Promise((done) => {
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.on('close', () => {
      const answers = out.split('\n').filter(Boolean).map((l) => {
        try { return JSON.parse(l); } catch { return null; }
      }).filter(Boolean);
      const calls = fs.existsSync(log)
        ? fs.readFileSync(log, 'utf8').split('\n').filter(Boolean)
          .map((l) => JSON.parse(l))
        : [];
      done({ answers, seen: calls.at(-1) ?? null, calls });
    });
  });
}

export const tool = (name, args, id = 2) => ({
  jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args },
});

export const answerTo = (answers, id) => answers.find((a) => a.id === id);

// One call per tool. Two contracts measure the whole argv against this list:
// one against the options himalaya actually has, one against the options that
// must never appear here.
export const EVERY_TOOL = [
  ['mailbox_list', {}],
  ['envelope_list', { mailbox: 'inbox' }],
  ['envelope_search', { mailbox: 'inbox', query: 'from alice' }],
  ['message_read', { id: '1', mailbox: 'inbox' }],
  ['attachment_list', { id: '1', mailbox: 'inbox' }],
  ['attachment_download', { id: '1', mailbox: 'inbox' }],
  ['flag_add', { id: '1', mailbox: 'inbox', flag: 'seen' }],
  ['flag_remove', { id: '1', mailbox: 'inbox', flag: 'seen' }],
  ['message_move', { id: '1' }],
  ['message_forward', { id: '1', mailbox: 'inbox', body: 'T', save: true }],
  ['message_compose', { to: 'a@x.org', subject: 'S', body: 'T', save: true }],
  ['message_reply', { id: '1', mailbox: 'inbox', body: 'T', save: true }],
];
