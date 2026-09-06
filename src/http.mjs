#!/usr/bin/env node
// Proton Mail over Streamable HTTP, for MCP clients that connect to a URL.
//
// WHAT FOR. A stdio server is started by the client as a child process and is
// therefore tied to one machine. It works for a CLI on that machine, but not
// for a browser client and not for a phone. A hosted connector reaches the
// server over HTTPS, so it has to be reachable.
//
// WHAT DOES NOT CHANGE. The tools are the same ones stdio uses (tools.mjs):
// no send path, no delete path, the one-time-code filter and the recipient
// rule for reply drafts.
//
// WHAT DOES CHANGE, and this is the point: whoever holds the token reads the
// mail, downloads attachments, marks messages as seen and creates drafts.
// Therefore:
//
//   * The server binds to 127.0.0.1 only. Exposure to the outside is the job
//     of a reverse proxy or tunnel you control, never of this process.
//   * Without a token file it refuses to start. If that file is readable by
//     group or others, or the token is too short, it also refuses to start.
//   * The comparison is constant-time, so the token cannot be guessed
//     character by character.
//   * Every request without a valid token ends in 401 before anything reaches
//     the MCP server.
//
// NO OAUTH. This server takes a static bearer token. The discovery paths must
// therefore answer 404, and they must do so BEFORE the token check: a 401 on
// /.well-known/* means "OAuth exists here, you are merely not signed in", and
// a client that believes it will try dynamic client registration and then fail
// with a confusing error. Observed 2026-09-06 with Claude's custom connectors:
//   401 GET /.well-known/oauth-protected-resource
//   401 GET /.well-known/oauth-authorization-server
// and in the UI "Couldn't register with ... sign-in service". For the same
// reason the 401 carries no WWW-Authenticate header: that header is the
// invitation to a flow that does not exist here.

import crypto, { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { register, resolveConfig } from './tools.mjs';

const CONFIG = resolveConfig();

const TOKEN_FILE = process.env.PROTONMAIL_MCP_TOKEN_FILE
  ?? `${process.env.HOME}/.config/protonmail-mcp/token`;
const PORT = Number(process.env.PROTONMAIL_MCP_PORT ?? 18790);
const ADDRESS = process.env.PROTONMAIL_MCP_ADDRESS ?? '127.0.0.1';
const MIN_LENGTH = 32;

function bail(reason) {
  process.stderr.write(`protonmail-mcp: ${reason}\n`);
  process.exit(2);
}

/** Read the token, checking the file's permissions on the way. */
function readToken() {
  let st;
  try {
    st = fs.lstatSync(TOKEN_FILE);
  } catch {
    bail(`token file missing: ${TOKEN_FILE}. Create it with\n`
      + `  mkdir -p "$(dirname ${TOKEN_FILE})" && `
      + `install -m 0600 /dev/null ${TOKEN_FILE} && `
      + `openssl rand -hex 32 > ${TOKEN_FILE}`);
  }
  if (!st.isFile() || st.nlink !== 1) {
    bail(`${TOKEN_FILE}: not a single regular file.`);
  }
  if ((st.mode & 0o077) !== 0) {
    bail(`${TOKEN_FILE}: readable by group or others `
      + `(${(st.mode & 0o777).toString(8)}). Expected 0600.`);
  }
  const token = fs.readFileSync(TOKEN_FILE, 'utf8').trim();
  if (token.length < MIN_LENGTH) {
    bail(`token is shorter than ${MIN_LENGTH} characters; too little for an `
      + 'endpoint meant to be reachable from the network.');
  }
  return token;
}

const TOKEN_HASH = crypto.createHash('sha256').update(readToken()).digest();

/** Constant-time comparison over hashes, so lengths give nothing away. */
function tokenOk(header) {
  if (typeof header !== 'string') return false;
  const hit = /^Bearer\s+(.+)$/i.exec(header.trim());
  if (!hit) return false;
  const given = crypto.createHash('sha256').update(hit[1].trim()).digest();
  return crypto.timingSafeEqual(given, TOKEN_HASH);
}

// One session, one transport. On initialize the client receives a session id
// and sends it back in the mcp-session-id header from then on.
const sessions = new Map();

function newSession() {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: randomUUID,
    onsessioninitialized: (id) => sessions.set(id, transport),
    onsessionclosed: (id) => sessions.delete(id),
  });
  transport.onclose = () => {
    if (transport.sessionId) sessions.delete(transport.sessionId);
  };
  const server = new McpServer({ name: 'protonmail', version: '1.0.0' });
  register(server, CONFIG);
  server.connect(transport);
  return transport;
}

/** One line per request to stderr, i.e. to the journal.
 *
 * Without this there is no way to tell from the outside whether a client is
 * reaching the server at all: an attempt that fails at the door looks exactly
 * like no attempt. Method, path, status and origin are logged; never the
 * token, never any content.
 */
function log(req, status, note = '') {
  const from = req.headers['cf-connecting-ip']
    ?? req.socket.remoteAddress ?? '?';
  const who = req.headers['user-agent']?.slice(0, 40) ?? '-';
  process.stderr.write(
    `protonmail-mcp: ${status} ${req.method} ${req.url} `
    + `from ${from} (${who})${note ? ' ' + note : ''}\n`,
  );
}

/** Log once the response is actually finished, with the status it really had.
 *
 * Logging an assumed 200 before handing the request to the transport is a lie
 * whenever the transport answers something else, and it hides exactly the
 * failures this log exists to reveal. Found 2026-09-06: the journal showed
 * nothing but 200 while every tool call from a stale session was answering
 * 400.
 */
function logWhenDone(req, res, note = '') {
  res.on('finish', () => log(req, res.statusCode, note));
  res.on('close', () => { if (!res.writableEnded) log(req, res.statusCode, 'aborted'); });
}

const service = http.createServer(async (req, res) => {
  // Before the token check, and with the same answer either way -- otherwise
  // it would be an oracle. See the header comment for why this is a 404.
  if (req.url?.startsWith('/.well-known/')) {
    log(req, 404, 'no OAuth on this server');
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
    return;
  }

  // The door first. Nothing reaches the MCP server above this line, not even
  // an initialize.
  if (!tokenOk(req.headers.authorization)) {
    log(req, 401, req.headers.authorization ? 'bad token' : 'no token');
    res.writeHead(401, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      error: 'unauthorized',
      hint: 'A static bearer token is expected in the Authorization header; '
        + 'this server has no OAuth flow.',
    }));
    return;
  }
  if (req.url !== '/mcp' && !req.url?.startsWith('/mcp?')) {
    log(req, 404, 'unknown path');
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
    return;
  }
  // An unknown session id must answer 404, not 400. 404 is what tells the
  // client "this session is gone, start a new one"; anything else and it keeps
  // retrying a session that will never come back. This matters after every
  // restart of this service: sessions live in memory only, so a redeploy
  // invalidates every one of them. Measured 2026-09-06 -- a connector that had
  // worked stayed broken across a restart, answering
  // `Bad Request: Server not initialized` to every tool call, because the
  // request fell through to a fresh uninitialized transport.
  const id = req.headers['mcp-session-id'];
  if (typeof id === 'string' && id && !sessions.has(id)) {
    log(req, 404, 'unknown session, client should re-initialize');
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      jsonrpc: '2.0', id: null,
      error: { code: -32001, message: 'Session not found; re-initialize.' },
    }));
    return;
  }
  try {
    logWhenDone(req, res);
    const transport = (typeof id === 'string' && sessions.get(id))
      || newSession();
    await transport.handleRequest(req, res);
  } catch (error) {
    process.stderr.write(`protonmail-mcp: ${error?.message ?? error}\n`);
    if (!res.headersSent) {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'internal' }));
    }
  }
});

service.listen(PORT, ADDRESS, () => {
  const { port } = service.address();
  // This line is the readiness signal the contract test waits for.
  process.stderr.write(`protonmail-mcp: ready on http://${ADDRESS}:${port}/mcp\n`);
});

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    service.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  });
}
