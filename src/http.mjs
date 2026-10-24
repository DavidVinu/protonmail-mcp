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

/** A transport without session management, for exactly one request.
 *
 * Claude's connector sends some requests with no session id and without a
 * prior initialize. A session transport answers those with 400 `Server not
 * initialized`; measured 2026-10-24, that was about a quarter of all POSTs.
 * The tools keep no state between calls, so such a request can simply be
 * served on its own.
 */
function oneShot(res) {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });
  const server = new McpServer({ name: 'protonmail', version: '1.0.0' });
  register(server, CONFIG);
  server.connect(transport);
  res.on('close', () => { transport.close(); server.close(); });
  return transport;
}

/** Read and parse a request body; undefined if it is not JSON. */
async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    return undefined;
  }
}

function isInitialize(body) {
  return [body].flat().some((m) => m?.method === 'initialize');
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
  const reason = rejectionReason(res);
  res.on('finish', () => log(req, res.statusCode,
    [note, reason() && `error="${reason()}"`].filter(Boolean).join(' ')));
  res.on('close', () => { if (!res.writableEnded) log(req, res.statusCode, 'aborted'); });
}

/** What a request was, without what it said: method, session, protocol.
 *
 * Found 2026-10-24: a quarter of the connector's POSTs answered 400, and the
 * journal could not tell which kind of request they were.
 */
function describe(req, body) {
  const methods = body === undefined ? [] : [body].flat()
    .map((m) => m?.method ?? (m && ('result' in m || 'error' in m) ? 'response' : '?'));
  return [
    methods.length ? `method=${methods.join(',')}` : '',
    `session=${req.headers['mcp-session-id'] ? 'yes' : 'no'}`,
    `proto=${req.headers['mcp-protocol-version'] ?? '-'}`,
  ].filter(Boolean).join(' ');
}

/** Keep the JSON-RPC error message of a 4xx/5xx answer, for the log.
 *
 * These are the transport's own messages (`Server already initialized` and
 * the like), never mail content: a tool result is always a 200.
 */
function rejectionReason(res) {
  let text = '';
  const keep = (chunk) => {
    if (res.statusCode < 400 || !chunk || text.length >= 1024) return;
    text += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
  };
  const { write, end } = res;
  res.write = function (chunk, ...rest) { keep(chunk); return write.call(this, chunk, ...rest); };
  res.end = function (chunk, ...rest) {
    if (typeof chunk !== 'function') keep(chunk);
    return end.call(this, chunk, ...rest);
  };
  return () => {
    try {
      return String(JSON.parse(text).error?.message ?? '').slice(0, 160);
    } catch {
      return '';
    }
  };
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
    log(req, 404, `${describe(req)} unknown session, client should re-initialize`);
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      jsonrpc: '2.0', id: null,
      error: { code: -32001, message: 'Session not found; re-initialize.' },
    }));
    return;
  }
  try {
    // Parsed here rather than in the transport, so the log can name the method.
    const body = req.method === 'POST' ? await readJson(req) : undefined;
    logWhenDone(req, res, describe(req, body));
    if (req.method === 'POST' && body === undefined) {
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0', id: null,
        error: { code: -32700, message: 'Parse error: Invalid JSON' },
      }));
      return;
    }
    if (typeof id === 'string' && id) {
      await sessions.get(id).handleRequest(req, res, body);
      return;
    }
    if (req.method !== 'POST') {
      await newSession().handleRequest(req, res);
      return;
    }
    // Without a session id the body decides: an initialize opens a session,
    // anything else is served once (see oneShot).
    const transport = isInitialize(body) ? newSession() : oneShot(res);
    await transport.handleRequest(req, res, body);
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
