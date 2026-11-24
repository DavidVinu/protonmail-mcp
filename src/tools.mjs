// The tools of the Proton Mail MCP server, shared by the stdio and HTTP entry
// points. Neither the transport nor the process environment is decided here.
//
// WHAT THE BOUNDARY IS. This server offers fourteen fixed tools. Every argv is
// assembled from typed parameters; there is no free-form command, no send
// path, no delete path, and no shell. A permission system could express all
// of that -- it is a question of WHETHER a tool may run.
//
// Two things in this file are different, and they are the reason the server
// exists rather than a thin wrapper:
//
//   1. The one-time-code filter (otp-filter.mjs). It changes WHAT the answer
//      contains. No permission dialog can do that.
//   2. The recipient rule for reply drafts: a draft is only created if the
//      original message was addressed to the account's own address. That is a
//      comparison of two header lines, not a tool right.
//
// WHAT THIS SERVER CANNOT DO, structurally rather than by policy:
//
//   * Send. No tool builds `--send`, and `message send` is not exposed. The
//     second leg is yours: point it at a himalaya configuration that has no
//     SMTP section, and sending is impossible even if this file were wrong.
//   * Delete. The only move is Drafts -> Trash, and Trash is recoverable.
//   * Reach a different configuration. HIMALAYA_* is stripped from the child
//     environment, so an ambient HIMALAYA_CONFIG cannot steer it. Pointing it
//     somewhere else is a deliberate act at service-definition time, via
//     PROTONMAIL_MCP_HIMALAYA_CONFIG.

import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
import { redact, scrub } from './otp-filter.mjs';
import { ALL_MAIL, MAX_MESSAGES, QUERY_WORDS, collectThread } from './thread.mjs';

const FLAGS = ['seen', 'answered', 'flagged'];

// A MIME part position. Digits only, because it lands in argv as a positional:
// anything starting with '-' would be read as an option instead.
const PART_ID = z.string().regex(/^\d+$/);

const MAX_TEXT = 200000;

const MAILBOX = z.string().min(1).describe('folder the id belongs to, as given in the '
  + 'envelope (UIDs differ per folder, e.g. inbox or All Mail)');

const DEFAULT_HIMALAYA_CONFIG = '.config/himalaya/config.toml';

/** Resolve configuration from the environment, once, at start-up.
 *
 * `HIMALAYA_BIN` is a convenience, not a boundary: anyone who can set the
 * environment of this process can already run any binary as this user. The
 * guarantees above live in argv construction and in the two filters, and none
 * of them can be reached through the environment.
 */
export function resolveConfig(env = process.env) {
  const home = env.HOME ?? '';
  return {
    himalaya: env.HIMALAYA_BIN || 'himalaya',
    // himalaya accepts several paths separated by ':'; the account lookup
    // below reads the first one.
    configPath: env.PROTONMAIL_MCP_HIMALAYA_CONFIG || null,
    attachmentDir: env.PROTONMAIL_MCP_ATTACHMENT_DIR
      || `${home}/.local/share/protonmail-mcp/attachments`,
    pdftotext: env.PDFTOTEXT_BIN || 'pdftotext',
    home,
  };
}

/** Run himalaya. No shell, and no HIMALAYA_* in the child environment.
 *
 * HIMALAYA_CONFIG would allow a substituted configuration, and himalaya's
 * `password.command` is executed through a shell. Reproduced 2026-09-02.
 * HOME stays: himalaya finds its configuration through it.
 */
function run(config, argv) {
  const full = config.configPath
    ? ['--config', config.configPath, ...argv]
    : argv;
  return exec(config.himalaya, full);
}

function exec(bin, argv, { timeout } = {}) {
  return new Promise((done) => {
    const env = Object.fromEntries(
      Object.entries(process.env).filter(([k]) => !k.startsWith('HIMALAYA_')),
    );
    const child = spawn(bin, argv, { env, timeout });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', (e) => done({ code: 127, out: '', err: String(e) }));
    child.on('close', (code) => done({ code: code ?? 0, out, err }));
  });
}

/** Connection failures where a READ path may end softly.
 *
 * Deliberately narrow: the connection itself, nothing else. An authentication
 * or mailbox error stays hard, because it means someone has to act, not "try
 * again later". Measured 2026-09-02 against a dead port: himalaya exits 1 and
 * writes the error to stdout, not to stderr.
 */
const CONNECTION_ERRORS = [
  'connection refused', 'connection reset', 'connection closed',
  'connection aborted', 'broken pipe', 'no route to host',
  'network is unreachable', 'timed out',
  'os error 104', 'os error 110', 'os error 111', 'os error 113',
];

/** Run, filter, and shape the result as MCP content. A failure is never swallowed. */
async function call(config, argv, { soft = false } = {}) {
  const { code, out, err } = await run(config, argv);
  if (code !== 0) return failure(code, out, err, soft);

  // Every output is filtered before it reaches the model. JSON field by field,
  // so the structure and the IMAP UIDs survive; anything else as plain text.
  let text = out || '(empty)';
  try {
    text = JSON.stringify(scrub(JSON.parse(text)));
  } catch {
    text = redact(text);
  }
  return { content: [{ type: 'text', text: text.slice(0, MAX_TEXT) }] };
}

/** Shape a failed himalaya run: soft for a lost connection on a read path. */
function failure(code, out, err, soft) {
  const lower = (out + err).toLowerCase();
  const hit = soft && CONNECTION_ERRORS.find((m) => lower.includes(m));
  if (hit) {
    // Deliberately WITHOUT an empty `envelopes`. A caller that only looks at
    // that field should fail rather than read this as "no mail". Turning a
    // detected outage into an undetected one is the worse failure.
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          soft: true,
          note: `Mailbox unreachable (${hit}); the data from this query is missing.`,
        }),
      }],
    };
  }
  return {
    isError: true,
    content: [{
      type: 'text',
      text: `himalaya exited with code ${code}.\n`
        + redact((err || out).slice(0, 4000)),
    }],
  };
}

/** The address a draft would be sent from.
 *
 * Read from the same file himalaya itself reads, so the rule needs no
 * configuration of its own and is correct for every user.
 */
async function ownAddress(config) {
  const path = config.configPath?.split(':')[0]
    ?? `${config.home}/${DEFAULT_HIMALAYA_CONFIG}`;
  const text = await readFile(path, 'utf8');
  // No TOML parser needed: we want the email line of the default account.
  const blocks = text.split(/^\[accounts\./m).slice(1);
  const emailOf = (b) => /^\s*email\s*=\s*"([^"]+)"/m.exec(b)?.[1];
  const preferred = blocks.find((b) => /^\s*default\s*=\s*true/m.test(b));
  const address = emailOf(preferred ?? '')
    ?? (blocks.length === 1 ? emailOf(blocks[0]) : null);
  if (!address) throw new Error('cannot determine the account address');
  return address.trim().toLowerCase();
}

/** Recipient rule: reply only from the address the message was sent to.
 *
 * The author's mailbox receives roughly half its mail at addresses this
 * account cannot send from (three Gmail addresses, a university address, two
 * other domains). Without this check every reply draft on those was silently
 * composed from the wrong sender.
 *
 * Only `To` and `Cc` are examined. With mail imported into Proton from Gmail,
 * `Delivered-To` and `X-Original-To` carry Proton's import address rather than
 * the address the mail was actually sent to; checking those lets through
 * exactly the cases this rule is about. Measured 2026-09-05.
 *
 * Fail closed: if the original cannot be read, no draft is created. A rule
 * that quietly stops applying when the mailbox is unreachable is not a rule.
 */
async function checkRecipient(config, id, mailbox) {
  const own = await ownAddress(config);
  const { code, out, err } = await run(config,
    ['message', 'read', id, '--mailbox', mailbox, '--raw']);
  if (code !== 0) {
    return { error: 'Cannot verify which address this message was sent to, so '
      + `no reply draft was created.\n${redact((err || out).slice(0, 300))}` };
  }
  const head = out.split(/\r?\n\r?\n/)[0];
  const lines = head.replace(/\r?\n[ \t]+/g, ' ').split(/\r?\n/);
  const recipients = new Set();
  for (const line of lines) {
    if (!/^(to|cc):/i.test(line)) continue;
    for (const hit of line.slice(line.indexOf(':') + 1).matchAll(
      /[\w.!#$%&'*+/=?^`{|}~-]+@[\w-]+(?:\.[\w-]+)+/g)) {
      recipients.add(hit[0].toLowerCase());
    }
  }
  if (recipients.has(own)) return { ok: true };
  return {
    error: `This message was sent to ${[...recipients].sort().join(', ') || 'no recognisable address'}. `
      + `A reply draft would be composed from ${own}.\n\n`
      + 'Rule: reply drafts only from the address that received the message, '
      + 'without exception. This account can only send from the address named '
      + 'above. Do not retry and do not rephrase; report this verbatim and let '
      + 'the user decide whether and from where to reply. This holds even when '
      + 'the draft was explicitly requested.',
  };
}

const TEXT_TYPES = /^(text\/|application\/(json|xml|csv|ics|.*\+xml|.*\+json)$)/;

/** Turn one downloaded attachment into text pages, or say why it cannot be.
 *
 * Only what can pass the one-time-code filter comes back. Images in
 * particular do not: a 2FA setup mail carries its secret as a QR code, and no
 * text filter sees into a picture.
 */
async function extract(config, file, mime) {
  if (TEXT_TYPES.test(mime)) {
    return { pages: [await readFile(file, 'utf8')] };
  }
  if (mime === 'application/pdf' || file.toLowerCase().endsWith('.pdf')) {
    const { code, out, err } = await exec(config.pdftotext,
      ['-enc', 'UTF-8', '-layout', file, '-'],
      // pdftotext parses bytes the sender chose; a crafted PDF must not hang it.
      { timeout: 60000 });
    if (code !== 0) {
      return { error: `pdftotext exited with code ${code}.\n${redact(err.slice(0, 300))}` };
    }
    // pdftotext ends every page with a form feed.
    const pages = out.split('\f');
    if (pages.at(-1) === '') pages.pop();
    if (!pages.some((p) => p.trim())) {
      return { error: 'This PDF has no text layer (probably a scan).' };
    }
    return { pages };
  }
  return { error: `Attachments of type ${mime} cannot be read as text. `
    + 'attachment_download stores it in the quarantine for the user.' };
}

export function shares(lengths, total) {
  const out = new Array(lengths.length);
  let left = total;
  const order = lengths.map((n, i) => [n, i]).sort((a, b) => a[0] - b[0]);
  order.forEach(([n, i], k) => {
    out[i] = Math.min(n, Math.floor(left / (order.length - k)));
    left -= out[i];
  });
  return out;
}

function withMailbox(result, mailbox) {
  if (result.isError) return result;
  try {
    const data = JSON.parse(result.content[0].text);
    if (!Array.isArray(data.envelopes)) return result;
    const envelopes = data.envelopes.map((e) => ({ ...e, mailbox }));
    return { content: [{ type: 'text', text: JSON.stringify({ ...data, mailbox, envelopes }) }] };
  } catch {
    return result;
  }
}

export function splitPhrases(query) {
  return query.replace(/\b(from|to|subject|body)\s+"([^"]*)"/gi, (whole, field, phrase) => {
    const words = phrase.split(/[^\p{L}\p{N}]+/u).filter((w) => w && !QUERY_WORDS.has(w.toLowerCase()));
    const ascii = words.filter((w) => !/[^\x00-\x7f]/.test(w));
    const used = ascii.length ? ascii : words;
    if (!used.length) return whole;
    const parts = used.map((w) => `${field} ${w}`);
    return parts.length === 1 ? parts[0] : `(${parts.join(' and ')})`;
  });
}

export function register(server, config = resolveConfig()) {
  // ------------------------------------------------------------- reading ----
  // Read paths are soft: if the mail bridge drops out mid-run, a note comes
  // back instead of an error, rather than toppling the whole task.

  server.registerTool('mailbox_list', {
    description: 'List all folders of the mailbox.',
    inputSchema: {},
  }, async () => call(config, ['mailbox', 'list', '--json']));

  server.registerTool('envelope_list', {
    description: 'List the envelopes of a folder (subject, sender, flags). '
      + 'If the answer contains "soft": true, the mailbox is currently '
      + 'unreachable and the list is incomplete. That is NOT "no mail".',
    inputSchema: {
      mailbox: z.string().default('inbox').describe('folder, e.g. inbox, Drafts'),
      page: z.number().int().min(1).optional(),
      pageSize: z.number().int().min(1).max(100).default(20),
    },
  }, async ({ mailbox, page, pageSize }) => {
    const argv = ['envelope', 'list', '--mailbox', mailbox];
    if (page !== undefined) argv.push('--page', String(page));
    // --has-attachment is opt-in: without it himalaya reports has-attachment
    // as null on every envelope, which reads as "no attachment" to a caller
    // that does not know the flag exists. Measured cost on an IMAP backend:
    // none worth mentioning.
    argv.push('--page-size', String(pageSize), '--has-attachment', '--json');
    return withMailbox(await call(config, argv, { soft: true }), mailbox);
  });

  server.registerTool('envelope_search', {
    description: 'Search envelopes. Defaults to "All Mail", so archived and sent '
      + 'mail is found too. The answer names its mailbox: the ids are UIDs of that '
      + 'folder only, so pass the same mailbox to message_read, message_reply, '
      + 'flag_add and the attachment tools, whose default is inbox. Query syntax (himalaya): '
      + 'conditions from <text>, to <text>, subject <text>, body <text>, '
      + 'date <yyyy-mm-dd>, after <yyyy-mm-dd>, flag <seen|answered|flagged|draft>; '
      + 'combine with and, or, not and parentheses; sort with order by '
      + '<date|from|to|subject> [asc|desc]. Each condition takes ONE word and '
      + 'matches it as a case-insensitive substring. A quoted phrase is split into '
      + 'one condition per word joined with and, so word order is not checked. '
      + 'Proton Bridge matches the encoded text, so words with umlauts or other '
      + 'non-ASCII letters usually find nothing: search Sitzung, not nächste. '
      + 'Examples: body Verband; from alice and subject invoice; '
      + '(subject AG and subject Vernetzung) or from verband; '
      + 'subject "Infos und Sitzung" and after 2026-10-01 order by date desc; '
      + 'not flag seen and after 2026-11-20.',
    inputSchema: {
      mailbox: z.string().default(ALL_MAIL)
        .describe('folder; inbox only searches the inbox itself'),
      query: z.string().min(1),
      pageSize: z.number().int().min(1).max(100).default(20),
    },
  }, async ({ mailbox, query, pageSize }) => {
    const result = await call(config,
      ['envelope', 'search', '--mailbox', mailbox, '--page-size', String(pageSize),
        '--has-attachment', '--json', splitPhrases(query)], { soft: true });
    return withMailbox(result, mailbox);
  });

  server.registerTool('thread_read', {
    description: 'Read a whole conversation in chronological order: every '
      + 'message linked to the given one by In-Reply-To or References, or '
      + 'carrying the same subject without Re:/AW:/Fwd:/WG: prefixes, a shared '
      + 'participant and a date within 180 days. Candidates come from a subject '
      + 'search, so a reply under a completely new subject is not found. Searches '
      + `"All Mail"; the ids in the answer are All Mail UIDs. At most ${MAX_MESSAGES} `
      + 'messages, the most recent ones; omitted counts the rest, and incomplete: '
      + 'true means the search hit its page limit and older messages may be missing. '
      + 'HTML is converted to text, and quoted history is cut unless quotes is true.',
    inputSchema: {
      id: z.string().min(1).describe('IMAP UID of any message in the thread'),
      mailbox: MAILBOX,
      quotes: z.boolean().default(false)
        .describe('keep the quoted history in every reply; off, each message shows only its own text'),
    },
  }, async ({ id, mailbox, quotes }) => {
    const own = await ownAddress(config).catch(() => null);
    const thread = await collectThread((argv) => run(config, argv), id, mailbox, { own, quotes });
    if (thread.failed) {
      const { code, out, err } = thread.failed;
      return failure(code, out, err, true);
    }
    const clean = thread.messages.map((m) => scrub(m));
    const budget = shares(clean.map((m) => m.text.length), MAX_TEXT);
    const messages = clean.map((m, i) => ({
      ...m,
      text: m.text.slice(0, budget[i]),
      truncated: m.text.length > budget[i],
    }));
    return { content: [{ type: 'text', text: JSON.stringify({
      mailbox: thread.mailbox,
      count: messages.length,
      omitted: thread.omitted,
      incomplete: thread.incomplete,
      messages,
    }) }] };
  });

  server.registerTool('message_read', {
    description: 'Read a message. Does NOT set the seen flag.',
    inputSchema: {
      id: z.string().min(1).describe('IMAP UID; valid only within its folder'),
      mailbox: MAILBOX,
      raw: z.boolean().default(false).describe('include full headers'),
    },
  }, async ({ id, mailbox, raw }) => {
    const argv = ['message', 'read', id, '--mailbox', mailbox];
    if (raw) argv.push('--raw');
    return call(config, argv, { soft: true });
  });

  server.registerTool('attachment_list', {
    description: 'List the attachments of a message with their part ids, '
      + 'file names, types and sizes.',
    inputSchema: {
      id: z.string().min(1),
      mailbox: MAILBOX,
      inline: z.boolean().default(false)
        .describe('also list inline parts, e.g. images embedded in HTML'),
    },
  }, async ({ id, mailbox, inline }) => {
    const argv = ['attachment', 'list', id, '--mailbox', mailbox];
    if (inline) argv.push('--inline');
    argv.push('--json');
    return call(config, argv, { soft: true });
  });

  server.registerTool('attachment_download', {
    description: 'Download attachments. They always land in the quarantine '
      + 'directory and nowhere else; the answer names the path.',
    inputSchema: {
      id: z.string().min(1),
      mailbox: MAILBOX,
      parts: z.array(PART_ID).optional()
        .describe('part ids from attachment_list; all attachments if omitted'),
    },
  }, async ({ id, mailbox, parts = [] }) => {
    // Both the file name and the content are chosen by whoever sent the mail.
    // The directory therefore sits outside PATH, and the caller cannot pick it.
    await mkdir(config.attachmentDir, { recursive: true });
    return call(config,
      ['attachment', 'download', id, ...parts, '--mailbox', mailbox,
        '--dir', config.attachmentDir, '--json'], { soft: true });
  });

  server.registerTool('attachment_read', {
    description: 'Read the content of one attachment as text: text files and '
      + 'PDFs with a text layer. Images and other binary formats are refused. '
      + 'Long documents come back in pages; use page and pageCount to go on.',
    inputSchema: {
      id: z.string().min(1),
      mailbox: MAILBOX,
      part: PART_ID.describe('part id from attachment_list'),
      page: z.number().int().min(1).default(1),
      pageCount: z.number().int().min(1).max(50).default(10),
    },
  }, async ({ id, mailbox, part, page, pageCount }) => {
    // A directory of its own per call, inside the quarantine, so the file is
    // found without trusting the name the sender chose, and is gone afterwards.
    await mkdir(config.attachmentDir, { recursive: true });
    const dir = await mkdtemp(join(config.attachmentDir, '.read-'));
    try {
      const { code, out, err } = await run(config,
        ['attachment', 'download', id, part, '--mailbox', mailbox,
          '--dir', dir, '--json']);
      if (code !== 0) return failure(code, out, err, true);
      const meta = JSON.parse(out).attachments?.find((a) => a.id === part);
      const files = await readdir(dir);
      if (!meta || files.length !== 1) {
        return { isError: true, content: [{ type: 'text',
          text: `Message ${id} has no attachment with part id ${part}.` }] };
      }
      const result = await extract(config, join(dir, files[0]), meta.mime);
      if (result.error) {
        return { isError: true, content: [{ type: 'text', text: result.error }] };
      }
      const last = Math.min(result.pages.length, page - 1 + pageCount);
      const shown = result.pages.slice(page - 1, last).map(redact).join('\f');
      return { content: [{ type: 'text', text: JSON.stringify({
        ...scrub({ filename: meta.filename, mime: meta.mime }),
        size: meta.size,
        pages: result.pages.length,
        shown: [page, last],
        text: shown.slice(0, MAX_TEXT),
        truncated: shown.length > MAX_TEXT,
      }) }] };
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  // ------------------------------------------------------------- writing ----
  // Nothing soft here: for a change, a soft exit would be a lie about
  // something that did not happen.

  const draftNote = 'Without save this only produces a preview. With save the '
    + 'draft lands in Drafts, NEVER in Sent, and nothing is transmitted: '
    + 'sending is the user’s own act.';

  server.registerTool('message_reply', {
    description: `Create a reply draft. ${draftNote} `
      + 'RULE WITHOUT EXCEPTION: a reply draft is only created if the message '
      + 'was sent to this account’s own address (To or Cc). If it went to '
      + 'a different address, the call is refused and both addresses are named. '
      + 'Do NOT retry and do not rephrase; report the message verbatim. This '
      + 'holds even when the draft was explicitly requested.',
    inputSchema: {
      id: z.string().min(1),
      mailbox: MAILBOX,
      body: z.string().min(1),
      save: z.boolean().default(false),
    },
  }, async ({ id, mailbox, body, save }) => {
    const verdict = await checkRecipient(config, id, mailbox);
    if (verdict.error) {
      return { isError: true, content: [{ type: 'text', text: verdict.error }] };
    }
    const argv = ['message', 'reply', id, '--mailbox', mailbox, '--body', body];
    if (save) argv.push('--save', 'Drafts');
    return call(config, argv);
  });

  server.registerTool('message_forward', {
    description: `Create a forward draft. ${draftNote}`,
    inputSchema: {
      id: z.string().min(1),
      mailbox: MAILBOX,
      body: z.string().min(1),
      save: z.boolean().default(false),
    },
  }, async ({ id, mailbox, body, save }) => {
    // Not subject to the recipient rule: a forward replies to nobody.
    const argv = ['message', 'forward', id, '--mailbox', mailbox, '--body', body];
    if (save) argv.push('--save', 'Drafts');
    return call(config, argv);
  });

  server.registerTool('message_compose', {
    description: `Create a new draft. ${draftNote} The sender is always the `
      + 'account’s own address; this path cannot write as any other identity.',
    inputSchema: {
      to: z.string().min(1).describe('recipient address'),
      subject: z.string().default(''),
      body: z.string().min(1),
      save: z.boolean().default(false),
    },
  }, async ({ to, subject, body, save }) => {
    const argv = ['message', 'compose', '--to', to, '--body', body];
    if (subject) argv.push('--subject', subject);
    if (save) argv.push('--save', 'Drafts');
    return call(config, argv);
  });

  server.registerTool('flag_add', {
    description: 'Set a flag. Only seen, answered and flagged; deleting via a '
      + 'delete flag is not possible.',
    inputSchema: {
      id: z.string().min(1),
      mailbox: MAILBOX,
      flag: z.enum(FLAGS),
    },
  }, async ({ id, mailbox, flag }) => call(config,
    ['flag', 'add', id, '--mailbox', mailbox, '-f', flag],
  ));

  server.registerTool('flag_remove', {
    description: 'Remove a flag. Same three flags as flag_add.',
    inputSchema: {
      id: z.string().min(1),
      mailbox: MAILBOX,
      flag: z.enum(FLAGS),
    },
  }, async ({ id, mailbox, flag }) => call(config,
    ['flag', 'remove', id, '--mailbox', mailbox, '-f', flag],
  ));

  server.registerTool('message_move', {
    description: 'Move an obsolete OWN draft to Trash. This is the only move '
      + 'path: from Drafts to Trash, and Trash is recoverable. No other folder '
      + 'is ever touched.',
    inputSchema: { id: z.string().min(1).describe('UID within the Drafts folder') },
  }, async ({ id }) => call(config,
    ['message', 'move', id, '-f', 'Drafts', '--to', 'Trash'],
  ));
}
