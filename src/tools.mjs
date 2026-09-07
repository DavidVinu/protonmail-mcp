// The tools of the Proton Mail MCP server, shared by the stdio and HTTP entry
// points. Neither the transport nor the process environment is decided here.
//
// WHAT THE BOUNDARY IS. This server offers twelve fixed tools. Every argv is
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
import { mkdir, readFile } from 'node:fs/promises';
import { z } from 'zod';
import { redact, scrub } from './otp-filter.mjs';

const FLAGS = ['seen', 'answered', 'flagged'];

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
  return new Promise((done) => {
    const env = Object.fromEntries(
      Object.entries(process.env).filter(([k]) => !k.startsWith('HIMALAYA_')),
    );
    const full = config.configPath
      ? ['--config', config.configPath, ...argv]
      : argv;
    const child = spawn(config.himalaya, full, { env });
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

  if (code !== 0) {
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

  // Every output is filtered before it reaches the model. JSON field by field,
  // so the structure and the IMAP UIDs survive; anything else as plain text.
  let text = out || '(empty)';
  try {
    text = JSON.stringify(scrub(JSON.parse(text)));
  } catch {
    text = redact(text);
  }
  return { content: [{ type: 'text', text: text.slice(0, 200000) }] };
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
    return call(config, argv, { soft: true });
  });

  server.registerTool('envelope_search', {
    description: 'Search the mailbox. The query uses himalaya syntax, '
      + 'for example: from alice and subject invoice.',
    inputSchema: {
      mailbox: z.string().default('inbox'),
      query: z.string().min(1),
      pageSize: z.number().int().min(1).max(100).default(20),
    },
  }, async ({ mailbox, query, pageSize }) => call(config,
    ['envelope', 'search', '--mailbox', mailbox, '--page-size', String(pageSize),
      '--has-attachment', '--json', query], { soft: true },
  ));

  server.registerTool('message_read', {
    description: 'Read a message. Does NOT set the seen flag.',
    inputSchema: {
      id: z.string().min(1).describe('IMAP UID; valid only within its folder'),
      mailbox: z.string().default('inbox'),
      raw: z.boolean().default(false).describe('include full headers'),
    },
  }, async ({ id, mailbox, raw }) => {
    const argv = ['message', 'read', id, '--mailbox', mailbox];
    if (raw) argv.push('--raw');
    return call(config, argv, { soft: true });
  });

  server.registerTool('attachment_list', {
    description: 'List the attachments of a message.',
    inputSchema: { id: z.string().min(1), mailbox: z.string().default('inbox') },
  }, async ({ id, mailbox }) => call(config,
    ['attachment', 'list', id, '--mailbox', mailbox], { soft: true },
  ));

  server.registerTool('attachment_download', {
    description: 'Download attachments. They always land in the quarantine '
      + 'directory and nowhere else; the answer names the path.',
    inputSchema: { id: z.string().min(1), mailbox: z.string().default('inbox') },
  }, async ({ id, mailbox }) => {
    // Both the file name and the content are chosen by whoever sent the mail.
    // The directory therefore sits outside PATH, and the caller cannot pick it.
    await mkdir(config.attachmentDir, { recursive: true });
    return call(config,
      ['attachment', 'download', id, '--mailbox', mailbox,
        '--dir', config.attachmentDir], { soft: true });
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
      mailbox: z.string().default('inbox'),
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
      mailbox: z.string().default('inbox'),
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
      mailbox: z.string().default('inbox'),
      flag: z.enum(FLAGS),
    },
  }, async ({ id, mailbox, flag }) => call(config,
    ['flag', 'add', id, '--mailbox', mailbox, '-f', flag],
  ));

  server.registerTool('flag_remove', {
    description: 'Remove a flag. Same three flags as flag_add.',
    inputSchema: {
      id: z.string().min(1),
      mailbox: z.string().default('inbox'),
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
