// Contract for the tools of the Proton Mail MCP server.
//
// The server is the whitelist, not a pass-through. That is what these tests
// measure: for every tool the exact argv is pinned. An argument the caller
// chooses freely and that reaches the command line unchecked would be the way
// around everything else here.
//
// Two of the cases are not about argv at all, and they are the reason this
// server exists rather than a permission rule: the one-time-code filter and
// the recipient rule for reply drafts. A permission system decides WHETHER a
// tool runs. It cannot change WHAT the answer contains, and it cannot compare
// two header lines.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import test from 'node:test';

import {
  EVERY_TOOL, OWN_ADDRESS, TO_OWN, answerTo, callServer, tool,
} from './helpers.mjs';

const HIMALAYA = process.env.HIMALAYA_BIN_FOR_TEST ?? 'himalaya';

/** Every long option that `himalaya <subcommand> --help` lists. */
function optionsOf(subcommand) {
  const help = execFileSync(HIMALAYA, [...subcommand, '--help'],
    { encoding: 'utf8' });
  return new Set(help.match(/--[a-z][a-z-]*/g) ?? []);
}

let himalayaPresent = false;
try {
  execFileSync(HIMALAYA, ['--version'], { stdio: 'ignore' });
  himalayaPresent = true;
} catch { /* the option check is skipped without it */ }

// ------------------------------------------------------------- the surface --

test('The tool list contains no way to send', async () => {
  const { answers } = await callServer([
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
  ]);
  const names = answerTo(answers, 2).result.tools.map((t) => t.name).sort();
  assert.ok(names.length > 0, 'the server offers tools at all');
  for (const forbidden of ['send', 'delete', 'delegate', 'forward_address']) {
    assert.ok(
      !names.some((n) => n.includes(forbidden)),
      `no tool may be named '${forbidden}', found: ${names.join(', ')}`,
    );
  }
  assert.deepEqual(names, [
    'attachment_download', 'attachment_list', 'envelope_list',
    'envelope_search', 'flag_add', 'flag_remove', 'mailbox_list',
    'message_compose', 'message_forward', 'message_move', 'message_read',
    'message_reply',
  ]);
});

// ------------------------------------------------------------------- argv --

test('mailbox_list calls himalaya with exactly three arguments', async () => {
  const { seen } = await callServer([tool('mailbox_list', {})],
    { stdout: '{"mailboxes":[]}' });
  assert.deepEqual(seen.argv, ['mailbox', 'list', '--json']);
});

test('A folder name cannot smuggle in extra arguments', async () => {
  // An argument stays one argument: it never passes through a shell.
  const { seen } = await callServer(
    [tool('envelope_list', { mailbox: 'inbox --send --config /tmp/x.toml' })],
    { stdout: '{"envelopes":[]}' });
  assert.deepEqual(seen.argv, [
    'envelope', 'list', '--mailbox', 'inbox --send --config /tmp/x.toml',
    '--page-size', '20', '--has-attachment', '--json',
  ]);
  assert.equal(seen.argv.filter((a) => a === '--config').length, 0);
});

test('Envelope listings ask for the attachment column', async () => {
  // himalaya reports has-attachment as null on every envelope unless the
  // opt-in flag is set, and null reads as "no attachment" to anyone who does
  // not know the flag exists. Regression found 2026-09-06: the wrapper that
  // used to sit in front added the flag itself, so removing the wrapper
  // silently removed the data.
  for (const [name, args] of [
    ['envelope_list', { mailbox: 'inbox' }],
    ['envelope_search', { mailbox: 'inbox', query: 'from alice' }],
  ]) {
    const { seen } = await callServer([tool(name, args)],
      { stdout: '{"envelopes":[]}' });
    assert.ok(seen.argv.includes('--has-attachment'),
      `${name}: ${seen.argv.join(' ')}`);
  }
});

test('The server uses no shell', async () => {
  // Were `shell: true` set anywhere, this argument would act as a redirection
  // instead of arriving as a string.
  const marker = `/tmp/protonmail-mcp-pwned-${process.pid}`;
  const { seen } = await callServer(
    [tool('envelope_list', { mailbox: `inbox; touch ${marker}` })],
    { stdout: '{"envelopes":[]}' });
  assert.ok(seen.argv.includes(`inbox; touch ${marker}`));
  assert.equal(fs.existsSync(marker), false);
});

test('flag_add accepts only harmless flags', async () => {
  const { answers, seen } = await callServer(
    [tool('flag_add', { id: '7', mailbox: 'inbox', flag: 'deleted' })]);
  const a = answerTo(answers, 2);
  assert.ok(a.result?.isError || a.error, 'a delete flag must be refused');
  assert.equal(seen, null, 'himalaya must not even start');
});

test('flag_add passes an allowed flag through exactly', async () => {
  const { seen } = await callServer(
    [tool('flag_add', { id: '7', mailbox: 'inbox', flag: 'seen' })]);
  assert.deepEqual(seen.argv,
    ['flag', 'add', '7', '--mailbox', 'inbox', '-f', 'seen']);
});

test('message_move only goes from Drafts to Trash', async () => {
  const { seen } = await callServer([tool('message_move', { id: '3' })]);
  assert.deepEqual(seen.argv,
    ['message', 'move', '3', '-f', 'Drafts', '--to', 'Trash']);
});

test('A draft is only saved to Drafts, never anywhere else', async () => {
  const { seen } = await callServer([tool('message_reply',
    { id: '9', mailbox: 'inbox', body: 'Text', save: true })],
    { raw: TO_OWN, stdout: 'ok' });
  assert.ok(seen.argv.includes('--save'));
  assert.equal(seen.argv[seen.argv.indexOf('--save') + 1], 'Drafts');
  assert.ok(!seen.argv.includes('Sent'));
});

test('Without save there is only a preview, no stored draft', async () => {
  const { seen } = await callServer([tool('message_reply',
    { id: '9', mailbox: 'inbox', body: 'Text' })],
    { raw: TO_OWN, stdout: 'ok' });
  assert.ok(!seen.argv.includes('--save'));
});

test('Every option the server builds is one himalaya knows',
  { skip: himalayaPresent ? false : 'himalaya not installed' }, async () => {
    // The case that would have found both defects of 2026-09-06 by itself:
    //   * `--weich` was invented by a wrapper that used to sit in between; it
    //     is not a himalaya flag, and every search would have exited 2.
    //   * `message reply --all` was on that wrapper's option list, but
    //     himalaya has no reply-all switch, only --to/--cc/--bcc. The
    //     parameter had never worked.
    // A contract that only pins which argv the server builds says nothing
    // about whether the other end understands it. This one measures that.
    for (const [name, args] of EVERY_TOOL) {
      const { calls } = await callServer([tool(name, args)],
        { raw: TO_OWN, stdout: 'ok' });
      assert.ok(calls.length > 0, `${name} did not call himalaya at all`);
      for (const c of calls) {
        const subcommand = c.argv.filter((x) => !x.startsWith('-')).slice(0, 2);
        const known = optionsOf(subcommand);
        for (const opt of c.argv.filter((x) => x.startsWith('--'))) {
          assert.ok(known.has(opt),
            `${name}: himalaya ${subcommand.join(' ')} does not know ${opt}`);
        }
      }
    }
  });

test('No call carries an option that must never appear here', async () => {
  // The other direction. himalaya DOES know these, and that is exactly why
  // they must never be built: `--send` on reply, forward or compose would be
  // the send path; `--config` and `--account` would be the way around the
  // configuration, which is the leg of the guarantee that lives outside this
  // file.
  const FORBIDDEN = ['--send', '-c', '--config', '-a', '--account',
    '-b', '--backend', '--attach'];
  for (const [name, args] of EVERY_TOOL) {
    const { calls } = await callServer([tool(name, args)],
      { raw: TO_OWN, stdout: 'ok' });
    assert.ok(calls.length > 0, `${name} did not call himalaya at all`);
    for (const c of calls) {
      for (const f of FORBIDDEN) {
        assert.ok(!c.argv.includes(f), `${name} builds ${f}: ${c.argv.join(' ')}`);
      }
    }
  }
});

test('--config appears only when the operator asked for it', async () => {
  // The one deliberate exception, and it is an operator decision made at
  // service-definition time, not something a caller or an ambient variable
  // can reach.
  const { seen } = await callServer([tool('mailbox_list', {})],
    { stdout: '{}', env: { PROTONMAIL_MCP_HIMALAYA_CONFIG: '/etc/x/himalaya.toml' } });
  assert.deepEqual(seen.argv,
    ['--config', '/etc/x/himalaya.toml', 'mailbox', 'list', '--json']);
});

// ------------------------------------------------------------ environment --

test('HIMALAYA_* never reaches himalaya, not even from the environment', async () => {
  // Reproduced 2026-09-02 against the wrapper this server replaced:
  // HIMALAYA_CONFIG=... bypassed its --config block entirely.
  const { seen } = await callServer([tool('mailbox_list', {})],
    { stdout: '{}', env: { HIMALAYA_CONFIG: '/tmp/substituted.toml' } });
  assert.ok(!Object.keys(seen.env).some((k) => k.startsWith('HIMALAYA_')));
  assert.ok(seen.env.HOME, 'HOME must stay, or himalaya finds no configuration');
});

// ------------------------------------------------- soft and hard failures --

const BRIDGE_DOWN = { stdout: 'Error: connect tcp 127.0.0.1:1143\n'
  + 'Connection refused (os error 111)', code: 1 };

test('A connection failure does not topple a read path', async () => {
  const { answers } = await callServer(
    [tool('envelope_list', { mailbox: 'inbox' })], BRIDGE_DOWN);
  const a = answerTo(answers, 2);
  assert.ok(!a.result?.isError, 'reading ends softly');
  const data = JSON.parse(a.result.content[0].text);
  assert.equal(data.soft, true);
  // Deliberately NO empty envelopes: a caller that only looks at that field
  // should fail rather than read this as "no mail".
  assert.ok(!('envelopes' in data), a.result.content[0].text);
});

test('For a change, a soft exit would be a lie', async () => {
  const { answers } = await callServer(
    [tool('flag_add', { id: '7', mailbox: 'inbox', flag: 'seen' })], BRIDGE_DOWN);
  assert.ok(answerTo(answers, 2).result?.isError, 'writing stays hard');
});

test('An authentication failure stays hard even when reading', async () => {
  // Somebody has to act; this is not "try again later". The difference to the
  // case above is the whole reason softness hangs on the kind of failure and
  // not on the tool.
  const { answers } = await callServer(
    [tool('envelope_list', { mailbox: 'inbox' })],
    { stdout: 'Error: cannot authenticate to imap server', code: 1 });
  assert.ok(answerTo(answers, 2).result?.isError);
});

test('A failure is reported, not swallowed', async () => {
  const { answers } = await callServer(
    [tool('message_read', { id: '1', mailbox: 'inbox' })],
    { stdout: 'himalaya: something went wrong', code: 2 });
  const a = answerTo(answers, 2);
  assert.ok(a.result?.isError || a.error, 'code 2 must arrive as an error');
});

// --------------------------------------------------------- the two filters --

test('One-time codes do not reach the model', async () => {
  const { answers } = await callServer(
    [tool('envelope_list', { mailbox: 'inbox' })],
    { stdout: JSON.stringify({ envelopes: [
      { id: '7529', subject: '416107 is your code' }] }) });
  const text = answerTo(answers, 2).result.content[0].text;
  assert.ok(!text.includes('416107'), 'the code must not get through');
  assert.ok(text.includes('[...]'));
  assert.ok(text.includes('7529'), 'the UID must survive');
});

test('A reply draft is only created from the address that received the mail', async () => {
  const toElsewhere = [
    'From: Google <no-reply@accounts.google.com>',
    'To: <someone.else@gmail.com>',
    // This is what mail imported from Gmail looks like at Proton: Delivered-To
    // carries the import address, not the address the mail was sent to.
    // Checking that header lets through exactly the cases this rule is about.
    'Delivered-To: importer@proton.me',
    '', 'Text', '',
  ].join('\n');

  const { answers, calls } = await callServer([tool('message_reply',
    { id: '7', mailbox: 'inbox', body: 'Text', save: true })],
    { raw: toElsewhere });
  const a = answerTo(answers, 2);
  assert.ok(a.result?.isError, 'the draft must be refused');
  const text = a.result.content[0].text;
  assert.ok(text.includes('someone.else@gmail.com'), text.slice(0, 200));
  assert.ok(text.includes(OWN_ADDRESS), 'both addresses must be named');
  assert.ok(!calls.some((c) => c.argv.includes('reply')),
    'himalaya reply must not run at all');
  assert.ok(!calls.some((c) => c.argv.includes('--save')),
    'nothing is created even with save');
});

test('A reply to own mail goes through, including from Cc', async () => {
  for (const head of [`To: <${OWN_ADDRESS}>`,
                      `To: <alice@example.org>\nCc: <${OWN_ADDRESS}>`,
                      `To: <a@x.org>, <b@x.org>, Me <${OWN_ADDRESS}>`]) {
    const raw = ['From: Alice <alice@example.org>', head, '', 'Text', ''].join('\n');
    const { answers } = await callServer(
      [tool('message_reply', { id: '7', mailbox: 'inbox', body: 'T' })],
      { raw, stdout: 'ok' });
    assert.ok(!answerTo(answers, 2).result?.isError, head);
  }
});

test('If the original cannot be read, no draft is created', async () => {
  // Fail closed. Without the mailbox the recipient cannot be checked, so the
  // answer is a stop, not a guess. A rule that quietly stops applying when the
  // mailbox is down is not a rule.
  const { answers, calls } = await callServer(
    [tool('message_reply', { id: '7', mailbox: 'inbox', body: 'T' })],
    { raw: 'Error: connect 127.0.0.1:1143\n', rawCode: 1 });
  assert.ok(answerTo(answers, 2).result?.isError);
  assert.ok(!calls.some((c) => c.argv.includes('reply')));
});

test('Forwards are not subject to the rule', async () => {
  // A forward replies to nobody.
  const { answers, calls } = await callServer([tool('message_forward',
    { id: '7', mailbox: 'inbox', body: 'T' })], { stdout: 'ok' });
  assert.ok(!answerTo(answers, 2).result?.isError);
  assert.equal(calls.length, 1, 'no read beforehand');
});
