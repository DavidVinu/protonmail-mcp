# protonmail-mcp

An MCP server that gives an AI assistant your Proton Mail inbox — read and
draft only. It **cannot send** and it **cannot delete**, and that is a property
of how it is built rather than a rule it promises to follow.

It talks to [Proton Mail Bridge](https://proton.me/mail/bridge) through
[himalaya](https://github.com/pimalaya/himalaya), so it works with any account
Bridge can serve, including the folders where imported Gmail or other mail
lives.

Two entry points, same fourteen tools:

| | |
| - | - |
| `src/stdio.mjs` | for clients that launch the server as a child process (Claude Code, Claude Desktop) |
| `src/http.mjs` | Streamable HTTP with a static bearer token, for hosted connectors |

## Why not just use permissions?

Most MCP clients now have a permission system: you can allow or deny each tool.
That covers most of what a wrapper around a mail CLI would do, and this server
leans on it — there simply is no send tool to allow.

Two things a permission system structurally cannot do, and they are the reason
this server exists rather than a thin pass-through:

**1. It cannot change what the answer contains.** The moment reading mail is
allowed, a confirmation code in a message body reaches the model. In the setup
this was built for, `Your email verification code is: 010299` was relayed
verbatim into a chat room. `src/otp-filter.mjs` masks codes before the text
leaves the server. Permissions decide *whether* a tool runs; only a filter
decides *what* comes back.

**2. It cannot compare two header lines.** A reply draft is only created if the
message was addressed to the account's own address (`To` or `Cc`). Roughly half
of the author's inbox arrives at addresses this account cannot send from, and
without the check every reply draft on those was silently composed from the
wrong sender. There is no way to express "allow reply, but only for messages
addressed to me" as a tool permission.

Everything else — a fixed tool set, no free-form command, no shell, argv built
from typed parameters — is here because it is cheap, not because permissions
could not do it.

## What it cannot do, and why

- **Send.** No tool builds `--send`, and `message send` is not exposed. The
  second leg is yours: point it at a himalaya configuration with **no SMTP
  section**, and sending is impossible even if this code were wrong.
- **Delete.** The only move is `Drafts → Trash`, and Trash is recoverable.
- **Reach a different configuration.** `HIMALAYA_*` is stripped from the child
  environment, so an ambient `HIMALAYA_CONFIG` cannot steer it — himalaya runs
  `password.command` through a shell, which makes that variable a real lever.
  Pointing it elsewhere is a deliberate act at service-definition time, via
  `PROTONMAIL_MCP_HIMALAYA_CONFIG`.
- **Write outside the quarantine.** Attachment file names and contents are
  chosen by whoever sent the mail, so downloads always land in one directory
  the caller cannot pick.

## Requirements

- Node.js 20 or newer
- `himalaya` v2 on `PATH` (or set `HIMALAYA_BIN`)
- `pdftotext` (poppler-utils) for `attachment_read` on PDFs; optional
- A working himalaya account. For Proton, that means Proton Mail Bridge running
  locally and an IMAP account pointed at it.

## Install

```sh
git clone https://github.com/DavidVinu/protonmail-mcp
cd protonmail-mcp
npm install
npm test
```

### As a local (stdio) server

For Claude Code:

```sh
claude mcp add protonmail --scope user -- /path/to/protonmail-mcp/src/stdio.mjs
claude mcp list
```

Note that Claude Code reads `~/.claude.json`, **not**
`claude_desktop_config.json`. An entry in the desktop configuration is silently
ignored by the CLI; the log then says `no stdio servers connected`.

For Claude Desktop, add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "protonmail": {
      "command": "/path/to/protonmail-mcp/src/stdio.mjs"
    }
  }
}
```

### As an HTTP server

Create a token file first — the server refuses to start without one, and
refuses if it is readable by group or others, or shorter than 32 characters:

```sh
mkdir -p ~/.config/protonmail-mcp
install -m 0600 /dev/null ~/.config/protonmail-mcp/token
openssl rand -hex 32 > ~/.config/protonmail-mcp/token
```

Then run `src/http.mjs`, or install `systemd/protonmail-mcp.service`.

The server binds to `127.0.0.1` only. **Exposing it is your job and your risk**:
whoever holds the token reads all your mail, downloads attachments, marks
messages as seen and creates drafts. Put it behind something you control — a
Tailscale tailnet, a Cloudflare tunnel, an authenticated reverse proxy. Do not
bind it to `0.0.0.0`.

Clients that support custom connectors need the URL and the token as a header:

```
URL:    https://your-host/mcp
Header: authorization: Bearer <the token>
```

This server has no OAuth. It deliberately answers `404` on `/.well-known/*` and
sends **no** `WWW-Authenticate` header on its `401`: both are invitations to a
flow that does not exist here, and a client that accepts the invitation will
try dynamic client registration and fail with a confusing error.

Sessions live in memory only, so restarting the service throws all of them
away. A client that comes back with its old session id gets a `404`, which is
the signal to start a new one; answering `400` there leaves it retrying a
session that will never come back, and a working connector then stays broken
across every redeploy until someone reconnects it by hand. That is worth
knowing if you put anything else in front of this server: pass the `404`
through.

The request log writes one line per request to stderr, with the status the
response actually had. Without that there is no way to tell from outside
whether a client is reaching the server at all — a request that fails at the
door looks exactly like no request.

## Configuration

All optional.

| Variable | Default | Meaning |
| - | - | - |
| `HIMALAYA_BIN` | `himalaya` | path to the binary |
| `PROTONMAIL_MCP_HIMALAYA_CONFIG` | himalaya's own default | passed as `--config` |
| `PROTONMAIL_MCP_ATTACHMENT_DIR` | `~/.local/share/protonmail-mcp/attachments` | download quarantine |
| `PDFTOTEXT_BIN` | `pdftotext` | PDF text extraction for `attachment_read` |
| `PROTONMAIL_MCP_TOKEN_FILE` | `~/.config/protonmail-mcp/token` | HTTP only |
| `PROTONMAIL_MCP_PORT` | `18790` | HTTP only |
| `PROTONMAIL_MCP_ADDRESS` | `127.0.0.1` | HTTP only; change at your own risk |

## Tools

| Tool | Reads | Writes |
| - | - | - |
| `mailbox_list` | folders | |
| `envelope_list` | envelopes of a folder | |
| `envelope_search` | himalaya query syntax, `All Mail` by default | |
| `message_read` | one message; does **not** set the seen flag | |
| `thread_read` | a whole conversation from `All Mail`, oldest first | |
| `attachment_list` | part ids, names, types, sizes | |
| `attachment_download` | | files, into the quarantine only |
| `attachment_read` | one attachment's text (text files, PDFs), paged and filtered | |
| `message_reply` | | a draft, subject to the recipient rule |
| `message_forward` | | a draft |
| `message_compose` | | a draft |
| `flag_add` / `flag_remove` | | `seen`, `answered`, `flagged` only |
| `message_move` | | `Drafts → Trash` only |

Drafts are only ever saved to `Drafts`, never to `Sent`, and nothing is
transmitted. Without `save: true` you get a preview and nothing is stored.

## Soft and hard failures

Read paths end **softly** when the mailbox is unreachable: exit code 0 and

```json
{ "soft": true, "note": "Mailbox unreachable (connection refused); the data from this query is missing." }
```

so one unreachable mailbox does not topple a longer task. Three deliberate
details:

- The soft answer contains **no empty `envelopes`**. A caller that only looks
  at that field should fail rather than read this as "no mail" — turning a
  detected outage into an undetected one is the worse failure.
- Only *connection* failures are soft. An **authentication failure stays hard**,
  because it means someone has to act, not "try again later".
- **Write paths are never soft.** For a change, a soft exit would be a lie
  about something that did not happen.

## Known edges

- The OTP filter masks a code-shaped string (four digits, 3+3 digits, spaced
  digits, five to eight alphanumerics with a digit) only when a keyword such as
  code, TAN, PIN, OTP, verification, one-time, guard, "enter this code", "confirm
  your email" or a German compound like Bestätigungscode stands within 40
  characters or when the message itself is a 2FA mail (keyword in the subject or a sender like `verify@` or `2fa@`).
  Text that announces a code strongly (OTP, TAN, one-time password, "your
  code", verification code, Bestätigungscode and the like) is treated as a 2FA
  mail as a whole. Only the code is replaced by `[...]`; dates, IBANs, German postcodes,
  amounts and phone numbers with a `+` prefix or a Tel label are never masked. A code with no keyword nearby in a mail without
  a 2FA subject or sender gets through; that is the price of readable mail.
  In a 2FA mail (announced code, 2FA subject or sender) the filter errs towards
  masking: single-digit tables and spaced characters near the code, and
  unlabelled phone numbers and US ZIP codes anywhere in the mail, can come back
  as `[...]`. Earlier attempts to keep them readable each let some code through.
- `envelope_search` passes the query to himalaya. Each condition takes one
  word. Quoted phrases do not work in himalaya against Proton Bridge, so the
  server splits `subject "a b"` into `(subject a and subject b)`. Bridge matches
  the encoded raw text, so words with umlauts and words that straddle an
  encoded-word boundary in a long subject, are often not found.
- `thread_read` searches `All Mail` for up to three words of the subject
  within 180 days before the given message, then keeps messages linked by
  `In-Reply-To`/`References` or with the same subject without
  `Re:`/`AW:`/`Fwd:`/`WG:` prefixes, a shared participant and a date within 180
  days. A reply under a subject that shares none of those words is not found.
  `incomplete: true` means the search hit its page limit or could not confirm
  that it found the message itself (typical for subjects with umlauts). HTML is converted to
  text and quoted history is cut (Outlook, Gmail, Proton and Apple markers,
  "Am ... schrieb", "On ... wrote", `>` lines), so each message shows only its
  own text; `quotes: true` keeps everything.
- `envelope_list` and `envelope_search` put the `mailbox` on every envelope,
  and every tool that takes a UID requires `mailbox` explicitly, because the
  same UID names a different message in another folder.
- The recipient rule fails closed: if the original cannot be read, no draft is
  created. A rule that quietly stops applying when the mailbox is down is not a
  rule.
- `attachment_read` returns text only. Images are refused: a 2FA setup mail
  carries its secret as a QR code, and no text filter sees into a picture.
  Office formats and scanned PDFs are refused too; `attachment_download` still
  stores them for you.
- The filter's word list is bilingual (English and German), because the mailbox
  it was built for is. Adding a language means extending `KEYWORDS` in
  `src/otp-filter.mjs`.

## Tests

```sh
npm test
```

111 cases. Two of them are skipped unless you point them at extras:

```sh
# compares the port against the Python original it came from, character for character
OTP_FILTER_PYTHON_REFERENCE=/path/to/einmalcode.py npm test

# compares the filter against the copy in the sibling gmail-mcp server
OTP_FILTER_SIBLING=/path/to/gmail-mcp/src/otp-filter.mjs npm test
```

The sibling check exists because the copy is deliberate, not accidental: two
servers, two deployments, two blast radii, so an edit for one cannot silently
change the other. The price of that is drift, and drift in a filter is
invisible until a code reaches a model. So the copies are compared by
**behaviour** rather than by text -- part of the divergence is intended, since
Gmail identifies messages by opaque hex strings where IMAP uses decimal UIDs.
`scrub` and `STRUCTURAL_FIELDS` are excluded for exactly that reason.

A third is skipped when `himalaya` is not installed: it runs every tool and
checks each option the server builds against `himalaya <subcommand> --help`.
That case exists because two real defects got through a contract that only
pinned *which* argv the server builds and never asked whether the other end
understood it — a flag invented by an intermediate wrapper, and a `--all` on
`message reply` that himalaya has never had. A fifth case checks the opposite
direction: that `--send`, `--config`, `--account`, `--backend` and `--attach`
never appear.

The tests spawn the real server over stdio and over HTTP; only himalaya itself
is a mock.

## License

AGPL-3.0-or-later, Copyright (C) 2026 David Vinu.
