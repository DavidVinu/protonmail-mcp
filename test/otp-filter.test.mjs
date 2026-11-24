// Contract for the one-time-code filter.
//
// This filter is the one thing a permission system cannot do: it does not
// decide WHETHER a tool may run, it changes WHAT the answer contains. As soon
// as reading mail is allowed, a confirmation code in the body reaches the
// model. Observed 2026-08-21 and 2026-08-22: "Your email verification code
// is: 010299" was relayed verbatim into a chat room.
//
// Two layers of checking:
//
//   1. Fixed cases, each from a real incident or a real message. Both
//      directions: codes that must be masked, and everyday numbers that must
//      not be. The second half matters as much as the first -- a filter that
//      destroys postcodes and IBANs makes the assistant useless for exactly
//      the tasks it exists for.
//   2. A differential test against the Python original this was ported from,
//      if OTP_FILTER_PYTHON_REFERENCE points at it. For every input both
//      implementations must return the same characters. That makes "faithful
//      port" a measurement rather than a claim.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import { MASK, maskCodes, maskTable, redact, scrub } from '../src/otp-filter.mjs';

const REFERENCE = process.env.OTP_FILTER_PYTHON_REFERENCE;
const referencePresent = Boolean(REFERENCE) && fs.existsSync(REFERENCE);

/** Send the same inputs through the Python original. */
function python(fn, inputs) {
  const dir = path.dirname(REFERENCE);
  const module = path.basename(REFERENCE, '.py');
  const script = `
import json, sys
sys.path.insert(0, ${JSON.stringify(dir)})
import ${module} as reference
data = json.load(sys.stdin)
print(json.dumps([getattr(reference, ${JSON.stringify(fn)})(x) for x in data]))
`;
  return JSON.parse(execFileSync('python3', ['-c', script], {
    input: JSON.stringify(inputs), encoding: 'utf8',
  }));
}

// One line per measured case. The comments name where each came from.
const MUST_MASK = [
  '416107 is your code',                       // real message, 2026-09-06
  '292137 is your code',
  '<strong>010299</strong>',                   // HTML; the relayed code, 08-24
  'Your email verification code is: 010299',
  'Code: 8 4 2 1 9 9',                         // spaced digits
  'PIN 123 456',                               // three plus three
  'Token AB3D-9F2K',                           // alphanumeric
];

const MUST_SURVIVE = [
  '10115 Berlin',                              // postcode, destroyed 08-25
  'DE89 3704 0044 0532 0130 00',               // IBAN
  'Zahlung bis 2026-09-22',                    // ISO date, destroyed 08-25
  'Frist 22.09.2026',
  'Betrag 1.234.567,89 Euro',
  'im Jahr 2026',
  'iPhone15 gekauft',                          // three lowercase letters
  'Rufen Sie 030 123 4567 an',                 // phone number
];

test('Codes are masked', () => {
  for (const t of MUST_MASK) {
    assert.ok(maskCodes(t).includes('[...]'), `not masked: ${t}`);
  }
});

test('Everyday numbers are left alone', () => {
  for (const t of MUST_SURVIVE) {
    assert.equal(maskCodes(t), t, `wrongly masked: ${t}`);
  }
});

test('redact masks a code only next to a keyword', () => {
  const cases = [
    ['Your email verification code is: 010299', 'Your email verification code is: [...]'],
    ['416107 is your code', '[...] is your code'],
    ['Dein Bestätigungscode lautet 482913.', 'Dein Bestätigungscode lautet [...].'],
    ['Sicherheitscode: 7731', 'Sicherheitscode: [...]'],
    ['Verifizierung: 4417 eingeben', 'Verifizierung: [...] eingeben'],
    ['Ihre TAN 553201', 'Ihre TAN [...]'],
    ['Your one-time password 291337', 'Your one-time password [...]'],
    ['Security code: KXJQMP', 'Security code: [...]'],
    ['Your verification code is 123456789', 'Your verification code is [...]'],
    ['Your confirmation code is below.<div style="font-size:28px;letter-spacing:4px;'
      + 'font-family:monospace">ABC-123</div>',
    'Your confirmation code is below.<div style="font-size:28px;letter-spacing:4px;'
      + 'font-family:monospace">[...]</div>'],
  ];
  for (const [input, expected] of cases) assert.equal(redact(input), expected);
});

test('redact leaves numbers without a keyword alone', () => {
  for (const t of [...MUST_SURVIVE, '<strong>010299</strong>', 'Raum 4711',
    'Bestellnummer 12345678', 'Message-ID: <18dde35b0d7fc70e.2bcdac6385e23e89@B250>',
    'Der Barcode 416107 auf dem Paket', 'Code: Bitte warten',
    'Zip code: 10785', 'source code at commit a1b2c3d', 'QR-Code 416107',
    'Informationen und den benötigten Buchungscode schicke ich dir']) {
    assert.equal(redact(t), t, `wrongly masked: ${t}`);
  }
});

test('A keyword further away than the window masks nothing', () => {
  const t = `Code ${'filler '.repeat(8)}416107`;
  assert.equal(redact(t), t);
});

test('A signature with phone number and date stays fully readable', () => {
  const mail = [
    'From: Frida <frida@verband.example>',
    'Subject: AG Vernetzung & KI - Infos und nächste Sitzung',
    '',
    'Hallo zusammen,',
    'die nächste Sitzung ist am 10.10.2026 um 18:30 Uhr. Den Buchungscode',
    'schicke ich euch separat.',
    '',
    'Viele Grüße',
    'Frida',
    'Verband - Verband der Ärztinnen und Ärzte Deutschlands e.V.',
    'Kurfürstenstraße 132, 10785 Berlin',
    'Tel.: +49 30 555012-25',
    'Fax: +49 30 555012-29',
  ].join('\n');
  assert.equal(redact(mail), mail);
});

test('A real 2FA mail loses only its code', () => {
  const mail = [
    'From: Apple <no_reply@email.apple.com>',
    'Subject: Your verification code',
    '',
    'Enter this code to sign in:',
    '',
    '<b>882199</b>',
    '',
    'If you did not request it, call +49 30 555012-25 or ignore this mail.',
  ].join('\n');
  const out = redact(mail);
  assert.equal(out, mail.replace('882199', '[...]'));
});

test('A sign-in subject marks a 2FA mail', () => {
  const mail = 'From: Slack <no-reply@slack.com>\nSubject: Sign in to Slack\n\nhere: ABC-123';
  assert.ok(!redact(mail).includes('ABC-123'));
});

test('A 2FA sender is enough, even without a keyword in the body', () => {
  const mail = 'From: Microsoft <account-security-noreply@accountprotection.microsoft.com>\n'
    + 'Subject: Microsoft account\n\nUse 4417 for the account ending in 12.';
  assert.ok(!redact(mail).includes('4417'));
  assert.ok(redact(mail).includes('Microsoft account'));
});

test('scrub takes the 2FA context from the envelope it is in', () => {
  const d = scrub({ envelopes: [
    { id: '1', subject: 'Your sign-in token', preview: 'use 4417 now' },
    { id: '2', subject: 'Raum 4711', preview: 'use 4417 now' },
  ] });
  assert.equal(d.envelopes[0].preview, 'use [...] now');
  assert.equal(d.envelopes[1].preview, 'use 4417 now');
  assert.equal(d.envelopes[1].subject, 'Raum 4711');
});

test('IMAP UIDs survive, or the message becomes unreachable', () => {
  // Measured 2026-08-25: scrub destroyed 30 of 30 UIDs because "7529" has the
  // shape of a four-digit code. After that no message_read, no flag_add and
  // no reply were possible at all. The exception is field name AND shape.
  const d = scrub({ envelopes: [{ id: '7529', subject: '416107 is your code' }] });
  assert.equal(d.envelopes[0].id, '7529');
  assert.ok(d.envelopes[0].subject.includes('[...]'));
  // An id field that is not a plain digit string is treated normally.
  assert.ok(scrub({ id: 'Token AB3D-9F2K' }).id.includes('[...]'));
});

test('scrub walks nested structures', () => {
  const d = scrub({ a: [{ b: { c: '416107 is your code' } }] });
  assert.ok(d.a[0].b.c.includes('[...]'));
  // Numbers, booleans and null stay what they are.
  const raw = { n: 42, b: true, z: null };
  assert.deepEqual(scrub(raw), raw);
});

test('Tables are handled column by column', () => {
  const table = '│ 7529 │ 416107 is your code │ Raum 4711 │';
  const out = maskTable(table);
  assert.ok(out.includes('[...]'), 'the code must go');
  assert.ok(out.includes('Raum 4711'), 'a column without a keyword stays');
  assert.equal((out.match(/│/g) || []).length, 4, 'the layout stays');
});

// ------------------------------------------------------------ differential --

const ALL = [...MUST_MASK, ...MUST_SURVIVE,
  '', 'nothing special', 'Bestellnummer 1234567890123',
  'Version 1.2.3', 'Raum 4711', '2026', '0000',
  'Telefon: +49 30 1234567', 'Konto 12345678 BLZ 10000000',
  'Mehrere: 416107 und 292137 im selben Satz',
  'Am 22.09.2026 um 14:30 Uhr, Code 8821',
];

test('maskCodes matches the Python original character for character',
  { skip: referencePresent ? false : 'OTP_FILTER_PYTHON_REFERENCE not set' },
  () => {
    const samples = ALL.filter((x) => !x.includes('+49'));
    const expected = python('mask_codes', samples);
    for (const [i, input] of samples.entries()) {
      assert.equal(maskCodes(input), expected[i],
        `difference at ${JSON.stringify(input)}`);
    }
  });

// ---------------------------------------------------------------- sibling --
//
// The gmail-mcp server carries its own copy of this filter, deliberately: two
// separate deployments with separate blast radii, so that an edit for one
// cannot silently change the other. The price of that decision is drift, and
// drift in a filter is invisible until a code reaches a model.
//
// So the copies are not shared, they are *compared* -- and by behaviour, not
// by text, because part of the divergence is intended. `scrub` and
// STRUCTURAL_FIELDS are excluded on purpose: Gmail identifies messages by
// opaque hex strings where IMAP uses decimal UIDs, and that difference is the
// whole reason the copies are not byte-identical.
//
//   OTP_FILTER_SIBLING=../gmail-mcp/src/otp-filter.mjs npm test

const SIBLING = process.env.OTP_FILTER_SIBLING;
const siblingPresent = Boolean(SIBLING) && fs.existsSync(SIBLING);

test('the sibling server masks exactly the same characters',
  { skip: siblingPresent ? false : 'OTP_FILTER_SIBLING not set' },
  async () => {
    const other = await import(path.resolve(SIBLING));
    // One sample per branch of the announcement list, plus every exception
    // it carves out. A corpus that misses a branch lets a change to that
    // branch through: the first version of this test did exactly that, and a
    // mutation of `passcode` survived it.
    const samples = [...ALL,
      // announcement words
      'TAN 8821', 'OTP 4711', '2FA 123456', 'MFA-Code 99213',
      'two factor 8821', 'two-factor 8821', '2-factor 8821',
      'Zwei-Faktor 8821', 'zwei faktor 8821',
      'one-time code 416107', 'one time password 416107',
      'onetime passcode 416107', 'Einmal-Kennwort 416107',
      'einmalpasswort 416107', 'passcode 416107',
      'Zugangscode 416107', 'Bestaetigungscode 416107',
      'Sicherheitscode 416107', 'Bestätigungscode 416107',
      'login code 416107', 'log-in code 416107', 'log in code 416107',
      'auth code 416107', 'authy code 416107', 'sms code 416107',
      'pin code 416107', 'zugangs code 416107',
      'verification code 416107', 'security code 416107',
      'access code 416107', 'confirmation code 416107',
      'Freigabe 416107',
      // the exceptions: ordinary words ending in "code" that must survive
      'Barcode 416107', 'QR-Code 416107', 'Quellcode 416107',
      'Unicode 416107', 'Dresscode 416107', 'Postcode 416107',
      'Zipcode 416107', 'Laendercode 416107', 'Ländercode 416107',
      'Farbcode 416107', 'Morsecode 416107', 'Geocode 416107',
      // the masking shapes themselves
      'PIN 123 456', '8 4 2 1 9 9', 'AB12-CD34', 'X7K9M2',
      // and the things that must never be touched
      'Rechnung 1234,50 EUR', 'am 2026-09-14', 'am 14-09-26',
      'Telefon (030) 123-4567', 'Jahr 2026', 'iPhone15',
      '│ 7529 │ 416107 is your code │'];
    for (const input of samples) {
      assert.equal(other.maskCodes(input), maskCodes(input),
        `maskCodes differs at ${JSON.stringify(input)}`);
      assert.equal(other.redact(input), redact(input),
        `redact differs at ${JSON.stringify(input)}`);
      assert.equal(other.maskTable(input), maskTable(input),
        `maskTable differs at ${JSON.stringify(input)}`);
    }
    // The masks themselves must agree, or one server hides a code behind a
    // word the other does not use and the difference is invisible in review.
    assert.equal(other.MASK, MASK);
  });

test('Text that announces a code strongly masks every code shape in it', () => {
  assert.equal(redact('Your one-time password follows below. Please do not share it with anyone at all: 4417'),
    'Your one-time password follows below. Please do not share it with anyone at all: [...]');
  assert.equal(redact('Your code for the portal (valid 10 minutes, do not share) follows here: 123456789'),
    'Your code for the portal (valid 10 minutes, do not share) follows here: [...]');
  assert.equal(redact('Your verification code: kxmqpz'), 'Your verification code: [...]');
  assert.equal(redact('Your confirmation code is below.'), 'Your confirmation code is below.');
});

test('A keyword behind heavy HTML markup still counts as near', () => {
  const pad = '<td style="font-family:Helvetica,Arial;padding:12px 24px;color:#333">'.repeat(8);
  assert.ok(!redact(`<td>Your verification code</td>${pad}<strong>482913</strong>`).includes('482913'));
});

test('An encoded subject is decoded before the 2FA check', () => {
  const mail = 'From: Bank <noreply@bank.de>\nSubject: =?UTF-8?Q?Ihr_Best=C3=A4tigungscode?=\n\n'
    + 'Bitte geben Sie folgende Zahl ein, um fortzufahren, danke sehr: 4471';
  assert.ok(!redact(mail).includes('4471'));
});

test('A German landline stays readable next to a booking code', () => {
  const t = 'Buchungscode schicke ich dir. Telefon: 030 555012-57, Raum 4711';
  assert.equal(redact(t), t);
});

test('Ordinary numbers in confirmation mails and next to ordinary codes survive', () => {
  for (const t of ['Please confirm your zip code: 69120', 'Your postal code: 69120 is wrong',
    'At one time we sent order 1234567890', 'Telefon: 030 555012-57',
    'From: Shop <shop@x.de>\nSubject: Bestätigung Ihrer Bestellung\n\nBestellnummer 1234567890',
    'From: Bank <security@bank.de>\nSubject: Info\n\nOrder 1234567890']) {
    assert.equal(redact(t), t, t);
  }
});

test('A code in two groups starting with 0 is masked completely', () => {
  assert.ok(!/\d/.test(redact('Your login code is 0421 9384')));
  assert.ok(!/\d/.test(redact('code 0621 482913')));
});

test('A code on the line or tag after its announcement is masked', () => {
  assert.equal(redact('<p>Your verification code</p><p><b>KXQPZM</b></p>'),
    '<p>Your verification code</p><p><b>[...]</b></p>');
  assert.equal(redact('Your verification code:\nKXQPZM'), 'Your verification code:\n[...]');
});

test('Layout numbers and ordinary compound codes survive', () => {
  for (const t of ['<table width="590" style="max-width: 600px">', 'X-MICROSOFT-LOCATIONPOSTALCODE:69120',
    '<td class="ab12cd maxw-660">']) {
    assert.ok(redact(`Your verification code is near. ${t}`).endsWith(t), t);
  }
  const company = 'Revolut Securities Europe UAB (company code: 304580906, Code ABC)';
  assert.equal(redact(company), company);
});

test('A label ending in a layout word does not shield the code', () => {
  for (const t of ['Your code for Desktop: 482913', 'Use this to sign in to your Android: 482913',
    'Valid: 482913 is your verification code']) {
    assert.ok(!redact(t).includes('482913'), t);
  }
});

test('A code split into boxes or a few words after its announcement is masked', () => {
  const boxes = 'Your verification code:<table><tr><td>4</td><td>8</td><td>2</td><td>9</td><td>1</td><td>3</td></tr></table>';
  assert.ok(!/\d/.test(redact(boxes)));
  assert.equal(redact('Your one-time password is below.\n\nxkcd-7Q2'),
    'Your one-time password is below.\n\n[...]');
});

test('Common code phrasings without the word code are masked', () => {
  for (const t of ['482913 is your Steam Guard number. Expires in 10 minutes.',
    'Welcome! Enter this number in the app to confirm your email address.\n\n482913',
    'From: verify@example.com\nSubject: Hello\n\nEnter 482913 to continue']) {
    assert.ok(!redact(t).includes('482913'), t);
  }
});

test('A long number keeps its context after earlier masks', () => {
  const t = `From: verify@x.com\nSubject: hi\n\n${'Ref AB12CD34 '.repeat(25)}Your PIN number 1234567890`;
  assert.ok(!redact(t).includes('1234567890'));
});

test('A phone number does not swallow the code after it', () => {
  assert.ok(!redact('Your SMS from +4915112345678 482913 is your code').includes('482913'));
  const t = 'Telefon +1 415 555 1234, Tel. +49 30 555012-25';
  assert.equal(redact(t), t);
});

test('Words after a strong label stay readable', () => {
  for (const t of ['OTP: please contact us', 'TAN: Bitte nicht weitergeben.']) assert.equal(redact(t), t);
});

test('Round five: lowercase codes, mixed masks, the reach limit and hidden html', () => {
  assert.ok(!redact('Ihr Bestätigungscode: wxyzab bitte eingeben').includes('wxyzab'));
  assert.ok(!redact('Your OTP: abcdef please').includes('abcdef'));
  assert.ok(!redact('Your one-time password is below. Order 4829 shipped.\n\nxkcd-7Q2').includes('7Q2'));
  const far = redact(`Your one-time password is below:${' '.repeat(280)}1a2b3c4d5e6f`);
  assert.ok(far.endsWith('[...]') && !far.includes('6f'));
  const html = redact('<title>Your one-time password</title><style>td{padding:0 10px}</style><p>xkcd-7q2</p>');
  assert.ok(html.includes('10px') && !html.includes('xkcd-7q2'));
  assert.ok(redact('Your SMS from +1 415 555 1234 4829 is your code').includes('+1 415 555 1234 [...]'));
});

test('Round five: login footers, security senders and digit runs stay readable', () => {
  for (const t of ['Hi, your login was successful. Kundennummer 48291, Rechnung 2026',
    'From: alerts@security.bank.de\nSubject: Kontoauszug\n\nKonto 12345678 Saldo 4829']) {
    assert.equal(redact(t), t);
  }
  assert.equal(redact('Your verification code:<td>4</td><td>8</td><td>2</td><td>9</td>'),
    'Your verification code:<td>[...]</td><td></td><td></td><td></td>');
});

test('A charset after an announcement stays readable', () => {
  const t = 'Your one-time password\nContent-Type: text/html; charset=utf-8';
  assert.equal(redact(t), t);
});

test('Round six: boxes further down, footers, status words and stray digits', () => {
  for (const t of ['Your verification code is below.<table><tr><td>4</td><td>8</td><td>2</td><td>9</td><td>1</td><td>3</td></tr></table>',
    'Your verification code</h1><p>Enter it in the app.</p><table><tr><td>4</td><td>8</td><td>2</td><td>9</td></tr></table>',
    'Your OTP is ready.<div>see</div> Q 7 X 2 9', 'Your code:4 8 2 9 1 3',
    'From: security@example.com\nSubject: Hello\n\nEnter 482913 to continue',
    'Your SMS from +14155551234 4829 is your code']) {
    assert.ok(!/[2-9]/.test(redact(t).replace(/\+14155551234/, '')), t);
  }
  assert.equal(redact('Your OTP: Q 7 X 2'), 'Your OTP: [...]');
  assert.ok(redact('Your verification code is 482913. Order shipped, invoice RE-2026-0042, room B250.')
    .endsWith('invoice RE-2026-0042, room B250.'));
  assert.equal(redact('Two-factor: enabled. MFA: active. TAN: Danke'), 'Two-factor: enabled. MFA: active. TAN: Danke');
  const footer = 'Please use the following link to reset: Order 48291 ships, ref AB12CD';
  assert.equal(redact(footer), footer);
});

test('A US address and a regulator authorisation code stay readable in ordinary mail', () => {
  for (const t of ['548 Market St, San Francisco, CA 94104', 'registration number of 304580906 and authorisation code of 900562',
    'Delivery to Acme Inc, Austin, TX 78701']) {
    assert.equal(redact(t), t, t);
  }
});

test('Round seven: lowercase boxes, plural nouns, two boxes and a validity note', () => {
  for (const t of ['Your verification code: a 7 x 2 9', 'Your verification code:&nbsp;a&nbsp;7&nbsp;x&nbsp;2&nbsp;9', 'Your 2FA code<td>a</td><td>7</td><td>x</td><td>2</td>',
    'Gib diese Zahlen ein: 4829', 'Your Steam Guard code: GB 48291', 'Your security code for order ID 48291',
    'Your code\n\n7 3 1 5\n\n2 8 4 6',
    'Your code is valid for 10 min.<table><tr><td>4</td><td>8</td><td>2</td><td>9</td></tr></table>']) {
    assert.ok(!/[2-9]\D*[2-9]/.test(redact(t).replace(/10 min/, '')), t);
  }
});

test('A code after two capitals and a country code is masked', () => {
  for (const t of ['Your Verification Code GB 48291', 'Your Code XY 48291', 'Ihr Code DE 48291', 'Your Code CA 48291']) {
    assert.ok(!redact(t).includes('48291'), t);
  }
});

test('Round nine: boxes after validity notes and after an inline copy are masked', () => {
  const box = '<td>4</td><td>8</td><td>2</td><td>9</td>';
  for (const t of [`Your code is valid for 24h: ${box}`, `Dein Code, gültig 2 h:${box}`,
    `Your code is valid for 1440 minutes${box}`, `Your code: [...] Enter${box}`,
    'Your code: 482913.\n<td>4</td><td>8</td><td>2</td><td>9</td><td>1</td><td>3</td>']) {
    assert.ok(!/<td>[2-9]<\/td>/.test(redact(t)), t);
  }
});

test('Round ten: a code after a state abbreviation is masked', () => {
  for (const t of ['Your Passcode CA 48291', 'Dein Sicherheitscode DE 48291', 'Your Token NY 48291',
    'Your code, CA 48291', 'Your Code, CA 48291', 'Your Verification Code For Acme Corp, CA 48291',
    'Your Microsoft verification code:\nAcme Corp ID 48291', 'Your security code:\nACME, CA 48291',
    'Ihr Bestätigungscode\nAcme Bank DE 48291', 'Ship to Austin TX 48291 is your code']) {
    assert.ok(!redact(t).includes('48291'), t);
  }
});

test('Accepted trade-off: in a mail that announces a code, nearby digit boxes are masked too', () => {
  assert.ok(!redact('Your code 482913.\nItems: <td>2</td><td>5</td><td>1</td><td>9</td>').includes('<td>2</td>'));
  assert.ok(redact('Your verification code is below. Step a 1 b 2').endsWith('Step [...]'));
});

test('Accepted trade-off: a US zip code in a mail that announces a code is masked', () => {
  assert.ok(redact('Your verification code: 482913\nShip to Austin, TX 78701').endsWith('TX [...]'));
});

test('Accepted trade-off: US zip codes anywhere in a 2FA mail are masked', () => {
  assert.ok(redact('Your verification code: 482913\n\nAcme Inc, 548 Market St, San Francisco, CA 94104').endsWith('CA [...]'));
  assert.ok(redact('Subject: Sign in to Acme\nFrom: noreply@acme.com\n\nOur office: San Francisco, CA 94104').endsWith('CA [...]'));
  assert.equal(redact('Ship to Austin, TX 78701', { twoFactor: true }), 'Ship to Austin, TX [...]');
});
