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

import { MASK, REDACTED, maskCodes, maskTable, redact, scrub } from '../src/otp-filter.mjs';

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

test('Text that announces a code is blanked entirely', () => {
  assert.equal(redact('Dein Verifizierungscode lautet'),
    '[one-time code hidden]');
  // Counter-check: words ending in "code" that are not codes.
  for (const t of ['Der Barcode auf dem Paket', 'QR-Code scannen',
                   'Postcode eingeben']) {
    assert.notEqual(redact(t), '[one-time code hidden]', t);
  }
});

test('Hyphenated announcements are recognised too', () => {
  // The Python original required the two word parts to be adjacent and
  // therefore missed the two most common English phrasings there are.
  // Found 2026-09-06 while writing this contract, in a version that had been
  // running for weeks. This is the one place the port deliberately differs.
  for (const t of ['Your one-time password', 'one-time code',
                   'one time passcode', 'Einmal Passwort']) {
    assert.equal(redact(t), '[one-time code hidden]', t);
  }
});

test('IMAP UIDs survive, or the message becomes unreachable', () => {
  // Measured 2026-08-25: scrub destroyed 30 of 30 UIDs because "7529" has the
  // shape of a four-digit code. After that no message_read, no flag_add and
  // no reply were possible at all. The exception is field name AND shape.
  const d = scrub({ envelopes: [{ id: '7529', subject: '416107 is your code' }] });
  assert.equal(d.envelopes[0].id, '7529');
  assert.ok(d.envelopes[0].subject.includes('[...]'));
  // An id field that is not a plain digit string is treated normally.
  assert.ok(scrub({ id: 'AB3D-9F2K' }).id.includes('[...]'));
});

test('scrub walks nested structures', () => {
  const d = scrub({ a: [{ b: { c: '416107 is your code' } }] });
  assert.ok(d.a[0].b.c.includes('[...]'));
  // Numbers, booleans and null stay what they are.
  const raw = { n: 42, b: true, z: null };
  assert.deepEqual(scrub(raw), raw);
});

test('Tables are handled column by column', () => {
  const table = '│ 7529 │ 416107 is your code │';
  const out = maskTable(table);
  assert.ok(out.includes('[...]'), 'the code must go');
  assert.equal((out.match(/│/g) || []).length, 3, 'the layout stays');
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
    const expected = python('mask_codes', ALL);
    for (const [i, input] of ALL.entries()) {
      assert.equal(maskCodes(input), expected[i],
        `difference at ${JSON.stringify(input)}`);
    }
  });

test('redact matches the Python original character for character',
  { skip: referencePresent ? false : 'OTP_FILTER_PYTHON_REFERENCE not set' },
  () => {
    // Without the four cases from the hyphenation test above: that is where
    // the port deliberately differs, because the original has a gap there.
    const samples = [...ALL, 'Dein Verifizierungscode lautet',
      'Der Barcode auf dem Paket',
      'QR-Code scannen', 'TAN eingeben', 'Freigabe erteilt',
      'Laendercode DE', 'Farbcode #ff00aa'];
    const expected = python('redact', samples);
    for (const [i, input] of samples.entries()) {
      // The mask constants differ by language; compare the shape, not the word.
      const mine = redact(input).replace('[one-time code hidden]', '<REDACTED>');
      const theirs = expected[i].replace('[Einmalcode ausgeblendet]', '<REDACTED>');
      assert.equal(mine, theirs, `difference at ${JSON.stringify(input)}`);
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
    assert.equal(other.REDACTED, REDACTED);
  });
