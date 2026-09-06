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

import { maskCodes, maskTable, redact, scrub } from '../src/otp-filter.mjs';

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
