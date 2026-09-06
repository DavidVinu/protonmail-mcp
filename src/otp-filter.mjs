// Strip one-time codes out of mail text before a model ever sees it.
//
// WHY THIS CANNOT BE A PERMISSION. A permission system decides WHETHER a tool
// may run. It cannot change WHAT the answer contains. The moment reading mail
// is allowed, a confirmation code inside the body reaches the model. Observed
// on 2026-08-21 and 2026-08-22 in the author's own setup: "Your email
// verification code is: 010299" was relayed verbatim into a chat room.
//
// That is the whole argument for this file. Everything else this server does
// -- a fixed set of tools, argv built from typed parameters, no free-form
// command -- a permission dialog could express. This it could not.
//
// The patterns are based on AOSP's OTP detection, extended with German
// compounds and with guards against false positives. Every guard has a real
// incident behind it; the comments name them.

export const MASK = '[...]';
export const REDACTED = '[one-time code hidden]';

// --- Shapes a code can take -------------------------------------------------
// Start: beginning of line, or a character that cannot be part of a longer
// number. End likewise. This keeps matches from landing in the middle of an
// IBAN or an order number. `<` and `&` belong in the END class, otherwise a
// code slips through inside HTML: "<strong>010299</strong>" used to.
const START = String.raw`(?:^|(?<=[\s>("'=\[;]))`;
const END = String.raw`(?=$|[\s.,;:?!)'\]"<&])`;

const FOUR_DIGITS = String.raw`\d{4}`;
const ALNUM_5_8 = String.raw`(?=[0-9A-Za-z-]{0,9}\d)[0-9A-Za-z](?:-?[0-9A-Za-z]){4,7}`;
const THREE_PLUS_THREE = String.raw`\d{3}[\s ]\d{3}`;
const SPACED_DIGITS = String.raw`\d(?:[\s -]\d){3,7}`;      // "8 4 2 1 9 9"

const CANDIDATE = new RegExp(
  `${START}(${[SPACED_DIGITS, THREE_PLUS_THREE, ALNUM_5_8, FOUR_DIGITS].join('|')})${END}`,
  'g',
);

// --- Guards against false positives -----------------------------------------
const YEAR = /^(?:19|20)\d{2}$/;
const THREE_LOWERCASE = /[a-zäöüß]{3}/;        // "iPhone15", "Termin1"
const DASHED_DATE = /[0-3]?\d-[0-3]?\d-(?:[12]\d)?\d\d/g;
// Measured 2026-08-25: "Zahlung bis 2026-09-22" (payment due) became "Zahlung
// bis [...]". DASHED_DATE only catches dd-mm-yyyy and does not cover the
// candidate fully. Recognising deadlines is the point of the whole system.
const ISO_DATE = /(?:19|20)\d{2}-[01]?\d-[0-3]?\d/g;
const PHONE = /\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4}/g;
const AMOUNT_AFTER = /^[.,]\d/;                // 1234,50
const NUMBERLIKE_BEFORE = /[\d.,/:]$/;         // part of a longer number

// Spans that must NEVER be masked. No one-time code looks like any of these,
// and the damage would be large: a destroyed IBAN or postcode makes exactly
// the tasks impossible that the assistant exists for. Found 2026-08-25 in a
// real draft: the postcode in "69120 Heidelberg" became "[...]".
const PROTECTED = [
  /\b[A-Z]{2}\d{2}(?:[  ]?[A-Z0-9]{4}){2,8}\b/g,        // IBAN
  /\b\d{5}(?=[  ]+[A-ZÄÖÜ])/g,                          // postcode + city
  /\b\d{1,3}(?:[. ]\d{3})+(?:,\d{2})?\b/g,              // 1.234.567,89
  /\b(?:19|20)\d{2}-\d{2}-\d{2}\b/g,                    // ISO date
  /\b\d{1,2}\.\d{1,2}\.(?:19|20)\d{2}\b/g,              // 22.09.2026
  /\b(?:19|20)\d{2}-\d{2}\b/g,                          // 2026-09
];

/** Does a protected span cover the candidate completely? */
function insideProtectedSpan(text, start, end) {
  for (const pattern of PROTECTED) {
    pattern.lastIndex = 0;
    for (const hit of text.matchAll(pattern)) {
      if (hit.index <= start && hit.index + hit[0].length >= end) return true;
    }
  }
  return false;
}

function isFalsePositive(text, raw, start, end) {
  if (YEAR.test(raw)) return true;
  if (insideProtectedSpan(text, start, end)) return true;
  if (THREE_LOWERCASE.test(raw)) return true;
  if (NUMBERLIKE_BEFORE.test(text.slice(Math.max(0, start - 1), start))) return true;
  if (AMOUNT_AFTER.test(text.slice(end, end + 2))) return true;
  for (const guard of [DASHED_DATE, ISO_DATE, PHONE]) {
    guard.lastIndex = 0;
    for (const hit of text.matchAll(guard)) {
      if (hit.index <= start && hit.index + hit[0].length >= end) return true;
    }
  }
  return false;
}

/** Layer 1: mask individual codes, leave everything else readable. */
export function maskCodes(text) {
  if (typeof text !== 'string' || !text) return text;
  const parts = [];
  let last = 0;
  CANDIDATE.lastIndex = 0;
  for (const m of text.matchAll(CANDIDATE)) {
    const raw = m[1];
    const start = m.index + m[0].indexOf(raw);
    const end = start + raw.length;
    if (isFalsePositive(text, raw, start, end)) continue;
    parts.push(text.slice(last, start), MASK);
    last = end;
  }
  parts.push(text.slice(last));
  return parts.join('');
}

// --- Announcement words ------------------------------------------------------
// Based on AOSP's ENGLISH_CONTEXT_WORDS, extended with German compounds; the
// author's mailbox is bilingual and a filter that only speaks English would
// miss half of it. Deliberately narrow: layer 1 already catches every visible
// code, so this layer only exists for text that ANNOUNCES a code without
// containing it as a literal string.
const OTP_WORDS = new RegExp(
  '('
  + String.raw`\b(tan|otp|2fa|mfa|(two|2)[-\s]?factor|zwei[-\s]?faktor)\b|`
  // Note the separator class. Requiring the two word parts to be adjacent
  // misses "one-time password" and "one-time code", the two most common
  // English phrasings there are. Found 2026-09-06 while writing the contract
  // test, in a version that had been running for weeks.
  + String.raw`\b(one[-\s]?time|einmal[-\s]?)[-\s]?(code|kennwort|passwort|passcode|password)\b|`
  + String.raw`\bpasscode\b|`
  // Any word ending in "code" is suspicious in German (Zugangscode,
  // Bestaetigungscode, Sicherheitscode ...) except these, which are ordinary.
  + String.raw`\b(?!(?:bar|qr|quell|uni|dress|post|zip|l[äa]nder|farb|morse|geo)code\b)`
  + String.raw`[a-zäöüß]{3,}code\b|`
  + String.raw`\b(login|log[-\s]?in|auth|authy|sms|pin|zugangs)[-\s]?code\b|`
  + String.raw`\b(verification|security|access|confirmation) code\b|`
  + String.raw`\bfreigabe\b)`,
  'i',
);

/** Layer 2: blank the whole text if it announces a code; else mask in place.
 *
 * Known edge: this blanks the ENTIRE string. A reply preview quotes the
 * original message, so replying to a mail about a confirmation code hides
 * your own draft text behind REDACTED as well. The draft itself is still
 * created correctly; only the preview is empty.
 */
export function redact(text) {
  if (!text) return text;
  return OTP_WORDS.test(text) ? REDACTED : maskCodes(text);
}

// --- Structural fields -------------------------------------------------------
// Measured 2026-08-25: scrub destroyed the "id" field of every envelope,
// 30 of 30 IMAP UIDs turned into "[...]" because "7529" satisfies FOUR_DIGITS.
// After that no message_read, no flag_add and no reply were possible at all:
// nobody ever got to see an id.
//
// A UID is assigned by the IMAP server, not by the sender, so it cannot carry
// a one-time code. It therefore stays -- but only if it also LOOKS like a UID.
// The exception is field name AND shape, never the name alone.
export const STRUCTURAL_FIELDS = ['id', 'uid'];
const DIGITS_ONLY = /^\d+$/;

function isUid(key, value, structuralFields) {
  return structuralFields.includes(key)
    && typeof value === 'string' && DIGITS_ONLY.test(value);
}

/** Clean a JSON structure field by field; shape and numbers stay untouched. */
export function scrub(value, structuralFields = STRUCTURAL_FIELDS) {
  if (typeof value === 'string') return redact(value);
  if (Array.isArray(value)) return value.map((x) => scrub(x, structuralFields));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = isUid(k, v, structuralFields) ? v : scrub(v, structuralFields);
    }
    return out;
  }
  return value;
}

// --- Tables ------------------------------------------------------------------
// Without --json, himalaya prints tables with box-drawing characters. Handle
// them column by column so the layout survives and the output stays readable.
const SEPARATOR = /([│┆])/;

export function maskTable(text) {
  if (typeof text !== 'string' || !text) return text;
  return text.split('\n').map((line) => {
    if (!SEPARATOR.test(line)) return redact(line);
    return line.split(SEPARATOR).map((part) => (
      SEPARATOR.test(part) ? part : redact(part)
    )).join('');
  }).join('\n');
}
