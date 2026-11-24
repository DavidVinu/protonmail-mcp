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
  /\+\d{1,3}(?:[ \/-]?\(?\d+\)?)+/g,
  /(?<![\d.,])0\d{2,5}[ \/]\d{4,8}(?:-\d{1,5})?(?!\d|[.,]\d)/g,
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

export function maskCodes(text, near = () => true) {
  if (typeof text !== 'string' || !text) return text;
  const parts = [];
  let last = 0;
  CANDIDATE.lastIndex = 0;
  for (const m of text.matchAll(CANDIDATE)) {
    const raw = m[1];
    const start = m.index + m[0].indexOf(raw);
    const end = start + raw.length;
    if (isFalsePositive(text, raw, start, end) || !near(start, end)) continue;
    parts.push(text.slice(last, start), MASK);
    last = end;
  }
  parts.push(text.slice(last));
  return parts.join('');
}

export const WINDOW = 40;

const L = 'a-zäöüß';
const ORDINARY = String.raw`bar|qr|quell|uni|dress|post|postal|zip|l[äa]nder|farb|morse|geo|source|country|area|colou?r`;
const CODE_WORD = String.raw`(?<!(?:${ORDINARY})[-\s])(?!(?:${ORDINARY})code)[${L}]*code`;
const KEYWORDS = [
  'tan', 'otp', 'pin', '2fa', 'mfa', 'token', 'passcode', 'passwor[dt]', 'kennwort',
  String.raw`(?:two|2|zwei)[-\s]?(?:factor|faktor)`,
  String.raw`(?:one|einmal)[-\s]?(?:time|code|kennwort|passwort)`,
  `verif[${L}]*`, `authenti[${L}]*`, CODE_WORD,
];
const CONTEXT = new RegExp(`(?<![${L}0-9])(?:${KEYWORDS.join('|')})s?(?![${L}])`, 'iu');

const STRONG_TERMS = [
  'otp', 'tan', '2fa', 'mfa', 'passcode',
  String.raw`(?:two|2|zwei)[-\s]?(?:factor|faktor)`,
  String.raw`(?:one|einmal)[-\s]?(?:time|code|kennwort|passwort)[${L}]*`,
  String.raw`(?:verification|security|confirmation|login|log[-\s]?in|sign[-\s]?in|authentication|access|sms)[-\s]code`,
  String.raw`(?:verifizierungs|bestätigungs|bestaetigungs|sicherheits|anmelde|zugangs|freigabe|login|einmal|authentifizierungs)[-\s]?code`,
  String.raw`(?:your|ihr|dein)[^\S\n]+(?:[${L}]+[^\S\n]+)?code`,
];
const STRONG = `(?<![${L}0-9])(?:${STRONG_TERMS.join('|')})s?(?![${L}])`;
const ANNOUNCES = new RegExp(STRONG, 'iu');

const SUBJECT_ONLY = new RegExp(`(?<![${L}])(?:sign[-\\s]?in|log[-\\s]?in|anmeld[${L}]*|security|sicherheit[${L}]*|confirm[${L}]*|bestätig[${L}]*)`, 'iu');

const SENDER_TOKENS = new Set(['verify', 'verification', 'security', 'otp', '2fa',
  'mfa', 'auth', 'login', 'signin', 'accountprotection', 'passcode']);

const LABEL_TAIL = String.raw`[^\S\n]*(?:(?:is|ist|lautet)[^\S\n]*:?|:)[^\S\n]*`;
const LABELLED = new RegExp(
  `(?<![${L}])(?:${CODE_WORD}|tan|pin|otp|passcode|token|passwor[dt]|kennwort)`
  + LABEL_TAIL + String.raw`([A-Z0-9](?:-?[A-Z0-9]){3,11})${END}`,
  'giu',
);
const STRONG_LABELLED = new RegExp(
  STRONG + String.raw`[^\S\n]*(?:(?:is|ist|lautet)[^\S\n]*)?:[^\S\n]*([a-z0-9](?:-?[a-z0-9]){3,11})${END}`, 'giu');
const LONG_NUMBER = new RegExp(`${START}(\\d{9,10})${END}`, 'g');

export function hasContext(text) {
  return typeof text === 'string' && CONTEXT.test(text);
}

export function isTwoFactorMail({ subject = '', from = '' } = {}) {
  if (hasContext(subject) || SUBJECT_ONLY.test(subject)) return true;
  const local = String(from).match(/([^\s<"@]+)@/)?.[1]?.toLowerCase() ?? '';
  return local.split(/[-._+]/).some((t) => SENDER_TOKENS.has(t));
}

function decodeWords(value) {
  return value.replace(/\?=\s+=\?/g, '?==?').replace(/=\?([^?]+)\?([bq])\?([^?]*)\?=/gi, (whole, charset, enc, data) => {
    try {
      const bytes = enc.toLowerCase() === 'b'
        ? Buffer.from(data, 'base64')
        : Buffer.from(data.replace(/_/g, ' ').replace(/=([0-9a-f]{2})/gi,
          (_, h) => String.fromCharCode(parseInt(h, 16))), 'latin1');
      return new TextDecoder(charset.toLowerCase()).decode(bytes);
    } catch {
      return whole;
    }
  });
}

export function headersOf(text) {
  const head = text.split(/\r?\n\r?\n/, 1)[0].replace(/\r?\n[ \t]+/g, ' ');
  const field = (name) => decodeWords(new RegExp(`^${name}:[^\\S\\n]*(.*)$`, 'mi').exec(head)?.[1] ?? '');
  return { subject: field('Subject'), from: field('From') };
}

const visible = (html) => html.replace(/^[^<]*>/, ' ').replace(/<[^>]*$/, ' ')
  .replace(/<[^<>]*>/g, ' ').replace(/[^\S\n]+/g, ' ');

function visibleBefore(text, start) {
  for (let n = 10 * WINDOW; ; n *= 2) {
    const seen = visible(text.slice(Math.max(0, start - n), start));
    if (seen.length >= WINDOW || n >= start) return seen.slice(-WINDOW);
  }
}

function visibleAfter(text, end) {
  for (let n = 10 * WINDOW; ; n *= 2) {
    const seen = visible(text.slice(end, end + n));
    if (seen.length >= WINDOW || end + n >= text.length) return seen.slice(0, WINDOW);
  }
}

function maskLabelled(text) {
  const masked = text.replace(LABELLED, (hit, code) => {
    if (code.includes(MASK)) return hit;
    if (!/\d/.test(code) && code !== code.toUpperCase()) return hit;
    return hit.slice(0, hit.length - code.length) + MASK;
  });
  return masked.replace(STRONG_LABELLED, (hit, code) => (
    code.includes(MASK) ? hit : hit.slice(0, hit.length - code.length) + MASK));
}

function maskAll(text) {
  const masked = maskCodes(text);
  return maskLabelled(masked.replace(LONG_NUMBER, (hit, digits, offset) => (
    insideProtectedSpan(masked, offset, offset + hit.length) ? hit : hit.replace(digits, MASK))));
}

export function redact(text, { twoFactor = false } = {}) {
  if (typeof text !== 'string' || !text) return text;
  if (twoFactor || ANNOUNCES.test(text) || isTwoFactorMail(headersOf(text))) return maskAll(text);
  const near = (start, end) => hasContext(
    visibleBefore(text, start) + text.slice(start, end) + visibleAfter(text, end));
  return maskLabelled(maskCodes(text, near));
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

function envelopeOf(value) {
  const from = [value.from].flat().map((f) => (typeof f === 'string' ? f : f?.email ?? '')).join(' ');
  return { subject: typeof value.subject === 'string' ? value.subject : '', from };
}

export function scrub(value, structuralFields = STRUCTURAL_FIELDS, twoFactor = false) {
  if (typeof value === 'string') return redact(value, { twoFactor });
  if (Array.isArray(value)) return value.map((x) => scrub(x, structuralFields, twoFactor));
  if (value && typeof value === 'object') {
    const mail = twoFactor || isTwoFactorMail(envelopeOf(value));
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = isUid(k, v, structuralFields) ? v : scrub(v, structuralFields, mail);
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
