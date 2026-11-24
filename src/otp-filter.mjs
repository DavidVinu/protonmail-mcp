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
const LAYOUT_BEFORE = /(?<![a-z-])(?:(?:width|height|size|padding|margin|spacing|border|radius|top|left|right|bottom|class|id|colspan|rowspan|cellpadding|cellspacing)\s*=\s*["']?|(?:(?:min-|max-|font-|line-|border-)?(?:width|height|size|padding|margin|spacing|radius|top|left|right|bottom))\s*:\s*)$/i;

// Spans that must NEVER be masked. No one-time code looks like any of these,
// and the damage would be large: a destroyed IBAN or postcode makes exactly
// the tasks impossible that the assistant exists for. Found 2026-08-25 in a
// real draft: the postcode in "69120 Heidelberg" became "[...]".
const PROTECTED = [
  /\b[A-Z]{2}\d{2}(?:[  ]?[A-Z0-9]{4}){2,8}\b/g,        // IBAN
  /\b\d{5}(?=[  ]+[A-ZÄÖÜ])/g,                          // postcode + city
  /(?<=,[ \u00a0][A-Z]{2}[ \u00a0])\d{5}(?:-\d{4})?\b/g,
  /\b\d{1,3}(?:[. ]\d{3})+(?:,\d{2})?\b/g,              // 1.234.567,89
  /\b(?:19|20)\d{2}-\d{2}-\d{2}\b/g,                    // ISO date
  /\b\d{1,2}\.\d{1,2}\.(?:19|20)\d{2}\b/g,              // 22.09.2026
  /\b(?:19|20)\d{2}-\d{2}\b/g,                          // 2026-09
  /(?<=(?:tel|telefon|phone|fon|fax|mobil|handy|mobile)\.?:?[^\S\n]{0,3})0\d{2,5}[ \/]\d{4,8}(?:-\d{1,5})?(?!\d|[.,]\d)/gi,
];

const INTERNATIONAL = /\+\d{1,3}(?:[ \/-]?\(?\d+\)?)+/g;
const MAX_PHONE_DIGITS = 15;

function phoneSpans(text) {
  const spans = [];
  INTERNATIONAL.lastIndex = 0;
  for (const hit of text.matchAll(INTERNATIONAL)) {
    const groups = hit[0].match(/[ \/-]?\(?\d+\)?/g);
    const limit = /^\+1(?:[ \/(-]|\d{10}(?!\d))/.test(hit[0]) ? 11 : MAX_PHONE_DIGITS;
    let length = 1;
    let digits = 0;
    let previous = 0;
    for (const group of groups) {
      const count = group.replace(/\D/g, '').length;
      if (digits + count > limit) break;
      if (digits && group[0] === ' ' && previous >= 6) break;
      length += group.length;
      digits += count;
      previous = count;
    }
    spans.push([hit.index, hit.index + length]);
  }
  return spans;
}

/** Does a protected span cover the candidate completely? */
function insideProtectedSpan(text, start, end) {
  for (const [from, to] of phoneSpans(text)) {
    if (from <= start && to >= end) return true;
  }
  for (const pattern of PROTECTED) {
    pattern.lastIndex = 0;
    for (const hit of text.matchAll(pattern)) {
      if (hit.index <= start && hit.index + hit[0].length >= end) return true;
    }
  }
  return false;
}

function badSurroundings(text, raw, start, end) {
  if (YEAR.test(raw) || insideProtectedSpan(text, start, end)) return true;
  if (NUMBERLIKE_BEFORE.test(text.slice(Math.max(0, start - 1), start))) return true;
  if (AMOUNT_AFTER.test(text.slice(end, end + 2))) return true;
  return LAYOUT_BEFORE.test(text.slice(Math.max(0, start - 20), start));
}

function isFalsePositive(text, raw, start, end) {
  if (badSurroundings(text, raw, start, end) || THREE_LOWERCASE.test(raw)) return true;
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
const ORDINARY = [
  'bar', 'qr', 'quell', 'uni', 'dress', 'post', 'postal', 'zip', 'l[äa]nder', 'farb', 'morse', 'geo',
  'source', 'country', 'area', 'colou?r', 'company', 'firmen', 'registration', 'register', 'tax',
  'steuer', 'vat', 'customer', 'kunden', 'order', 'bestell', 'product', 'produkt', 'artikel',
  'article', 'discount', 'rabatt', 'gutschein', 'voucher', 'promo', 'coupon', 'booking', 'buchungs',
  'reference', 'referenz', 'tracking', 'sendungs', 'swift', 'bank', 'sort', 'branch', 'airport',
  'currency', 'status', 'error', 'authori[sz]ation', 'fehler', 'html', 'css', 'tarif', 'event', 'veranstaltungs',
].join('|');
const CODE_WORD = String.raw`(?<!(?:${ORDINARY})[-\s])(?![${L}]*(?:${ORDINARY})code)[${L}]*code`;
const KEYWORDS = [
  'tan', 'otp', 'pin', '2fa', 'mfa', 'token', 'passcode', 'passwor[dt]', 'kennwort',
  String.raw`(?:two|2|zwei)[-\s]?(?:factor|faktor)`,
  String.raw`(?:one|einmal)[-\s]?(?:time|code|kennwort|passwort)`,
  `verif[${L}]*`, `authenti[${L}]*`, CODE_WORD, 'guard',
  String.raw`(?:use|enter|gib|nutze|verwende)[^\S\n]+(?:this|these|the[^\S\n]+following|following|diesen?|folgenden?)[^\S\n]+(?:codes?|numbers?|nummern?|zahlen|zahl|pin|digits|ziffern)`,
  String.raw`(?:use|enter)[^\S\n]+(?:this|it)[^\S\n]+to[^\S\n]+(?:sign|log)[-\s]?in`,
  String.raw`(?:confirm|best(?:ä|ae)tig)[${L}]*[^\S\n]+(?:(?:sie|your|ihre?|deine?)[^\S\n]+)?(?:e-?mail|account|konto|identity|identität|login|anmeldung)`,
];
const CONTEXT = new RegExp(`(?<![${L}0-9])(?:${KEYWORDS.join('|')})s?(?![${L}])`, 'iu');

const STRONG_TERMS = [
  'otp', 'tan', '2fa', 'mfa', 'passcode',
  String.raw`(?:two|2|zwei)[-\s]?(?:factor|faktor)`,
  String.raw`one[-\s]?time[-\s]?(?:code|password|passcode|pin)`,
  String.raw`einmal[-\s]?(?:code|kennwort|passwort|pin)`,
  String.raw`(?:verification|security|confirmation|login|log[-\s]?in|sign[-\s]?in|authentication|access|sms)[-\s]code`,
  String.raw`(?:verifizierungs|bestätigungs|bestaetigungs|sicherheits|anmelde|zugangs|freigabe|login|einmal|authentifizierungs)[-\s]?code`,
  String.raw`(?:your|ihr|dein)[^\S\n]+(?:(?!(?:${ORDINARY})(?![${L}]))[${L}]+[^\S\n]+)?code`,
];
const STRONG = `(?<![${L}0-9])(?:${STRONG_TERMS.join('|')})s?(?![${L}])`;
const ANNOUNCES = new RegExp(STRONG, 'iu');

const SUBJECT_ONLY = new RegExp(`(?<![${L}])(?:sign[-\\s]?in|log[-\\s]?in|verify|verifizier[${L}]*)(?![${L}])`, 'iu');

const SENDER_TOKENS = new Set(['verify', 'verification', 'otp', '2fa',
  'mfa', 'auth', 'signin', 'accountprotection', 'passcode']);

const LABEL_TAIL = String.raw`[^\S\n]*(?:(?:is|ist|lautet)[^\S\n]*:?|:)[^\S\n]*`;
const LABELLED = new RegExp(
  `(?<![${L}])(?:${CODE_WORD}|tan|pin|otp|passcode|token|passwor[dt]|kennwort)`
  + LABEL_TAIL + String.raw`([A-Z0-9](?:-?[A-Z0-9]){3,11})${END}`,
  'giu',
);
const STRONG_LABELLED = new RegExp(
  STRONG + String.raw`[^\S\n]*(?:(?:is|ist|lautet)[^\S\n]*)?:[^\S\n]*([a-z0-9](?:-?[a-z0-9]){3,11})${END}`, 'giu');
const LONG_NUMBER = new RegExp(`${START}(\\d{9,10})${END}`, 'g');
const BOX_GAP = String.raw`(?:\s|<[^<>]*>|&nbsp;)+`;
const BOXED = new RegExp(String.raw`(?<![A-Za-z0-9])[A-Za-z0-9](?:${BOX_GAP}[A-Za-z0-9](?![A-Za-z0-9])){3,9}`, 'g');
const PROSE = new Set(['please', 'contact', 'see', 'below', 'above', 'follows', 'none', 'not',
  'required', 'optional', 'sent', 'expired', 'invalid', 'bitte', 'siehe', 'unten', 'oben', 'folgt',
  'nicht', 'keine', 'kein', 'erforderlich', 'gesendet', 'abgelaufen', 'ungültig', 'nur', 'only',
  'enabled', 'disabled', 'active', 'inactive', 'aktiv', 'inaktiv', 'aktiviert', 'deaktiviert', 'on', 'off',
  'an', 'aus', 'yes', 'no', 'ja', 'nein', 'danke', 'thanks', 'thank', 'used', 'verwendet', 'benutzt']);
const PROSE_ENDING = /(?:ed|ing|iert|ung|ive|tion|lich|bar)$/i;
const NOT_A_CODE = /^(?:utf|iso|windows|latin|ucs)-?\d|^\d+(?:\.\d+)?(?:ms|s|px|pt|em|rem|vh|vw|dpi|deg)$/i;
const HIDDEN_BLOCK = /<(style|script|head)\b[\s\S]*?<\/\1>/gi;
const LOOSE_TOKEN = /(?<![A-Za-z0-9-])(?=[A-Za-z-]*\d)[A-Za-z0-9](?:-?[A-Za-z0-9]){3,11}(?![A-Za-z0-9-])/g;
const LOOSE_REACH = 300;
const GAP = String.raw`(?:\s|<[^<>]*>|&nbsp;|[:–-])*`;
const NEXT_TOKEN = new RegExp(
  STRONG + GAP + String.raw`(?:(?:is|ist|lautet)(?![${L}])${GAP})?`
  + String.raw`((?<![${L}0-9])[A-Z0-9](?:-?[A-Z0-9]){3,11})(?=$|[\s<.,;:!?)'"&])`, 'giu');

export function hasContext(text) {
  return typeof text === 'string' && CONTEXT.test(text);
}

export function isTwoFactorMail({ subject = '', from = '' } = {}) {
  if (hasContext(subject) || SUBJECT_ONLY.test(subject)) return true;
  const [, local = '', host = ''] = String(from).toLowerCase().match(/([^\s<"@]+)@([^\s>".]+)/) ?? [];
  return local === 'security' || [...local.split(/[-._+]/), host].some((t) => SENDER_TOKENS.has(t));
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

function replaceCode(pattern, text, keep) {
  return text.replace(pattern, (hit, code, offset) => {
    const start = offset + hit.length - code.length;
    if (code.includes(MASK) || keep(code, text.slice(start + code.length))
      || insideProtectedSpan(text, start, start + code.length)) return hit;
    return hit.slice(0, hit.length - code.length) + MASK;
  });
}

const lettersOnlyLower = (code) => !/\d/.test(code) && code !== code.toUpperCase();

function maskLabelled(text) {
  const masked = replaceCode(LABELLED, text, lettersOnlyLower);
  return replaceCode(STRONG_LABELLED, masked,
    (code) => YEAR.test(code) || (!/\d/.test(code)
      && (PROSE.has(code.toLowerCase()) || PROSE_ENDING.test(code))));
}

const nearIn = (text) => (start, end) => hasContext(
  visibleBefore(text, start) + text.slice(start, end) + visibleAfter(text, end));

function announcementRanges(text) {
  return [...text.matchAll(new RegExp(STRONG, 'giu'))]
    .map((a) => [a.index + a[0].length, a.index + a[0].length + LOOSE_REACH]);
}

const TIME = /\d+[^\S\n]*(?:min(?:ute[ns]?|s)?|minuten|h|hours?|stunden?|sec(?:onds?)?|sekunden)(?![a-zäöü])/gi;
const firstAfter = (text, ranges, index) => ranges.some(([from, to]) => index >= from && index < to
  && !/\d/.test(visible(text.slice(from, index)).replaceAll(MASK, ' ').replace(TIME, ' ')));

function maskBoxes(text) {
  const ranges = announcementRanges(text);
  return text.replace(BOXED, (box, offset) => {
    const chars = box.replace(/<[^<>]*>|&nbsp;|\s/g, '');
    if (!firstAfter(text, ranges, offset) || !/\d/.test(chars) || YEAR.test(chars)
      || /[\d.,/]$/.test(text.slice(Math.max(0, offset - 1), offset))
      || AMOUNT_AFTER.test(text.slice(offset + box.length, offset + box.length + 2))
      || LAYOUT_BEFORE.test(text.slice(Math.max(0, offset - 20), offset))
      || insideProtectedSpan(text, offset, offset + box.length)) return box;
    let first = true;
    return box.replace(/<[^<>]*>|&nbsp;|\s+|([A-Za-z0-9])/g, (part, char) => {
      if (!char) return part.startsWith('<') ? part : '';
      const out = first ? MASK : '';
      first = false;
      return out;
    });
  });
}

function standsAlone(text, start, end) {
  const before = text.slice(Math.max(0, start - 200), start);
  const after = text.slice(end, end + 200);
  return /(?:^|\n|>)(?:[^\S\n]|&nbsp;)*$/.test(before) && /^(?:[^\S\n]|&nbsp;|[.!])*(?:$|\r?\n|<)/.test(after);
}

function hiddenAt(text, index, blocks) {
  if (/<[^>]*$/.test(text.slice(Math.max(0, text.lastIndexOf('>', index) + 1), index))) return true;
  return blocks.some(([from, to]) => index >= from && index < to);
}

function maskAfterAnnouncement(text) {
  const blocks = [...text.matchAll(HIDDEN_BLOCK)].map((b) => [b.index, b.index + b[0].length]);
  const tokens = [...text.matchAll(LOOSE_TOKEN)];
  const hits = new Map();
  for (const [from, to] of announcementRanges(text)) {
    const found = tokens.filter((t) => t.index >= from && t.index < to && !NOT_A_CODE.test(t[0])
      && !hiddenAt(text, t.index, blocks)
      && !badSurroundings(text, t[0], t.index, t.index + t[0].length));
    const alone = found.filter((t) => standsAlone(text, t.index, t.index + t[0].length));
    const mask = text.indexOf(MASK, from);
    const codeMasked = mask >= 0 && mask < to && (!found.length || mask < found[0].index);
    const chosen = alone.length || codeMasked ? alone : found.slice(0, 1);
    for (const t of chosen) hits.set(t.index, t[0].length);
  }
  let out = text;
  for (const [index, length] of [...hits].sort((x, y) => y[0] - x[0])) {
    out = out.slice(0, index) + MASK + out.slice(index + length);
  }
  return out;
}

function maskAll(text, strong) {
  let masked = strong ? maskBoxes(text) : text;
  masked = maskCodes(masked);
  masked = replaceCode(NEXT_TOKEN, masked, (code) => lettersOnlyLower(code) || YEAR.test(code));
  const near = nearIn(masked);
  const before = masked;
  masked = masked.replace(LONG_NUMBER, (hit, digits, offset) => (
    insideProtectedSpan(before, offset, offset + hit.length)
      || !(strong || near(offset, offset + hit.length))
      ? hit : hit.replace(digits, MASK)));
  masked = maskLabelled(masked);
  if (strong) masked = maskAfterAnnouncement(masked);
  return masked;
}

export function redact(text, { twoFactor = false } = {}) {
  if (typeof text !== 'string' || !text) return text;
  const strong = ANNOUNCES.test(text);
  if (strong || twoFactor || isTwoFactorMail(headersOf(text))) return maskAll(text, strong);
  return maskLabelled(maskCodes(text, nearIn(text)));
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
