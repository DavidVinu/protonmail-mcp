import { readable } from './readable.mjs';

export const ALL_MAIL = 'All Mail';

const PREFIX = /^(?:\s*(?:re|aw|fwd?|wg|antw|sv|vs|tr)\s*(?:\[\d+\])?\s*:)+/i;
const PAGE_SIZE = 100;
const MAX_PAGES = 5;
export const MAX_MESSAGES = 50;
export const SPAN_DAYS = 180;
const DAY = 86400000;

export function baseSubject(subject = '') {
  return subject.replace(PREFIX, '').replace(/\s+/g, ' ').trim().toLowerCase();
}

export const QUERY_WORDS = new Set(['and', 'or', 'not', 'order', 'by', 'asc', 'desc',
  'date', 'after', 'before', 'flag', 'from', 'to', 'subject', 'body']);

export function searchQuery(subject) {
  const words = [...new Set(baseSubject(subject).split(/[\s\p{P}\p{S}]+/u)
    .filter((w) => w.length >= 3 && !/[^\x00-\x7f]/.test(w) && !QUERY_WORDS.has(w)))]
    .sort((a, b) => b.length - a.length)
    .slice(0, 3);
  return words.length ? words.map((w) => `subject ${w}`).join(' or ') : null;
}

const time = (date) => {
  const t = Date.parse(date);
  return Number.isNaN(t) ? null : t;
};

const emails = (value) => [...String(value).matchAll(/[\w.!#$%&'*+/=?^`{|}~-]+@[\w-]+(?:\.[\w-]+)+/g)]
  .map((m) => m[0].toLowerCase());

const addresses = (list) => [list].flat().filter(Boolean)
  .map((a) => (typeof a === 'string' ? a : a.email ?? '').toLowerCase());

const ids = (value = '') => [...value.matchAll(/<([^<>\s]+)>/g)].map((m) => m[1]);

export function parseRaw(raw) {
  const head = raw.split(/\r?\n\r?\n/, 1)[0].replace(/\r?\n[ \t]+/g, ' ');
  const field = (name) => new RegExp(`^${name}:(.*)$`, 'mi').exec(head)?.[1] ?? '';
  return {
    messageId: ids(field('Message-Id'))[0] ?? null,
    links: [...ids(field('In-Reply-To')), ...ids(field('References'))],
  };
}

export function headerOf(text, name) {
  return new RegExp(`^${name}:[^\\S\\n]*(.*)$`, 'mi').exec(text.split(/\r?\n\r?\n/, 1)[0])?.[1] ?? '';
}

export function members(seed, envelopes) {
  const known = new Set([seed.messageId, ...seed.links].filter(Boolean));
  const base = baseSubject(seed.subject);
  const people = new Set(seed.participants.filter((a) => a !== seed.own));
  const near = (e) => {
    const t = time(e.date);
    return seed.time === null || t === null || Math.abs(t - seed.time) <= SPAN_DAYS * DAY;
  };
  const involves = (e) => [...addresses(e.from), ...addresses(e.to)].some((a) => people.has(a));
  const chosen = new Map();
  let grew = true;
  while (grew) {
    grew = false;
    for (const e of envelopes) {
      if (chosen.has(e.id)) continue;
      const links = e['in-reply-to'] ?? [];
      const linked = known.has(e['message-id']) || links.some((l) => known.has(l));
      const sameTopic = seed.own && base && baseSubject(e.subject) === base && near(e) && involves(e);
      if (!linked && !sameTopic) continue;
      chosen.set(e.id, e);
      for (const l of [e['message-id'], ...links]) if (l) known.add(l);
      grew = true;
    }
  }
  return [...chosen.values()].sort((a, b) => (time(a.date) ?? 0) - (time(b.date) ?? 0));
}

const day = (t) => new Date(t).toISOString().slice(0, 10);

export async function collectThread(himalaya, id, mailbox, { own = null, quotes = false } = {}) {
  const plain = await himalaya(['message', 'read', id, '--mailbox', mailbox]);
  if (plain.code !== 0) return { failed: plain };
  const raw = await himalaya(['message', 'read', id, '--mailbox', mailbox, '--raw']);
  if (raw.code !== 0) return { failed: raw };
  const seed = {
    ...parseRaw(raw.out),
    subject: headerOf(plain.out, 'Subject'),
    time: time(headerOf(plain.out, 'Date')),
    participants: ['From', 'To', 'Cc'].flatMap((h) => emails(headerOf(plain.out, h))),
    own,
  };

  const words = searchQuery(seed.subject);
  const query = words && seed.time !== null
    ? `(${words}) and after ${day(seed.time - SPAN_DAYS * DAY)}`
    : words;
  const envelopes = [];
  let incomplete = !query;
  for (let page = 1; query; page += 1) {
    if (page > MAX_PAGES) { incomplete = true; break; }
    const found = await himalaya(['envelope', 'search', '--mailbox', ALL_MAIL,
      '--page', String(page), '--page-size', String(PAGE_SIZE), '--json', query]);
    if (found.code !== 0) return { failed: found };
    let batch;
    try {
      batch = JSON.parse(found.out).envelopes ?? [];
    } catch {
      return { failed: { ...found, code: found.code || 1 } };
    }
    envelopes.push(...batch);
    if (batch.length < PAGE_SIZE - 1) break;
  }

  const thread = members(seed, envelopes);
  if (!thread.length) {
    return { mailbox, messages: [{ id, text: readable(plain.out, { quotes }) }], omitted: 0, incomplete };
  }
  const shown = thread.slice(-MAX_MESSAGES);
  const messages = [];
  for (const e of shown) {
    const read = await himalaya(['message', 'read', e.id, '--mailbox', ALL_MAIL]);
    if (read.code !== 0) return { failed: read };
    messages.push({ id: e.id, date: e.date, from: e.from, subject: e.subject,
      text: readable(read.out, { quotes }) });
  }
  return { mailbox: ALL_MAIL, messages, omitted: thread.length - shown.length, incomplete };
}
