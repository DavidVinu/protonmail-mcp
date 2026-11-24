export const ALL_MAIL = 'All Mail';

const PREFIX = /^(?:\s*(?:re|aw|fwd?|wg|antw|sv|vs|tr)\s*(?:\[\d+\])?\s*:)+/i;
const PAGE_SIZE = 100;
const MAX_PAGES = 5;
export const MAX_MESSAGES = 50;

export function baseSubject(subject = '') {
  return subject.replace(PREFIX, '').replace(/\s+/g, ' ').trim().toLowerCase();
}

export function searchQuery(subject) {
  const words = [...new Set(baseSubject(subject).split(/[\s\p{P}\p{S}]+/u)
    .filter((w) => w.length >= 3 && !/[^\x00-\x7f]/.test(w)))]
    .sort((a, b) => b.length - a.length)
    .slice(0, 3);
  return words.length ? words.map((w) => `subject ${w}`).join(' or ') : null;
}

const ids = (value = '') => [...value.matchAll(/<([^<>\s]+)>/g)].map((m) => m[1]);

export function parseRaw(raw) {
  const head = raw.split(/\r?\n\r?\n/, 1)[0].replace(/\r?\n[ \t]+/g, ' ');
  const field = (name) => new RegExp(`^${name}:(.*)$`, 'mi').exec(head)?.[1] ?? '';
  return {
    messageId: ids(field('Message-Id'))[0] ?? null,
    links: [...ids(field('In-Reply-To')), ...ids(field('References'))],
  };
}

export function subjectOf(text) {
  return /^Subject:[^\S\n]*(.*)$/mi.exec(text.split(/\r?\n\r?\n/, 1)[0])?.[1] ?? '';
}

export function members(seed, envelopes) {
  const known = new Set([seed.messageId, ...seed.links].filter(Boolean));
  const base = baseSubject(seed.subject);
  const chosen = new Map();
  let grew = true;
  while (grew) {
    grew = false;
    for (const e of envelopes) {
      if (chosen.has(e.id)) continue;
      const links = e['in-reply-to'] ?? [];
      const linked = known.has(e['message-id']) || links.some((l) => known.has(l));
      if (!linked && !(base && baseSubject(e.subject) === base)) continue;
      chosen.set(e.id, e);
      for (const l of [e['message-id'], ...links]) if (l) known.add(l);
      grew = true;
    }
  }
  return [...chosen.values()].sort((a, b) => String(a.date).localeCompare(String(b.date)));
}

export async function collectThread(himalaya, id, mailbox) {
  const plain = await himalaya(['message', 'read', id, '--mailbox', mailbox]);
  if (plain.code !== 0) return { failed: plain };
  const raw = await himalaya(['message', 'read', id, '--mailbox', mailbox, '--raw']);
  if (raw.code !== 0) return { failed: raw };
  const seed = { ...parseRaw(raw.out), subject: subjectOf(plain.out) };

  const query = searchQuery(seed.subject);
  const envelopes = [];
  for (let page = 1; query && page <= MAX_PAGES; page += 1) {
    const found = await himalaya(['envelope', 'search', '--mailbox', ALL_MAIL,
      '--page', String(page), '--page-size', String(PAGE_SIZE), '--json', query]);
    if (found.code !== 0) return { failed: found };
    const batch = JSON.parse(found.out).envelopes ?? [];
    envelopes.push(...batch);
    if (batch.length < PAGE_SIZE - 1) break;
  }

  const thread = members(seed, envelopes);
  if (!thread.length) {
    return { mailbox, messages: [{ id, text: plain.out }], omitted: 0 };
  }
  const shown = thread.slice(-MAX_MESSAGES);
  const messages = [];
  for (const e of shown) {
    const read = await himalaya(['message', 'read', e.id, '--mailbox', ALL_MAIL]);
    if (read.code !== 0) return { failed: read };
    messages.push({ id: e.id, date: e.date, from: e.from, subject: e.subject, text: read.out });
  }
  return { mailbox: ALL_MAIL, messages, omitted: thread.length - shown.length };
}
