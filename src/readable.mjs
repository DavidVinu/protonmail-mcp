const ENTITIES = {
  nbsp: ' ', amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", shy: '',
  auml: 'ä', ouml: 'ö', uuml: 'ü', Auml: 'Ä', Ouml: 'Ö', Uuml: 'Ü', szlig: 'ß',
  eacute: 'é', egrave: 'è', agrave: 'à', ccedil: 'ç', euro: '€', copy: '©', reg: '®',
  ndash: '–', mdash: '—', hellip: '…', bull: '•', middot: '·',
  bdquo: '„', ldquo: '“', rdquo: '”', lsquo: '‘', rsquo: '’', sbquo: '‚',
  laquo: '«', raquo: '»',
};

const HTML_QUOTE = /<(?:div|blockquote|hr)\b[^>]*(?:gmail_quote|protonmail_quote|divRplyFwdMsg|appendonsend|moz-cite-prefix|yahoo_quoted|type="?cite)[^>]*>/i;

const TEXT_QUOTE = [
  /^-{2,}\s*(?:Original Message|Ursprüngliche Nachricht|Forwarded message|Weitergeleitete Nachricht)\s*-{2,}/mi,
  /^(?:Von|From):[^\n]*\n(?:[^\n]*\n){0,2}?(?:Gesendet|Sent|Datum|Date):/mi,
  /^(?:Am|On)\s[^\n]{4,120}(?:schrieb|wrote)[^\n]*:\s*$/mi,
];

function decode(text) {
  return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (whole, name) => {
    if (name[0] === '#') {
      const code = name[1].toLowerCase() === 'x' ? parseInt(name.slice(2), 16) : Number(name.slice(1));
      return Number.isFinite(code) && code > 0 && code < 0x110000 ? String.fromCodePoint(code) : whole;
    }
    return ENTITIES[name] ?? ENTITIES[name.toLowerCase()] ?? whole;
  });
}

export function htmlToText(html, { quotes = true } = {}) {
  let body = html.replace(/<(style|script|head|title)\b[\s\S]*?<\/\1>/gi, '')
    .replace(/<!--[\s\S]*?-->/g, '');
  if (!quotes) {
    const cut = body.search(HTML_QUOTE);
    if (cut >= 0) body = body.slice(0, cut);
  }
  return decode(body
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(?:p|div|tr|li|h[1-6]|table|blockquote)>/gi, '\n')
    .replace(/<li\b[^>]*>/gi, '- ')
    .replace(/<\/?[a-z][a-z0-9]*(?:\s[^<>]*)?\/?>/gi, ''))
    .replace(/[^\S\n]+/g, ' ')
    .replace(/ *\n */g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

export function stripQuotes(text) {
  let out = text;
  for (const marker of TEXT_QUOTE) {
    const cut = out.search(marker);
    if (cut > 0) out = out.slice(0, cut);
  }
  return out.split('\n').filter((line) => !/^\s*>/.test(line)).join('\n').trimEnd();
}

export function readable(text, { quotes = false } = {}) {
  const blank = text.search(/\r?\n\r?\n/);
  const head = blank >= 0 ? text.slice(0, blank) : text;
  let body = blank >= 0 ? text.slice(blank).replace(/^\r?\n\r?\n/, '') : '';
  body = body.replace(/<html\b[\s\S]*?(?:<\/html>|$)/gi, (html) => `\n${htmlToText(html, { quotes })}\n`);
  if (!/<html\b/i.test(text) && /^\[\d+\] text\/html\b/m.test(body)) {
    body = htmlToText(body, { quotes });
  }
  if (!quotes) body = stripQuotes(body);
  return `${head}\n\n${body.replace(/\n{3,}/g, '\n\n').replace(/^\n+/, '')}`.trimEnd();
}
