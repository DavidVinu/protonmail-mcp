import assert from 'node:assert/strict';
import test from 'node:test';

import { htmlToText, readable, stripQuotes } from '../src/readable.mjs';

const HEAD = 'Date: Mon, 2 Nov 2026 13:15:28 +0000\nFrom: A <a@x.org>\nSubject: AW: Test';

test('HTML becomes text without markup, styles or entities', () => {
  const html = '<html><head><style>p{color:red}</style></head><body>'
    + '<p>Hallo&nbsp;Frida,</p><div>Kosten &amp; Reise<br>Gr&uuml;&szlig;e &#8211; David</div></body></html>';
  assert.equal(htmlToText(html), 'Hallo Frida,\nKosten & Reise\nGrüße – David');
});

test('Outlook, Gmail and Proton quotes are cut from HTML', () => {
  for (const marker of ['<div id="appendonsend"></div>', '<div class="gmail_quote">',
    '<blockquote class="protonmail_quote">', '<div id="divRplyFwdMsg">']) {
    const html = `<html><body><p>Neu</p>${marker}<p>Alt</p></body></html>`;
    assert.equal(htmlToText(html, { quotes: false }), 'Neu', marker);
    assert.ok(htmlToText(html).includes('Alt'), marker);
  }
});

test('Plain-text quotes are cut at the reply header and > lines are dropped', () => {
  assert.equal(stripQuotes('Danke!\n\nAm 12.10.2026 um 10:00 schrieb Frida <f@x.org>:\nAlt'), 'Danke!');
  assert.equal(stripQuotes('Thanks\n\nOn Mon, 12 Oct 2026, Frida wrote:\nold'), 'Thanks');
  assert.equal(stripQuotes('Ja\n\nVon: Frida\nGesendet: Montag\nAn: David\nAlt'), 'Ja');
  assert.equal(stripQuotes('Ja\n> alt\n> alt'), 'Ja');
});

test('readable keeps the header block and the own text of a reply', () => {
  const mail = `${HEAD}\n\n[3] text/html (41 KiB)\n\n<html><body><p>Neue Frage</p>`
    + '<div id="appendonsend"></div><p>Zitat</p></body></html>';
  const out = readable(mail);
  assert.ok(out.startsWith(HEAD));
  assert.ok(out.includes('Neue Frage'));
  assert.ok(!out.includes('Zitat'));
  assert.ok(readable(mail, { quotes: true }).includes('Zitat'));
});

test('A plain-text mail without quotes comes back unchanged', () => {
  const mail = `${HEAD}\n\nHallo,\nTel.: +49 30 555012-25`;
  assert.equal(readable(mail), mail);
});
