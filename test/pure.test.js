'use strict';
require('./obsidian-stub');
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { __test: T } = require('../main.js');

function server(handler) {
    return new Promise(resolve => {
        const s = http.createServer(handler).listen(0, '127.0.0.1', () => resolve(s));
    });
}

test('pwndocApi GET returns datas', async () => {
    const s = await server((req, res) => res.end(JSON.stringify({ status: 'success', datas: { a: 1 } })));
    const base = `http://127.0.0.1:${s.address().port}`;
    assert.deepEqual(await T.pwndocApi(base, 'T', 'GET', '/api/x'), { a: 1 });
    s.closeAllConnections(); s.close();
});

test('pwndocApi PUT sends JSON body and JWT cookie', async () => {
    const s = await server((req, res) => {
        let b = '';
        req.on('data', c => b += c);
        req.on('end', () => res.end(JSON.stringify({ datas: { body: JSON.parse(b), cookie: req.headers.cookie, method: req.method } })));
    });
    const base = `http://127.0.0.1:${s.address().port}`;
    const r = await T.pwndocApi(base, 'T', 'PUT', '/api/x', { body: { k: 'v' } });
    assert.deepEqual(r, { body: { k: 'v' }, cookie: 'token= JWT T', method: 'PUT' });
    s.closeAllConnections(); s.close();
});

test('pwndocApi rejects with HTTP status on 500', async () => {
    const s = await server((req, res) => { res.statusCode = 500; res.end('boom'); });
    const base = `http://127.0.0.1:${s.address().port}`;
    await assert.rejects(T.pwndocApi(base, 'T', 'GET', '/api/x'), /HTTP 500/);
    s.closeAllConnections(); s.close();
});

test('migratePassword moves plaintext password into secretStorage and drops it from settings', () => {
    const calls = [];
    const store = { setSecret: (id, v) => calls.push([id, v]) };
    const out = T.migratePassword({ apiUrl: 'u', apiPassword: 'x' }, store);
    assert.deepEqual(calls, [[T.SECRET_ID, 'x']]);
    assert.equal('apiPassword' in out, false);
    assert.equal(out.apiUrl, 'u');
});

test('migratePassword leaves settings alone when no plaintext password', () => {
    const calls = [];
    const store = { setSecret: (id, v) => calls.push([id, v]) };
    const out = T.migratePassword({ apiPassword: '' }, store);
    assert.deepEqual(calls, []);
    assert.equal('apiPassword' in out, false);
});

const NOTE = [
    '---', 'severity: HIGH', 'pwndoc: true', '---', '',
    '', '---', '## Descrizione', '', 'desc text', '',
    '## Impatto', '', 'impact text', '',
    '## Evidenza', '', 'evidence **bold**', '', '```', '## not a heading', '```', '',
    '## Assets', '', 'asset1', '',
    '## Remediation', '', 'fix it', '',
    '## References', '', 'http://x', '',
].join('\n');

test('parseSections extracts each known section body', () => {
    const s = T.parseSections(NOTE);
    assert.equal(s.description.text, 'desc text');
    assert.equal(s.observation.text, 'impact text');
    assert.equal(s.scope.text, 'asset1');
    assert.equal(s.remediation.text, 'fix it');
    assert.equal(s.references.text, 'http://x');
});

test('parseSections keeps a heading-like line inside a code fence in the section', () => {
    const s = T.parseSections(NOTE);
    assert.equal(s.poc.text, 'evidence **bold**\n\n```\n## not a heading\n```');
});

test('parseSections accepts alias headings case-insensitively', () => {
    const s = T.parseSections('## evidence\n\nx\n');
    assert.equal(s.poc.text, 'x');
});

test('replaceSection changes only the target section', () => {
    const out = T.replaceSection(NOTE, 'poc', 'NEW');
    const before = T.parseSections(NOTE), after = T.parseSections(out);
    assert.equal(after.poc.text, 'NEW');
    for (const k of ['description', 'observation', 'scope', 'remediation', 'references']) {
        assert.equal(after[k].text, before[k].text);
    }
    assert.equal(out.slice(0, before.poc.start), NOTE.slice(0, before.poc.start));
});

test('replaceSection appends the section when missing', () => {
    const out = T.replaceSection('## Descrizione\n\nd\n', 'poc', 'E');
    assert.equal(T.parseSections(out).poc.text, 'E');
    assert.equal(T.parseSections(out).description.text, 'd');
    assert.match(out, /## Evidenza/);
});

// ── converters ────────────────────────────────────────────────────────────────
const txt = s => ({ nodeType: 3, textContent: s });
const el = (tag, attrs = {}, ...kids) => ({
    nodeType: 1, tagName: tag.toUpperCase(), childNodes: kids.map(k => typeof k === 'string' ? txt(k) : k),
    getAttribute: n => (n in attrs ? attrs[n] : null),
    get textContent() { return this.childNodes.map(c => c.textContent).join(''); },
});

test('serializeWhitelist keeps allowed tags, drops script content, unwraps unknown tags, escapes text', () => {
    const root = el('div', {},
        el('p', {}, 'a < b ', el('strong', {}, 'bold'), el('script', {}, 'alert(1)'), el('custom', {}, 'kept')));
    assert.equal(T.serializeWhitelist(root), '<p>a &lt; b <strong>bold</strong>kept</p>');
});

test('serializeWhitelist passes images through the resolver and drops unresolved ones', () => {
    const img = el('img', { src: 'app://local/a.png', alt: 'Fig "1"' });
    assert.equal(T.serializeWhitelist(el('p', {}, img), () => 'ID1'), '<p><img src="ID1" alt="Fig &quot;1&quot;"></p>');
    assert.equal(T.serializeWhitelist(el('p', {}, img)), '<p></p>');
});

test('serializeWhitelist flattens highlighted code blocks to pre/code text without the copy button', () => {
    const pre = el('pre', {}, el('button', {}, 'Copy'), el('code', {}, el('span', {}, 'GET /'), '\nHost: x'));
    assert.equal(T.serializeWhitelist(el('div', {}, pre)), '<pre><code>GET /\nHost: x</code></pre>');
});

test('serializeWhitelist drops javascript: hrefs but keeps the link text', () => {
    const a = el('a', { href: 'javascript:alert(1)' }, 'click');
    const ok = el('a', { href: 'https://x.io/?a=1&b=2' }, 'ok');
    assert.equal(T.serializeWhitelist(el('p', {}, a, ok)), '<p>click<a href="https://x.io/?a=1&amp;b=2">ok</a></p>');
});

test('image tokens round-trip id and alt, even with markdown-special characters', () => {
    const tok = T.imgToken('6ae342352f6b9b3e849af420', 'Figura 1 – *x* _y_');
    assert.match(tok, /^[^*_\s]+$/);
    assert.equal(T.expandImgTokens(`<p>${tok}</p>`), '<p><img src="6ae342352f6b9b3e849af420" alt="Figura 1 – *x* _y_"></p>');
});
