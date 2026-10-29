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

// ── association ───────────────────────────────────────────────────────────────
test('resolveAuditId: note wins over folder, nearest ancestor wins, none gives null', () => {
    const fa = { 'Clients/A': { auditId: 'A1' }, 'Clients/A/web': { auditId: 'A2' } };
    assert.equal(T.resolveAuditId('Clients/A/web/VT-01 - x.md', {}, fa), 'A2');
    assert.equal(T.resolveAuditId('Clients/A/mobile/M-01 - x.md', {}, fa), 'A1');
    assert.equal(T.resolveAuditId('Clients/A/web/VT-01 - x.md', { pwndoc_audit_id: 'N' }, fa), 'N');
    assert.equal(T.resolveAuditId('Other/VT-01 - x.md', {}, fa), null);
    assert.equal(T.resolveAuditId('Clients/AB/VT-01 - x.md', {}, fa), null);
});

test('renameFolderKeys rewrites the folder and its descendants only', () => {
    const fa = { 'Clients/A': { auditId: 'A1' }, 'Clients/A/web': { auditId: 'A2' }, 'Clients/AB': { auditId: 'B' } };
    assert.deepEqual(T.renameFolderKeys(fa, 'Clients/A', 'Clients/Z'),
        { 'Clients/Z': { auditId: 'A1' }, 'Clients/Z/web': { auditId: 'A2' }, 'Clients/AB': { auditId: 'B' } });
});

test('rankFindings puts the exact title first, then partial matches, then the rest by identifier', () => {
    const fs_ = [
        { _id: 'c', identifier: '3', title: 'Other' },
        { _id: 'b', identifier: '2', title: 'SQL Injection in login' },
        { _id: 'a', identifier: '1', title: 'sql  injection' },
    ];
    assert.deepEqual(T.rankFindings('SQL Injection', fs_).map(f => f._id), ['a', 'b', 'c']);
});

test('titleFromBasename strips the VT/M prefix only', () => {
    assert.equal(T.titleFromBasename('VT-03 - SQL Injection'), 'SQL Injection');
    assert.equal(T.titleFromBasename('M-12 - A - B'), 'A - B');
    assert.equal(T.titleFromBasename('Plain title'), 'Plain title');
});

// ── images ────────────────────────────────────────────────────────────────────
const IMD = [
    'a ![Figura 1 – login](img/a b.png) b ![[shot.png|caption]] c ![[big.png|300]] d ![](x%20y.png)',
    '```', '![in fence](nope.png)', '```', '![w|200](sized.png)', '![r](https://x.io/a.png)',
].join('\n');

test('extractImageRefs finds markdown and wikilink images, decodes src, drops sizes, skips fences', () => {
    const refs = T.extractImageRefs(IMD).map(({ src, alt, remote }) => ({ src, alt, remote: !!remote }));
    assert.deepEqual(refs, [
        { src: 'img/a b.png', alt: 'Figura 1 – login', remote: false },
        { src: 'shot.png', alt: 'caption', remote: false },
        { src: 'big.png', alt: '', remote: false },
        { src: 'x y.png', alt: '', remote: false },
        { src: 'sized.png', alt: 'w', remote: false },
        { src: 'https://x.io/a.png', alt: 'r', remote: true },
    ]);
});

test('replaceImageRefs rewrites every ref outside fences and leaves fenced text alone', () => {
    const out = T.replaceImageRefs(IMD, r => `<${r.src}>`);
    assert.match(out, /^a <img\/a b\.png> b <shot\.png> c <big\.png> d <x y\.png>/);
    assert.match(out, /!\[in fence\]\(nope\.png\)/);
});

function imgCtx(files = {}) {
    const posts = [];
    const cache = {};
    return {
        posts, cache, files,
        resolvePath: src => (src in files ? src : null),
        readBinary: async p => files[p],
        api: async (method, path, opts) => {
            if (method === 'POST') { posts.push(opts.body.name); return { _id: 'a'.repeat(23) + posts.length }; }
            throw new Error('unexpected ' + method + ' ' + path);
        },
        save: async () => {},
        imageCache: cache,
    };
}

test('uploadImage uploads once per content hash and reuses the cached id', async () => {
    const bytes = Buffer.from('PNGDATA');
    const ctx = imgCtx({ 'a.png': bytes, 'b.png': bytes });
    const id1 = await T.uploadImage(ctx, 'AUD', 'a.png');
    const id2 = await T.uploadImage(ctx, 'AUD', 'b.png');
    assert.equal(id1, id2);
    assert.equal(ctx.posts.length, 1);
});

test('uploadImage rejects a missing file and an oversized file before any POST', async () => {
    const ctx = imgCtx({ 'big.png': Buffer.alloc(13 * 1024 * 1024) });
    await assert.rejects(T.uploadImage(ctx, 'AUD', 'nope.png'), /missing image: nope\.png/);
    await assert.rejects(T.uploadImage(ctx, 'AUD', 'big.png'), /too large/);
    assert.equal(ctx.posts.length, 0);
});

test('uploadImage rejects unsupported extensions and remote URLs', async () => {
    const ctx = imgCtx({ 'x.exe': Buffer.from('x') });
    await assert.rejects(T.uploadImage(ctx, 'AUD', 'x.exe'), /unsupported image type/);
    await assert.rejects(T.uploadImage(ctx, 'AUD', 'https://x.io/a.png'), /remote image/);
});

test('tokenizeImages uploads every ref and swaps it for a token; a failing ref aborts with nothing replaced', async () => {
    const ctx = imgCtx({ 'a.png': Buffer.from('A'), 'b.png': Buffer.from('B') });
    const out = await T.tokenizeImages(ctx, 'AUD', 'x ![One](a.png) y ![[b.png|Two]]');
    assert.equal((out.match(/⟦pwimg:/g) || []).length, 2);
    assert.equal(T.expandImgTokens(out).includes('alt="Two"'), true);
    await assert.rejects(T.tokenizeImages(imgCtx({ 'a.png': Buffer.from('A') }), 'AUD', '![](a.png) ![](gone.png)'), /missing image: gone\.png/);
});

test('pullImages downloads PwnDoc image ids into the folder and rewrites them to vault paths', async () => {
    const ID = '6ae342352f6b9b3e849af420';
    const written = {};
    const ctx = {
        api: async (m, p) => ({ _id: ID, name: 'spike.png', value: 'data:image/png;base64,' + Buffer.from('PNG').toString('base64') }),
        exists: async p => p in written,
        writeBinary: async (p, buf) => { written[p] = buf; },
    };
    const out = await T.pullImages(ctx, `text ![Fig 1](${ID}) and ![ext](https://x.io/a.png)`, 'attachments');
    assert.equal(out, `text ![Fig 1](attachments/${ID}.png) and ![ext](https://x.io/a.png)`);
    assert.equal(written[`attachments/${ID}.png`].toString(), 'PNG');
    await T.pullImages(ctx, `![Fig 1](${ID})`, 'attachments'); // second pull: already there
    assert.equal(Object.keys(written).length, 1);
});
