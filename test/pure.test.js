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

// ── diff / comparison ─────────────────────────────────────────────────────────
test('lineDiff marks equal, deleted and added lines', () => {
    assert.deepEqual(T.lineDiff('a\nb', 'a\nc'), [
        { op: 'eq', line: 'a' }, { op: 'del', line: 'b' }, { op: 'add', line: 'c' }]);
    assert.deepEqual(T.lineDiff('x', 'x').map(d => d.op), ['eq']);
    assert.deepEqual(T.lineDiff('', 'a').map(d => d.op), ['add']);
    assert.deepEqual(T.lineDiff('a', '').map(d => d.op), ['del']);
});

const cmpCtx = {
    normalize: async md => md.trim(),
    htmlToMd: html => html.replace(/<[^>]+>/g, '').trim(),
    cfLabels: {},
};
const FINDING = {
    description: '<p>remote desc</p>', observation: '<p>remote obs</p>', poc: '<p>remote poc</p>',
    scope: 'a1', remediation: '<p>rem</p>', references: ['http://x', 'http://y'], customFields: [],
};

test('buildComparison: a note with only Evidenza filled differs on poc and flags the empty local sections', async () => {
    const note = '## Descrizione\n\n\n## Impatto\n\n\n## Evidenza\n\nlocal poc\n\n## Assets\n\n\n## Remediation\n\n\n';
    const rows = await T.buildComparison(cmpCtx, note, FINDING, ['description', 'poc', 'scope']);
    const by = Object.fromEntries(rows.map(r => [r.key, r]));
    assert.equal(by.poc.changed, true);
    assert.equal(by.poc.local, 'local poc');
    assert.equal(by.poc.remote, 'remote poc');
    assert.equal(by.description.localEmpty, true);
    assert.equal(by.description.remoteEmpty, false);
    assert.equal(by.scope.localEmpty, true);
});

test('buildComparison: identical content after normalisation is not changed; references compare as a list', async () => {
    const note = '## Evidenza\n\nremote poc\n\n## References\n\n- http://x\n- http://y\n';
    const rows = await T.buildComparison(cmpCtx, note, FINDING, ['poc', 'references']);
    assert.equal(rows.find(r => r.key === 'poc').changed, false);
    assert.equal(rows.find(r => r.key === 'references').changed, false);
});

test('buildComparison: a missing PoC on PwnDoc (remote empty) is flagged', async () => {
    const note = '## Evidenza\n\nlocal poc\n';
    const rows = await T.buildComparison(cmpCtx, note, { ...FINDING, poc: '' }, ['poc']);
    assert.equal(rows[0].remoteEmpty, true);
    assert.equal(rows[0].changed, true);
});

// ── history store ─────────────────────────────────────────────────────────────
function memAdapter() {
    const files = new Map();
    return {
        files,
        exists: async p => files.has(p) || [...files.keys()].some(k => k.startsWith(p + '/')),
        mkdir: async () => {},
        write: async (p, d) => { files.set(p, d); },
        read: async p => { if (!files.has(p)) throw new Error('ENOENT ' + p); return files.get(p); },
        remove: async p => { files.delete(p); },
        list: async dir => ({ files: [...files.keys()].filter(k => k.startsWith(dir + '/') && !k.slice(dir.length + 1).includes('/')), folders: [] }),
    };
}
const entry = (ts, op = 'push') => ({ ts, op, forced: false, auditId: 'A', findingId: 'F', notePath: 'n.md', sections: ['poc'], remoteBefore: { poc: '<p>x</p>' }, localBefore: '# n' });

test('historyDir nests under the plugin dir per finding', () => {
    assert.equal(T.historyDir('.obsidian/plugins/pwndoc-importer', 'F1'), '.obsidian/plugins/pwndoc-importer/history/F1');
});

test('recordHistory then listHistory returns the entry, newest first', async () => {
    const ad = memAdapter();
    const dir = T.historyDir('p', 'F');
    await T.recordHistory(ad, dir, entry('2026-10-29T10:00:00.000Z'), 50);
    await T.recordHistory(ad, dir, entry('2026-10-29T11:00:00.000Z', 'pull'), 50);
    const list = await T.listHistory(ad, dir);
    assert.deepEqual(list.map(e => e.op), ['pull', 'push']);
    assert.equal(list[1].localBefore, '# n');
});

test('recordHistory keeps only the newest `limit` entries and never prunes base.json', async () => {
    const ad = memAdapter();
    const dir = T.historyDir('p', 'F');
    await T.saveBase(ad, dir, { ts: 't', sections: { poc: 'x' } });
    for (const h of ['01', '02', '03']) await T.recordHistory(ad, dir, entry(`2026-10-29T${h}:00:00.000Z`), 2);
    const list = await T.listHistory(ad, dir);
    assert.deepEqual(list.map(e => e.ts), ['2026-10-29T03:00:00.000Z', '2026-10-29T02:00:00.000Z']);
    assert.notEqual(await T.loadBase(ad, dir), null);
});

test('listHistory skips corrupt files', async () => {
    const ad = memAdapter();
    const dir = T.historyDir('p', 'F');
    await T.recordHistory(ad, dir, entry('2026-10-29T10:00:00.000Z'), 50);
    await ad.write(`${dir}/2026-10-29T12-00-00-000Z-push-zzzz.json`, '{not json');
    assert.equal((await T.listHistory(ad, dir)).length, 1);
});

test('pruneNames returns the oldest names beyond the limit', () => {
    assert.deepEqual(T.pruneNames(['a', 'b', 'c'], 2), ['a']);
    assert.deepEqual(T.pruneNames(['a'], 2), []);
});

test('loadBase is null without a file; saveBase merges sections across calls', async () => {
    const ad = memAdapter();
    const dir = T.historyDir('p', 'F');
    assert.equal(await T.loadBase(ad, dir), null);
    await T.saveBase(ad, dir, { ts: '1', sections: { poc: 'p1' } });
    await T.saveBase(ad, dir, { ts: '2', sections: { description: 'd1' } });
    const b = await T.loadBase(ad, dir);
    assert.deepEqual(b.sections, { poc: 'p1', description: 'd1' });
    assert.equal(b.ts, '2');
});

// ── push / pull pipeline ──────────────────────────────────────────────────────
const AID = 'A'.repeat(24), FID = 'F'.repeat(24);
function syncCtx({ state = 'EDIT', remote = {}, confirmEmpty = async () => true, files = {} } = {}) {
    const finding = { _id: FID, title: 'T', description: '<p>remote desc</p>', observation: '<p>remote obs</p>', poc: '<p>remote poc</p>',
        scope: 'a1', remediation: '<p>rem</p>', references: ['http://x'], cvssv3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', customFields: [], ...remote };
    const log = { puts: [], posts: [] };
    const hist = memAdapter();
    const ctx = {
        log, hist, finding,
        notePath: 'n.md',
        api: async (method, path, opts) => {
            if (method === 'GET' && path === `/api/audits/${AID}`) return { _id: AID, state, findings: [finding] };
            if (method === 'PUT') { log.puts.push({ path, body: opts.body }); Object.assign(finding, opts.body); return 'ok'; }
            if (method === 'POST') { log.posts.push(opts.body.name); return { _id: 'b'.repeat(23) + log.posts.length }; }
            if (method === 'GET' && path.startsWith('/api/images/')) return { value: 'data:image/png;base64,' + Buffer.from('PNG').toString('base64') };
            throw new Error(`unexpected ${method} ${path}`);
        },
        mdToHtml: async md => T.expandImgTokens(md.split(/\n\n+/).map(p => `<p>${p}</p>`).join('')),
        htmlToMd: html => html.replace(/<\/p><p>/g, '\n\n').replace(/<[^>]+>/g, '').trim(),
        normalize: async md => md.trim(),
        cfLabels: {},
        resolvePath: s => (s in files ? s : null),
        readBinary: async p => files[p],
        imageCache: {}, save: async () => {},
        exists: async () => false, writeBinary: async () => {},
        adapter: hist, historyDir: 'h/F', historyLimit: 50, attachmentsFolder: 'attachments',
        confirmEmpty,
    };
    return ctx;
}
const NOTE_ONLY_POC = '## Descrizione\n\n\n## Impatto\n\n\n## Evidenza\n\nlocal poc\n\n## Assets\n\n\n## Remediation\n\n\n';
const clone = o => JSON.parse(JSON.stringify(o));
const pushArgs = (ctx, extra) => ({ auditId: AID, findingId: FID, noteMd: NOTE_ONLY_POC, sections: ['poc'], snapshotFinding: clone(ctx.finding), force: false, ...extra });

test('findingHash only covers the selected sections', () => {
    const f = { poc: 'a', description: 'd' };
    assert.equal(T.findingHash(f, ['poc']), T.findingHash({ ...f, description: 'changed' }, ['poc']));
    assert.notEqual(T.findingHash(f, ['poc']), T.findingHash({ ...f, poc: 'b' }, ['poc']));
});

test('assertEditable blocks non-EDIT audits unless forced', () => {
    assert.throws(() => T.assertEditable({ state: 'REVIEW' }, false), /REVIEW/);
    T.assertEditable({ state: 'REVIEW' }, true);
    T.assertEditable({ state: 'EDIT' }, false);
});

test('pushSections on a populated PwnDoc finding with only Evidenza written locally sends only the PoC patch', async () => {
    const ctx = syncCtx();
    const r = await T.pushSections(ctx, pushArgs(ctx));
    assert.deepEqual(ctx.log.puts.map(p => p.body), [{ poc: '<p>local poc</p>' }]);
    assert.equal(ctx.finding.description, '<p>remote desc</p>');
    const h = await T.listHistory(ctx.hist, ctx.historyDir);
    assert.equal(h[0].op, 'push');
    assert.equal(h[0].remoteBefore.poc, '<p>remote poc</p>');
    assert.equal(h[0].localBefore, NOTE_ONLY_POC);
    assert.equal((await T.loadBase(ctx.hist, ctx.historyDir)).sections.poc, 'local poc');
    assert.equal(r.entryId, h[0].id);
});

test('pushSections refuses to blank a populated remote section unless the user confirms', async () => {
    const ctx = syncCtx({ confirmEmpty: async () => false });
    await assert.rejects(T.pushSections(ctx, pushArgs(ctx, { sections: ['poc', 'description'] })), /empty/i);
    assert.equal(ctx.log.puts.length, 0);
    assert.equal((await T.listHistory(ctx.hist, ctx.historyDir)).length, 0);
});

test('pushSections aborts when a selected field changed on PwnDoc after the compare, but not when an unselected one did', async () => {
    const ctx = syncCtx();
    const snap = clone(ctx.finding);
    ctx.finding.description = '<p>edited by someone else</p>';
    await T.pushSections(ctx, pushArgs(ctx, { snapshotFinding: snap }));
    assert.equal(ctx.log.puts.length, 1);
    ctx.finding.poc = '<p>edited too</p>';
    await assert.rejects(T.pushSections(ctx, pushArgs(ctx, { snapshotFinding: snap })), /changed on PwnDoc/);
    assert.equal(ctx.log.puts.length, 1);
});

test('pushSections is blocked on a REVIEW audit and goes through with force, recording forced', async () => {
    const ctx = syncCtx({ state: 'REVIEW' });
    await assert.rejects(T.pushSections(ctx, pushArgs(ctx)), /REVIEW/);
    assert.equal(ctx.log.puts.length, 0);
    await T.pushSections(ctx, pushArgs(ctx, { force: true }));
    assert.equal(ctx.log.puts.length, 1);
    assert.equal((await T.listHistory(ctx.hist, ctx.historyDir))[0].forced, true);
});

test('pushSections uploads images as tokens and aborts before any PUT when an image is missing', async () => {
    const ok = syncCtx({ files: { 'a.png': Buffer.from('PNGDATA') } });
    await T.pushSections(ok, pushArgs(ok, { noteMd: '## Evidenza\n\n![Figura 1](a.png)\n' }));
    assert.match(ok.log.puts[0].body.poc, /<img src="b+1" alt="Figura 1">/);
    const bad = syncCtx();
    await assert.rejects(T.pushSections(bad, pushArgs(bad, { noteMd: '## Evidenza\n\n![x](gone.png)\n' })), /missing image: gone\.png/);
    assert.equal(bad.log.puts.length, 0);
    assert.equal((await T.listHistory(bad.hist, bad.historyDir)).length, 0);
});

test('pushSections refuses read-only sections', async () => {
    const ctx = syncCtx();
    await assert.rejects(T.pushSections(ctx, pushArgs(ctx, { sections: ['customFields'] })), /read-only/);
});

test('pullSections fills only the requested section of a note that only had Evidenza, records history and base', async () => {
    const ctx = syncCtx({ remote: { poc: `<p>pulled</p><p><img src="${'c'.repeat(24)}" alt="F1"></p>` } });
    const note = '## Descrizione\n\nmine\n\n## Evidenza\n\n\n## Assets\n\n';
    ctx.htmlToMd = html => html.replace(/<img src="([^"]+)" alt="([^"]*)">/g, '![$2]($1)').replace(/<\/p><p>/g, '\n\n').replace(/<[^>]+>/g, '').trim();
    const r = await T.pullSections(ctx, { auditId: AID, findingId: FID, noteMd: note, sections: ['poc'], force: false });
    const secs = T.parseSections(r.noteMd);
    assert.equal(secs.description.text, 'mine');
    assert.match(secs.poc.text, /^pulled\n\n!\[F1\]\(attachments\/c+\.png\)$/);
    const h = await T.listHistory(ctx.hist, ctx.historyDir);
    assert.equal(h[0].op, 'pull');
    assert.equal(h[0].localBefore, note);
    assert.ok((await T.loadBase(ctx.hist, ctx.historyDir)).sections.poc);
});

test('pullSections refuses to blank a populated local section when PwnDoc has none, unless confirmed', async () => {
    const ctx = syncCtx({ remote: { poc: '' }, confirmEmpty: async () => false });
    await assert.rejects(T.pullSections(ctx, { auditId: AID, findingId: FID, noteMd: '## Evidenza\n\nmy evidence\n', sections: ['poc'], force: false }), /empty/i);
});

// ── rollback ──────────────────────────────────────────────────────────────────
test('restoreRemotePatch builds a patch from the snapshot for the requested sections only', () => {
    const snap = { poc: '<p>old poc</p>', description: '<p>old desc</p>', scope: 'old', references: ['r1'] };
    assert.deepEqual(T.restoreRemotePatch(snap, ['poc', 'scope', 'references']), { poc: '<p>old poc</p>', scope: 'old', references: ['r1'] });
});

test('restoreLocal puts the snapshot sections back and leaves the others alone', () => {
    const snap = '## Descrizione\n\nold desc\n\n## Evidenza\n\nold poc\n';
    const cur = '## Descrizione\n\nnew desc\n\n## Evidenza\n\nnew poc\n';
    const out = T.restoreLocal(cur, snap, ['poc']);
    assert.equal(T.parseSections(out).poc.text, 'old poc');
    assert.equal(T.parseSections(out).description.text, 'new desc');
});

test('rollbackSections restores PwnDoc from a push entry, records a rollback entry, and can itself be rolled back', async () => {
    const ctx = syncCtx();
    const original = clone(ctx.finding);
    await T.pushSections(ctx, pushArgs(ctx));
    const [pushEntry] = await T.listHistory(ctx.hist, ctx.historyDir);
    assert.equal(ctx.finding.poc, '<p>local poc</p>');

    await T.rollbackSections(ctx, { entry: pushEntry, auditId: AID, findingId: FID, side: 'remote', sections: ['poc'], noteMd: NOTE_ONLY_POC, force: false });
    assert.equal(ctx.finding.poc, original.poc);
    const hist = await T.listHistory(ctx.hist, ctx.historyDir);
    assert.equal(hist[0].op, 'rollback');
    assert.equal(hist[0].remoteBefore.poc, '<p>local poc</p>');

    await T.rollbackSections(ctx, { entry: hist[0], auditId: AID, findingId: FID, side: 'remote', sections: ['poc'], noteMd: NOTE_ONLY_POC, force: false });
    assert.equal(ctx.finding.poc, '<p>local poc</p>');
});

test('rollbackSections on PwnDoc honours the audit state guard', async () => {
    const ctx = syncCtx({ state: 'REVIEW' });
    const entry = { remoteBefore: { ...ctx.finding, poc: '<p>old</p>' }, localBefore: null, sections: ['poc'] };
    await assert.rejects(T.rollbackSections(ctx, { entry, auditId: AID, findingId: FID, side: 'remote', sections: ['poc'], noteMd: '', force: false }), /REVIEW/);
    assert.equal(ctx.log.puts.length, 0);
    await T.rollbackSections(ctx, { entry, auditId: AID, findingId: FID, side: 'remote', sections: ['poc'], noteMd: '', force: true });
    assert.equal(ctx.log.puts.length, 1);
});

test('rollbackSections on the note returns the restored text and records the old note', async () => {
    const ctx = syncCtx();
    const entry = { remoteBefore: null, localBefore: '## Evidenza\n\nold poc\n', sections: ['poc'] };
    const r = await T.rollbackSections(ctx, { entry, auditId: AID, findingId: FID, side: 'local', sections: ['poc'], noteMd: '## Evidenza\n\nnew poc\n', force: false });
    assert.equal(T.parseSections(r.noteMd).poc.text, 'old poc');
    const h = await T.listHistory(ctx.hist, ctx.historyDir);
    assert.equal(h[0].localBefore, '## Evidenza\n\nnew poc\n');
    assert.equal(ctx.log.puts.length, 0);
});

test('buildRollbackComparison marks which sections differ from the snapshot', async () => {
    const entry = { remoteBefore: { poc: '<p>old</p>', description: '<p>same</p>' }, localBefore: null, sections: ['poc'] };
    const cur = { poc: '<p>new</p>', description: '<p>same</p>' };
    const rows = await T.buildRollbackComparison(syncCtx(), entry, 'remote', cur, '', ['poc', 'description']);
    assert.deepEqual(rows.map(r => [r.key, r.changed]), [['poc', true], ['description', false]]);
});

// ── title and CVSS ────────────────────────────────────────────────────────────
const V = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';

test('isValidCvss31 accepts a full 3.1 vector and rejects other versions, missing and bad metrics', () => {
    assert.equal(T.isValidCvss31(V), true);
    assert.equal(T.isValidCvss31(V.replace('3.1', '3.0')), false);
    assert.equal(T.isValidCvss31('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H'), false);
    assert.equal(T.isValidCvss31(V.replace('AV:N', 'AV:X')), false);
    assert.equal(T.isValidCvss31(''), false);
});

test('cvssFrontmatter derives the same frontmatter fields as the importer', () => {
    assert.deepEqual(T.cvssFrontmatter(V), {
        severity: 'CRITICAL', cvss_vector: V, cvss_link: `https://www.first.org/cvss/calculator/3-1#${V}`, cvss_score: 9.8, cvss_severity: 'CRITICAL',
    });
});

test('localValue reads the title from the file name and the CVSS vector from the frontmatter', () => {
    const info = { basename: 'VT-03 - SQL Injection', fm: { cvss_vector: V }, md: '' };
    assert.equal(T.localValue(info, T.SECTION_DEFS.find(d => d.key === 'title')), 'SQL Injection');
    assert.equal(T.localValue(info, T.SECTION_DEFS.find(d => d.key === 'cvssv3')), V);
    assert.equal(T.localValue({ ...info, fm: {} }, T.SECTION_DEFS.find(d => d.key === 'cvssv3')), '');
});

test('buildComparison includes title and CVSS rows when given the note info', async () => {
    const info = { basename: 'VT-01 - New title', fm: { cvss_vector: V.replace('H/I:H/A:H', 'L/I:L/A:L') } };
    const rows = await T.buildComparison(cmpCtx, '', { ...FINDING, title: 'Old title', cvssv3: V }, ['title', 'cvssv3'], info);
    assert.deepEqual(rows.map(r => [r.key, r.changed]), [['title', true], ['cvssv3', true]]);
});

test('pushSections sends title and cvssv3 patches, sanitising the title', async () => {
    const ctx = syncCtx();
    ctx.noteInfo = { basename: 'VT-03 - A/B: new', fm: { cvss_vector: V.replace('S:U', 'S:C') } };
    await T.pushSections(ctx, pushArgs(ctx, { sections: ['title', 'cvssv3'] }));
    assert.deepEqual(ctx.log.puts[0].body, { title: 'A-B- new', cvssv3: V.replace('S:U', 'S:C') });
});

test('pushSections refuses an invalid CVSS vector before any write', async () => {
    const ctx = syncCtx();
    ctx.noteInfo = { basename: 'VT-03 - x', fm: { cvss_vector: 'CVSS:3.1/AV:N' } };
    await assert.rejects(T.pushSections(ctx, pushArgs(ctx, { sections: ['cvssv3'] })), /invalid CVSS/);
    assert.equal(ctx.log.puts.length, 0);
    assert.equal((await T.listHistory(ctx.hist, ctx.historyDir)).length, 0);
});

test('pullSections returns title and CVSS as meta and leaves the note body alone', async () => {
    const ctx = syncCtx({ remote: { title: 'Remote title', cvssv3: V } });
    ctx.noteInfo = { basename: 'VT-03 - Old', fm: {} };
    const note = '## Descrizione\n\nkeep\n';
    const r = await T.pullSections(ctx, { auditId: AID, findingId: FID, noteMd: note, sections: ['title', 'cvssv3'], force: false });
    assert.equal(r.noteMd, note);
    assert.deepEqual(r.meta, { title: 'Remote title', cvssv3: V });
});

test('labelOf names every section, including title and CVSS which have no heading alias', () => {
    assert.deepEqual(T.SECTION_DEFS.map(T.labelOf), ['Descrizione', 'Impatto', 'Evidenza', 'Assets', 'Remediation', 'References', 'Custom Fields', 'Title', 'CVSS vector']);
});
