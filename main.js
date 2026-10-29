'use strict';

const { Plugin, PluginSettingTab, Setting, FuzzySuggestModal, SuggestModal, Modal, Notice, normalizePath, SecretComponent, Component, MarkdownRenderer, htmlToMarkdown, Menu, MarkdownView } = require('obsidian');

// ── CSV Parser ────────────────────────────────────────────────────────────────
function parseCSV(text) {
    text = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const records = [];
    let i = 0;

    while (i <= text.length) {
        const fields = [];
        while (true) {
            let field = '';
            if (i < text.length && text[i] === '"') {
                i++;
                while (i < text.length) {
                    if (text[i] === '"') {
                        if (i + 1 < text.length && text[i + 1] === '"') { field += '"'; i += 2; }
                        else { i++; break; }
                    } else { field += text[i++]; }
                }
            } else {
                while (i < text.length && text[i] !== ',' && text[i] !== '\n') field += text[i++];
            }
            fields.push(field);
            if (i < text.length && text[i] === ',') { i++; continue; }
            break;
        }
        if (i < text.length && text[i] === '\n') i++;
        if (fields.length > 0 && !(fields.length === 1 && fields[0] === '')) records.push(fields);
        if (i >= text.length) break;
    }

    if (records.length < 2) return [];
    const headers = records[0].map(h => h.trim());
    return records.slice(1).map(fields => {
        const row = {};
        headers.forEach((h, idx) => { row[h] = fields[idx] ?? ''; });
        return row;
    });
}

// ── CVSS 3.1 score calculator ─────────────────────────────────────────────────
function computeCVSS31(vector) {
    if (!vector || !vector.startsWith('CVSS:3.1/')) return { score: '0.0', severity: 'INFO' };

    const parts = {};
    vector.replace('CVSS:3.1/', '').split('/').forEach(p => {
        const [k, v] = p.split(':');
        parts[k] = v;
    });

    const W = {
        AV:  { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
        AC:  { L: 0.77, H: 0.44 },
        PR:  { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.50 } },
        UI:  { N: 0.85, R: 0.62 },
        CIA: { N: 0.0,  L: 0.22, H: 0.56 },
    };

    const { AV, AC, PR, UI, S, C, I, A } = parts;
    if (!AV || !AC || !PR || !UI || !S || !C || !I || !A) return { score: '0.0', severity: 'INFO' };

    const iss = 1 - (1 - W.CIA[C]) * (1 - W.CIA[I]) * (1 - W.CIA[A]);
    const impact = S === 'U'
        ? 6.42 * iss
        : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    const exploit = 8.22 * W.AV[AV] * W.AC[AC] * W.PR[S][PR] * W.UI[UI];

    let base = 0;
    if (impact > 0) {
        base = S === 'U'
            ? Math.min(impact + exploit, 10)
            : Math.min(1.08 * (impact + exploit), 10);
    }

    const score = (Math.ceil(base * 10) / 10).toFixed(1);
    const n = parseFloat(score);
    const severity = n === 0.0 ? 'INFO' : n <= 3.9 ? 'LOW' : n <= 6.9 ? 'MEDIUM' : n <= 8.9 ? 'HIGH' : 'CRITICAL';
    return { score, severity };
}

// ── Note sections ─────────────────────────────────────────────────────────────
// Frontmatter-backed fields share one shape: cmpLocal(raw frontmatter value) and cmpRemote(finding value) give the same
// comparison string, toRemote(cmp) the value to PUT (undefined = not representable), toFm(cmp, current) the frontmatter
// value a pull writes (undefined = leave as is)
const STATUS_DONE = 0, STATUS_OPEN = 1; // finding.status in PwnDoc: 0 completed, 1 in progress
const enumCodec = names => ({
    cmpLocal: raw => { const n = Number(raw); return raw !== '' && raw != null && Number.isInteger(n) && n >= 1 && n <= names.length ? names[n - 1] : String(raw ?? '').trim().toLowerCase(); },
    cmpRemote: v => names[v - 1] ?? '',
    toRemote: cmp => { const i = names.indexOf(cmp); return i >= 0 ? i + 1 : undefined; },
    toFm: cmp => cmp || undefined,
});
const isCompletedLocal = raw => /^(completed|done)$/i.test(String(raw ?? '').trim());
const statusCodec = {
    cmpLocal: raw => (isCompletedLocal(raw) ? 'completed' : 'in progress'),
    cmpRemote: v => (v === STATUS_DONE ? 'completed' : 'in progress'),
    toRemote: cmp => (cmp === 'completed' ? STATUS_DONE : STATUS_OPEN),
    toFm: (cmp, cur) => (cmp === 'completed' ? 'COMPLETED' : isCompletedLocal(cur) ? 'DRAFT' : undefined),
};
const SECTION_DEFS = [
    { key: 'description',  field: 'description',  kind: 'html',   aliases: ['Descrizione', 'Description'] },
    { key: 'observation',  field: 'observation',  kind: 'html',   aliases: ['Impatto', 'Impact', 'Observation'] },
    { key: 'poc',          field: 'poc',          kind: 'html',   aliases: ['Evidenza', 'Evidenze', 'Evidence', 'Proof'] },
    { key: 'scope',        field: 'scope',        kind: 'text',   aliases: ['Assets'] },
    { key: 'remediation',  field: 'remediation',  kind: 'html',   aliases: ['Remediation'] },
    { key: 'references',   field: 'references',   kind: 'list',   aliases: ['References'] },
    { key: 'customFields', field: 'customFields', kind: 'custom', aliases: ['Custom Fields'] }, // **label** blocks, one per PwnDoc custom field
    { key: 'title',  field: 'title',  kind: 'text', aliases: [], label: 'Title',       source: 'filename' },
    { key: 'cvssv3', field: 'cvssv3', kind: 'text', aliases: [], label: 'CVSS vector', source: 'frontmatter', fmKey: 'cvss_vector' },
    { key: 'vulnType', field: 'vulnType', kind: 'text', aliases: [], label: 'Vulnerability type', source: 'frontmatter', fmKey: 'category',
      cmpLocal: raw => String(raw ?? '').trim(), cmpRemote: v => String(v ?? '').trim(), toRemote: c => c || undefined, toFm: c => c || undefined },
    { key: 'priority', field: 'priority', kind: 'enum', aliases: [], label: 'Priority', source: 'frontmatter', fmKey: 'priority',
      ...enumCodec(['low', 'medium', 'high', 'urgent']) },
    { key: 'remediationComplexity', field: 'remediationComplexity', kind: 'enum', aliases: [], label: 'Remediation complexity', source: 'frontmatter', fmKey: 'remediation_complexity',
      ...enumCodec(['easy', 'medium', 'hard']) },
    { key: 'status', field: 'status', kind: 'status', aliases: [], label: 'Completed', source: 'frontmatter', fmKey: 'status', ...statusCodec },
];
const DEFAULT_SYNC_SECTIONS = ['poc'];
const ALIAS_TO_KEY = new Map(SECTION_DEFS.flatMap(d => d.aliases.map(a => [a.toLowerCase(), d.key])));

// Level-2 headings outside code fences, with the offsets where the heading line and its body start
function scanHeadings(md) {
    const heads = [];
    let fence = null;
    let off = 0;
    for (const line of md.split('\n')) {
        const lineEnd = off + line.length + 1;
        const f = line.match(/^\s*(```+|~~~+)/);
        if (f) {
            if (!fence) fence = f[1][0];
            else if (f[1][0] === fence) fence = null;
        } else if (!fence) {
            const h = line.match(/^## +(.+?)\s*$/);
            if (h) heads.push({ title: h[1], lineStart: off, bodyStart: Math.min(lineEnd, md.length) });
        }
        off = lineEnd;
    }
    return heads;
}

// { key: { text, start, end } } where [start, end) is the raw body region (heading excluded)
function parseSections(md) {
    const heads = scanHeadings(md);
    const out = {};
    heads.forEach((h, i) => {
        const key = ALIAS_TO_KEY.get(h.title.toLowerCase());
        if (!key || out[key]) return;
        const end = i + 1 < heads.length ? heads[i + 1].lineStart : md.length;
        out[key] = { text: md.slice(h.bodyStart, end).trim(), start: h.bodyStart, end };
    });
    return out;
}

function replaceSection(md, key, newText) {
    const sec = parseSections(md)[key];
    const body = newText.trim();
    if (!sec) {
        const title = SECTION_DEFS.find(d => d.key === key).aliases[0];
        return md.replace(/\n*$/, '\n\n') + `## ${title}\n\n${body}\n`;
    }
    const atEof = sec.end >= md.length;
    return md.slice(0, sec.start) + '\n' + (body ? body + '\n' : '') + (atEof ? '' : '\n') + md.slice(sec.end);
}

// ── Converters (HTML <-> Markdown) ────────────────────────────────────────────
const ALLOWED_TAGS = new Set(['p', 'ul', 'ol', 'li', 'strong', 'em', 'code', 'pre', 'a', 'br', 'blockquote',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'table', 'thead', 'tbody', 'tr', 'th', 'td']);
const DROP_TAGS = new Set(['script', 'style', 'button', 'iframe', 'object', 'embed']);
const TAG_ALIAS = { b: 'strong', i: 'em' };

const escHtml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const escAttr = s => escHtml(s).replace(/"/g, '&quot;');

// Serialise a rendered DOM subtree into the HTML subset PwnDoc's editor stores.
// imgResolver(src, alt) returns the value for <img src>, or null to drop the image.
function serializeWhitelist(node, imgResolver = () => null) {
    if (node.nodeType === 3) return escHtml(node.textContent);
    if (node.nodeType !== 1) return '';
    const tag = TAG_ALIAS[node.tagName.toLowerCase()] || node.tagName.toLowerCase();
    if (DROP_TAGS.has(tag)) return '';
    if (tag === 'pre') return `<pre><code>${escHtml(textWithoutDropped(node))}</code></pre>`;
    if (tag === 'img') {
        const src = imgResolver(node.getAttribute('src') || '', node.getAttribute('alt') || '');
        return src ? `<img src="${escAttr(src)}" alt="${escAttr(node.getAttribute('alt') || '')}">` : '';
    }
    const inner = Array.from(node.childNodes).map(c => serializeWhitelist(c, imgResolver)).join('');
    if (tag === 'br') return '<br>';
    if (!ALLOWED_TAGS.has(tag)) return inner;
    if (tag === 'a') {
        const href = node.getAttribute('href') || '';
        return /^(https?:|mailto:)/i.test(href) ? `<a href="${escAttr(href)}">${inner}</a>` : inner;
    }
    return `<${tag}>${inner}</${tag}>`;
}

function textWithoutDropped(node) {
    if (node.nodeType === 3) return node.textContent;
    if (node.nodeType !== 1 || DROP_TAGS.has(node.tagName.toLowerCase())) return '';
    return Array.from(node.childNodes).map(textWithoutDropped).join('');
}

// Image refs are swapped for inert tokens before rendering and expanded after serialising,
// so the renderer never sees (or rewrites) vault paths. Alt is hex encoded: no markdown-special chars.
const IMG_TOKEN_RE = /⟦pwimg:([0-9a-f]+):([0-9a-f]*)⟧/g;
const imgToken = (id, alt) => `⟦pwimg:${id}:${Buffer.from(alt, 'utf8').toString('hex')}⟧`;
const expandImgTokens = html => html.replace(IMG_TOKEN_RE, (_, id, hex) =>
    `<img src="${id}" alt="${escAttr(Buffer.from(hex, 'hex').toString('utf8'))}">`);

// Runtime-only (needs Obsidian): markdown -> PwnDoc HTML
async function mdToHtml(app, md, strict = false) {
    const div = document.createElement('div');
    const comp = new Component();
    comp.load();
    try { await MarkdownRenderer.render(app, md, div, '', comp); }
    finally { comp.unload(); }
    return expandImgTokens(serializeWhitelist(div, strict ? strictImageResolver : undefined));
}

const htmlToMd = (html, { convert = htmlToMarkdown, parse } = {}) =>
    (html ? demoteHeadings(convert(sanitizeHtml(html, parse)).trim()) : '');

// Comparison form: both sides pass through the same renderer so formatting noise cancels out
async function normalizeMd(app, md, keyOf = async src => src) {
    return withImagesPreserved(md, keyOf, async m => htmlToMd(await mdToHtml(app, m)));
}

// ── Engagement association ────────────────────────────────────────────────────
const parentDir = p => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');

// Note frontmatter wins; otherwise the nearest associated ancestor folder
function resolveAuditId(notePath, fm, folderAudits) {
    if (fm?.pwndoc_audit_id) return fm.pwndoc_audit_id;
    return folderAuditFor(notePath, folderAudits)?.auditId ?? null;
}

function renameFolderKeys(folderAudits, oldPath, newPath) {
    const out = {};
    for (const [k, v] of Object.entries(folderAudits)) {
        if (k === oldPath) out[newPath] = v;
        else if (k.startsWith(oldPath + '/')) out[newPath + k.slice(oldPath.length)] = v;
        else out[k] = v;
    }
    return out;
}

// Title as PwnDoc knows it: the note name without the "VT-NN - " / "M-NN - " prefix
const titleFromBasename = basename => basename.replace(/^(VT|M)-\d+ - /, '');

const normTitle = t => String(t || '').toLowerCase().replace(/\s+/g, ' ').trim();

// Findings ordered so the best title match comes first
function rankFindings(title, findings) {
    const t = normTitle(title);
    const score = f => {
        const ft = normTitle(f.title);
        return ft === t ? 0 : (ft.includes(t) || t.includes(ft)) ? 1 : 2;
    };
    return [...findings].sort((a, b) => score(a) - score(b) || Number(a.identifier) - Number(b.identifier));
}

const pwndocListAudits = async (baseUrl, token, ignoreSsl) =>
    (await pwndocApi(baseUrl, token, 'GET', '/api/audits', { ignoreSsl })) || [];
// What the "send to PwnDoc" picker offers: the findings best match first, plus "create a new one"
// (on top when no finding has this title, since that is then the likely answer)
function findingChoices(title, findings) {
    const ranked = rankFindings(title, findings).map(finding => ({ finding }));
    const exact = findings.some(f => normTitle(f.title) === normTitle(title));
    return exact ? [...ranked, { create: true }] : [{ create: true }, ...ranked];
}

const pwndocGetAudit = (baseUrl, token, id, ignoreSsl) =>
    pwndocApi(baseUrl, token, 'GET', `/api/audits/${id}`, { ignoreSsl });

// ── Images ────────────────────────────────────────────────────────────────────
const IMAGE_MIME = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp' };
const MIME_EXT = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/gif': 'gif', 'image/webp': 'webp' };
const MAX_IMAGE_BYTES = 12 * 1024 * 1024; // PwnDoc rejects bodies above ~17.8 MB, base64 adds a third
const IMAGE_RE = /!\[\[([^\]|\n]+)(?:\|([^\]\n]*))?\]\]|!\[((?:[^\[\]\n]|\[[^\]\n]*\])*)\]\(([^)\n]*)\)/g;
const SIZE_SUFFIX_RE = /^\d+(x\d+)?$/;

// Apply fn to the text outside ``` / ~~~ code fences
// ponytail: inline `code` spans are not excluded, an image ref inside one gets rewritten too
function mapOutsideFences(md, fn) {
    const out = [];
    let chunk = [];
    let fence = null;
    const flush = () => { if (chunk.length) { out.push(fn(chunk.join('\n'))); chunk = []; } };
    for (const line of md.split('\n')) {
        const f = line.match(/^\s*(```+|~~~+)/);
        if (f && !fence) { flush(); fence = f[1][0]; out.push(line); }
        else if (f && f[1][0] === fence) { fence = null; out.push(line); }
        else if (fence) out.push(line);
        else chunk.push(line);
    }
    flush();
    return out.join('\n');
}

function parseImageMatch(m) {
    const wiki = m[1] !== undefined;
    let src = (wiki ? m[1] : m[4]).trim().replace(/^<(.*)>$/, '$1');
    try { src = decodeURIComponent(src); } catch { /* keep as written */ }
    let alt = (wiki ? (m[2] || '') : m[3]).replace(/\|\d+(x\d+)?$/, '');
    if (SIZE_SUFFIX_RE.test(alt)) alt = '';
    return { raw: m[0], src, alt, remote: /^https?:\/\//i.test(src) };
}

function extractImageRefs(md) {
    const refs = [];
    mapOutsideFences(md, t => { for (const m of t.matchAll(IMAGE_RE)) refs.push(parseImageMatch(m)); return t; });
    return refs;
}

function replaceImageRefs(md, fn) {
    return mapOutsideFences(md, t => t.replace(IMAGE_RE, (...m) => fn(parseImageMatch(m))));
}

// ctx: { resolvePath(src) -> vaultPath|null, readBinary(path) -> Buffer|ArrayBuffer, api(method, path, opts),
//        imageCache: { [auditId]: { [sha256]: imageId } }, save() }
// ponytail: a cached id is trusted; an image deleted in PwnDoc is not re-uploaded until the cache entry is removed
async function uploadImage(ctx, auditId, src) {
    if (/^https?:\/\//i.test(src)) throw new Error(`remote image not supported: ${src}`);
    const path = ctx.resolvePath(src);
    if (!path) throw new Error(`missing image: ${src}`);
    const ext = path.split('.').pop().toLowerCase();
    if (!IMAGE_MIME[ext]) throw new Error(`unsupported image type: ${path}`);
    const bytes = Buffer.from(await ctx.readBinary(path));
    if (bytes.length > MAX_IMAGE_BYTES) throw new Error(`image too large (${(bytes.length / 1048576).toFixed(1)} MB, max 12): ${path}`);
    const hash = require('crypto').createHash('sha256').update(bytes).digest('hex');
    const cached = ctx.imageCache[auditId]?.[hash];
    if (cached) return cached;
    const res = await ctx.api('POST', '/api/images', {
        body: { value: `data:${IMAGE_MIME[ext]};base64,${bytes.toString('base64')}`, name: path.split('/').pop(), auditId },
    });
    (ctx.imageCache[auditId] ||= {})[hash] = res._id;
    await ctx.save();
    return res._id;
}

// Upload every image of a section and swap the refs for tokens; throws before replacing anything if one fails
async function tokenizeImages(ctx, auditId, md) {
    const ids = new Map();
    for (const r of extractImageRefs(md)) if (!ids.has(r.src)) ids.set(r.src, await uploadImage(ctx, auditId, r.src));
    return replaceImageRefs(md, r => imgToken(ids.get(r.src), r.alt));
}

// ctx: { api, exists(path), writeBinary(path, Buffer) }
async function downloadImage(ctx, imageId, destFolder) {
    const meta = await ctx.api('GET', `/api/images/${imageId}`);
    const m = /^data:(image\/[a-z]+);base64,(.*)$/s.exec(meta.value || '');
    if (!m || !MIME_EXT[m[1]]) throw new Error(`unsupported image in PwnDoc: ${imageId}`);
    const path = `${destFolder ? destFolder + '/' : ''}${imageId}.${MIME_EXT[m[1]]}`;
    if (!(await ctx.exists(path))) await ctx.writeBinary(path, Buffer.from(m[2], 'base64'));
    return path;
}

// Rewrite ![alt](<pwndoc image id>) from a pulled section into vault paths, downloading what is missing
async function pullImages(ctx, md, destFolder) {
    const paths = new Map();
    for (const r of extractImageRefs(md)) {
        if (/^[0-9a-f]{24}$/.test(r.src) && !paths.has(r.src)) paths.set(r.src, await downloadImage(ctx, r.src, destFolder));
    }
    return replaceImageRefs(md, r => (paths.has(r.src) ? `![${r.alt}](${encodeURI(paths.get(r.src))})` : r.raw));
}

// ── Diff / comparison ─────────────────────────────────────────────────────────
// Line-level LCS diff. ponytail: O(n*m) table, fine for note sections, use a Myers diff for huge ones
function lineDiff(a, b) {
    const x = a === '' ? [] : a.split('\n');
    const y = b === '' ? [] : b.split('\n');
    const lcs = Array.from({ length: x.length + 1 }, () => new Array(y.length + 1).fill(0));
    for (let i = x.length - 1; i >= 0; i--) {
        for (let j = y.length - 1; j >= 0; j--) {
            lcs[i][j] = x[i] === y[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
        }
    }
    const out = [];
    let i = 0, j = 0;
    while (i < x.length && j < y.length) {
        if (x[i] === y[j]) { out.push({ op: 'eq', line: x[i] }); i++; j++; }
        else if (lcs[i + 1][j] >= lcs[i][j + 1]) out.push({ op: 'del', line: x[i++] });
        else out.push({ op: 'add', line: y[j++] });
    }
    while (i < x.length) out.push({ op: 'del', line: x[i++] });
    while (j < y.length) out.push({ op: 'add', line: y[j++] });
    return out;
}

// Custom fields rendered the way createVulnNote writes them: **label** + value, empty ones omitted
function renderCustomFields(finding, ctx) {
    return (finding.customFields || [])
        .map(cf => ({ label: ctx.cfLabels?.[cf.customField?._id || cf.customField] || cf.customField?.label || '', value: ctx.htmlToMd(cf.text || '') }))
        .filter(c => c.label && c.value)
        .flatMap(c => [`**${c.label}**`, '', c.value, ''])
        .join('\n').trim();
}

const listLines = text => text.split(/\n|; /).map(l => l.replace(/^\s*[-*]\s+/, '').trim()).filter(Boolean).join('\n');

// ctx: { normalize(md) -> Promise<string>, htmlToMd(html) -> string, cfLabels }
// One row per requested section: local and remote in comparison form, plus emptiness flags used to guard overwrites
async function buildComparison(ctx, noteMd, finding, keys, noteInfo = {}, base = null) {
    const secs = parseSections(noteMd);
    const rows = [];
    for (const key of keys) {
        const def = SECTION_DEFS.find(d => d.key === key);
        const localRaw = def.source ? localValue({ ...noteInfo, md: noteMd }, def) : secs[key]?.text || '';
        let local, remote;
        if (def.kind === 'html') {
            local = await ctx.normalize(localRaw);
            remote = await ctx.normalize(ctx.htmlToMd(finding[def.field] || ''));
        } else if (def.kind === 'list') {
            local = listLines(localRaw);
            remote = (finding[def.field] || []).map(s => s.trim()).filter(Boolean).join('\n');
        } else if (def.kind === 'custom') {
            local = canonCustom(localRaw);
            remote = renderCustomFields(finding, ctx);
        } else if (def.cmpLocal) {
            local = def.cmpLocal(localRaw);
            remote = def.cmpRemote(finding[def.field]);
        } else {
            local = localRaw.trim();
            remote = def.key === 'title' ? sanitizeTitle(finding.title) : String(finding[def.field] || '').trim();
        }
        const baseText = base?.sections?.[key];
        const status = classify(baseText, local, remote);
        const merge = status === 'conflict' && !def.source ? merge3(baseText, local, remote) : null;
        rows.push({ key, local, remote, base: baseText, status, merge, changed: local !== remote, localEmpty: def.cmpLocal ? String(localRaw ?? '').trim() === '' : local === '', remoteEmpty: remote === '', diff: lineDiff(remote, local) });
    }
    return rows;
}

// ── History store ─────────────────────────────────────────────────────────────
// One JSON per operation under <plugin dir>/history/<findingId>/, plus base.json (last synced state per section).
// adapter = app.vault.adapter. The directory holds client data: it is git-ignored.
const BASE_FILE = 'base.json';
const historyDir = (manifestDir, findingId) => `${manifestDir}/history/${findingId}`;
const historyFiles = async (adapter, dir) =>
    (await adapter.exists(dir) ? (await adapter.list(dir)).files : [])
        .filter(f => f.endsWith('.json') && !f.endsWith(`/${BASE_FILE}`));

// Names (oldest first) to delete so that `limit` newest remain
const pruneNames = (names, limit) => [...names].sort().slice(0, Math.max(0, names.length - limit));

async function recordHistory(adapter, dir, entry, limit) {
    if (!(await adapter.exists(dir))) await adapter.mkdir(dir);
    const id = `${entry.ts.replace(/[:.]/g, '-')}-${entry.op}-${Math.random().toString(16).slice(2, 6)}`;
    await adapter.write(`${dir}/${id}.json`, JSON.stringify({ ...entry, id }, null, 1));
    for (const f of pruneNames(await historyFiles(adapter, dir), limit)) await adapter.remove(f);
    return id;
}

// Newest first; unreadable files are skipped
async function listHistory(adapter, dir) {
    const out = [];
    for (const f of (await historyFiles(adapter, dir)).sort().reverse()) {
        try { out.push(JSON.parse(await adapter.read(f))); } catch { /* corrupt entry, skip */ }
    }
    return out;
}

async function loadBase(adapter, dir) {
    try { return JSON.parse(await adapter.read(`${dir}/${BASE_FILE}`)); } catch { return null; }
}

async function saveBase(adapter, dir, base) {
    const prev = await loadBase(adapter, dir);
    if (!(await adapter.exists(dir))) await adapter.mkdir(dir);
    await adapter.write(`${dir}/${BASE_FILE}`, JSON.stringify({ ts: base.ts, sections: { ...prev?.sections, ...base.sections } }, null, 1));
}

// ── Push / pull pipeline ──────────────────────────────────────────────────────
class AuditLockedError extends Error {
    constructor(state) {
        super(`audit is in state ${state}, not EDIT (tick "Enforce" to write anyway)`);
        this.state = state;
    }
}

function assertEditable(audit, force) {
    if (audit.state !== 'EDIT' && !force) throw new AuditLockedError(audit.state);
}

// The finding has no updatedAt, so "unchanged since compare" means the selected fields hash the same
function findingHash(finding, sections) {
    const fields = sections.map(k => SECTION_DEFS.find(d => d.key === k).field).sort();
    return require('crypto').createHash('sha256').update(JSON.stringify(fields.map(f => [f, finding[f] ?? null]))).digest('hex');
}

function assertUnchanged(snapshotHash, fresh, sections) {
    if (findingHash(fresh, sections) !== snapshotHash) throw new Error('finding changed on PwnDoc since compare');
}

// Empty = no text and no image (an evidence section that is only a screenshot is not empty)
function isEmptyValue(v) {
    if (Array.isArray(v)) return v.length === 0;
    const s = String(v ?? '');
    return s.replace(/<(?!img\b)[^>]*>/gi, '').trim() === '';
}

const defOf = key => SECTION_DEFS.find(d => d.key === key);

async function localToRemote(ctx, auditId, def, text, fresh) {
    if (def.toRemote) {
        if (String(text ?? '').trim() === '') return undefined; // an absent field is not a value (status would read as "in progress")
        const cmp = def.cmpLocal(text);
        const v = def.toRemote(cmp);
        if (v === undefined && cmp !== '') throw new Error(`invalid ${labelOf(def)}: ${text}`);
        return v; // undefined: nothing to send, the field is left alone
    }
    if (def.kind === 'custom') return customFieldsPatch(ctx, auditId, fresh, text);
    if (def.key === 'cvssv3' && text && !isValidCvss31(text)) throw new Error(`invalid CVSS vector: ${text}`);
    const v = await localToRemoteBase(ctx, auditId, def, text);
    return def.key === 'title' ? v.replace(FILENAME_UNSAFE_RE, '-') : v;
}

async function localToRemoteBase(ctx, auditId, def, text) {
    if (def.kind === 'html') return text === '' ? '' : ctx.mdToHtml(await tokenizeImages(ctx, auditId, text));
    if (def.kind === 'list') return listLines(text).split('\n').filter(Boolean);
    return text.trim();
}

async function remoteToLocal(ctx, def, value, fresh) {
    if (def.kind === 'custom') return renderCustomFields(fresh, ctx);
    if (def.kind === 'html') return pullImages(ctx, ctx.htmlToMd(value || ''), ctx.attachmentsFolder);
    if (def.kind === 'list') return (value || []).map(s => `- ${s}`).join('\n');
    return String(value ?? '');
}

async function comparisonForm(ctx, def, text) {
    if (def.cmpLocal) return def.cmpLocal(text);
    if (def.kind === 'custom') return canonCustom(text);
    if (def.kind === 'html') return ctx.normalize(text);
    if (def.kind === 'list') return listLines(text);
    return text.trim();
}

async function fetchFinding(ctx, auditId, findingId) {
    const audit = await ctx.api('GET', `/api/audits/${auditId}`);
    const finding = audit.findings?.find(f => f._id === findingId);
    if (!finding) throw new Error('finding not found in the audit');
    return { audit, finding };
}

// ctx: see Plugin.syncCtx. Writes PwnDoc: only the patch of the selected fields (PUT merges), after the
// state guard, the changed-since-compare check and a history entry. Nothing is written if any step throws.
async function pushSections(ctx, { auditId, findingId, noteMd, sections, snapshotFinding, force, op = 'push', localBefore = noteMd }) {
    const defs = sections.map(defOf);
    const { audit, finding: fresh } = await fetchFinding(ctx, auditId, findingId);
    assertEditable(audit, force);
    assertUnchanged(findingHash(snapshotFinding, sections), fresh, sections);

    const secs = parseSections(noteMd);
    const patch = {};
    const baseSections = {};
    for (const def of defs) {
        const text = def.source ? localValue({ ...ctx.noteInfo, md: noteMd }, def) : secs[def.key]?.text || '';
        const value = await localToRemote(ctx, auditId, def, text, fresh);
        if (value === undefined) continue;
        if (isEmptyValue(value) && !isEmptyValue(fresh[def.field]) && !(await ctx.confirmEmpty(def.key, 'push'))) {
            throw new Error(`local section ${def.key} is empty, refusing to blank it on PwnDoc`);
        }
        baseSections[def.key] = await comparisonForm(ctx, def, text);
        if (def.key === 'title' && text === sanitizeTitle(fresh.title)) continue; // differs only by filename sanitising
        patch[def.field] = value;
    }
    if (!Object.keys(patch).length) return { patch, entryId: null }; // nothing representable to send
    const ts = new Date().toISOString();
    const entryId = await recordHistory(ctx.adapter, ctx.historyDir, {
        ts, op, forced: !!force && audit.state !== 'EDIT', auditId, findingId, notePath: ctx.notePath,
        sections, remoteBefore: fresh, localBefore,
    }, ctx.historyLimit);
    await ctx.api('PUT', `/api/audits/${auditId}/findings/${findingId}`, { body: patch });
    await saveBase(ctx.adapter, ctx.historyDir, { ts, sections: baseSections });
    return { patch, entryId };
}

// Local only: returns the new note text, the caller writes it
async function pullSections(ctx, { auditId, findingId, noteMd, sections }) {
    const defs = sections.map(defOf);
    const { finding: fresh } = await fetchFinding(ctx, auditId, findingId);
    const secs = parseSections(noteMd);
    let md = noteMd;
    const meta = {};
    const baseSections = {};
    for (const def of defs) {
        if (def.source) {
            meta[def.key] = def.cmpRemote ? def.cmpRemote(fresh[def.field]) : String(fresh[def.field] ?? '');
            baseSections[def.key] = def.cmpRemote ? meta[def.key] : def.key === 'title' ? sanitizeTitle(meta[def.key]) : meta[def.key].trim();
            continue;
        }
        const remoteEmpty = def.kind === 'custom' ? renderCustomFields(fresh, ctx) === '' : isEmptyValue(fresh[def.field]);
        if (remoteEmpty && (secs[def.key]?.text || '') !== '' && !(await ctx.confirmEmpty(def.key, 'pull'))) {
            throw new Error(`PwnDoc section ${def.key} is empty, refusing to blank it in the note`);
        }
        const text = await remoteToLocal(ctx, def, fresh[def.field], fresh);
        md = replaceSection(md, def.key, text);
        baseSections[def.key] = await comparisonForm(ctx, def, text);
    }
    const ts = new Date().toISOString();
    const entryId = await recordHistory(ctx.adapter, ctx.historyDir, {
        ts, op: 'pull', forced: false, auditId, findingId, notePath: ctx.notePath,
        sections, remoteBefore: fresh, localBefore: noteMd,
    }, ctx.historyLimit);
    await saveBase(ctx.adapter, ctx.historyDir, { ts, sections: baseSections });
    return { noteMd: md, entryId, meta };
}

// ── Rollback ──────────────────────────────────────────────────────────────────
// Patch that puts the snapshot values of the given sections back on PwnDoc
function restoreRemotePatch(snapshotFinding, sections) {
    const patch = {};
    for (const key of sections) {
        const def = defOf(key);
        const v = snapshotFinding?.[def.field];
        if (v === undefined && def.cmpRemote) continue; // the snapshot never had this field
        patch[def.field] = v ?? (def.kind === 'list' || def.kind === 'custom' ? [] : '');
    }
    return patch;
}

function restoreLocal(noteMd, snapshotMd, sections) {
    const snap = parseSections(snapshotMd);
    return sections.reduce((md, key) => replaceSection(md, key, snap[key]?.text || ''), noteMd);
}

async function remoteForm(ctx, def, value) {
    if (def.cmpRemote) return def.cmpRemote(value);
    if (def.kind === 'custom') return renderCustomFields({ customFields: value || [] }, ctx);
    if (def.kind === 'html') return ctx.normalize(ctx.htmlToMd(value || ''));
    if (def.kind === 'list') return (value || []).map(s => s.trim()).filter(Boolean).join('\n');
    return String(value ?? '').trim();
}

// Current state vs the snapshot of a history entry, per section (side: 'remote' | 'local')
async function buildRollbackComparison(ctx, entry, side, currentFinding, currentNoteMd, keys) {
    const rows = [];
    for (const key of keys) {
        const def = defOf(key);
        let cur, snap;
        if (side === 'remote') {
            cur = await remoteForm(ctx, def, currentFinding?.[def.field]);
            snap = await remoteForm(ctx, def, entry.remoteBefore?.[def.field]);
        } else {
            cur = await comparisonForm(ctx, def, parseSections(currentNoteMd)[key]?.text || '');
            snap = await comparisonForm(ctx, def, parseSections(entry.localBefore || '')[key]?.text || '');
        }
        rows.push({ key, current: cur, snapshot: snap, changed: cur !== snap, diff: lineDiff(cur, snap) });
    }
    return rows;
}

// Restore the sections of a history entry on PwnDoc (side 'remote', state guard applies) or in the note
// (side 'local', returns the new text). The rollback is itself recorded, so it can be rolled back.
async function rollbackSections(ctx, { entry, side, sections, noteMd, auditId, findingId, force, snapshotFinding }) {
    const ts = new Date().toISOString();
    if (side === 'local') {
        const newMd = restoreLocal(noteMd, entry.localBefore || '', sections);
        const entryId = await recordHistory(ctx.adapter, ctx.historyDir, {
            ts, op: 'rollback', forced: false, auditId, findingId, notePath: ctx.notePath, sections, remoteBefore: null, localBefore: noteMd,
        }, ctx.historyLimit);
        return { noteMd: newMd, entryId };
    }
    const patch = restoreRemotePatch(entry.remoteBefore, sections);
    const { audit, finding: fresh } = await fetchFinding(ctx, auditId, findingId);
    assertEditable(audit, force);
    if (snapshotFinding) assertUnchanged(findingHash(snapshotFinding, sections), fresh, sections);
    const entryId = await recordHistory(ctx.adapter, ctx.historyDir, {
        ts, op: 'rollback', forced: !!force && audit.state !== 'EDIT', auditId, findingId, notePath: ctx.notePath,
        sections, remoteBefore: fresh, localBefore: noteMd,
    }, ctx.historyLimit);
    await ctx.api('PUT', `/api/audits/${auditId}/findings/${findingId}`, { body: patch });
    return { entryId };
}

// ── Custom fields, completion status, frontmatter of pulled fields ────────────
// ponytail: a value line that is only **bold** reads as a new label
function parseCustomFieldsText(text) {
    const out = [];
    for (const line of String(text || '').split('\n')) {
        const m = line.match(/^\*\*(.+)\*\*\s*$/);
        if (m) out.push({ label: m[1].trim(), lines: [] });
        else if (out.length) out.at(-1).lines.push(line);
    }
    return out.map(c => ({ label: c.label, md: c.lines.join('\n').trim() }));
}

// The form renderCustomFields produces, so a note and PwnDoc compare equal when they say the same
const canonCustom = text => parseCustomFieldsText(text).filter(c => c.md).flatMap(c => [`**${c.label}**`, '', c.md, '']).join('\n').trim();

const PLAIN_CF_TYPES = ['input', 'date', 'radio', 'select'];

// The customFields array to PUT: the finding's own entries, with the text of the ones named in the note replaced.
// Rich text goes through the same markdown to HTML path as the body sections, input-like fields stay plain.
async function customFieldsPatch(ctx, auditId, fresh, text) {
    const entries = (fresh.customFields || []).map(cf => {
        const id = cf.customField?._id ?? cf.customField;
        return { id, label: ctx.cfLabels?.[id] || cf.customField?.label || '', type: cf.customField?.fieldType || ctx.cfTypes?.[id], text: cf.text };
    });
    for (const { label, md } of parseCustomFieldsText(text)) {
        if (!md) continue;
        let e = entries.find(x => x.label === label);
        if (!e) {
            const id = Object.keys(ctx.cfLabels || {}).find(k => ctx.cfLabels[k] === label);
            if (!id) throw new Error(`unknown custom field "${label}"`);
            entries.push(e = { id, label, type: ctx.cfTypes?.[id], text: '' });
        }
        if (e.type && e.type !== 'text' && !PLAIN_CF_TYPES.includes(e.type)) throw new Error(`custom field "${label}" (${e.type}) cannot be edited here`);
        if (Array.isArray(e.text)) throw new Error(`custom field "${label}" cannot be edited here`);
        if (md === ctx.htmlToMd(String(e.text ?? '')).trim()) continue; // not touched by the user: keep PwnDoc's exact value
        const rich = e.type ? e.type === 'text' : /<\/?\w+[^>]*>/.test(String(e.text ?? ''));
        e.text = rich ? await ctx.mdToHtml(await tokenizeImages(ctx, auditId, md)) : md;
    }
    return entries.map(e => ({ customField: e.id, text: e.text }));
}

// Mark a finding completed or reopen it: patches only `status`, after the state guard, with a history entry
async function setFindingStatus(ctx, { auditId, findingId, completed, force, localBefore = '' }) {
    const { audit, finding: fresh } = await fetchFinding(ctx, auditId, findingId);
    assertEditable(audit, force);
    const ts = new Date().toISOString();
    await recordHistory(ctx.adapter, ctx.historyDir, {
        ts, op: 'status', forced: !!force && audit.state !== 'EDIT', auditId, findingId, notePath: ctx.notePath,
        sections: ['status'], remoteBefore: fresh, localBefore,
    }, ctx.historyLimit);
    await ctx.api('PUT', `/api/audits/${auditId}/findings/${findingId}`, { body: { status: completed ? STATUS_DONE : STATUS_OPEN } });
    await saveBase(ctx.adapter, ctx.historyDir, { ts, sections: { status: completed ? 'completed' : 'in progress' } });
}

// Frontmatter keys to write after a pull, from the codec form of the pulled fields
function metaToFrontmatter(meta, fm = {}) {
    const out = {};
    for (const def of SECTION_DEFS) {
        if (!def.toFm || meta[def.key] === undefined) continue;
        const v = def.toFm(meta[def.key], fm[def.fmKey]);
        if (v !== undefined) out[def.fmKey] = v;
    }
    return out;
}

// ── Title and CVSS (not body sections: they live in the file name and the frontmatter) ──
const FILENAME_UNSAFE_RE = /[\\/:*?"<>|]/g;
const CVSS31_RE = /^CVSS:3\.1\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]$/;
const isValidCvss31 = v => CVSS31_RE.test(v || '');
const labelOf = def => def.label || def.aliases[0];

// Same fields, in the same formats, that createVulnNote writes
function cvssFrontmatter(vector) {
    const { score, severity } = computeCVSS31(vector);
    return {
        severity,
        cvss_vector: vector,
        cvss_link: `https://www.first.org/cvss/calculator/3-1#${vector}`,
        cvss_score: parseFloat(score),
        cvss_severity: severity,
    };
}

// info: { basename, fm, md }. Local value of a key that is not a heading section
function localValue(info, def) {
    if (def.source === 'filename') return titleFromBasename(info.basename || '');
    return String(info.fm?.[def.fmKey] ?? '');
}

// ── Three-way merge ───────────────────────────────────────────────────────────
// base = the section as it was at the last successful sync (history/<finding>/base.json)
function classify(base, local, remote) {
    if (local === remote) return 'same';
    if (base === undefined) return 'unknown';
    if (local === base) return 'remote';
    if (remote === base) return 'local';
    return 'conflict';
}

const CONFLICT_MARKER_RE = /^(<<<<<<< local|=======|>>>>>>> pwndoc)$/m;
const hasConflictMarkers = text => CONFLICT_MARKER_RE.test(text);

// m[i] = index in x of the line matched to b[i] by the LCS, or -1
function align(b, x) {
    const lcs = Array.from({ length: b.length + 1 }, () => new Array(x.length + 1).fill(0));
    for (let i = b.length - 1; i >= 0; i--) {
        for (let j = x.length - 1; j >= 0; j--) {
            lcs[i][j] = b[i] === x[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
        }
    }
    const m = new Array(b.length).fill(-1);
    for (let i = 0, j = 0; i < b.length && j < x.length;) {
        if (b[i] === x[j]) { m[i++] = j++; }
        else if (lcs[i + 1][j] >= lcs[i][j + 1]) i++;
        else j++;
    }
    return m;
}

// Line-level diff3. Like git, changes on adjacent lines are a conflict.
// ponytail: line granularity, split by word if conflicts on long paragraphs become a nuisance
function merge3(base, local, remote) {
    const split = s => (s === '' ? [] : s.split('\n'));
    const b = split(base), l = split(local), r = split(remote);
    const ml = align(b, l), mr = align(b, r);
    const same = (x, y) => x.length === y.length && x.every((v, k) => v === y[k]);
    const out = [];
    let conflicts = 0;
    let pb = -1, pl = -1, pr = -1;
    const hunk = (i, li, ri) => {
        const B = b.slice(pb + 1, i), L = l.slice(pl + 1, li), R = r.slice(pr + 1, ri);
        if (same(L, B)) out.push(...R);
        else if (same(R, B) || same(L, R)) out.push(...L);
        else { conflicts++; out.push('<<<<<<< local', ...L, '=======', ...R, '>>>>>>> pwndoc'); }
    };
    for (let i = 0; i < b.length; i++) {
        if (ml[i] < 0 || mr[i] < 0) continue;
        hunk(i, ml[i], mr[i]);
        out.push(b[i]);
        pb = i; pl = ml[i]; pr = mr[i];
    }
    hunk(b.length, l.length, r.length);
    return { text: out.join('\n'), conflicts };
}

// Apply user-resolved texts: write them to PwnDoc (one PUT) and into the note. Returns the new note text.
async function applyMerged(ctx, { auditId, findingId, noteMd, merged, snapshotFinding, force }) {
    const keys = Object.keys(merged);
    let md = noteMd;
    for (const key of keys) {
        if (hasConflictMarkers(merged[key])) throw new Error(`section ${key} still has merge conflict markers`);
        // the remote side of the text carries PwnDoc image ids: bring those images into the vault first
        md = replaceSection(md, key, await pullImages(ctx, merged[key], ctx.attachmentsFolder));
    }
    await pushSections(ctx, { auditId, findingId, noteMd: md, sections: keys, snapshotFinding, force, op: 'merge', localBefore: noteMd });
    return { noteMd: md };
}

// ── Create a finding ──────────────────────────────────────────────────────────
// The finding of the audit whose title equals the note title (case and spacing ignored); null if none or ambiguous
function matchFinding(title, findings) {
    const hits = findings.filter(f => normTitle(f.title) === normTitle(title));
    return hits.length === 1 ? hits[0] : null;
}

// vuln: full library entry (GET /api/vulnerabilities/detail/:id). Uses the detail in the audit language.
function buildFindingFromLibrary(vuln, locale) {
    const d = vuln.details.find(x => x.locale === locale) || vuln.details[0];
    return {
        title: d.title,
        vulnType: d.vulnType || vuln.category,
        ...(vuln.cvssv3 ? { cvssv3: vuln.cvssv3 } : {}),
        description: d.description || '',
        observation: d.observation || '',
        remediation: d.remediation || '',
        poc: '',
        scope: '',
        references: d.references || [],
        customFields: d.customFields || [],
    };
}

function buildFindingFromNote(title, cvssVector, vulnType) {
    return {
        title, vulnType,
        ...(isValidCvss31(cvssVector) ? { cvssv3: cvssVector } : {}),
        description: '', observation: '', remediation: '', poc: '', scope: '', references: [], customFields: [],
    };
}

// PwnDoc's POST does not return the new id: it is the finding that was not in the audit before
async function createFinding(ctx, auditId, body, force) {
    const before = await ctx.api('GET', `/api/audits/${auditId}`);
    assertEditable(before, force);
    const known = new Set((before.findings || []).map(f => f._id));
    await ctx.api('POST', `/api/audits/${auditId}/findings`, { body });
    const after = await ctx.api('GET', `/api/audits/${auditId}`);
    const created = (after.findings || []).find(f => !known.has(f._id));
    if (!created) throw new Error('finding created but not found in the audit afterwards');
    return created._id;
}

// ── Review fixes: image-safe comparison, pull sanitising, strict push ─────────
const sanitizeTitle = t => String(t ?? '').replace(FILENAME_UNSAFE_RE, '-').trim();

// Push resolver: any <img> that did not come from an uploaded token is an unsupported syntax, never silently dropped
function strictImageResolver(src, alt) {
    throw new Error(`unrecognised image syntax in the section, it would not be uploaded: ${alt || src}`);
}

// A pulled heading must never become a section boundary of the note
function demoteHeadings(md) {
    return mapOutsideFences(md, t => t.replace(/^#{1,2} /gm, '### '));
}

const defaultParse = html => new DOMParser().parseFromString(html, 'text/html').body;
// PwnDoc HTML is untrusted on its way into the vault: same whitelist as the push side, images kept
function sanitizeHtml(html, parse = defaultParse) {
    return serializeWhitelist(parse(html), src => src);
}

// The same picture gets the same key on both sides: PwnDoc id, id embedded in a pulled file name,
// id of identical content already uploaded to this audit, else the path itself
async function canonicalImageKey(ctx, auditId, src) {
    if (/^[0-9a-f]{24}$/.test(src)) return src;
    const named = src.split('/').pop().match(/^([0-9a-f]{24})\.[a-z]+$/i);
    if (named) return named[1];
    const path = ctx.resolvePath(src);
    if (!path) return src;
    try {
        const hash = require('crypto').createHash('sha256').update(Buffer.from(await ctx.readBinary(path))).digest('hex');
        return ctx.imageCache[auditId]?.[hash] || src;
    } catch { return src; }
}

// normalizeCore (render + htmlToMd) drops images; park them as tokens around it and restore them as ![alt](key)
const CMP_TOKEN_RE = /⟦pwcmp:(\d+)⟧/g;
async function withImagesPreserved(md, keyOf, normalizeCore) {
    const refs = extractImageRefs(md);
    const keys = [];
    for (const r of refs) keys.push(await keyOf(r.src));
    let i = 0;
    const parked = replaceImageRefs(md, () => `⟦pwcmp:${i++}⟧`);
    return (await normalizeCore(parked)).replace(CMP_TOKEN_RE, (_, n) => `![${refs[n].alt}](${keys[n]})`);
}

// Explicit ids win over the metadata cache, which lags behind a frontmatter write
function resolveFindingLink(notePath, fm, folderAudits, override = {}) {
    const findingId = override.findingId ?? fm?.pwndoc_finding_id;
    const auditId = override.auditId ?? resolveAuditId(notePath, fm, folderAudits);
    return auditId && findingId ? { auditId, findingId } : null;
}

// ── Engagement attribute on notes, status and quick actions ───────────────────
// Nearest associated folder of a note: { auditId, name, folder } or null
function folderAuditFor(notePath, folderAudits) {
    for (let dir = parentDir(notePath); ; dir = parentDir(dir)) {
        if (folderAudits[dir]) return { ...folderAudits[dir], folder: dir };
        if (!dir) return null;
    }
}

// Notes whose engagement comes from `folder`, not from a more specific subfolder
const notesOwnedBy = (paths, folderAudits, folder) =>
    paths.filter(p => folderAuditFor(p, folderAudits)?.folder === folder);

// A note linked to a finding of another audit keeps its audit: moving it would orphan the link
const linkedElsewhere = (fm, entry) => !!(fm?.pwndoc_finding_id && fm?.pwndoc_audit_id && fm.pwndoc_audit_id !== entry.auditId);
const shouldStamp = (fm, entry) =>
    !linkedElsewhere(fm, entry) && !(fm?.pwndoc_audit_id === entry.auditId && fm?.pwndoc_audit === entry.name);

function engagementStatus(fm, entry) {
    const name = fm?.pwndoc_audit || entry?.name
        || (fm?.pwndoc_audit_id ? `audit ${String(fm.pwndoc_audit_id).slice(0, 6)}…` : '');
    if (!name) return { text: '', linked: false };
    const linked = !!fm?.pwndoc_finding_id;
    return { text: `PwnDoc: ${name}${linked ? '' : ' · no finding'}`, linked };
}

// ── Side-by-side view and import of findings that exist only on PwnDoc ────────
// diff = lineDiff(pwndocText, noteText). Rows for two aligned columns: left PwnDoc, right note, null = no counterpart
function sideBySide(diff) {
    const rows = [];
    let dels = [], adds = [];
    const flush = () => {
        for (let i = 0; i < Math.max(dels.length, adds.length); i++) {
            const left = dels[i] ?? null, right = adds[i] ?? null;
            rows.push({ left, right, kind: left !== null && right !== null ? 'mod' : left !== null ? 'del' : 'add' });
        }
        dels = []; adds = [];
    };
    for (const d of diff) {
        if (d.op === 'eq') { flush(); rows.push({ left: d.line, right: d.line, kind: 'eq' }); }
        else if (d.op === 'del') dels.push(d.line);
        else adds.push(d.line);
    }
    flush();
    return rows;
}

// Findings of the audit that no note points to yet, in audit order
const missingFindings = (audit, linkedFindingIds) => (audit.findings || []).filter(f => !linkedFindingIds.has(f._id));

// What createVulnNote needs for a note born from a finding; the body sections are pulled right after
const findingToNoteRow = (finding, audit) => ({
    id: '', title: finding.title, category: finding.vulnType, cvssv3: finding.cvssv3 || '', locale: audit.language,
    description: '', observation: '', remediation: '', references: '',
});

const IMPORT_SECTIONS = ['description', 'observation', 'poc', 'scope', 'remediation', 'references'];

// ── Lint before a push, figures ───────────────────────────────────────────────
const CAPTION_RE = /^\*(Figura|Figure)\s+(\d+)\s*([–—-])\s*(.+?)\*\s*$/;
const captionWord = locale => (/^IT/i.test(locale || '') ? 'Figura' : /^EN/i.test(locale || '') ? 'Figure' : null);
const figureCaption = (locale, n, text) => `*${captionWord(locale) || 'Figure'} ${n} – ${text}*`;
const nextFigureNumber = md => Math.max(0, ...md.split('\n').map(l => +(l.match(CAPTION_RE)?.[2] ?? 0))) + 1;

// Every line with whether it is inside a code fence (the fence lines themselves count as fenced)
function linesWithFence(text) {
    let fence = null;
    return text.split('\n').map(line => {
        const f = line.match(/^\s*(```+|~~~+)/);
        if (f) { fence = !fence ? f[1][0] : f[1][0] === fence ? null : fence; return { line, fenced: true }; }
        return { line, fenced: !!fence };
    });
}

const fenceOpen = text => {
    let fence = null;
    for (const line of text.split('\n')) {
        const f = line.match(/^\s*(```+|~~~+)/);
        if (f) fence = !fence ? f[1][0] : f[1][0] === fence ? null : fence;
    }
    return !!fence;
};

// Problems that make a push wrong ('error', the push is blocked) or sloppy ('warn', the user may go on).
// opts: { sections: keys about to be pushed, fm, basename, locale, exists(src) -> bool }
function lintNote(md, { sections, fm = {}, basename = '', locale = '', exists = () => true }) {
    const issues = [];
    const add = (level, section, message) => issues.push({ level, section, message });
    const secs = parseSections(md);
    const word = captionWord(locale);

    // caption numbering runs through the whole note, in document order, whatever is being pushed
    const captions = Object.entries(secs).sort((a, b) => a[1].start - b[1].start)
        .flatMap(([key, s]) => linesWithFence(s.text).filter(l => !l.fenced).map(l => ({ key, m: l.line.match(CAPTION_RE) })).filter(c => c.m));
    captions.forEach(({ key, m }, i) => {
        if (!sections.includes(key)) return;
        if (+m[2] !== i + 1) add('warn', key, `figure numbering: expected ${i + 1}, found ${m[2]}`);
        if (word && m[1] !== word) add('warn', key, `"${m[1]}" in an ${locale} note, expected "${word}"`);
        if (m[3] !== '–') add('warn', key, `caption "${m[0].slice(0, 30)}": use an en dash (–) after the number`);
    });

    for (const key of sections) {
        const def = defOf(key);
        if (def.source) {
            if (key === 'title' && !titleFromBasename(basename).trim()) add('error', key, 'title is empty');
            if (key === 'cvssv3') { const v = String(fm[def.fmKey] ?? ''); if (v && !isValidCvss31(v)) add('error', key, `invalid CVSS vector: ${v}`); }
            if (def.toRemote) { const raw = fm[def.fmKey]; if (def.toRemote(def.cmpLocal(raw ?? '')) === undefined && def.cmpLocal(raw ?? '') !== '') add('error', key, `invalid ${labelOf(def)}: ${raw}`); }
            continue;
        }
        const text = secs[key]?.text || '';
        if (text === '') add('warn', key, 'section is empty');
        if (hasConflictMarkers(text)) add('error', key, 'unresolved merge conflict markers');
        if (fenceOpen(text)) add('error', key, 'unclosed code fence');
        if (def.kind !== 'html') continue;
        const lines = linesWithFence(text);
        lines.forEach(({ line, fenced }, i) => {
            if (fenced) return;
            for (const r of extractImageRefs(line)) {
                if (r.remote) { add('error', key, `remote image not supported: ${r.src}`); }
                else if (!exists(r.src)) add('error', key, `missing image: ${r.src}`);
                const next = lines.slice(i + 1).find(l => l.line.trim() !== '')?.line;
                if (!CAPTION_RE.test(next || '')) add('warn', key, `image without caption: ${r.src}`);
            }
        });
    }
    return issues;
}

// ── Dashboard, remote changes, orphans ────────────────────────────────────────
const STATE_RANK = { same: 0, unknown: 1, remote: 2, local: 3, conflict: 4 };
const overallState = rows => rows.reduce((s, r) => (STATE_RANK[r.status] > STATE_RANK[s] ? r.status : s), 'same');

// The rows worth looking at: the default sections always, the others once they have content or a synced base
const watchedRows = rows => rows.filter(r => DEFAULT_SYNC_SECTIONS.includes(r.key) || r.base !== undefined || !r.localEmpty);
const remoteChanges = rows => watchedRows(rows).filter(r => r.status === 'remote' || r.status === 'conflict').map(r => r.key);

const orphanReason = (fm, audit) => !fm?.pwndoc_finding_id ? ''
    : !audit ? 'engagement not found on PwnDoc'
    : (audit.findings || []).some(f => f._id === fm.pwndoc_finding_id) ? '' : 'finding not found in the engagement';

// notes: [{ path, basename, fm, md }] of this engagement. One row per linked note, plus what does not pair up.
async function buildDashboard(ctxFor, { audit, notes, linkedIds, loadBase }) {
    const out = { rows: [], orphans: [], unlinked: [], missing: missingFindings(audit, linkedIds) };
    const keys = SECTION_DEFS.map(d => d.key);
    for (const n of notes) {
        const findingId = n.fm?.pwndoc_finding_id;
        if (!findingId) { out.unlinked.push(n); continue; }
        const finding = audit.findings?.find(f => f._id === findingId);
        if (!finding) { out.orphans.push({ path: n.path, findingId, reason: orphanReason(n.fm, audit) }); continue; }
        const ctx = typeof ctxFor === 'function' ? ctxFor(n, findingId) : ctxFor; // image paths resolve per note
        const rows = watchedRows(await buildComparison(ctx, n.md, finding, keys, { basename: n.basename, fm: n.fm }, await loadBase(findingId)));
        out.rows.push({
            path: n.path, findingId, title: finding.title, completed: finding.status === STATUS_DONE,
            state: overallState(rows), changed: rows.filter(r => r.changed).map(r => r.key),
            sections: Object.fromEntries(rows.map(r => [r.key, { status: r.status, localEmpty: r.localEmpty, remoteEmpty: r.remoteEmpty }])),
        });
    }
    return out;
}

// What a bulk push or pull may do for one dashboard row: never overwrite a side that changed on its own
function bulkPlan(row, direction, keys) {
    const run = [], blocked = [];
    for (const key of keys) {
        const i = row.sections?.[key];
        if (!i || i.status === 'same') continue;
        // without a base "differs" may well be PwnDoc's own work: a push only fills what PwnDoc has not got, a pull only what the note has not got
        const ok = direction === 'push' ? i.status === 'local' || (i.status === 'unknown' && !i.localEmpty && i.remoteEmpty)
            : i.status === 'remote' || (i.status === 'unknown' && i.localEmpty);
        if (ok) run.push(key);
        else blocked.push({ key, why: i.status === 'unknown'
            ? (direction === 'push' ? (i.localEmpty ? 'note empty' : 'differs from PwnDoc, no sync base: use Compare') : 'note has content, no sync base')
            : i.status });
    }
    return { run, blocked };
}

// ── Dashboard view: order, filter, preview of a bulk action ───────────────────
const sortDashboardRows = rows => [...rows].sort((a, b) => STATE_RANK[b.state] - STATE_RANK[a.state] || a.title.localeCompare(b.title));
const dashboardCounts = rows => rows.reduce((c, r) => ({ ...c, [r.state]: (c[r.state] || 0) + 1 }), {});
const filterDashboardRows = (rows, { state = '', query = '' }) =>
    rows.filter(r => (!state || r.state === state) && r.title.toLowerCase().includes(query.toLowerCase()));

// What a bulk push or pull of `keys` over `rows` would do: notes written, sections written, sections skipped
function bulkSummary(rows, direction, keys) {
    const out = { notes: 0, sections: 0, skipped: 0 };
    for (const r of rows) {
        const p = bulkPlan(r, direction, keys);
        if (p.run.length) { out.notes++; out.sections += p.run.length; }
        out.skipped += p.blocked.length;
    }
    return out;
}

// ── Report template of the engagement and report generation ───────────────────
const templateIdOf = audit => audit.template?._id ?? audit.template ?? null;

function templateLabel(audit, templates) {
    const id = templateIdOf(audit);
    if (!id) return 'no template';
    const t = templates.find(x => x._id === id);
    return t ? `${t.name} (${t.ext})` : 'unknown template';
}

// The report template lives on the audit: choosing one is a write to the audit (state guard applies)
async function setAuditTemplate(ctx, { auditId, templateId, force }) {
    const audit = await ctx.api('GET', `/api/audits/${auditId}`);
    const previous = templateIdOf(audit);
    if (previous === templateId) return { changed: false, previous };
    assertEditable(audit, force);
    await ctx.api('PUT', `/api/audits/${auditId}/general`, { body: { template: templateId } });
    return { changed: true, previous };
}

// ── General information of the engagement: what the export needs ──────────────
const GENERAL_FIELDS = {
    name: 'Name', auditType: 'Audit type', language: 'Language', template: 'Template', company: 'Company', client: 'Client',
    date: 'Report date', date_start: 'Start date', date_end: 'End date', location: 'Location', scope: 'Scope',
};
const DEFAULT_GENERAL_REQUIRED = ['name', 'auditType', 'language', 'template', 'company', 'client', 'date_start', 'date_end'];

// Blank = nothing a template could print: empty text, empty list, or an object (company, client, template) with no value in it
const isBlankValue = v => v == null || (typeof v === 'string' ? v.trim() === '' : Array.isArray(v) ? v.length === 0
    : typeof v === 'object' ? Object.values(v).every(isBlankValue) : false);

// [{ key, label }] of the mandatory General Information fields the audit leaves blank, then the required custom fields
// of the general section. required: keys of GENERAL_FIELDS; cfDefs: GET /api/data/custom-fields
function missingGeneralFields(audit, required, cfDefs = []) {
    const out = required.filter(k => isBlankValue(audit[k])).map(k => ({ key: k, label: GENERAL_FIELDS[k] || k }));
    for (const d of cfDefs.filter(x => x.required && x.display === 'general')) {
        const entry = (audit.customFields || []).find(c => (c.customField?._id ?? c.customField) === d._id);
        if (isBlankValue(entry?.text)) out.push({ key: `cf:${d._id}`, label: d.label || d._id });
    }
    return out;
}

const reportFailureLines = (error, auditName, missing) => [`The export of "${auditName}" failed: ${error.message}`,
    ...(missing.length ? ['Missing in General Information:', ...missing.map(m => `- ${m.label}`), 'Fill them in on PwnDoc (Audit, General) and generate the report again.']
        : ['The General Information looks complete: check the placeholders of the template and the PwnDoc server log.'])];

// PwnDoc renders the report with the template stored on the audit, so that is the one used here
async function generateReport(ctx, { auditId }) {
    const audit = await ctx.api('GET', `/api/audits/${auditId}`);
    const templates = (await ctx.api('GET', '/api/templates')) || [];
    const id = templateIdOf(audit);
    if (!id) throw new Error('the engagement has no report template: set one first');
    const buf = await ctx.api('GET', `/api/audits/${auditId}/generate`, { rawResponse: true });
    return { buf, ext: templates.find(t => t._id === id)?.ext || 'docx', auditName: audit.name, templateName: templateLabel(audit, templates) };
}

const reportFileName = (auditName, ext, date = new Date()) => `${sanitizeTitle(auditName)} - ${date.toISOString().slice(0, 10)}.${ext}`;
const pastedImageName = (basename, date = new Date()) => `${basename.replace(/[()\[\]#%]/g, '-')} ${date.toISOString().replace(/\D/g, '').slice(0, 14)}.png`;

// ── Read file (absolute path or vault-relative) ───────────────────────────────
async function readFilePath(app, filePath) {
    if (/^([A-Za-z]:[\\/]|\/)/.test(filePath)) {
        return require('fs').readFileSync(filePath, 'utf8');
    }
    return await app.vault.adapter.read(normalizePath(filePath));
}

// ── PwnDoc API client ─────────────────────────────────────────────────────────
const PRIORITY_MAP_API = { 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical' };

function httpRequest(urlStr, { method = 'GET', headers = {}, body = null, ignoreSsl = false, raw = false } = {}) {
    return new Promise((resolve, reject) => {
        const url = new URL(urlStr);
        const isHttps = url.protocol === 'https:';
        const lib = require(isHttps ? 'https' : 'http');
        const options = {
            hostname: url.hostname,
            port: url.port || (isHttps ? 443 : 80),
            path: url.pathname + url.search,
            method,
            headers,
        };
        if (isHttps) options.rejectUnauthorized = !ignoreSsl;
        const req = lib.request(options, res => {
            const chunks = [];
            res.on('data', chunk => chunks.push(chunk));
            res.on('end', () => {
                const buf = Buffer.concat(chunks);
                if (res.statusCode >= 200 && res.statusCode < 300) resolve(raw ? buf : buf.toString('utf8'));
                else reject(new Error(`HTTP ${res.statusCode}: ${buf.toString('utf8').slice(0, 200)}`));
            });
        });
        req.setTimeout(60000, () => req.destroy(new Error('request timed out')));
        req.on('error', reject);
        if (body) req.write(body);
        req.end();
    });
}

// Generic authenticated call. Returns `datas` of the JSON envelope (or the raw Buffer with rawResponse).
async function pwndocApi(baseUrl, token, method, path, { body, ignoreSsl = false, rawResponse = false } = {}) {
    const headers = { 'Cookie': `token= JWT ${token}` };
    let payload = null;
    if (body !== undefined) {
        payload = JSON.stringify(body);
        headers['Content-Type'] = 'application/json';
        headers['Content-Length'] = Buffer.byteLength(payload);
    }
    const res = await httpRequest(new URL(path, baseUrl).toString(), { method, headers, body: payload, ignoreSsl, raw: rawResponse });
    return rawResponse ? res : JSON.parse(res)?.datas;
}

async function pwndocLogin(baseUrl, username, password, ignoreSsl) {
    const url = new URL('/api/users/token', baseUrl).toString();
    const body = JSON.stringify({ username, password, totpToken: '' });
    const raw = await httpRequest(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
        body,
        ignoreSsl,
    });
    const data = JSON.parse(raw);
    const token = data?.datas?.token;
    if (!token) throw new Error('Login failed: no token in response');
    return token;
}

async function pwndocFetchVulns(baseUrl, token, ignoreSsl) {
    return (await pwndocApi(baseUrl, token, 'GET', '/api/vulnerabilities', { ignoreSsl })) || [];
}

async function pwndocFetchVulnDetail(baseUrl, token, id, ignoreSsl) {
    return (await pwndocApi(baseUrl, token, 'GET', `/api/vulnerabilities/detail/${id}`, { ignoreSsl })) || null;
}

// Fetch full detail for every vuln in the list, N at a time
async function pwndocFetchAllDetails(baseUrl, token, ignoreSsl, list, dbg, onProgress) {
    const CONCURRENCY = 5;
    const details = [];
    for (let i = 0; i < list.length; i += CONCURRENCY) {
        const batch = list.slice(i, i + CONCURRENCY);
        const results = await Promise.all(batch.map(v =>
            pwndocFetchVulnDetail(baseUrl, token, v._id, ignoreSsl)
                .catch(e => { dbg(`detail fetch failed for ${v._id}:`, e.message); return null; })
        ));
        details.push(...results.filter(Boolean));
        if (onProgress) onProgress(Math.min(i + CONCURRENCY, list.length), list.length);
    }
    return details;
}

async function pwndocFetchCustomFields(baseUrl, token, ignoreSsl, dbg) {
    dbg('pwndocFetchCustomFields: GET /api/data/custom-fields');
    const datas = await pwndocApi(baseUrl, token, 'GET', '/api/data/custom-fields', { ignoreSsl });
    dbg('pwndocFetchCustomFields: raw datas', datas);
    const map = {};
    for (const cf of (datas || [])) {
        if (cf._id) {
            map[cf._id] = cf.label || cf._id;
            dbg(`  mapped ${cf._id} → "${map[cf._id]}" (label="${cf.label}")`);
        }
    }
    dbg('pwndocFetchCustomFields: final map', map);
    return map;
}

const STANDARD_FIELDS = new Set(['id', 'cvssv3', 'priority', 'category', 'locale', 'title', 'description', 'observation', 'remediation', 'references']);

function flattenVulnsFromApi(vulns, cfLabels = {}) {
    const rows = [];
    for (const vuln of vulns) {
        for (const detail of (vuln.details || [])) {
            const refs = detail.references || [];
            const references = Array.isArray(refs) ? refs.join('; ') : String(refs);
            const row = {
                id:          vuln._id        || '',
                cvssv3:      vuln.cvssv3     || '',
                priority:    PRIORITY_MAP_API[vuln.priority] || String(vuln.priority || ''),
                category:    vuln.category   || '',
                locale:      detail.locale   || '',
                title:       detail.title    || '',
                description: detail.description || '',
                observation: detail.observation || '',
                remediation: detail.remediation || '',
                references,
            };
            for (const cf of (detail.customFields || [])) {
                if (cf.customField) {
                    const key = cfLabels[cf.customField] || `cf_${cf.customField}`;
                    let val = cf.text || '';
                    if (Array.isArray(val)) val = val.join('; ');
                    row[key] = val;
                }
            }
            rows.push(row);
        }
    }
    return rows;
}

// ── API password in Obsidian secretStorage ────────────────────────────────────
const SECRET_ID = 'pwndoc-importer-api-password';

// Move a legacy plaintext password out of settings into secretStorage
function migratePassword(settings, secretStorage) {
    const { apiPassword, ...rest } = settings;
    if (apiPassword) secretStorage.setSecret(rest.apiPasswordSecret || SECRET_ID, apiPassword);
    return rest;
}

function getApiPassword(app, settings) {
    return app.secretStorage.getSecret(settings.apiPasswordSecret || SECRET_ID) ?? '';
}

// ── Settings ──────────────────────────────────────────────────────────────────
const DEFAULT_SETTINGS = {
    csvPath:         '',
    locale:          'EN-en',
    quickImportSource: 'csv', // 'csv' | 'api'
    quickImportLocale: '',    // '' = all locales
    owaspFieldId:    'cf_62d92f1597c7c5001833273f',
    cweFieldId:      'cf_63ab317fafe66f0011b89881',
    apiUrl:          '',
    apiUsername:     '',
    apiPasswordSecret: SECRET_ID,
    apiIgnoreSsl:    false,
    csvOutputFolder: '',
    debugMode:       false,
    templates:       [], // [{ label: string, path: string, position: 'top'|'bottom' }]
    folderAudits:    {}, // { [vault folder path]: { auditId, name } }
    historyLimit:    50, // history entries kept per finding
    imageCache:      {}, // { [auditId]: { [sha256]: pwndoc image id } }
    attachmentsFolder: 'attachments', // where pulled images are saved (vault path)
    watchRemote:     true,  // warn when PwnDoc changed a synced section of the open note
    watchIntervalMin: 5,    // 0 = only when a note is opened
    reportsFolder:   'reports', // where generated reports are saved (vault path)
    generalRequired: DEFAULT_GENERAL_REQUIRED.join(','), // General Information fields checked when an export fails
};

// ── Modal: fuzzy search over vuln list ────────────────────────────────────────
class VulnSearchModal extends FuzzySuggestModal {
    constructor(app, vulns, onChoose) {
        super(app);
        this.vulns = vulns;
        this.onChoose = onChoose;
        this.setPlaceholder('Type to search vulnerability name...');
    }
    getItems() { return this.vulns; }
    getItemText(item) { return `${item.title || item.id || 'Unknown'} ${item.locale || ''}`; }
    renderSuggestion(item, el) {
        const v = item.item;
        el.createEl('div', { text: v.title || 'Unknown', cls: 'pwndoc-title' });
        el.createEl('small', {
            text: [v.locale, v.category, v.priority].filter(Boolean).join(' · '),
            cls: 'pwndoc-meta',
        });
    }
    onChooseItem(item) { this.onChoose(item); }
}

// ── Modal: choose import source (ribbon entry point) ─────────────────────────
class ImportSourceModal extends SuggestModal {
    constructor(app, onChoose) {
        super(app);
        this.onChoose = onChoose;
        this.setPlaceholder('Select vulnerability source...');
    }
    getSuggestions(query) {
        const options = [
            { label: 'CSV  — local file',        value: 'csv' },
            { label: 'API  — live PwnDoc server', value: 'api' },
        ];
        return options.filter(o => o.label.toLowerCase().includes(query.toLowerCase()));
    }
    renderSuggestion(item, el) {
        el.createEl('div', { text: item.label });
    }
    onChooseSuggestion(item) { this.onChoose(item.value); }
}

// ── Modal: choose locale/language before the vuln search ─────────────────────
class LocaleModal extends SuggestModal {
    constructor(app, locales, preferred, onChoose) {
        super(app);
        // locales: array of distinct locale strings present in the data
        this.locales = locales;
        this.onChoose = onChoose; // (locale | '') => void   '' means all locales
        this.setPlaceholder('Select language / locale...');
        // Put the preferred (settings) locale first if present
        if (preferred && locales.includes(preferred)) {
            this.locales = [preferred, ...locales.filter(l => l !== preferred)];
        }
    }
    getSuggestions(query) {
        const q = query.toLowerCase();
        const opts = [
            ...this.locales.map(l => ({ label: l, value: l })),
            { label: 'All locales', value: '' },
        ];
        return opts.filter(o => o.label.toLowerCase().includes(q));
    }
    renderSuggestion(item, el) { el.createEl('div', { text: item.label }); }
    onChooseSuggestion(item) { this.onChoose(item.value); }
}

// ── Modal: choose VT or M prefix ─────────────────────────────────────────────
class PrefixModal extends SuggestModal {
    constructor(app, onChoose) {
        super(app);
        this.onChoose = onChoose;
        this.setPlaceholder('Select note type...');
    }
    getSuggestions(query) {
        const options = [
            { label: 'VT — Vulnerability Ticket', value: 'VT' },
            { label: 'M  — Mobile',               value: 'M'  },
        ];
        return options.filter(o => o.label.toLowerCase().includes(query.toLowerCase()));
    }
    renderSuggestion(item, el) {
        el.createEl('div', { text: item.label });
    }
    onChooseSuggestion(item) { this.onChoose(item.value); }
}

// ── Modal: choose target folder (fuzzy over vault dirs) ──────────────────────
class FolderModal extends FuzzySuggestModal {
    constructor(app, currentFolder, onChoose) {
        super(app);
        this.currentFolder = currentFolder;
        this.onChoose = onChoose;
        this.setPlaceholder('Search vault folder...');
    }

    getItems() {
        const paths = [];
        const walk = (folder) => {
            paths.push(folder.path === '/' ? '' : folder.path);
            for (const child of folder.children) {
                if (child.children !== undefined) walk(child);
            }
        };
        walk(this.app.vault.getRoot());
        paths.sort((a, b) => a.localeCompare(b));
        if (this.currentFolder !== undefined && paths.includes(this.currentFolder)) {
            return [this.currentFolder, ...paths.filter(f => f !== this.currentFolder)];
        }
        return paths;
    }

    getItemText(item) { return item || '/ (vault root)'; }

    renderSuggestion(item, el) {
        const folder = item.item;
        const label = folder || '/ (vault root)';
        el.createEl('div', { text: label });
        if (folder === this.currentFolder) {
            el.createEl('small', { text: 'current', cls: 'pwndoc-meta' });
        }
    }

    onChooseItem(item) { this.onChoose(item); }
}

// ── CSV serialiser ────────────────────────────────────────────────────────────
function rowsToCsv(rows) {
    if (!rows.length) return '';
    const seen = {};
    for (const row of rows) for (const k of Object.keys(row)) seen[k] = true;
    const headers = Object.keys(seen);
    const esc = v => {
        const s = String(v ?? '');
        return (s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r'))
            ? '"' + s.replace(/"/g, '""') + '"'
            : s;
    };
    const lines = [headers.map(esc).join(',')];
    for (const row of rows) lines.push(headers.map(h => esc(row[h] ?? '')).join(','));
    return lines.join('\r\n');
}

// ── Modal: PwnDoc API credentials ────────────────────────────────────────────
class ApiCredentialsModal extends Modal {
    constructor(app, settings, onConnect, onDismiss) {
        super(app);
        this.settings  = settings;
        this.onConnect = onConnect; // ({url, username, password, ignoreSsl, save}) => void
        this.onDismiss = onDismiss; // () => void, when closed without connecting
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.createEl('h3', { text: 'Connect to PwnDoc' });

        const mkRow = (label, inputFn) => {
            const wrap = contentEl.createEl('div');
            wrap.style.cssText = 'display:flex;flex-direction:column;margin-bottom:10px;';
            wrap.createEl('label', { text: label }).style.cssText = 'font-size:0.85em;margin-bottom:3px;';
            return inputFn(wrap);
        };

        const mkCheck = (labelText, checked) => {
            const wrap = contentEl.createEl('div');
            wrap.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:10px;';
            const el = wrap.createEl('input', { type: 'checkbox' });
            el.checked = checked;
            wrap.createEl('span', { text: labelText }).style.cssText = 'font-size:0.85em;';
            return el;
        };

        const s = this.settings;

        const urlInput  = mkRow('URL (e.g. https://localhost:8443)', wrap => {
            const el = wrap.createEl('input', { type: 'text' });
            el.placeholder = 'https://localhost:8443';
            el.value = s.apiUrl || '';
            el.style.cssText = 'width:100%;';
            return el;
        });

        const userInput = mkRow('Username', wrap => {
            const el = wrap.createEl('input', { type: 'text' });
            el.value = s.apiUsername || '';
            el.style.cssText = 'width:100%;';
            return el;
        });

        const passInput = mkRow('Password', wrap => {
            const el = wrap.createEl('input', { type: 'password' });
            el.value = getApiPassword(this.app, s);
            el.style.cssText = 'width:100%;';
            return el;
        });

        const sslCheck  = mkCheck('Ignore SSL certificate errors (self-signed certs)', s.apiIgnoreSsl || false);
        const saveCheck = mkCheck('Save credentials in plugin settings', false);

        const btn = contentEl.createEl('button', { text: 'Connect', cls: 'mod-cta' });
        btn.style.cssText = 'width:100%;margin-top:4px;';
        const doConnect = () => {
            const url      = urlInput.value.trim();
            const username = userInput.value.trim();
            const password = passInput.value;
            if (!url)      { new Notice('Please enter the PwnDoc URL.');  return; }
            if (!username) { new Notice('Please enter your username.');    return; }
            if (!password) { new Notice('Please enter your password.');    return; }
            this.done = true;
            this.close();
            this.onConnect({ url, username, password, ignoreSsl: sslCheck.checked, save: saveCheck.checked });
        };
        btn.onclick = doConnect;
        passInput.addEventListener('keydown', e => { if (e.key === 'Enter') doConnect(); });
        urlInput.focus();
    }

    onClose() { this.contentEl.empty(); if (!this.done) this.onDismiss?.(); }
}

// ── Modal: choose where to save the fetched CSV ───────────────────────────────
class CsvOutputModal extends Modal {
    constructor(app, defaultFolder, onChoose) {
        super(app);
        this.defaultFolder = defaultFolder;
        this.onChoose = onChoose; // (absolutePath | null) => void
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.createEl('h3', { text: 'Save fetched vulnerabilities as CSV?' });
        contentEl.createEl('p', {
            text: 'Enter an absolute folder path. The file will be saved as vulnerabilities.csv inside it.',
            cls: 'setting-item-description',
        });

        const input = contentEl.createEl('input', { type: 'text' });
        input.placeholder = 'C:/tools/pwndoc  or  /home/user/pwndoc';
        input.value = this.defaultFolder || '';
        input.style.cssText = 'width:100%;margin-bottom:10px;';

        const saveBtn = contentEl.createEl('button', { text: 'Save & Import', cls: 'mod-cta' });
        saveBtn.style.cssText = 'width:100%;margin-bottom:6px;';
        saveBtn.onclick = () => {
            const folder = input.value.trim();
            if (!folder) { new Notice('Please enter a folder path.'); return; }
            this.close();
            const sep = folder.includes('\\') ? '\\' : '/';
            this.onChoose(folder.replace(/[\\/]+$/, '') + sep + 'vulnerabilities.csv');
        };

        const skipBtn = contentEl.createEl('button', { text: 'Skip (import without saving)' });
        skipBtn.style.cssText = 'width:100%;';
        skipBtn.onclick = () => { this.close(); this.onChoose(null); };

        input.addEventListener('keydown', e => { if (e.key === 'Enter') saveBtn.click(); });
        input.focus();
    }

    onClose() { this.contentEl.empty(); }
}

// ── Modal: vault file picker for templates ────────────────────────────────────
class VaultFileSuggestModal extends FuzzySuggestModal {
    constructor(app, onChoose) {
        super(app);
        this.onChoose = onChoose;
        this.setPlaceholder('Type to search vault files...');
    }
    getItems() {
        return this.app.vault.getMarkdownFiles().sort((a, b) => a.path.localeCompare(b.path));
    }
    getItemText(file) { return file.path; }
    renderSuggestion(item, el) {
        el.createEl('div', { text: item.item.basename });
        el.createEl('small', { text: item.item.parent?.path || '/', cls: 'pwndoc-meta' });
    }
    onChooseItem(file) { this.onChoose(file.path.replace(/\.md$/, '')); }
}

// ── Settings tab ──────────────────────────────────────────────────────────────
class PwnDocSettingTab extends PluginSettingTab {
    constructor(app, plugin) {
        super(app, plugin);
        this.plugin = plugin;
    }

    display() {
        const { containerEl } = this;
        containerEl.empty();
        containerEl.createEl('h2', { text: 'PwnDoc 2Sync' });

        new Setting(containerEl)
            .setName('CSV file path')
            .setDesc('Absolute path or vault-relative path to vulnerabilities.csv')
            .addText(t => t
                .setPlaceholder('C:/tools/pwndoc-api/vulnerabilities.csv')
                .setValue(this.plugin.settings.csvPath)
                .onChange(async v => { this.plugin.settings.csvPath = v.trim(); await this.plugin.saveSettings(); }));

        new Setting(containerEl)
            .setName('Default locale')
            .setDesc('Locale pre-selected in the language picker shown before the vuln search')
            .addDropdown(d => d
                .addOption('EN-en', 'EN-en (English)')
                .addOption('IT-it', 'IT-it (Italian)')
                .addOption('', 'All locales')
                .setValue(this.plugin.settings.locale)
                .onChange(async v => { this.plugin.settings.locale = v; await this.plugin.saveSettings(); }));

        containerEl.createEl('h3', { text: 'Quick import' });
        containerEl.createEl('p', {
            text: 'Options for the "Quick import vulnerability" command (assign it a hotkey in Settings → Hotkeys). Skips the source and language pickers by using the defaults below.',
            cls: 'setting-item-description',
        });

        new Setting(containerEl)
            .setName('Default source')
            .setDesc('Where the quick import fetches vulnerabilities from')
            .addDropdown(d => d
                .addOption('csv', 'CSV — local file')
                .addOption('api', 'API — live PwnDoc server')
                .setValue(this.plugin.settings.quickImportSource)
                .onChange(async v => { this.plugin.settings.quickImportSource = v; await this.plugin.saveSettings(); }));

        new Setting(containerEl)
            .setName('Default language')
            .setDesc('Locale filter applied before opening the vuln list in the quick import')
            .addDropdown(d => d
                .addOption('EN-en', 'EN-en (English)')
                .addOption('IT-it', 'IT-it (Italian)')
                .addOption('', 'All locales')
                .setValue(this.plugin.settings.quickImportLocale)
                .onChange(async v => { this.plugin.settings.quickImportLocale = v; await this.plugin.saveSettings(); }));

        containerEl.createEl('h3', { text: 'Custom field IDs' });
        containerEl.createEl('p', {
            text: 'cf_<objectId> column names in the CSV for OWASP and CWE values.',
            cls: 'setting-item-description',
        });

        new Setting(containerEl)
            .setName('OWASP field column')
            .addText(t => t
                .setValue(this.plugin.settings.owaspFieldId)
                .onChange(async v => { this.plugin.settings.owaspFieldId = v.trim(); await this.plugin.saveSettings(); }));

        new Setting(containerEl)
            .setName('CWE field column')
            .addText(t => t
                .setValue(this.plugin.settings.cweFieldId)
                .onChange(async v => { this.plugin.settings.cweFieldId = v.trim(); await this.plugin.saveSettings(); }));

        containerEl.createEl('h3', { text: 'API credentials' });
        containerEl.createEl('p', {
            text: 'Credentials are stored in plain text in the plugin data file. Leave blank to be prompted each time.',
            cls: 'setting-item-description',
        });

        new Setting(containerEl)
            .setName('PwnDoc URL')
            .addText(t => t
                .setPlaceholder('https://localhost:8443')
                .setValue(this.plugin.settings.apiUrl)
                .onChange(async v => { this.plugin.settings.apiUrl = v.trim(); await this.plugin.saveSettings(); }));

        new Setting(containerEl)
            .setName('Username')
            .addText(t => t
                .setValue(this.plugin.settings.apiUsername)
                .onChange(async v => { this.plugin.settings.apiUsername = v.trim(); await this.plugin.saveSettings(); }));

        new Setting(containerEl)
            .setName('Password')
            .setDesc('Stored in Obsidian secret storage, not in the plugin data file.')
            .addComponent(el => new SecretComponent(this.app, el)
                .setValue(this.plugin.settings.apiPasswordSecret)
                .onChange(async v => { this.plugin.settings.apiPasswordSecret = v; await this.plugin.saveSettings(); }));

        new Setting(containerEl)
            .setName('Ignore SSL certificate errors')
            .setDesc('Enable for self-signed certificates')
            .addToggle(tg => tg
                .setValue(this.plugin.settings.apiIgnoreSsl)
                .onChange(async v => { this.plugin.settings.apiIgnoreSsl = v; await this.plugin.saveSettings(); }));

        containerEl.createEl('h3', { text: 'CSV output' });

        new Setting(containerEl)
            .setName('Default CSV output folder')
            .setDesc('Absolute path to the folder where vulnerabilities.csv will be saved after an API fetch. Leave blank to be prompted each time.')
            .addText(t => t
                .setPlaceholder('C:/tools/pwndoc')
                .setValue(this.plugin.settings.csvOutputFolder)
                .onChange(async v => { this.plugin.settings.csvOutputFolder = v.trim(); await this.plugin.saveSettings(); }));

        containerEl.createEl('h3', { text: 'Engagement sync' });

        new Setting(containerEl)
            .setName('Attachments folder')
            .setDesc('Vault folder where images pulled from PwnDoc are saved')
            .addText(t => t
                .setPlaceholder('attachments')
                .setValue(this.plugin.settings.attachmentsFolder)
                .onChange(async v => { this.plugin.settings.attachmentsFolder = v.trim().replace(/\/+$/, ''); await this.plugin.saveSettings(); }));

        new Setting(containerEl)
            .setName('History entries per finding')
            .setDesc('How many push/pull/merge/rollback snapshots are kept for each finding; older ones are deleted')
            .addText(t => t
                .setValue(String(this.plugin.settings.historyLimit))
                .onChange(async v => {
                    const n = parseInt(v, 10);
                    if (n >= 1) { this.plugin.settings.historyLimit = n; await this.plugin.saveSettings(); }
                }));

        new Setting(containerEl)
            .setName('Warn about changes on PwnDoc')
            .setDesc('Check the open note against PwnDoc when it is opened (and periodically) and show which sections changed remotely')
            .addToggle(t => t.setValue(this.plugin.settings.watchRemote)
                .onChange(async v => { this.plugin.settings.watchRemote = v; await this.plugin.saveSettings(); }));

        new Setting(containerEl)
            .setName('Check interval (minutes)')
            .setDesc('0 = only when a note is opened. Takes effect after reloading the plugin.')
            .addText(t => t
                .setValue(String(this.plugin.settings.watchIntervalMin))
                .onChange(async v => {
                    const n = parseInt(v, 10);
                    if (n >= 0) { this.plugin.settings.watchIntervalMin = n; await this.plugin.saveSettings(); }
                }));

        new Setting(containerEl)
            .setName('Mandatory General Information fields')
            .setDesc('Checked when a report export fails (and by "Check the General Information"). Comma separated keys: ' + Object.keys(GENERAL_FIELDS).join(', '))
            .addText(t => t
                .setValue(this.plugin.settings.generalRequired)
                .onChange(async v => { this.plugin.settings.generalRequired = v.trim(); await this.plugin.saveSettings(); }));

        new Setting(containerEl)
            .setName('Reports folder')
            .setDesc('Vault folder where generated reports are saved')
            .addText(t => t
                .setPlaceholder('reports')
                .setValue(this.plugin.settings.reportsFolder)
                .onChange(async v => { this.plugin.settings.reportsFolder = v.trim().replace(/\/+$/, ''); await this.plugin.saveSettings(); }));

        containerEl.createEl('h3', { text: 'Debug' });

        new Setting(containerEl)
            .setName('Debug mode')
            .setDesc('Log detailed information to the browser console (Ctrl+Shift+I → Console) during API imports.')
            .addToggle(tg => tg
                .setValue(this.plugin.settings.debugMode)
                .onChange(async v => { this.plugin.settings.debugMode = v; await this.plugin.saveSettings(); }));

        // ── Note Templates ────────────────────────────────────────────────────
        containerEl.createEl('h3', { text: 'Note Templates' });
        containerEl.createEl('p', {
            text: 'Vault-relative paths to .md files whose content is inserted at the top (after frontmatter) or bottom of every created vuln note.',
            cls: 'setting-item-description',
        });

        const templateListEl = containerEl.createEl('div');

        const renderTemplates = () => {
            templateListEl.empty();
            const templates = this.plugin.settings.templates;

            templates.forEach((tpl, idx) => {
                const row = templateListEl.createEl('div');
                row.style.cssText = 'display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap;';

                const labelIn = row.createEl('input', { type: 'text' });
                labelIn.placeholder = 'Label (optional)';
                labelIn.value = tpl.label || '';
                labelIn.style.cssText = 'flex:1;min-width:100px;';
                labelIn.addEventListener('change', async () => {
                    templates[idx].label = labelIn.value.trim();
                    await this.plugin.saveSettings();
                });

                const pathIn = row.createEl('input', { type: 'text' });
                pathIn.placeholder = 'templates/my-template';
                pathIn.value = tpl.path || '';
                pathIn.style.cssText = 'flex:3;min-width:180px;';
                pathIn.addEventListener('change', async () => {
                    templates[idx].path = pathIn.value.trim().replace(/\.md$/, '');
                    pathIn.value = templates[idx].path;
                    await this.plugin.saveSettings();
                });

                const browseBtn = row.createEl('button', { text: '📂' });
                browseBtn.title = 'Browse vault files';
                browseBtn.style.cssText = 'flex:0 0 auto;';
                browseBtn.onclick = () => {
                    new VaultFileSuggestModal(this.plugin.app, async chosen => {
                        templates[idx].path = chosen;
                        pathIn.value = chosen;
                        await this.plugin.saveSettings();
                    }).open();
                };

                const posSelect = row.createEl('select');
                posSelect.style.cssText = 'flex:0 0 auto;';
                for (const pos of ['top', 'bottom']) {
                    const opt = posSelect.createEl('option', { value: pos, text: pos });
                    if (tpl.position === pos) opt.selected = true;
                }
                posSelect.addEventListener('change', async () => {
                    templates[idx].position = posSelect.value;
                    await this.plugin.saveSettings();
                });

                const delBtn = row.createEl('button', { text: '✕' });
                delBtn.style.cssText = 'flex:0 0 auto;color:var(--text-error);';
                delBtn.onclick = async () => {
                    templates.splice(idx, 1);
                    await this.plugin.saveSettings();
                    renderTemplates();
                };
            });

            const addBtn = templateListEl.createEl('button', { text: '+ Add template' });
            addBtn.style.cssText = 'margin-top:6px;';
            addBtn.onclick = async () => {
                this.plugin.settings.templates.push({ label: '', path: '', position: 'bottom' });
                await this.plugin.saveSettings();
                renderTemplates();
            };
        };

        renderTemplates();
    }
}

// ── Modal: choose a PwnDoc audit (engagement) ─────────────────────────────────
class AuditPickModal extends FuzzySuggestModal {
    constructor(app, audits, onChoose) {
        super(app);
        this.audits = [...audits].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
        this.onChoose = onChoose;
        this.setPlaceholder('Search engagement (audit)...');
    }
    getItems() { return this.audits; }
    getItemText(a) { return `${a.name || ''} ${a.company?.name || ''}`; }
    renderSuggestion(item, el) {
        const a = item.item;
        el.createEl('div', { text: a.name || a._id });
        el.createEl('small', {
            text: [a.company?.name, a.language, a.state, (a.createdAt || '').slice(0, 10)].filter(Boolean).join(' · '),
            cls: 'pwndoc-meta',
        });
    }
    onChooseItem(a) { this.chosen = true; this.onChoose(a); }
    onClose() { super.onClose(); setTimeout(() => { if (!this.chosen) this.onChoose(null); }, 0); }
}

// ── Modal: choose a finding of the audit (best title match first) ─────────────
class FindingPickModal extends FuzzySuggestModal {
    constructor(app, findings, suggestedTitle, onChoose) {
        super(app);
        this.findings = rankFindings(suggestedTitle, findings);
        this.onChoose = onChoose;
        this.setPlaceholder('Search finding in the audit...');
    }
    getItems() { return this.findings; }
    getItemText(f) { return `${f.identifier || ''} ${f.title || ''}`; }
    renderSuggestion(item, el) {
        const f = item.item;
        el.createEl('div', { text: f.title || f._id });
        el.createEl('small', { text: [`#${f.identifier}`, f.vulnType, f.cvssv3].filter(Boolean).join(' · '), cls: 'pwndoc-meta' });
    }
    onChooseItem(f) { this.chosen = true; this.onChoose(f); }
    onClose() { super.onClose(); setTimeout(() => { if (!this.chosen) this.onChoose(null); }, 0); }
}

// ── Modal: pick the finding to send a note to, or create it ───────────────────
class FindingOrCreateModal extends SuggestModal {
    constructor(app, findings, title, onChoose) {
        super(app);
        this.findings = findings;
        this.title = title;
        this.onChoose = onChoose; // ({ finding } | { create: true } | null) => void
        this.chosen = false;
        this.setPlaceholder('Finding of the engagement to send this note to, or create a new one...');
    }
    getSuggestions(q) {
        const query = q.toLowerCase();
        return findingChoices(this.title, this.findings)
            .filter(c => c.create || `${c.finding.identifier} ${c.finding.title}`.toLowerCase().includes(query));
    }
    renderSuggestion(c, el) {
        if (c.create) { el.createEl('div', { text: `+ Create a new finding "${this.title}" on PwnDoc` }); el.createEl('small', { text: 'from a library vulnerability or blank', cls: 'pwndoc-meta' }); return; }
        el.createEl('div', { text: c.finding.title || c.finding._id });
        el.createEl('small', { text: [`#${c.finding.identifier}`, c.finding.vulnType, c.finding.cvssv3].filter(Boolean).join(' · '), cls: 'pwndoc-meta' });
    }
    onChooseSuggestion(c) { this.chosen = true; this.onChoose(c); }
    onClose() { super.onClose(); setTimeout(() => { if (!this.chosen) this.onChoose(null); }, 0); }
}

// ── Modal: yes/no confirmation ────────────────────────────────────────────────
class ConfirmModal extends Modal {
    constructor(app, message, onAnswer) {
        super(app);
        this.message = message;
        this.onAnswer = onAnswer; // (boolean) => void
        this.answered = false;
    }
    onOpen() {
        const { contentEl } = this;
        contentEl.createEl('p', { text: this.message });
        const answer = v => { this.answered = true; this.close(); this.onAnswer(v); };
        contentEl.createEl('button', { text: 'Yes, continue', cls: 'mod-warning' }).onclick = () => answer(true);
        const no = contentEl.createEl('button', { text: 'Cancel' });
        no.style.marginLeft = '8px';
        no.onclick = () => answer(false);
    }
    onClose() { this.contentEl.empty(); if (!this.answered) this.onAnswer(false); }
}

// ── Modal: per-section compare, PwnDoc and note side by side ──────────────────
// rows: buildComparison() rows. onApply({ push: key[], pull: key[], merge: { [key]: text }, force })
// Per section the user picks: skip, use the PwnDoc version (pull), use the note version (push) or merge both
class MergeModal extends Modal {
    constructor(app, rows, { defaultKeys, auditState, onApply }) {
        super(app);
        this.rows = rows;
        this.defaultKeys = defaultKeys;
        this.auditState = auditState;
        this.onApply = onApply;
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        this.modalEl.style.width = 'min(1100px, 95vw)';
        contentEl.createEl('h3', { text: 'Compare with PwnDoc' });

        let forceBox = null;
        if (this.auditState !== 'EDIT') {
            const warn = contentEl.createEl('div');
            warn.style.cssText = 'padding:6px 8px;margin-bottom:8px;border:1px solid var(--text-error);border-radius:4px;';
            warn.createEl('div', { text: `Audit state is ${this.auditState}: writing to PwnDoc is blocked.` });
            const wrap = warn.createEl('label');
            forceBox = wrap.createEl('input', { type: 'checkbox' });
            wrap.createEl('span', { text: ' Enforce write on non-EDIT audit (this operation only)' });
        }

        const STATUS = { same: 'identical', local: 'changed in the note', remote: 'changed on PwnDoc', conflict: 'changed on both sides', unknown: 'differs (no sync base)' };
        const TINT = { del: 'var(--background-modifier-error)', add: 'var(--background-modifier-success)', none: 'var(--background-secondary)' };

        const ui = this.rows.map(row => {
            const def = SECTION_DEFS.find(d => d.key === row.key);
            const locked = !row.changed;
            let value = locked ? 'skip'
                : !this.defaultKeys.includes(row.key) ? 'skip'
                : row.merge ? 'merge' : row.status === 'remote' ? 'pwndoc' : 'note';

            const box = contentEl.createEl('div');
            box.style.cssText = 'margin-bottom:12px;padding:6px 8px;border:1px solid var(--background-modifier-border);border-radius:6px;';
            const head = box.createEl('div');
            head.style.cssText = 'display:flex;flex-wrap:wrap;align-items:center;gap:10px;';
            head.createEl('strong', { text: labelOf(def) });
            head.createEl('small', {
                text: [STATUS[row.status],
                    row.localEmpty ? 'note empty' : '', row.remoteEmpty ? 'PwnDoc empty' : ''].filter(Boolean).join(' · '),
                cls: 'pwndoc-meta',
            });

            const group = head.createEl('div');
            group.style.cssText = 'margin-left:auto;display:flex;gap:4px;';
            const choices = [['skip', 'Skip'], ['pwndoc', 'Use PwnDoc'], ['note', 'Use note'], ...(row.merge ? [['merge', 'Merge both']] : [])];
            const btns = {};
            let area = null, headL = null, headR = null;
            const set = v => {
                value = v;
                for (const [k, b] of Object.entries(btns)) b.toggleClass('mod-cta', k === v);
                if (area) area.style.display = v === 'merge' ? '' : 'none';
                if (headL) headL.style.outline = v === 'pwndoc' ? '2px solid var(--interactive-accent)' : '';
                if (headR) headR.style.outline = v === 'note' ? '2px solid var(--interactive-accent)' : '';
            };
            for (const [k, label] of choices) {
                const b = group.createEl('button', { text: label });
                b.disabled = locked && k !== 'skip';
                b.onclick = () => set(k);
                btns[k] = b;
            }

            if (row.changed) {
                const grid = box.createEl('div');
                grid.style.cssText = 'display:grid;grid-template-columns:1fr 1fr;gap:0 8px;margin-top:6px;max-height:280px;overflow:auto;font-family:var(--font-monospace);font-size:0.8em;';
                const colHead = (text, pick) => {
                    const h = grid.createEl('div', { text });
                    h.style.cssText = 'position:sticky;top:0;z-index:1;font-weight:bold;padding:2px 4px;background:var(--background-primary);' + (locked ? '' : 'cursor:pointer;');
                    if (!locked) h.onclick = () => set(pick);
                    return h;
                };
                headL = colHead('PwnDoc', 'pwndoc');
                headR = colHead('Note', 'note');
                for (const r of sideBySide(row.diff)) {
                    for (const [text, side] of [[r.left, 'left'], [r.right, 'right']]) {
                        const c = grid.createEl('div');
                        c.style.cssText = 'white-space:pre-wrap;word-break:break-word;padding:0 4px;min-height:1.2em;';
                        c.setText(text ?? '');
                        if (text === null) c.style.background = TINT.none;
                        else if (r.kind === 'mod') c.style.background = side === 'left' ? TINT.del : TINT.add;
                        else if (r.kind === 'del' || r.kind === 'add') c.style.background = r.kind === 'del' ? TINT.del : TINT.add;
                    }
                }
            }
            if (row.merge) {
                area = box.createEl('textarea');
                area.value = row.merge.text;
                area.rows = 8;
                area.style.cssText = 'width:100%;margin-top:6px;font-family:var(--font-monospace);font-size:0.8em;';
                box.createEl('small', {
                    text: row.merge.conflicts ? `${row.merge.conflicts} conflict(s): resolve the markers (<<<<<<< / ======= / >>>>>>>) before applying` : 'merged without conflicts, review before applying',
                    cls: 'pwndoc-meta',
                });
            }
            set(value);
            return { row, locked, value: () => value, set, area };
        });

        const bar = contentEl.createEl('div');
        bar.style.cssText = 'display:flex;gap:8px;margin-top:10px;';
        const setAll = v => ui.forEach(u => { if (!u.locked) u.set(v); });
        bar.createEl('button', { text: 'All: PwnDoc' }).onclick = () => setAll('pwndoc');
        bar.createEl('button', { text: 'All: note' }).onclick = () => setAll('note');
        bar.createEl('button', { text: 'None' }).onclick = () => setAll('skip');
        const apply = bar.createEl('button', { text: 'Apply', cls: 'mod-cta' });
        apply.style.marginLeft = 'auto';
        apply.onclick = () => {
            const keysOf = v => ui.filter(u => u.value() === v).map(u => u.row.key);
            const push = keysOf('note');
            const pull = keysOf('pwndoc');
            const merge = Object.fromEntries(ui.filter(u => u.value() === 'merge').map(u => [u.row.key, u.area.value]));
            if (!push.length && !pull.length && !Object.keys(merge).length) { new Notice('PwnDoc 2Sync: nothing selected.'); return; }
            const bad = Object.entries(merge).find(([, t]) => hasConflictMarkers(t));
            if (bad) { new Notice(`PwnDoc 2Sync: resolve the conflict markers in "${labelOf(defOf(bad[0]))}" first.`); return; }
            if ((push.length || Object.keys(merge).length) && this.auditState !== 'EDIT' && !forceBox?.checked) {
                new Notice(`PwnDoc 2Sync: audit is ${this.auditState}, tick "Enforce" to write to PwnDoc.`);
                return;
            }
            this.close();
            this.onApply({ push, pull, merge, force: !!forceBox?.checked });
        };
    }

    onClose() { this.contentEl.empty(); }
}

// ── Modal: findings on PwnDoc that have no note yet ───────────────────────────
class MissingFindingsModal extends SuggestModal {
    constructor(app, findings, onChoose) {
        super(app);
        this.findings = findings;
        this.onChoose = onChoose; // (finding[] | null) => void
        this.chosen = false;
        this.setPlaceholder('Findings on PwnDoc without a note...');
    }
    getSuggestions(q) {
        const query = q.toLowerCase();
        const items = this.findings.filter(f => `${f.identifier} ${f.title}`.toLowerCase().includes(query)).map(f => ({ f }));
        return query ? items : [{ all: true }, ...items];
    }
    renderSuggestion(i, el) {
        if (i.all) { el.createEl('div', { text: `Import all ${this.findings.length} findings` }); return; }
        el.createEl('div', { text: i.f.title });
        el.createEl('small', { text: [`#${i.f.identifier}`, i.f.vulnType, i.f.cvssv3].filter(Boolean).join(' · '), cls: 'pwndoc-meta' });
    }
    onChooseSuggestion(i) { this.chosen = true; this.onChoose(i.all ? this.findings : [i.f]); }
    onClose() { super.onClose(); setTimeout(() => { if (!this.chosen) this.onChoose(null); }, 0); }
}

// ── Modal: pick a history entry, then where to restore it ─────────────────────
class HistoryModal extends SuggestModal {
    constructor(app, entries, onChoose) {
        super(app);
        this.entries = entries;
        this.onChoose = onChoose; // ({ entry, side }) => void
        this.setPlaceholder('Pick a snapshot to restore...');
    }
    getSuggestions(query) {
        const q = query.toLowerCase();
        const items = [];
        for (const e of this.entries) {
            if (e.remoteBefore) items.push({ e, side: 'remote', label: 'PwnDoc as it was' });
            if (e.localBefore) items.push({ e, side: 'local', label: 'note as it was' });
        }
        return items.filter(i => `${i.e.ts} ${i.e.op} ${i.e.sections.join(' ')} ${i.label}`.toLowerCase().includes(q));
    }
    renderSuggestion(i, el) {
        el.createEl('div', { text: `${i.e.ts.replace('T', ' ').slice(0, 19)} · before ${i.e.op} · ${i.label}` });
        el.createEl('small', { text: `${i.e.sections.join(', ')}${i.e.forced ? ' · forced' : ''}`, cls: 'pwndoc-meta' });
    }
    onChooseSuggestion(i) { this.onChoose({ entry: i.e, side: i.side }); }
}

// ── Modal: choose the sections of a snapshot to restore ───────────────────────
class RollbackModal extends Modal {
    constructor(app, rows, { entry, side, auditState, onApply }) {
        super(app);
        this.rows = rows;
        this.entry = entry;
        this.side = side;
        this.auditState = auditState;
        this.onApply = onApply; // ({ sections, force }) => void
    }
    onOpen() {
        const { contentEl } = this;
        contentEl.createEl('h3', { text: `Restore ${this.side === 'remote' ? 'PwnDoc' : 'the note'} from ${this.entry.ts.slice(0, 19).replace('T', ' ')}` });
        let forceBox = null;
        const guarded = this.side === 'remote' && this.auditState !== 'EDIT';
        if (guarded) {
            const wrap = contentEl.createEl('label');
            forceBox = wrap.createEl('input', { type: 'checkbox' });
            wrap.createEl('span', { text: ` Audit is ${this.auditState}: Enforce write (this operation only)` });
        }
        const ui = this.rows.map(row => {
            const def = defOf(row.key);
            const box = contentEl.createEl('div');
            const head = box.createEl('label');
            const check = head.createEl('input', { type: 'checkbox' });
            check.checked = row.changed && this.entry.sections.includes(row.key);
            check.disabled = !row.changed;
            head.createEl('strong', { text: ` ${labelOf(def)} ` });
            head.createEl('small', { text: row.changed ? 'differs from the snapshot' : 'same as the snapshot', cls: 'pwndoc-meta' });
            if (row.changed) {
                const det = box.createEl('details');
                det.createEl('summary', { text: 'diff (current → snapshot)' });
                const pre = det.createEl('pre');
                pre.style.cssText = 'max-height:180px;overflow:auto;font-size:0.8em;';
                for (const d of row.diff) {
                    const l = pre.createEl('div', { text: `${{ eq: '  ', add: '+ ', del: '- ' }[d.op]}${d.line}` });
                    if (d.op === 'add') l.style.color = 'var(--text-success)';
                    if (d.op === 'del') l.style.color = 'var(--text-error)';
                }
            }
            return { row, check };
        });
        const apply = contentEl.createEl('button', { text: 'Restore', cls: 'mod-cta' });
        apply.style.marginTop = '10px';
        apply.onclick = () => {
            const sections = ui.filter(u => u.check.checked).map(u => u.row.key);
            if (!sections.length) { new Notice('PwnDoc 2Sync: nothing selected.'); return; }
            if (guarded && !forceBox.checked) { new Notice(`PwnDoc 2Sync: audit is ${this.auditState}, tick "Enforce" to restore.`); return; }
            this.close();
            this.onApply({ sections, force: !!forceBox?.checked });
        };
    }
    onClose() { this.contentEl.empty(); }
}

// ── Modal: pick a library vuln to create the finding from (or a blank one) ────
class LibraryVulnPickModal extends FuzzySuggestModal {
    constructor(app, vulns, suggestedId, locale, onChoose) {
        super(app);
        const titleOf = v => (v.details.find(d => d.locale === locale) || v.details[0])?.title || v._id;
        const items = vulns.map(v => ({ vuln: v, title: titleOf(v), suggested: v._id === suggestedId }));
        items.sort((a, b) => Number(b.suggested) - Number(a.suggested));
        this.items = [...items, { blank: true, title: 'New blank finding (title and CVSS from the note)' }];
        this.onChoose = onChoose; // (vuln | 'blank' | null) => void
        this.chosen = false;
        this.setPlaceholder('Pick the library vulnerability to create the finding from...');
    }
    getItems() { return this.items; }
    getItemText(i) { return i.vuln ? i.vuln.details.map(d => d.title).join(' ') : i.title; }
    renderSuggestion(item, el) {
        const i = item.item;
        el.createEl('div', { text: i.title });
        if (i.vuln) el.createEl('small', { text: [i.suggested ? 'suggested' : '', i.vuln.category, i.vuln.cvssv3].filter(Boolean).join(' · '), cls: 'pwndoc-meta' });
    }
    onChooseItem(i) { this.chosen = true; this.onChoose(i.blank ? 'blank' : i.vuln); }
    onClose() { super.onClose(); setTimeout(() => { if (!this.chosen) this.onChoose(null); }, 0); }
}

// ── Modal: lint result before a push (or on demand) ───────────────────────────
// onAnswer(true) only when there are no errors and the user chose to go on
class LintModal extends Modal {
    constructor(app, issues, onAnswer) {
        super(app);
        this.issues = issues;
        this.onAnswer = onAnswer; // (boolean) => void, null when only shown
        this.answered = false;
    }
    onOpen() {
        const { contentEl } = this;
        const errors = this.issues.filter(i => i.level === 'error').length;
        contentEl.createEl('h3', { text: this.issues.length ? `Lint: ${errors} error(s), ${this.issues.length - errors} warning(s)` : 'Lint: no issues' });
        for (const i of this.issues) {
            const line = contentEl.createEl('div');
            line.style.cssText = `margin:2px 0;color:${i.level === 'error' ? 'var(--text-error)' : 'var(--text-warning)'};`;
            line.setText(`${i.level === 'error' ? '✗' : '!'} [${labelOf(defOf(i.section))}] ${i.message}`);
        }
        const answer = v => { this.answered = true; this.close(); this.onAnswer?.(v); };
        const bar = contentEl.createEl('div');
        bar.style.cssText = 'display:flex;gap:8px;margin-top:12px;';
        if (this.onAnswer && !errors) bar.createEl('button', { text: 'Continue anyway', cls: 'mod-warning' }).onclick = () => answer(true);
        bar.createEl('button', { text: this.onAnswer ? 'Cancel' : 'Close' }).onclick = () => answer(false);
    }
    onClose() { this.contentEl.empty(); if (!this.answered) this.onAnswer?.(false); }
}

// ── Modal: one line of text (figure caption) ──────────────────────────────────
class PromptModal extends Modal {
    constructor(app, title, placeholder, onSubmit) {
        super(app);
        this.title = title;
        this.placeholder = placeholder;
        this.onSubmit = onSubmit; // (string | null) => void
        this.done = false;
    }
    onOpen() {
        const { contentEl } = this;
        contentEl.createEl('h3', { text: this.title });
        const input = contentEl.createEl('input', { type: 'text', placeholder: this.placeholder });
        input.style.width = '100%';
        const submit = v => { this.done = true; this.close(); this.onSubmit(v); };
        input.addEventListener('keydown', e => { if (e.key === 'Enter' && input.value.trim()) submit(input.value.trim()); });
        const ok = contentEl.createEl('button', { text: 'Insert', cls: 'mod-cta' });
        ok.style.marginTop = '8px';
        ok.onclick = () => { if (input.value.trim()) submit(input.value.trim()); };
        setTimeout(() => input.focus(), 0);
    }
    onClose() { this.contentEl.empty(); if (!this.done) this.onSubmit(null); }
}

// ── Modal: a titled list of lines ─────────────────────────────────────────────
class InfoModal extends Modal {
    constructor(app, title, lines) { super(app); this.title = title; this.lines = lines; }
    onOpen() {
        const { contentEl } = this;
        contentEl.createEl('h3', { text: this.title });
        for (const l of this.lines) contentEl.createEl('div', { text: l }).style.cssText = 'margin:2px 0;white-space:pre-wrap;';
        contentEl.createEl('button', { text: 'Close' }).onclick = () => this.close();
    }
    onClose() { this.contentEl.empty(); }
}

// ── Modal: choose the report template ─────────────────────────────────────────
class TemplatePickModal extends SuggestModal {
    constructor(app, templates, currentId, onChoose) {
        super(app);
        this.templates = templates;
        this.currentId = currentId;
        this.onChoose = onChoose; // (templateId | null) => void
        this.chosen = false;
        this.setPlaceholder('Report template...');
    }
    getSuggestions(q) {
        const query = q.toLowerCase();
        return this.templates.filter(t => `${t.name} ${t.ext}`.toLowerCase().includes(query))
            .sort((a, b) => (b._id === this.currentId) - (a._id === this.currentId));
    }
    renderSuggestion(t, el) {
        el.createEl('div', { text: t.name });
        el.createEl('small', { text: [t.ext, t._id === this.currentId ? 'current template of the audit' : ''].filter(Boolean).join(' · '), cls: 'pwndoc-meta' });
    }
    onChooseSuggestion(t) { this.chosen = true; this.onChoose(t._id); }
    onClose() { super.onClose(); setTimeout(() => { if (!this.chosen) this.onChoose(null); }, 0); }
}

// ── Modal: engagement dashboard and orphan list ───────────────────────────────
// data: buildDashboard() result (rows may be empty for the orphan view); audit: the PwnDoc audit or null
// One tab per kind of thing: notes in sync with a finding, notes without a finding, orphans, findings without a note
class DashboardModal extends Modal {
    constructor(app, plugin, data, { title, subtitle = '', audit }) {
        super(app);
        this.plugin = plugin;
        this.data = data;
        this.title = title;
        this.subtitle = subtitle;
        this.audit = audit;
    }

    onOpen() {
        const { contentEl, data, audit } = this;
        contentEl.empty();
        this.modalEl.style.width = 'min(980px, 96vw)';
        const STATE = {
            conflict: ['conflict', 'var(--text-error)'], local: ['note changed', 'var(--text-warning)'], remote: ['PwnDoc changed', 'var(--text-accent)'],
            unknown: ['no sync base', 'var(--text-muted)'], same: ['in sync', 'var(--text-success)'],
        };
        const open = async path => {
            const f = this.app.vault.getAbstractFileByPath(path);
            if (f) await this.app.workspace.getLeaf().openFile(f);
        };
        const css = (el, text) => { el.style.cssText = text; return el; };
        const btn = (parent, text, fn, small = true) => {
            const b = parent.createEl('button', { text });
            if (small) css(b, 'padding:2px 10px;font-size:0.85em;');
            b.onclick = fn;
            return b;
        };
        const pill = (parent, text, color) =>
            css(parent.createEl('span', { text }), `color:${color};border:1px solid ${color};border-radius:10px;padding:0 8px;font-size:0.78em;white-space:nowrap;`);
        const note = (parent, text) => css(parent.createEl('p', { text }), 'color:var(--text-muted);font-size:0.9em;margin:4px 0 10px;');

        // view state
        const sel = new Set();
        const sections = new Set(DEFAULT_SYNC_SECTIONS);
        const view = { tab: '', state: '', query: '', force: false };
        const rowsSorted = sortDashboardRows(data.rows);

        css(contentEl.createEl('h3', { text: this.title }), 'margin-bottom:2px;');
        if (this.subtitle) css(contentEl.createEl('div', { text: this.subtitle }), 'color:var(--text-muted);font-size:0.85em;margin-bottom:10px;');

        const tabsEl = contentEl.createEl('div');
        const bodyEl = contentEl.createEl('div');
        const footEl = contentEl.createEl('div');

        const TABS = [
            ['notes', 'Notes', data.rows.length], ['unlinked', 'No finding yet', data.unlinked.length],
            ['orphans', 'Orphans', data.orphans.length], ['missing', 'Only on PwnDoc', data.missing.length],
        ].filter(t => t[2]);
        if (!TABS.length) { contentEl.createEl('p', { text: 'Nothing to show.' }); return; }
        view.tab = TABS[0][0];

        const renderTabs = () => {
            tabsEl.empty();
            css(tabsEl, 'display:flex;gap:4px;border-bottom:1px solid var(--background-modifier-border);margin-bottom:10px;');
            for (const [id, label, n] of TABS) {
                const b = tabsEl.createEl('button', { text: `${label} (${n})` });
                css(b, `border:none;border-radius:6px 6px 0 0;box-shadow:none;padding:4px 12px;background:${view.tab === id ? 'var(--background-modifier-active-hover)' : 'transparent'};font-weight:${view.tab === id ? '600' : '400'};`);
                b.onclick = () => { view.tab = id; renderAll(); };
            }
        };

        const selectedRows = () => data.rows.filter(r => sel.has(r.path));

        const renderFoot = () => {
            footEl.empty();
            if (view.tab !== 'notes') return;
            css(footEl, 'display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin-top:12px;padding-top:10px;border-top:1px solid var(--background-modifier-border);');
            const rows = selectedRows();
            const keys = [...sections];
            const push = bulkSummary(rows, 'push', keys), pull = bulkSummary(rows, 'pull', keys);
            const info = css(footEl.createEl('div'), 'flex:1;min-width:240px;font-size:0.85em;color:var(--text-muted);');
            info.setText(rows.length
                ? `${rows.length} selected. Push would write ${push.sections} section(s) in ${push.notes} note(s); pull ${pull.sections} in ${pull.notes}. Never overwrites a side that changed on its own.`
                : 'Tick the notes to push or pull the chosen sections in bulk.');
            const locked = audit && audit.state !== 'EDIT';
            if (locked) {
                const w = footEl.createEl('label');
                const c = w.createEl('input', { type: 'checkbox' });
                c.checked = view.force;
                c.onchange = () => { view.force = c.checked; renderFoot(); };
                w.createEl('span', { text: ` Enforce (audit is ${audit.state})` });
            }
            const go = direction => async () => {
                this.close();
                await this.plugin.bulkSync(audit, rows, keys, direction, view.force);
            };
            const pushBtn = btn(footEl, `Push ${push.notes ? `(${push.notes})` : ''}`, go('push'), false);
            pushBtn.addClass('mod-cta');
            pushBtn.disabled = !push.notes || (locked && !view.force);
            if (locked && !view.force) pushBtn.title = `Audit is ${audit.state}: tick Enforce to write`;
            const pullBtn = btn(footEl, `Pull ${pull.notes ? `(${pull.notes})` : ''}`, go('pull'), false);
            pullBtn.disabled = !pull.notes;
        };

        const renderNotes = () => {
            // filters: state chips, search, sections
            const bar = css(bodyEl.createEl('div'), 'display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-bottom:8px;');
            const counts = dashboardCounts(data.rows);
            const chip = (label, state, n) => {
                const on = view.state === state;
                const b = bar.createEl('button', { text: `${label} ${n}` });
                css(b, `padding:1px 10px;font-size:0.82em;border-radius:12px;${on ? 'background:var(--interactive-accent);color:var(--text-on-accent);' : ''}`);
                b.onclick = () => { view.state = on ? '' : state; renderAll(); };
            };
            chip('All', '', data.rows.length);
            for (const k of ['conflict', 'local', 'remote', 'unknown', 'same']) if (counts[k]) chip(STATE[k][0], k, counts[k]);
            const search = bar.createEl('input', { type: 'search', placeholder: 'Filter by title...' });
            css(search, 'margin-left:auto;width:180px;');
            search.value = view.query;
            search.oninput = () => { view.query = search.value; renderList(); renderFoot(); };

            // sections to push or pull in bulk
            const det = css(bodyEl.createEl('details'), 'margin-bottom:8px;');
            const sum = det.createEl('summary');
            const sumText = () => sum.setText(`Sections for bulk actions: ${[...sections].map(k => labelOf(defOf(k))).join(', ') || 'none'}`);
            sumText();
            const grid = css(det.createEl('div'), 'display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:2px 12px;padding:6px 0;');
            for (const def of SECTION_DEFS) {
                const l = grid.createEl('label');
                const c = l.createEl('input', { type: 'checkbox' });
                c.checked = sections.has(def.key);
                c.onchange = () => { c.checked ? sections.add(def.key) : sections.delete(def.key); sumText(); renderFoot(); };
                l.createEl('span', { text: ' ' + labelOf(def) });
            }

            listEl = bodyEl.createEl('div');
            renderList();
        };

        let listEl = null;
        const COLS = '24px minmax(160px,1fr) 78px 112px minmax(120px,1.1fr) 130px';
        const renderList = () => {
            listEl.empty();
            const rows = filterDashboardRows(rowsSorted, view);
            const head = css(listEl.createEl('div'), `display:grid;grid-template-columns:${COLS};gap:8px;align-items:center;padding:4px 6px;font-size:0.78em;color:var(--text-muted);border-bottom:1px solid var(--background-modifier-border);`);
            const all = head.createEl('input', { type: 'checkbox' });
            all.checked = rows.length > 0 && rows.every(r => sel.has(r.path));
            all.onchange = () => { rows.forEach(r => (all.checked ? sel.add(r.path) : sel.delete(r.path))); renderList(); renderFoot(); };
            for (const h of ['Note', 'Finding', 'Sync', 'Differs in', '']) head.createEl('span', { text: h });
            if (!rows.length) { note(listEl, 'No note matches the filter.'); return; }
            const wrap = css(listEl.createEl('div'), 'max-height:48vh;overflow:auto;');
            for (const r of rows) {
                const line = css(wrap.createEl('div'), `display:grid;grid-template-columns:${COLS};gap:8px;align-items:center;padding:5px 6px;border-bottom:1px solid var(--background-modifier-border);`);
                const c = line.createEl('input', { type: 'checkbox' });
                c.checked = sel.has(r.path);
                c.onchange = () => { c.checked ? sel.add(r.path) : sel.delete(r.path); renderFoot(); };
                const t = line.createEl('div');
                css(t.createEl('div', { text: r.title }), 'font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;');
                css(t.createEl('div', { text: r.path }), 'font-size:0.75em;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;');
                t.title = r.path;
                css(line.createEl('span', { text: r.completed ? 'completed' : 'in progress' }), `font-size:0.8em;color:${r.completed ? 'var(--text-success)' : 'var(--text-muted)'};`);
                pill(line, STATE[r.state][0], STATE[r.state][1]);
                const diffs = css(line.createEl('div'), 'display:flex;flex-wrap:wrap;gap:3px;');
                for (const k of r.changed.slice(0, 3)) css(diffs.createEl('span', { text: labelOf(defOf(k)) }), 'font-size:0.75em;background:var(--background-secondary);border-radius:4px;padding:0 5px;');
                if (r.changed.length > 3) css(diffs.createEl('span', { text: `+${r.changed.length - 3}`, title: r.changed.slice(3).map(k => labelOf(defOf(k))).join(', ') }), 'font-size:0.75em;color:var(--text-muted);');
                const acts = css(line.createEl('div'), 'display:flex;gap:4px;justify-content:flex-end;');
                btn(acts, 'Open', () => open(r.path));
                btn(acts, 'Compare', async () => { this.close(); await open(r.path); this.plugin.compareWithPwndoc(); });
            }
        };

        const simpleList = (items, render) => {
            const wrap = css(bodyEl.createEl('div'), 'max-height:52vh;overflow:auto;');
            for (const it of items) {
                const l = css(wrap.createEl('div'), 'display:flex;align-items:center;gap:8px;padding:5px 6px;border-bottom:1px solid var(--background-modifier-border);');
                render(l, it);
            }
        };
        const renderOther = () => {
            if (view.tab === 'unlinked') {
                note(bodyEl, 'Notes of this engagement that are not linked to a finding yet. Open one and run "Send note to PwnDoc" to pick or create its finding.');
                simpleList(data.unlinked, (l, n) => { css(l.createEl('span', { text: n.path }), 'flex:1;'); btn(l, 'Open', () => open(n.path)); });
            } else if (view.tab === 'orphans') {
                note(bodyEl, 'These notes point to a finding (or an engagement) that no longer exists on PwnDoc. Unlink them, then link them again with "Send note to PwnDoc". Nothing is changed on PwnDoc.');
                simpleList(data.orphans, (l, o) => {
                    const t = css(l.createEl('div'), 'flex:1;');
                    t.createEl('div', { text: o.path });
                    css(t.createEl('div', { text: o.reason }), 'font-size:0.75em;color:var(--text-muted);');
                    btn(l, 'Open', () => open(o.path));
                    btn(l, 'Unlink', async () => { if (await this.plugin.unlinkNote(this.app.vault.getAbstractFileByPath(o.path))) l.remove(); });
                });
            } else if (view.tab === 'missing') {
                note(bodyEl, 'Findings of the engagement that no note points to. Importing creates the notes from PwnDoc; it never writes to PwnDoc.');
                if (audit) btn(bodyEl, 'Import these findings...', () => { this.close(); this.plugin.importFindingsFromPwndoc(undefined, audit._id); }, false).addClass('mod-cta');
                simpleList(data.missing, (l, f) => {
                    css(l.createEl('span', { text: f.title }), 'flex:1;');
                    css(l.createEl('small', { text: [`#${f.identifier ?? ''}`, f.status === STATUS_DONE ? 'completed' : 'in progress'].join(' · ') }), 'color:var(--text-muted);');
                });
            }
        };

        const renderAll = () => {
            renderTabs();
            bodyEl.empty();
            if (view.tab === 'notes') renderNotes(); else renderOther();
            renderFoot();
        };
        renderAll();
    }

    onClose() { this.contentEl.empty(); }
}

// ── Plugin ────────────────────────────────────────────────────────────────────
class PwnDocImporterPlugin extends Plugin {
    async onload() {
        await this.loadSettings();
        this.remoteWarn = new Map();   // note path -> sections PwnDoc changed since the last sync
        this.remoteSeen = new Map();   // note path -> last warned signature
        this.checking = new Set();
        this.remoteBackoff = 0;       // after a failed check (bad password, host down) stay quiet for a while
        this.addSettingTab(new PwnDocSettingTab(this.app, this));
        this.addRibbonIcon('shield-plus', 'Add vulnerability (PwnDoc)', () => {
            new ImportSourceModal(this.app, source => {
                if (source === 'csv') this.openSearchModal();
                else this.openApiImportModal();
            }).open();
        });

        this.addCommand({
            id: 'import-vuln-from-csv',
            name: 'Import vulnerability from CSV',
            callback: () => this.openSearchModal(),
        });
        this.addCommand({
            id: 'import-vuln-from-api',
            name: 'Fetch and import vulnerability from PwnDoc API',
            callback: () => this.openApiImportModal(),
        });
        this.addCommand({
            id: 'quick-import-vuln',
            name: 'Quick import vulnerability (use default source and language)',
            callback: () => this.quickImport(),
        });
        this.addCommand({
            id: 'associate-folder-to-audit',
            name: 'Associate folder to PwnDoc engagement',
            callback: () => this.associateFolder(),
        });
        this.addCommand({
            id: 'associate-note-to-finding',
            name: 'Associate note to PwnDoc finding',
            callback: () => this.associateNote(),
        });
        this.addCommand({
            id: 'compare-with-pwndoc',
            name: 'Compare with PwnDoc and merge sections',
            callback: () => this.compareWithPwndoc(),
        });
        this.addCommand({
            id: 'rollback-from-history',
            name: 'Restore from PwnDoc sync history (rollback)',
            callback: () => this.rollbackFromHistory(),
        });
        this.addCommand({
            id: 'create-finding-in-pwndoc',
            name: 'Create PwnDoc finding for this note (from library or blank)',
            callback: () => this.createFindingForNote(),
        });
        this.registerEvent(this.app.vault.on('rename', async (file, oldPath) => {
            if (file.children === undefined) { this.stampLater(file); return; } // a moved note adopts its new folder's engagement
            const next = renameFolderKeys(this.settings.folderAudits, oldPath, file.path);
            if (JSON.stringify(next) === JSON.stringify(this.settings.folderAudits)) return;
            this.settings.folderAudits = next;
            await this.saveSettings();
        }));

        this.statusEl = this.addStatusBarItem();
        this.statusEl.addClass('mod-clickable');
        this.statusEl.onclick = e => this.openQuickMenu(e);
        this.addCommand({
            id: 'import-findings-from-pwndoc',
            name: 'Import findings that exist only on PwnDoc',
            callback: () => this.importFindingsFromPwndoc(),
        });
        this.addCommand({
            id: 'refresh-engagement-attributes',
            name: 'Refresh engagement attribute on notes',
            callback: () => this.refreshEngagementAttributes(),
        });
        const cmd = (id, name, callback) => this.addCommand({ id, name, callback });
        cmd('send-to-pwndoc', 'Send note to PwnDoc (select or create the finding, then push)', () => this.sendToPwndoc());
        cmd('engagement-dashboard', 'Engagement dashboard (sync status of every note)', () => this.openDashboard());
        cmd('lint-note', 'Lint this note before pushing', () => this.lintCurrentNote());
        cmd('unlink-note', 'Unlink note from its PwnDoc finding', () => this.unlinkNote());
        cmd('find-orphans', 'Find orphan notes (finding or engagement gone from PwnDoc)', () => this.findOrphans());
        cmd('finding-completed', 'Mark PwnDoc finding as completed', () => this.setCompleted(true));
        cmd('finding-reopen', 'Reopen PwnDoc finding (in progress)', () => this.setCompleted(false));
        cmd('check-general-information', 'Check the General Information of the engagement (mandatory fields)', () => this.checkGeneralCommand());
        cmd('set-report-template', 'Choose the report template of the engagement', () => this.setTemplateCommand());
        cmd('generate-report', 'Generate PwnDoc report (docx from the engagement template)', () => this.generateReportCommand());
        this.addCommand({
            id: 'paste-image-with-caption',
            name: 'Paste clipboard image with numbered caption',
            editorCallback: (editor, view) => this.pasteImageWithCaption(editor, view),
        });
        this.registerEvent(this.app.workspace.on('file-open', f => f && this.checkRemote(f)));
        if (this.settings.watchIntervalMin > 0) {
            this.registerInterval(window.setInterval(() => this.checkRemote(this.app.workspace.getActiveFile()), this.settings.watchIntervalMin * 60000));
        }
        const refresh = () => this.refreshChrome();
        this.registerEvent(this.app.workspace.on('file-open', refresh));
        this.registerEvent(this.app.workspace.on('active-leaf-change', refresh));
        this.registerEvent(this.app.metadataCache.on('changed', f => { if (f === this.app.workspace.getActiveFile()) refresh(); }));
        this.registerEvent(this.app.workspace.on('file-menu', (menu, file) => {
            if (file.children === undefined) return;
            menu.addItem(i => i.setTitle('Associate to PwnDoc engagement').setIcon('shield-plus')
                .onClick(() => this.associateFolder(file.path === '/' ? '' : file.path)));
            menu.addItem(i => i.setTitle('Engagement dashboard').setIcon('layout-dashboard')
                .onClick(() => this.openDashboard(file.path === '/' ? '' : file.path)));
            menu.addItem(i => i.setTitle('Import findings from PwnDoc here').setIcon('download')
                .onClick(() => this.importFindingsFromPwndoc(file.path === '/' ? '' : file.path)));
        }));
        this.app.workspace.onLayoutReady(() => {
            refresh();
            this.registerEvent(this.app.vault.on('create', f => this.stampLater(f)));
        });
    }

    async loadSettings() {
        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
        if ('apiPassword' in this.settings) {
            this.settings = migratePassword(this.settings, this.app.secretStorage);
            await this.saveSettings();
        }
    }
    async saveSettings() { await this.saveData(this.settings); }

    dbg(...args) {
        if (this.settings.debugMode) console.log('[PwnDoc 2Sync]', ...args);
    }

    // Step 1 — load CSV and open vuln search
    async openSearchModal({ quick = false } = {}) {
        const { csvPath } = this.settings;
        if (!csvPath) {
            new Notice('PwnDoc 2Sync: set the CSV path in Settings first.');
            return;
        }

        let text;
        try { text = await readFilePath(this.app, csvPath); }
        catch (e) { new Notice(`PwnDoc 2Sync: cannot read CSV — ${e.message}`); return; }

        let rows = parseCSV(text);
        if (rows.length === 0) {
            new Notice('PwnDoc 2Sync: CSV is empty or could not be parsed.');
            return;
        }

        this.chooseLocaleThenSearch(rows, { quick });
    }

    // Quick import — single command driven by the default source/language settings
    quickImport() {
        if (this.settings.quickImportSource === 'api') {
            if (!this.settings.apiUrl || !this.settings.apiUsername || !getApiPassword(this.app, this.settings)) {
                new Notice('PwnDoc 2Sync: save API credentials in Settings to use the quick API import.');
                return;
            }
            const { apiUrl: url, apiUsername: username, apiIgnoreSsl: ignoreSsl } = this.settings;
            const password = getApiPassword(this.app, this.settings);
            this.fetchFromApi({ url, username, password, ignoreSsl, save: false, quick: true });
        } else {
            this.openSearchModal({ quick: true });
        }
    }

    // Ask which locale to filter by (options built from the data), then open the vuln search
    chooseLocaleThenSearch(rows, { quick = false } = {}) {
        const locales = [...new Set(rows.map(r => r.locale).filter(Boolean))].sort();
        const openSearch = locale => {
            const filtered = locale ? rows.filter(r => r.locale === locale) : rows;
            if (filtered.length === 0) {
                new Notice(`PwnDoc 2Sync: no vulnerabilities found for locale "${locale}".`);
                return;
            }
            new VulnSearchModal(this.app, filtered, vuln => this.askPrefix(vuln)).open();
        };
        if (quick) {
            const pref = this.settings.quickImportLocale || '';
            if (pref && !locales.includes(pref)) {
                new Notice(`PwnDoc 2Sync: locale "${pref}" not present in the data — showing all locales.`);
                return openSearch('');
            }
            return openSearch(pref);
        }
        // Nothing to choose from → skip the extra modal
        if (locales.length <= 1) { openSearch(locales[0] || ''); return; }
        new LocaleModal(this.app, locales, this.settings.locale, openSearch).open();
    }

    // API import — step 1: ask for credentials (pre-filled from settings)
    openApiImportModal() {
        new ApiCredentialsModal(this.app, this.settings, creds => this.fetchFromApi(creds)).open();
    }

    // API import — step 2: connect, optionally save CSV, then open vuln search
    async fetchFromApi({ url, username, password, ignoreSsl, save, quick = false }) {
        if (save) {
            this.settings.apiUrl      = url;
            this.settings.apiUsername = username;
            this.app.secretStorage.setSecret(this.settings.apiPasswordSecret || SECRET_ID, password);
            this.settings.apiIgnoreSsl = ignoreSsl;
            await this.saveSettings();
        }
        const dbg = this.dbg.bind(this);
        const notice = new Notice('PwnDoc 2Sync: connecting…', 0);
        let rows;
        try {
            dbg('logging in to', url);
            const token = await pwndocLogin(url, username, password, ignoreSsl);
            dbg('login OK, fetching vuln list + custom fields');
            notice.setMessage('PwnDoc 2Sync: fetching vulnerability list…');
            const [list, cfLabels] = await Promise.all([
                pwndocFetchVulns(url, token, ignoreSsl),
                pwndocFetchCustomFields(url, token, ignoreSsl, dbg).catch(e => { dbg('custom fields fetch failed:', e.message); return {}; }),
            ]);
            dbg(`list returned ${list.length} vulns, ${Object.keys(cfLabels).length} custom field definitions`);

            const details = await pwndocFetchAllDetails(url, token, ignoreSsl, list, dbg, (done, total) => {
                notice.setMessage(`PwnDoc 2Sync: fetching details ${done}/${total}…`);
            });
            notice.hide();

            dbg(`fetched full detail for ${details.length}/${list.length} vulns`);
            this.cfLabels = cfLabels;
            rows = flattenVulnsFromApi(details, cfLabels);
            dbg(`flattened to ${rows.length} rows; sample keys:`, rows[0] ? Object.keys(rows[0]) : []);
            if (rows.length === 0) { new Notice('PwnDoc 2Sync: no vulnerabilities returned from API.'); return; }
        } catch (e) {
            notice.hide();
            new Notice(`PwnDoc 2Sync: ${e.message}`);
            console.error(e);
            return;
        }

        // Step 3: ask where to save the CSV (or skip). In quick mode, silently save
        // to the default output folder when set, otherwise skip saving entirely.
        if (quick) {
            if (this.settings.csvOutputFolder) {
                try {
                    const sep = this.settings.csvOutputFolder.includes('\\') ? '\\' : '/';
                    const csvPath = this.settings.csvOutputFolder.replace(/[\\/]+$/, '') + sep + 'vulnerabilities.csv';
                    require('fs').writeFileSync(csvPath, rowsToCsv(rows), 'utf8');
                    this.dbg(`quick import: CSV auto-saved to ${csvPath}`);
                } catch (e) {
                    this.dbg(`quick import: auto-save failed: ${e.message}`);
                }
            }
            return this.chooseLocaleThenSearch(rows, { quick: true });
        }

        new CsvOutputModal(this.app, this.settings.csvOutputFolder, async csvPath => {
            if (csvPath) {
                try {
                    require('fs').writeFileSync(csvPath, rowsToCsv(rows), 'utf8');
                    new Notice(`PwnDoc 2Sync: CSV saved to ${csvPath}`);
                } catch (e) {
                    new Notice(`PwnDoc 2Sync: could not save CSV — ${e.message}`);
                    console.error(e);
                    // Continue anyway — don't block the import
                }
            }

            // Step 4: choose locale, then open search
            this.chooseLocaleThenSearch(rows);
        }).open();
    }

    // ── Engagement sync: session and association ─────────────────────────────────

    // Logged-in session {url, token, ignoreSsl}; credentials from settings/secretStorage, popup if incomplete
    async session(force = false) {
        if (this._session && !force) return this._session;
        const s = this.settings;
        const password = getApiPassword(this.app, s);
        const creds = (s.apiUrl && s.apiUsername && password)
            ? { url: s.apiUrl, username: s.apiUsername, password, ignoreSsl: s.apiIgnoreSsl }
            : await new Promise(resolve => new ApiCredentialsModal(this.app, s, resolve, () => resolve(null)).open());
        if (!creds) throw new Error('login cancelled');
        const token = await pwndocLogin(creds.url, creds.username, creds.password, creds.ignoreSsl);
        if (creds.save) {
            Object.assign(this.settings, { apiUrl: creds.url, apiUsername: creds.username, apiIgnoreSsl: creds.ignoreSsl });
            this.app.secretStorage.setSecret(this.settings.apiPasswordSecret || SECRET_ID, creds.password);
            await this.saveSettings();
        }
        this._session = { url: creds.url, token, ignoreSsl: creds.ignoreSsl };
        return this._session;
    }

    // Authenticated call; one re-login when the token is rejected
    async api(method, path, opts = {}) {
        let sess = await this.session();
        try { return await pwndocApi(sess.url, sess.token, method, path, { ignoreSsl: sess.ignoreSsl, ...opts }); }
        catch (e) {
            if (!/HTTP 401/.test(e.message)) throw e;
            sess = await this.session(true);
            return pwndocApi(sess.url, sess.token, method, path, { ignoreSsl: sess.ignoreSsl, ...opts });
        }
    }

    pickAudit() {
        return new Promise(async resolve => {
            let audits;
            try { audits = (await this.api('GET', '/api/audits')) || []; }
            catch (e) { new Notice(`PwnDoc 2Sync: ${e.message}`); return resolve(null); }
            new AuditPickModal(this.app, audits, resolve).open();
        });
    }

    // Associate a folder with an engagement and write it on every note it owns (subfolders included)
    async associateFolder(folderArg) {
        const run = async folder => {
            const audit = await this.pickAudit();
            if (!audit) return;
            this.settings.folderAudits[folder] = { auditId: audit._id, name: audit.name };
            await this.saveSettings();
            await this.stampFolder(folder);
        };
        if (folderArg !== undefined) return run(folderArg);
        const active = this.app.workspace.getActiveFile();
        new FolderModal(this.app, active?.parent?.path === '/' ? '' : (active?.parent?.path ?? ''), run).open();
    }

    // pwndoc_audit_id + pwndoc_audit (the engagement name) in the frontmatter of the notes `folder` owns
    async stampFolder(folder, { quiet = false } = {}) {
        const entry = this.settings.folderAudits[folder];
        if (!entry) return;
        const files = this.app.vault.getMarkdownFiles().filter(f => !folder || f.path.startsWith(folder + '/'));
        const owned = new Set(notesOwnedBy(files.map(f => f.path), this.settings.folderAudits, folder));
        let done = 0, skipped = 0;
        for (const f of files.filter(x => owned.has(x.path))) {
            const fm = this.app.metadataCache.getFileCache(f)?.frontmatter;
            if (linkedElsewhere(fm, entry)) { skipped++; continue; }
            if (!shouldStamp(fm, entry)) continue;
            await this.app.fileManager.processFrontMatter(f, p => { p.pwndoc_audit_id = entry.auditId; p.pwndoc_audit = entry.name; });
            done++;
        }
        if (!quiet) {
            new Notice(`PwnDoc 2Sync: "${folder || '/'}" → ${entry.name}; engagement written on ${done} note(s)`
                + (skipped ? `, ${skipped} skipped (linked to a finding of another engagement)` : '') + '.');
        }
    }

    // Re-read the engagement names from PwnDoc (if reachable) and rewrite the attribute everywhere
    async refreshEngagementAttributes() {
        try {
            const audits = (await this.api('GET', '/api/audits')) || [];
            for (const entry of Object.values(this.settings.folderAudits)) {
                const a = audits.find(x => x._id === entry.auditId);
                if (a) entry.name = a.name;
            }
            await this.saveSettings();
        } catch (e) { new Notice(`PwnDoc 2Sync: names not refreshed (${e.message}), using the stored ones.`); }
        for (const folder of Object.keys(this.settings.folderAudits)) await this.stampFolder(folder, { quiet: true });
        new Notice('PwnDoc 2Sync: engagement attribute refreshed on all associated folders.');
    }

    // A note created in or moved into an associated folder gets the attribute too
    stampLater(file) {
        if (file.extension !== 'md') return;
        const entry = folderAuditFor(file.path, this.settings.folderAudits);
        if (!entry) return;
        setTimeout(async () => {
            const f = this.app.vault.getAbstractFileByPath(file.path);
            if (!f) return;
            const fm = this.app.metadataCache.getFileCache(f)?.frontmatter;
            if (shouldStamp(fm, entry)) {
                await this.app.fileManager.processFrontMatter(f, p => { p.pwndoc_audit_id = entry.auditId; p.pwndoc_audit = entry.name; });
            }
        }, 500);
    }

    // Status bar text and the buttons in the header of the open note
    refreshChrome() {
        const view = this.app.workspace.getActiveViewOfType(MarkdownView);
        const file = view?.file;
        const fm = file && this.app.metadataCache.getFileCache(file)?.frontmatter;
        const entry = file && folderAuditFor(file.path, this.settings.folderAudits);
        const st = file ? engagementStatus(fm, entry) : { text: '', linked: false };
        const warn = file && this.remoteWarn.get(file.path);
        this.statusEl.setText(st.text + (warn?.length ? ` · changed on PwnDoc: ${warn.map(k => labelOf(defOf(k))).join(', ')}` : ''));
        this.statusEl.style.color = warn?.length ? 'var(--text-warning)' : '';
        this.statusEl.style.display = st.text ? '' : 'none';
        this.statusEl.title = st.text ? 'PwnDoc 2Sync: click for quick actions' : '';
        if (!view) return;

        this.headerActions ||= new WeakMap();
        let a = this.headerActions.get(view);
        if (!a) {
            const act = (icon, title, fn) => view.addAction(icon, title, () => {
                this.app.workspace.setActiveLeaf(view.leaf, { focus: true });
                fn();
            });
            a = {
                compare: act('git-compare', 'Compare with PwnDoc and merge', () => this.compareWithPwndoc()),
                history: act('history', 'PwnDoc sync history (rollback)', () => this.rollbackFromHistory()),
                send:    act('upload-cloud', 'Send note to PwnDoc (select or create the finding)', () => this.sendToPwndoc()),
            };
            this.headerActions.set(view, a);
        }
        const related = !!(fm?.pwndoc_audit_id || fm?.pwndoc || entry);
        const show = (el, v) => { el.style.display = v ? '' : 'none'; };
        show(a.compare, related && st.linked);
        show(a.history, related && st.linked);
        show(a.send, related && !st.linked);
    }

    openQuickMenu(evt) {
        const menu = new Menu();
        const item = (title, icon, fn) => menu.addItem(i => i.setTitle(title).setIcon(icon).onClick(fn));
        item('Send note to PwnDoc (select or create the finding)', 'upload-cloud', () => this.sendToPwndoc());
        item('Compare with PwnDoc and merge', 'git-compare', () => this.compareWithPwndoc());
        item('Associate note to finding', 'link', () => this.associateNote());
        item('Create PwnDoc finding for this note', 'plus-circle', () => this.createFindingForNote());
        item('Import findings that exist only on PwnDoc', 'download', () => this.importFindingsFromPwndoc());
        item('Sync history (rollback)', 'history', () => this.rollbackFromHistory());
        item('Mark finding as completed', 'check-circle', () => this.setCompleted(true));
        item('Reopen finding', 'rotate-ccw', () => this.setCompleted(false));
        item('Lint this note', 'list-checks', () => this.lintCurrentNote());
        item('Unlink from finding', 'unlink', () => this.unlinkNote());
        menu.addSeparator();
        item('Engagement dashboard', 'layout-dashboard', () => this.openDashboard());
        item('Find orphan notes', 'search-x', () => this.findOrphans());
        item('Check General Information', 'clipboard-check', () => this.checkGeneralCommand());
        item('Choose report template', 'file-cog', () => this.setTemplateCommand());
        item('Generate report', 'file-output', () => this.generateReportCommand());
        menu.addSeparator();
        item('Associate folder to engagement', 'folder-plus', () => this.associateFolder());
        item('Refresh engagement attribute on notes', 'refresh-cw', () => this.refreshEngagementAttributes());
        menu.showAtMouseEvent(evt);
    }

    // Resolve the audit for a note: its frontmatter, then the nearest associated folder, else ask
    async auditIdFor(file) {
        const fm = this.app.metadataCache.getFileCache(file)?.frontmatter;
        return resolveAuditId(file.path, fm, this.settings.folderAudits)
            ?? (await this.pickAudit())?._id ?? null;
    }

    // One entry point to get a note into PwnDoc: linked notes go straight to the compare, others first
    // pick the finding of the engagement (best title match first) or create it, then the compare opens
    // with Evidenza selected
    async sendToPwndoc() {
        const file = this.app.workspace.getActiveFile();
        if (!file) { new Notice('PwnDoc 2Sync: open a note first.'); return; }
        if (this.app.metadataCache.getFileCache(file)?.frontmatter?.pwndoc_finding_id) return this.compareWithPwndoc();
        try {
            const auditId = await this.auditIdFor(file);
            if (!auditId) return;
            const audit = await this.api('GET', `/api/audits/${auditId}`);
            const choice = await new Promise(r => new FindingOrCreateModal(this.app, audit.findings || [], titleFromBasename(file.basename), r).open());
            if (!choice) return;
            if (choice.create) return this.createFindingForNote(auditId);
            await this.app.fileManager.processFrontMatter(file, fm => {
                fm.pwndoc_audit_id = auditId;
                fm.pwndoc_audit = audit.name;
                fm.pwndoc_finding_id = choice.finding._id;
            });
            new Notice(`PwnDoc 2Sync: linked to "${choice.finding.title}"`);
            await this.compareWithPwndoc({ auditId, findingId: choice.finding._id });
        } catch (e) { new Notice(`PwnDoc 2Sync: ${e.message}`); console.error(e); }
    }

    async associateNote() {
        const file = this.app.workspace.getActiveFile();
        if (!file) { new Notice('PwnDoc 2Sync: open a note first.'); return; }
        const auditId = await this.auditIdFor(file);
        if (!auditId) return;
        let audit;
        try { audit = await this.api('GET', `/api/audits/${auditId}`); }
        catch (e) { new Notice(`PwnDoc 2Sync: ${e.message}`); return; }
        const title = titleFromBasename(file.basename);
        if (!matchFinding(title, audit.findings || [])
            && await new Promise(r => new ConfirmModal(this.app, `No finding titled "${title}" in this audit. Create it now?`, r).open())) {
            return this.createFindingForNote();
        }
        if (!audit.findings?.length) { new Notice('PwnDoc 2Sync: this audit has no findings yet.'); return; }
        new FindingPickModal(this.app, audit.findings, title, async finding => {
            if (!finding) return;
            await this.app.fileManager.processFrontMatter(file, fm => {
                fm.pwndoc_audit_id = auditId;
                fm.pwndoc_audit = audit.name;
                fm.pwndoc_finding_id = finding._id;
            });
            new Notice(`PwnDoc 2Sync: linked to "${finding.title}"`);
        }).open();
    }

    // ── Engagement sync: compare / merge ─────────────────────────────────────────

    // Everything the push/pull pipeline needs from the Obsidian side
    syncCtx(file, findingId, auditId) {
        const app = this.app;
        const adapter = app.vault.adapter;
        const ctx = {
            notePath: file.path,
            noteInfo: { basename: file.basename, fm: app.metadataCache.getFileCache(file)?.frontmatter || {} },
            api: (m, p, o) => this.api(m, p, o),
            mdToHtml: md => mdToHtml(app, md, true),
            htmlToMd,
            cfLabels: this.cfLabels || {},
            cfTypes: this.cfTypes || {},
            resolvePath: src => (app.metadataCache.getFirstLinkpathDest(src, file.path)
                ?? app.vault.getAbstractFileByPath(normalizePath(`${parentDir(file.path)}/${src}`)))?.path ?? null,
            readBinary: async p => Buffer.from(await adapter.readBinary(p)),
            imageCache: this.settings.imageCache,
            save: () => this.saveSettings(),
            exists: p => adapter.exists(p),
            writeBinary: async (p, buf) => {
                const dir = parentDir(p);
                if (dir && !(await adapter.exists(dir))) await adapter.mkdir(dir);
                await adapter.writeBinary(p, buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
            },
            adapter,
            historyDir: historyDir(this.manifest.dir, findingId),
            historyLimit: this.settings.historyLimit,
            attachmentsFolder: this.settings.attachmentsFolder,
            confirmEmpty: (key, direction) => new Promise(resolve => new ConfirmModal(app,
                direction === 'push'
                    ? `The "${labelOf(defOf(key))}" section of the note is empty but PwnDoc has content. Overwrite PwnDoc with an empty section?`
                    : `PwnDoc has no content in "${labelOf(defOf(key))}" but the note does. Overwrite the note section with an empty one?`,
                resolve).open()),
        };
        ctx.normalize = md => normalizeMd(app, md, src => canonicalImageKey(ctx, auditId, src));
        return ctx;
    }

    async compareWithPwndoc(override = {}) {
        const file = this.app.workspace.getActiveFile();
        const fm = file && this.app.metadataCache.getFileCache(file)?.frontmatter;
        if (!file) { new Notice('PwnDoc 2Sync: open a note first.'); return; }
        const link = resolveFindingLink(file.path, fm, this.settings.folderAudits, override);
        if (!link) { new Notice('PwnDoc 2Sync: associate this note to a finding first.'); return; }
        const { auditId, findingId } = link;

        let audit, finding, rows, noteMd;
        await this.loadCustomFieldDefs();
        const ctx = this.syncCtx(file, findingId, auditId);
        try {
            ({ audit, finding } = await fetchFinding(ctx, auditId, findingId));
            noteMd = await this.app.vault.read(file);
            rows = await buildComparison(ctx, noteMd, finding, SECTION_DEFS.map(d => d.key), ctx.noteInfo, await loadBase(ctx.adapter, ctx.historyDir));
        } catch (e) { new Notice(`PwnDoc 2Sync: ${e.message}`); console.error(e); return; }

        new MergeModal(this.app, rows, {
            defaultKeys: DEFAULT_SYNC_SECTIONS,
            auditState: audit.state,
            onApply: async ({ push, pull, merge, force }) => {
                try {
                    if (push.length && !(await this.lintGate(file, noteMd, push, audit.language, ctx))) return;
                    if (Object.keys(merge).length) {
                        const r = await applyMerged(ctx, { auditId, findingId, noteMd, merged: merge, snapshotFinding: finding, force });
                        await this.app.vault.modify(file, r.noteMd);
                        noteMd = r.noteMd;
                    }
                    if (push.length) {
                        await pushSections(ctx, { auditId, findingId, noteMd, sections: push, snapshotFinding: finding, force });
                    }
                    if (pull.length) {
                        const r = await pullSections(ctx, { auditId, findingId, noteMd: await this.app.vault.read(file), sections: pull });
                        await this.app.vault.modify(file, r.noteMd);
                        await this.applyPullMeta(file, r.meta);
                    }
                    new Notice(`PwnDoc 2Sync: pushed ${push.length}, pulled ${pull.length}, merged ${Object.keys(merge).length} section(s).`);
                    this.checkRemote(file);
                } catch (e) { new Notice(`PwnDoc 2Sync: ${e.message}`); console.error(e); }
            },
        }).open();
    }

    async rollbackFromHistory() {
        const file = this.app.workspace.getActiveFile();
        const fm = file && this.app.metadataCache.getFileCache(file)?.frontmatter;
        if (!fm?.pwndoc_finding_id) { new Notice('PwnDoc 2Sync: associate this note to a finding first.'); return; }
        const auditId = resolveAuditId(file.path, fm, this.settings.folderAudits);
        const findingId = fm.pwndoc_finding_id;
        await this.loadCustomFieldDefs();
        const ctx = this.syncCtx(file, findingId, auditId);
        const entries = await listHistory(ctx.adapter, ctx.historyDir);
        if (!entries.length) { new Notice('PwnDoc 2Sync: no history for this finding yet.'); return; }

        new HistoryModal(this.app, entries, async ({ entry, side }) => {
            try {
                const { audit, finding } = await fetchFinding(ctx, auditId, findingId);
                const noteMd = await this.app.vault.read(file);
                const keys = SECTION_DEFS.filter(d => side === 'remote' || !d.source).map(d => d.key);
                const rows = await buildRollbackComparison(ctx, entry, side, finding, noteMd, keys);
                new RollbackModal(this.app, rows, {
                    entry, side, auditState: audit.state,
                    onApply: async ({ sections, force }) => {
                        try {
                            if (side === 'remote') {
                                await rollbackSections(ctx, { entry, side, sections, noteMd, auditId, findingId, force, snapshotFinding: finding });
                            } else {
                                const r = await rollbackSections(ctx, { entry, side, sections, noteMd: await this.app.vault.read(file), auditId, findingId, force });
                                await this.app.vault.modify(file, r.noteMd);
                            }
                            new Notice(`PwnDoc 2Sync: restored ${sections.length} section(s).`);
                        } catch (e) { new Notice(`PwnDoc 2Sync: ${e.message}`); console.error(e); }
                    },
                }).open();
            } catch (e) { new Notice(`PwnDoc 2Sync: ${e.message}`); console.error(e); }
        }).open();
    }

    // Title and CVSS pulled from PwnDoc: rename the note (keeping its VT-NN prefix) and refresh the frontmatter
    async applyPullMeta(file, meta) {
        const upd = metaToFrontmatter(meta, this.app.metadataCache.getFileCache(file)?.frontmatter);
        if (Object.keys(upd).length) await this.app.fileManager.processFrontMatter(file, fm => Object.assign(fm, upd));
        if (meta.cvssv3 !== undefined) {
            if (isValidCvss31(meta.cvssv3)) {
                await this.app.fileManager.processFrontMatter(file, fm => Object.assign(fm, cvssFrontmatter(meta.cvssv3)));
            } else new Notice(`PwnDoc 2Sync: PwnDoc CVSS "${meta.cvssv3}" is not a 3.1 vector, frontmatter left unchanged.`);
        }
        if (meta.title) {
            const prefix = file.basename.match(/^(VT|M)-\d+ - /)?.[0] || '';
            const dir = parentDir(file.path);
            const target = normalizePath(`${dir ? dir + '/' : ''}${prefix}${meta.title.replace(FILENAME_UNSAFE_RE, '-')}.md`);
            if (target === file.path) return;
            if (this.app.vault.getAbstractFileByPath(target)) { new Notice(`PwnDoc 2Sync: cannot rename, "${target}" already exists.`); return; }
            await this.app.fileManager.renameFile(file, target);
        }
    }

    // Note without a finding: link an existing one with the same title, else create it from the library or from scratch
    async createFindingForNote(auditIdArg) {
        const file = this.app.workspace.getActiveFile();
        if (!file) { new Notice('PwnDoc 2Sync: open a note first.'); return; }
        const fm = this.app.metadataCache.getFileCache(file)?.frontmatter || {};
        const auditId = auditIdArg ?? await this.auditIdFor(file);
        if (!auditId) return;
        const confirm = message => new Promise(resolve => new ConfirmModal(this.app, message, resolve).open());
        try {
            const audit = await this.api('GET', `/api/audits/${auditId}`);
            const title = titleFromBasename(file.basename);
            const existing = matchFinding(title, audit.findings || []);
            if (existing && await confirm(`The audit already has a finding titled "${existing.title}". Link this note to it instead of creating a new one?`)) {
                await this.app.fileManager.processFrontMatter(file, f => { f.pwndoc_audit_id = auditId; f.pwndoc_audit = audit.name; f.pwndoc_finding_id = existing._id; });
                new Notice(`PwnDoc 2Sync: linked to "${existing.title}"`);
                return;
            }

            const vulns = (await this.api('GET', '/api/vulnerabilities')) || [];
            const pick = await new Promise(resolve => new LibraryVulnPickModal(this.app, vulns, fm.pwndoc_id, audit.language, resolve).open());
            if (!pick) return;
            const body = pick === 'blank'
                ? buildFindingFromNote(title, fm.cvss_vector, fm.category || 'WAPT')
                : buildFindingFromLibrary(await this.api('GET', `/api/vulnerabilities/detail/${pick._id}`), audit.language);

            const force = audit.state !== 'EDIT'
                && await confirm(`The audit is in state ${audit.state}. Enforce: create the finding anyway?`);
            const findingId = await createFinding({ api: (m, p, o) => this.api(m, p, o) }, auditId, body, force);
            await this.app.fileManager.processFrontMatter(file, f => { f.pwndoc_audit_id = auditId; f.pwndoc_audit = audit.name; f.pwndoc_finding_id = findingId; });
            await recordHistory(this.app.vault.adapter, historyDir(this.manifest.dir, findingId), {
                ts: new Date().toISOString(), op: 'create', forced: force, auditId, findingId, notePath: file.path,
                sections: [], remoteBefore: null, localBefore: await this.app.vault.read(file),
            }, this.settings.historyLimit);
            new Notice(`PwnDoc 2Sync: created "${body.title}"`);
            await this.compareWithPwndoc({ auditId, findingId }); // opens the merge with Evidence preselected
        } catch (e) { new Notice(`PwnDoc 2Sync: ${e.message}`); console.error(e); }
    }

    // Findings that exist on PwnDoc but have no note in the vault: create the notes from them (download only)
    async importFindingsFromPwndoc(folderArg, auditIdArg) {
        const active = this.app.workspace.getActiveFile();
        try {
            const auditId = auditIdArg ?? await this.currentAuditId(folderArg);
            if (!auditId) return;

            const audit = await this.api('GET', `/api/audits/${auditId}`);
            const linked = new Set(this.app.vault.getMarkdownFiles()
                .map(f => this.app.metadataCache.getFileCache(f)?.frontmatter?.pwndoc_finding_id).filter(Boolean));
            const missing = missingFindings(audit, linked);
            if (!missing.length) { new Notice(`PwnDoc 2Sync: every finding of "${audit.name}" already has a note.`); return; }

            const picked = await new Promise(resolve => new MissingFindingsModal(this.app, missing, resolve).open());
            if (!picked?.length) return;
            const prefix = await new Promise(resolve => new PrefixModal(this.app, resolve).open());
            const folder = folderArg ?? await new Promise(resolve =>
                new FolderModal(this.app, active?.parent?.path === '/' ? '' : (active?.parent?.path ?? ''), resolve).open());

            let n = 0;
            for (const finding of picked) {
                const file = await this.createVulnNote(findingToNoteRow(finding, audit), prefix, folder,
                    { findingId: finding._id, audit, open: picked.length === 1 });
                if (!file) continue;
                const ctx = this.syncCtx(file, finding._id, auditId);
                const r = await pullSections(ctx, { auditId, findingId: finding._id, noteMd: await this.app.vault.read(file), sections: IMPORT_SECTIONS });
                await this.app.vault.modify(file, r.noteMd);
                n++;
            }
            new Notice(`PwnDoc 2Sync: imported ${n} finding(s) from "${audit.name}".`);
        } catch (e) { new Notice(`PwnDoc 2Sync: ${e.message}`); console.error(e); }
    }

    // ── Dashboard, bulk sync, orphans, unlink ────────────────────────────────────

    // Engagement of the open note, or of the folder given, else ask
    async currentAuditId(folderArg) {
        const active = this.app.workspace.getActiveFile();
        const id = folderArg !== undefined
            ? folderAuditFor(`${folderArg ? folderArg + '/' : ''}x.md`, this.settings.folderAudits)?.auditId
            : active ? resolveAuditId(active.path, this.app.metadataCache.getFileCache(active)?.frontmatter, this.settings.folderAudits) : null;
        return id || (await this.pickAudit())?._id || null;
    }

    // id -> label and id -> field type of the PwnDoc custom fields, needed to read and write them
    async loadCustomFieldDefs() {
        if (this.cfTypes) return;
        try {
            const defs = (await this.api('GET', '/api/data/custom-fields')) || [];
            this.cfLabels = { ...Object.fromEntries(defs.map(d => [d._id, d.label])), ...this.cfLabels };
            this.cfTypes = Object.fromEntries(defs.map(d => [d._id, d.fieldType]));
            this.cfDefs = defs;
        } catch (e) { this.dbg('custom field definitions not loaded:', e.message); }
    }

    // Notes of an engagement, with the text of the linked ones
    async notesOfAudit(auditId) {
        const out = [];
        for (const f of this.app.vault.getMarkdownFiles()) {
            const fm = this.app.metadataCache.getFileCache(f)?.frontmatter || {};
            if (resolveAuditId(f.path, fm, this.settings.folderAudits) !== auditId) continue;
            if (!fm.pwndoc_finding_id && !/^(VT|M)-\d+ - /.test(f.basename)) continue;
            out.push({ path: f.path, basename: f.basename, fm, md: fm.pwndoc_finding_id ? await this.app.vault.cachedRead(f) : '' });
        }
        return out;
    }

    linkedFindingIds() {
        return new Set(this.app.vault.getMarkdownFiles()
            .map(f => this.app.metadataCache.getFileCache(f)?.frontmatter?.pwndoc_finding_id).filter(Boolean));
    }

    async openDashboard(folderArg) {
        const notice = new Notice('PwnDoc 2Sync: reading the engagement…', 0);
        try {
            const auditId = await this.currentAuditId(folderArg);
            if (!auditId) return;
            await this.loadCustomFieldDefs();
            const audit = await this.api('GET', `/api/audits/${auditId}`);
            const data = await buildDashboard(
                (n, findingId) => this.syncCtx(this.app.vault.getAbstractFileByPath(n.path), findingId, auditId),
                { audit, notes: await this.notesOfAudit(auditId), linkedIds: this.linkedFindingIds(),
                  loadBase: id => loadBase(this.app.vault.adapter, historyDir(this.manifest.dir, id)) });
            const tpl = await this.api('GET', '/api/templates').then(t => templateLabel(audit, t || []), () => null);
            new DashboardModal(this.app, this, data, { title: audit.name, subtitle: [`state ${audit.state}`, tpl && `report template: ${tpl}`, audit.language].filter(Boolean).join(' · '), audit }).open();
        } catch (e) { new Notice(`PwnDoc 2Sync: ${e.message}`); console.error(e); }
        finally { notice.hide(); }
    }

    // Push or pull the same sections of several notes; per note, only what bulkPlan allows
    async bulkSync(audit, rows, sections, direction, force) {
        const done = [], skipped = [], failed = [];
        for (const row of rows) {
            const file = this.app.vault.getAbstractFileByPath(row.path);
            const plan = bulkPlan(row, direction, sections);
            if (plan.blocked.length) skipped.push(`${row.title}: ${plan.blocked.map(b => `${b.key} (${b.why})`).join(', ')}`);
            if (!file || !plan.run.length) continue;
            try {
                const ctx = this.syncCtx(file, row.findingId, audit._id);
                const noteMd = await this.app.vault.read(file);
                if (direction === 'push') {
                    const err = lintNote(noteMd, { sections: plan.run, fm: ctx.noteInfo.fm, basename: file.basename, locale: audit.language, exists: s => !!ctx.resolvePath(s) })
                        .find(i => i.level === 'error');
                    if (err) throw new Error(`lint: ${err.message}`);
                    await pushSections(ctx, { auditId: audit._id, findingId: row.findingId, noteMd, sections: plan.run, snapshotFinding: audit.findings.find(f => f._id === row.findingId), force });
                } else {
                    const r = await pullSections(ctx, { auditId: audit._id, findingId: row.findingId, noteMd, sections: plan.run });
                    await this.app.vault.modify(file, r.noteMd);
                    await this.applyPullMeta(file, r.meta);
                }
                done.push(row.title);
            } catch (e) { failed.push(`${row.title}: ${e.message}`); console.error(e); }
        }
        const text = [`${direction === 'push' ? 'Pushed' : 'Pulled'} ${done.length} note(s).`,
            ...(skipped.length ? [`Skipped (not overwriting the other side):`, ...skipped] : []),
            ...(failed.length ? ['Failed:', ...failed] : [])].join('\n');
        new Notice(`PwnDoc 2Sync: ${text}`, skipped.length || failed.length ? 15000 : 5000);
        console.log('[PwnDoc 2Sync] bulk', direction, { done, skipped, failed });
    }

    // Remove the finding link (the engagement attribute stays). Returns true when done.
    async unlinkNote(file) {
        if (file === undefined) file = this.app.workspace.getActiveFile(); // an explicit null means the note is gone
        const fm = file && this.app.metadataCache.getFileCache(file)?.frontmatter;
        if (!fm?.pwndoc_finding_id) { new Notice('PwnDoc 2Sync: this note is not linked to a finding.'); return false; }
        if (!(await new Promise(r => new ConfirmModal(this.app, `Unlink "${file.basename}" from its PwnDoc finding? The note and the finding stay as they are; the sync history is kept.`, r).open()))) return false;
        await this.app.fileManager.processFrontMatter(file, f => { delete f.pwndoc_finding_id; });
        this.remoteWarn.delete(file.path);
        new Notice('PwnDoc 2Sync: note unlinked.');
        return true;
    }

    // Notes of the whole vault whose finding or engagement no longer exists on PwnDoc
    async findOrphans() {
        const notice = new Notice('PwnDoc 2Sync: checking linked notes…', 0);
        try {
            const byAudit = new Map();
            for (const f of this.app.vault.getMarkdownFiles()) {
                const fm = this.app.metadataCache.getFileCache(f)?.frontmatter;
                const auditId = fm?.pwndoc_finding_id && resolveAuditId(f.path, fm, this.settings.folderAudits);
                if (auditId) (byAudit.get(auditId) || byAudit.set(auditId, []).get(auditId)).push({ path: f.path, fm });
            }
            const orphans = [];
            for (const [auditId, notes] of byAudit) {
                let audit = null;
                try { audit = await this.api('GET', `/api/audits/${auditId}`); }
                catch (e) { if (!/HTTP 404/.test(e.message)) throw e; }
                for (const n of notes) {
                    const reason = orphanReason(n.fm, audit);
                    if (reason) orphans.push({ path: n.path, findingId: n.fm.pwndoc_finding_id, reason });
                }
            }
            new DashboardModal(this.app, this, { rows: [], orphans, unlinked: [], missing: [] }, { title: 'Orphan notes', subtitle: 'linked notes whose finding or engagement is gone from PwnDoc', audit: null }).open();
        } catch (e) { new Notice(`PwnDoc 2Sync: ${e.message}`); console.error(e); }
        finally { notice.hide(); }
    }

    // ── Lint, remote changes, completion status, report, figures ─────────────────

    // false when the push must not go on: errors block, warnings ask
    async lintGate(file, md, keys, locale, ctx) {
        const issues = lintNote(md, { sections: keys, fm: ctx.noteInfo.fm, basename: file.basename, locale, exists: s => !!ctx.resolvePath(s) });
        if (!issues.length) return true;
        return new Promise(resolve => new LintModal(this.app, issues, resolve).open());
    }

    async lintCurrentNote() {
        const file = this.app.workspace.getActiveFile();
        if (!file) { new Notice('PwnDoc 2Sync: open a note first.'); return; }
        const md = await this.app.vault.read(file);
        const ctx = this.syncCtx(file, '', '');
        const body = Object.keys(parseSections(md)).filter(k => !defOf(k).source && k !== 'customFields');
        const locale = ctx.noteInfo.fm.locale || '';
        new LintModal(this.app, lintNote(md, { sections: [...body, 'title', 'cvssv3', 'vulnType', 'priority', 'remediationComplexity'],
            fm: ctx.noteInfo.fm, basename: file.basename, locale, exists: s => !!ctx.resolvePath(s) }), null).open();
    }

    hasCredentials() {
        const s = this.settings;
        return !!(s.apiUrl && s.apiUsername && getApiPassword(this.app, s));
    }

    // Has PwnDoc changed a synced section since the last sync of this note? Never prompts, never writes.
    async checkRemote(file) {
        if (!this.settings.watchRemote || !file || file.extension !== 'md' || !this.hasCredentials()) return;
        const fm = this.app.metadataCache.getFileCache(file)?.frontmatter;
        const link = resolveFindingLink(file.path, fm, this.settings.folderAudits);
        if (!link || this.checking.has(file.path) || Date.now() < this.remoteBackoff) return;
        this.checking.add(file.path);
        try {
            await this.loadCustomFieldDefs();
            const ctx = this.syncCtx(file, link.findingId, link.auditId);
            const base = await loadBase(ctx.adapter, ctx.historyDir);
            if (!base) { this.remoteWarn.delete(file.path); return; }
            const { finding } = await fetchFinding(ctx, link.auditId, link.findingId);
            const rows = await buildComparison(ctx, await this.app.vault.cachedRead(file), finding, SECTION_DEFS.map(d => d.key), ctx.noteInfo, base);
            const keys = remoteChanges(rows);
            if (keys.length) this.remoteWarn.set(file.path, keys); else this.remoteWarn.delete(file.path);
            const sig = keys.join(',');
            if (keys.length && this.remoteSeen.get(file.path) !== sig) {
                this.remoteSeen.set(file.path, sig);
                new Notice(`PwnDoc 2Sync: "${file.basename}" changed on PwnDoc (${keys.map(k => labelOf(defOf(k))).join(', ')}). Compare before you push.`, 8000);
            }
            if (!keys.length) this.remoteSeen.delete(file.path);
        } catch (e) { this.remoteBackoff = Date.now() + 10 * 60000; this.dbg('remote check failed, pausing the background check for 10 minutes:', e.message); }
        finally { this.checking.delete(file.path); this.refreshChrome(); }
    }

    // Mark the finding of the open note completed (or open again) on PwnDoc and mirror it in the frontmatter
    async setCompleted(completed) {
        const file = this.app.workspace.getActiveFile();
        const fm = file && this.app.metadataCache.getFileCache(file)?.frontmatter;
        const link = file && resolveFindingLink(file.path, fm, this.settings.folderAudits);
        if (!link) { new Notice('PwnDoc 2Sync: associate this note to a finding first.'); return; }
        try {
            const ctx = this.syncCtx(file, link.findingId, link.auditId);
            const args = { ...link, completed, localBefore: await this.app.vault.read(file) };
            try { await setFindingStatus(ctx, { ...args, force: false }); }
            catch (e) {
                if (!(e instanceof AuditLockedError) || !(await new Promise(r => new ConfirmModal(this.app, `${e.message}. Enforce this change?`, r).open()))) throw e;
                await setFindingStatus(ctx, { ...args, force: true });
            }
            const upd = metaToFrontmatter({ status: completed ? 'completed' : 'in progress' }, fm);
            if (Object.keys(upd).length) await this.app.fileManager.processFrontMatter(file, f => Object.assign(f, upd));
            new Notice(`PwnDoc 2Sync: finding ${completed ? 'marked as completed' : 'reopened'} on PwnDoc.`);
            this.checkRemote(file);
        } catch (e) { new Notice(`PwnDoc 2Sync: ${e.message}`); console.error(e); }
    }

    // Pick the report template of an engagement and store it on the audit. Returns the template id, or null if cancelled.
    async chooseAuditTemplate(auditId) {
        const [audit, templates] = await Promise.all([this.api('GET', `/api/audits/${auditId}`), this.api('GET', '/api/templates')]);
        if (!templates?.length) { new Notice('PwnDoc 2Sync: PwnDoc has no report templates.'); return null; }
        const templateId = await new Promise(r => new TemplatePickModal(this.app, templates, templateIdOf(audit), r).open());
        if (!templateId) return null;
        const ctx = { api: (m, p, o) => this.api(m, p, o) };
        let res;
        try { res = await setAuditTemplate(ctx, { auditId, templateId, force: false }); }
        catch (e) {
            if (!(e instanceof AuditLockedError) || !(await new Promise(r => new ConfirmModal(this.app, `${e.message}. Enforce this change of template?`, r).open()))) throw e;
            res = await setAuditTemplate(ctx, { auditId, templateId, force: true });
        }
        const was = res.previous ? templates.find(t => t._id === res.previous)?.name || res.previous : 'none';
        new Notice(res.changed
            ? `PwnDoc 2Sync: template of "${audit.name}" is now "${templates.find(t => t._id === templateId).name}" (was: ${was}).`
            : `PwnDoc 2Sync: "${audit.name}" already uses that template.`);
        return templateId;
    }

    async setTemplateCommand() {
        try {
            const auditId = await this.currentAuditId();
            if (auditId) await this.chooseAuditTemplate(auditId);
        } catch (e) { new Notice(`PwnDoc 2Sync: ${e.message}`); console.error(e); }
    }

    // Why did the export fail? Check the General Information of the engagement and show what is missing
    async explainReportFailure(auditId, error) {
        let audit = { name: auditId };
        let missing = [];
        try {
            await this.loadCustomFieldDefs();
            audit = await this.api('GET', `/api/audits/${auditId}`);
            missing = missingGeneralFields(audit, this.generalRequired(), this.cfDefs || []);
        } catch (e) { this.dbg('general information check failed:', e.message); }
        new InfoModal(this.app, 'Report export failed', reportFailureLines(error, audit.name, missing)).open();
    }

    generalRequired() {
        return String(this.settings.generalRequired || '').split(',').map(k => k.trim()).filter(Boolean);
    }

    async checkGeneralCommand() {
        try {
            const auditId = await this.currentAuditId();
            if (!auditId) return;
            await this.loadCustomFieldDefs();
            const audit = await this.api('GET', `/api/audits/${auditId}`);
            const missing = missingGeneralFields(audit, this.generalRequired(), this.cfDefs || []);
            new InfoModal(this.app, `General Information of "${audit.name}"`,
                missing.length ? ['Missing:', ...missing.map(m => `- ${m.label}`)] : ['All the mandatory fields are filled in.']).open();
        } catch (e) { new Notice(`PwnDoc 2Sync: ${e.message}`); console.error(e); }
    }

    // Generate the report of an engagement from the template stored on it (asked for when there is none) and save it in the vault
    async generateReportCommand() {
        try {
            const auditId = await this.currentAuditId();
            if (!auditId) return;
            const audit = await this.api('GET', `/api/audits/${auditId}`);
            if (!templateIdOf(audit) && !(await this.chooseAuditTemplate(auditId))) return;

            const notice = new Notice('PwnDoc 2Sync: generating the report…', 0);
            let r;
            try { r = await generateReport({ api: (m, p, o) => this.api(m, p, o) }, { auditId }); }
            catch (e) { notice.hide(); console.error(e); await this.explainReportFailure(auditId, e); return; }
            finally { notice.hide(); }
            const adapter = this.app.vault.adapter;
            const folder = this.settings.reportsFolder;
            if (folder && !(await adapter.exists(folder))) await adapter.mkdir(folder);
            const path = normalizePath(`${folder ? folder + '/' : ''}${reportFileName(audit.name, r.ext)}`);
            await adapter.writeBinary(path, r.buf.buffer.slice(r.buf.byteOffset, r.buf.byteOffset + r.buf.byteLength));
            new Notice(`PwnDoc 2Sync: report saved to ${path} (template: ${r.templateName})`, 8000);
            this.app.openWithDefaultApp?.(path);
        } catch (e) { new Notice(`PwnDoc 2Sync: ${e.message}`); console.error(e); }
    }

    // Clipboard image into the attachments folder, linked at the cursor with its numbered caption
    async pasteImageWithCaption(editor, view) {
        let img;
        try { img = require('electron').clipboard.readImage(); }
        catch { new Notice('PwnDoc 2Sync: the clipboard is not available here.'); return; }
        if (img.isEmpty()) { new Notice('PwnDoc 2Sync: there is no image in the clipboard.'); return; }
        const file = view.file;
        const caption = await new Promise(r => new PromptModal(this.app, 'Figure caption', 'e.g. Login request intercepted in Burp', r).open());
        if (!caption) return;
        const png = img.toPNG();
        if (png.length > MAX_IMAGE_BYTES) new Notice('PwnDoc 2Sync: the image is above 12 MB, PwnDoc will refuse it on push.');
        const adapter = this.app.vault.adapter;
        const folder = this.settings.attachmentsFolder;
        if (folder && !(await adapter.exists(folder))) await adapter.mkdir(folder);
        const path = normalizePath(`${folder ? folder + '/' : ''}${pastedImageName(file.basename)}`);
        await adapter.writeBinary(path, png.buffer.slice(png.byteOffset, png.byteOffset + png.byteLength));
        const locale = this.app.metadataCache.getFileCache(file)?.frontmatter?.locale || '';
        editor.replaceSelection(`![](${encodeURI(path)})\n${figureCaption(locale, nextFigureNumber(editor.getValue()), caption)}\n`);
    }

    // Step 2 — ask VT or M
    askPrefix(vuln) {
        new PrefixModal(this.app, prefix => this.askFolder(vuln, prefix)).open();
    }

    // Step 3 — ask current folder or custom
    askFolder(vuln, prefix) {
        const activeFile = this.app.workspace.getActiveFile();
        const currentFolder = activeFile?.parent?.path ?? '';
        new FolderModal(this.app, currentFolder, folder => this.createVulnNote(vuln, prefix, folder)).open();
    }

    // Step 4 — create the note
    async createVulnNote(vuln, prefix, folder, extra = {}) {
        // Next sequential number for the chosen prefix inside the target folder
        const allFiles = this.app.vault.getMarkdownFiles();
        const folderFiles = folder
            ? allFiles.filter(f => f.parent?.path === folder)
            : allFiles.filter(f => !f.parent || f.parent.path === '/');

        const existing = folderFiles
            .map(f => { const m = f.basename.match(new RegExp(`^${prefix}-(\\d+)`)); return m ? parseInt(m[1]) : 0; })
            .filter(n => n > 0);
        const nextNum = existing.length > 0 ? Math.max(...existing) + 1 : 1;
        const num = String(nextNum).padStart(2, '0');

        // CVSS
        const { score: cvssScore, severity: cvssSeverity } = computeCVSS31(vuln.cvssv3);
        const cvssVector = vuln.cvssv3 || 'N/A';
        const cvssLink = cvssVector !== 'N/A' ? `https://www.first.org/cvss/calculator/3-1#${cvssVector}` : '';

        // Platform from category
        const platformMap = { WAPT: 'WEB', Android: 'Android', iOS: 'iOS', Mobile: 'Android' };
        const platform = prefix === 'M'
            ? (platformMap[vuln.category] || 'Android')
            : (platformMap[vuln.category] || 'WEB');

        // OWASP + CWE — resolve setting id (may be cf_<id> or label) to actual row key
        const cfLabels = this.cfLabels || {};
        const resolveKey = s => (s.startsWith('cf_') && cfLabels[s.slice(3)]) ? cfLabels[s.slice(3)] : s;
        const owaspKey = resolveKey(this.settings.owaspFieldId);
        const cweKey   = resolveKey(this.settings.cweFieldId);
        const owasp = vuln[owaspKey] || '';
        const cwe   = vuln[cweKey]   || '';

        // Extra custom fields (non-standard, non-owasp/cwe, non-empty)
        const reservedKeys = new Set([owaspKey, cweKey, this.settings.owaspFieldId, this.settings.cweFieldId]);
        const extraCf = Object.keys(vuln)
            .filter(k => !STANDARD_FIELDS.has(k) && !reservedKeys.has(k))
            .map(k => ({
                label: k,
                value: htmlToMd(vuln[k] || ''),
            }))
            .filter(({ value }) => value !== '');

        // Content sections (HTML stripped)
        const description  = htmlToMd(vuln.description);
        const observation  = htmlToMd(vuln.observation);
        const remediation  = htmlToMd(vuln.remediation);
        const references   = vuln.references || '';

        const title    = (vuln.title || 'Untitled').replace(/[\\/:*?"<>|]/g, '-');
        const noteName = `${prefix}-${num} - ${title}`;
        const filePath = folder ? `${folder}/${noteName}.md` : `${noteName}.md`;
        const auditEntry = folderAuditFor(filePath, this.settings.folderAudits);
        const auditId = extra.audit?._id ?? auditEntry?.auditId ?? null;
        const auditName = extra.audit?.name ?? auditEntry?.name;

        // Custom fields section at the end
        const cfSection = extraCf.length > 0
            ? ['## Custom Fields', '', ...extraCf.flatMap(({ label, value }) => [`**${label}**`, '', value, ''])]
            : [];

        // Load top/bottom templates
        const topChunks    = [];
        const bottomChunks = [];
        for (const tpl of (this.settings.templates || [])) {
            if (!tpl.path) continue;
            try {
                const raw = await this.app.vault.adapter.read(normalizePath(tpl.path + '.md'));
                const chunk = raw.trim();
                if (tpl.position === 'top') topChunks.push(chunk);
                else                        bottomChunks.push(chunk);
            } catch (e) {
                this.dbg(`template load failed (${tpl.path}): ${e.message}`);
                new Notice(`PwnDoc 2Sync: could not read template "${tpl.path}"`);
            }
        }

        const frontmatter = [
            '---',
            `severity: ${cvssSeverity}`,
            `platform: ${platform}`,
            `cvss_vector: "${cvssVector}"`,
            `cvss_link: "${cvssLink}"`,
            `cvss_score: ${parseFloat(cvssScore)}`,
            `cvss_severity: ${cvssSeverity}`,
            `status: "DRAFT"`,
            `pwndoc: true`,
            ...(vuln.id ? [`pwndoc_id: "${vuln.id}"`] : []),
            `locale: "${vuln.locale}"`,
            `category: "${vuln.category}"`,
            `assets: "INSERT_ASSET"`,
            ...(auditId ? [`pwndoc_audit_id: "${auditId}"`] : []),
            ...(auditName ? [`pwndoc_audit: ${JSON.stringify(auditName)}`] : []),
            ...(extra.findingId ? [`pwndoc_finding_id: "${extra.findingId}"`] : []),
            '---',
        ].join('\n');

        const body = [
            ...(topChunks.length > 0 ? [...topChunks.flatMap(c => [c, '']), ''] : []),
            '',
            '---',
            '## Descrizione',
            '',
            description,
            '',
            '## Impatto',
            '',
            observation,
            '',
            '## Evidenza',
            '',
            '',
            '## Assets',
            '',
            '',
            '## Remediation',
            '',
            remediation,
            '',
            ...(references ? ['## References', '', references, ''] : []),
            ...cfSection,
            ...(bottomChunks.length > 0 ? ['', ...bottomChunks.flatMap(c => [c, ''])] : []),
        ].join('\n');

        const content = (frontmatter + '\n\n' + body).trimEnd() + '\n';

        try {
            if (folder && !this.app.vault.getAbstractFileByPath(folder)) {
                await this.app.vault.createFolder(folder);
            }
            const file = await this.app.vault.create(normalizePath(filePath), content);
            if (extra.open !== false) await this.app.workspace.getLeaf().openFile(file);
            new Notice(`Created: ${noteName}`);
            return file;
        } catch (e) {
            new Notice(`PwnDoc 2Sync: failed to create note — ${e.message}`);
            console.error(e);
        }
    }
}

module.exports = PwnDocImporterPlugin;
module.exports.__test = { sortDashboardRows, dashboardCounts, filterDashboardRows, bulkSummary, missingGeneralFields, reportFailureLines, GENERAL_FIELDS, DEFAULT_GENERAL_REQUIRED, setAuditTemplate, templateLabel, findingChoices, bulkPlan, lintNote, nextFigureNumber, figureCaption, orphanReason, watchedRows, remoteChanges, overallState, buildDashboard, generateReport, reportFileName, pastedImageName, STATUS_DONE, STATUS_OPEN, parseCustomFieldsText, customFieldsPatch, setFindingStatus, metaToFrontmatter, pwndocApi, migratePassword, SECRET_ID, SECTION_DEFS, DEFAULT_SYNC_SECTIONS, parseSections, replaceSection, serializeWhitelist, imgToken, expandImgTokens, resolveAuditId, renameFolderKeys, titleFromBasename, rankFindings,
    extractImageRefs, replaceImageRefs, uploadImage, tokenizeImages, downloadImage, pullImages,
    lineDiff, buildComparison, renderCustomFields,
    sideBySide, missingFindings, findingToNoteRow, IMPORT_SECTIONS, folderAuditFor, notesOwnedBy, linkedElsewhere, shouldStamp, engagementStatus, canonicalImageKey, withImagesPreserved, strictImageResolver, demoteHeadings, sanitizeHtml, sanitizeTitle, resolveFindingLink, htmlToMd,
    matchFinding, buildFindingFromLibrary, buildFindingFromNote, createFinding, classify, merge3, hasConflictMarkers, applyMerged, isValidCvss31, cvssFrontmatter, localValue, labelOf, historyDir, pruneNames, recordHistory, listHistory, loadBase, saveBase,
    AuditLockedError, assertEditable, findingHash, assertUnchanged, isEmptyValue, pushSections, pullSections,
    restoreRemotePatch, restoreLocal, buildRollbackComparison, rollbackSections };
