'use strict';

const { Plugin, PluginSettingTab, Setting, FuzzySuggestModal, SuggestModal, Modal, Notice, normalizePath, SecretComponent, Component, MarkdownRenderer, htmlToMarkdown } = require('obsidian');

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
const SECTION_DEFS = [
    { key: 'description',  field: 'description',  kind: 'html',   aliases: ['Descrizione', 'Description'] },
    { key: 'observation',  field: 'observation',  kind: 'html',   aliases: ['Impatto', 'Impact', 'Observation'] },
    { key: 'poc',          field: 'poc',          kind: 'html',   aliases: ['Evidenza', 'Evidenze', 'Evidence', 'Proof'] },
    { key: 'scope',        field: 'scope',        kind: 'text',   aliases: ['Assets'] },
    { key: 'remediation',  field: 'remediation',  kind: 'html',   aliases: ['Remediation'] },
    { key: 'references',   field: 'references',   kind: 'list',   aliases: ['References'] },
    { key: 'customFields', field: 'customFields', kind: 'custom', aliases: ['Custom Fields'] },
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

const escHtml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const escAttr = s => escHtml(s).replace(/"/g, '&quot;');

// Serialise a rendered DOM subtree into the HTML subset PwnDoc's editor stores.
// imgResolver(src, alt) returns the value for <img src>, or null to drop the image.
function serializeWhitelist(node, imgResolver = () => null) {
    if (node.nodeType === 3) return escHtml(node.textContent);
    if (node.nodeType !== 1) return '';
    const tag = node.tagName.toLowerCase();
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
async function mdToHtml(app, md) {
    const div = document.createElement('div');
    const comp = new Component();
    comp.load();
    try { await MarkdownRenderer.render(app, md, div, '', comp); }
    finally { comp.unload(); }
    return expandImgTokens(serializeWhitelist(div));
}

const htmlToMd = html => (html ? htmlToMarkdown(html).trim() : '');

// Comparison form: both sides pass through the same renderer so formatting noise cancels out
async function normalizeMd(app, md) { return htmlToMd(await mdToHtml(app, md)); }

// ── Engagement association ────────────────────────────────────────────────────
const parentDir = p => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');

// Note frontmatter wins; otherwise the nearest associated ancestor folder
function resolveAuditId(notePath, fm, folderAudits) {
    if (fm?.pwndoc_audit_id) return fm.pwndoc_audit_id;
    for (let dir = parentDir(notePath); ; dir = parentDir(dir)) {
        if (folderAudits[dir]) return folderAudits[dir].auditId;
        if (!dir) return null;
    }
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
const pwndocGetAudit = (baseUrl, token, id, ignoreSsl) =>
    pwndocApi(baseUrl, token, 'GET', `/api/audits/${id}`, { ignoreSsl });

// ── Images ────────────────────────────────────────────────────────────────────
const IMAGE_MIME = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp' };
const MIME_EXT = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/gif': 'gif', 'image/webp': 'webp' };
const MAX_IMAGE_BYTES = 12 * 1024 * 1024; // PwnDoc rejects bodies above ~17.8 MB, base64 adds a third
const IMAGE_RE = /!\[\[([^\]|\n]+)(?:\|([^\]\n]*))?\]\]|!\[([^\]]*)\]\(([^)\n]*)\)/g;
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
async function buildComparison(ctx, noteMd, finding, keys) {
    const secs = parseSections(noteMd);
    const rows = [];
    for (const key of keys) {
        const def = SECTION_DEFS.find(d => d.key === key);
        const localRaw = secs[key]?.text || '';
        let local, remote;
        if (def.kind === 'html') {
            local = await ctx.normalize(localRaw);
            remote = await ctx.normalize(ctx.htmlToMd(finding[def.field] || ''));
        } else if (def.kind === 'list') {
            local = listLines(localRaw);
            remote = (finding[def.field] || []).map(s => s.trim()).filter(Boolean).join('\n');
        } else if (def.kind === 'custom') {
            local = localRaw.trim();
            remote = renderCustomFields(finding, ctx);
        } else {
            local = localRaw.trim();
            remote = String(finding[def.field] || '').trim();
        }
        rows.push({ key, local, remote, changed: local !== remote, localEmpty: local === '', remoteEmpty: remote === '', diff: lineDiff(remote, local) });
    }
    return rows;
}

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
    constructor(app, settings, onConnect) {
        super(app);
        this.settings  = settings;
        this.onConnect = onConnect; // ({url, username, password, ignoreSsl, save}) => void
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
            this.close();
            this.onConnect({ url, username, password, ignoreSsl: sslCheck.checked, save: saveCheck.checked });
        };
        btn.onclick = doConnect;
        passInput.addEventListener('keydown', e => { if (e.key === 'Enter') doConnect(); });
        urlInput.focus();
    }

    onClose() { this.contentEl.empty(); }
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
        containerEl.createEl('h2', { text: 'PwnDoc Importer' });

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
    onChooseItem(a) { this.onChoose(a); }
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
    onChooseItem(f) { this.onChoose(f); }
}

// ── Plugin ────────────────────────────────────────────────────────────────────
class PwnDocImporterPlugin extends Plugin {
    async onload() {
        await this.loadSettings();
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
        this.registerEvent(this.app.vault.on('rename', async (file, oldPath) => {
            if (file.children === undefined) return; // folders only
            const next = renameFolderKeys(this.settings.folderAudits, oldPath, file.path);
            if (JSON.stringify(next) === JSON.stringify(this.settings.folderAudits)) return;
            this.settings.folderAudits = next;
            await this.saveSettings();
        }));
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
        if (this.settings.debugMode) console.log('[PwnDoc Importer]', ...args);
    }

    // Step 1 — load CSV and open vuln search
    async openSearchModal({ quick = false } = {}) {
        const { csvPath } = this.settings;
        if (!csvPath) {
            new Notice('PwnDoc Importer: set the CSV path in Settings first.');
            return;
        }

        let text;
        try { text = await readFilePath(this.app, csvPath); }
        catch (e) { new Notice(`PwnDoc Importer: cannot read CSV — ${e.message}`); return; }

        let rows = parseCSV(text);
        if (rows.length === 0) {
            new Notice('PwnDoc Importer: CSV is empty or could not be parsed.');
            return;
        }

        this.chooseLocaleThenSearch(rows, { quick });
    }

    // Quick import — single command driven by the default source/language settings
    quickImport() {
        if (this.settings.quickImportSource === 'api') {
            if (!this.settings.apiUrl || !this.settings.apiUsername || !getApiPassword(this.app, this.settings)) {
                new Notice('PwnDoc Importer: save API credentials in Settings to use the quick API import.');
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
                new Notice(`PwnDoc Importer: no vulnerabilities found for locale "${locale}".`);
                return;
            }
            new VulnSearchModal(this.app, filtered, vuln => this.askPrefix(vuln)).open();
        };
        if (quick) {
            const pref = this.settings.quickImportLocale || '';
            if (pref && !locales.includes(pref)) {
                new Notice(`PwnDoc Importer: locale "${pref}" not present in the data — showing all locales.`);
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
        const notice = new Notice('PwnDoc Importer: connecting…', 0);
        let rows;
        try {
            dbg('logging in to', url);
            const token = await pwndocLogin(url, username, password, ignoreSsl);
            dbg('login OK, fetching vuln list + custom fields');
            notice.setMessage('PwnDoc Importer: fetching vulnerability list…');
            const [list, cfLabels] = await Promise.all([
                pwndocFetchVulns(url, token, ignoreSsl),
                pwndocFetchCustomFields(url, token, ignoreSsl, dbg).catch(e => { dbg('custom fields fetch failed:', e.message); return {}; }),
            ]);
            dbg(`list returned ${list.length} vulns, ${Object.keys(cfLabels).length} custom field definitions`);

            const details = await pwndocFetchAllDetails(url, token, ignoreSsl, list, dbg, (done, total) => {
                notice.setMessage(`PwnDoc Importer: fetching details ${done}/${total}…`);
            });
            notice.hide();

            dbg(`fetched full detail for ${details.length}/${list.length} vulns`);
            this.cfLabels = cfLabels;
            rows = flattenVulnsFromApi(details, cfLabels);
            dbg(`flattened to ${rows.length} rows; sample keys:`, rows[0] ? Object.keys(rows[0]) : []);
            if (rows.length === 0) { new Notice('PwnDoc Importer: no vulnerabilities returned from API.'); return; }
        } catch (e) {
            notice.hide();
            new Notice(`PwnDoc Importer: ${e.message}`);
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
                    new Notice(`PwnDoc Importer: CSV saved to ${csvPath}`);
                } catch (e) {
                    new Notice(`PwnDoc Importer: could not save CSV — ${e.message}`);
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
            : await new Promise(resolve => new ApiCredentialsModal(this.app, s, resolve).open());
        const token = await pwndocLogin(creds.url, creds.username, creds.password, creds.ignoreSsl);
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
            catch (e) { new Notice(`PwnDoc Importer: ${e.message}`); return resolve(null); }
            new AuditPickModal(this.app, audits, resolve).open();
        });
    }

    async associateFolder() {
        const active = this.app.workspace.getActiveFile();
        new FolderModal(this.app, active?.parent?.path === '/' ? '' : (active?.parent?.path ?? ''), async folder => {
            const audit = await this.pickAudit();
            if (!audit) return;
            this.settings.folderAudits[folder] = { auditId: audit._id, name: audit.name };
            await this.saveSettings();
            new Notice(`PwnDoc Importer: "${folder || '/'}" → ${audit.name}`);
        }).open();
    }

    // Resolve the audit for a note: its frontmatter, then the nearest associated folder, else ask
    async auditIdFor(file) {
        const fm = this.app.metadataCache.getFileCache(file)?.frontmatter;
        return resolveAuditId(file.path, fm, this.settings.folderAudits)
            ?? (await this.pickAudit())?._id ?? null;
    }

    async associateNote() {
        const file = this.app.workspace.getActiveFile();
        if (!file) { new Notice('PwnDoc Importer: open a note first.'); return; }
        const auditId = await this.auditIdFor(file);
        if (!auditId) return;
        let audit;
        try { audit = await this.api('GET', `/api/audits/${auditId}`); }
        catch (e) { new Notice(`PwnDoc Importer: ${e.message}`); return; }
        if (!audit.findings?.length) { new Notice('PwnDoc Importer: this audit has no findings yet.'); return; }
        new FindingPickModal(this.app, audit.findings, titleFromBasename(file.basename), async finding => {
            await this.app.fileManager.processFrontMatter(file, fm => {
                fm.pwndoc_audit_id = auditId;
                fm.pwndoc_finding_id = finding._id;
            });
            new Notice(`PwnDoc Importer: linked to "${finding.title}"`);
        }).open();
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
    async createVulnNote(vuln, prefix, folder) {
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
        const auditId = resolveAuditId(filePath, {}, this.settings.folderAudits);

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
                new Notice(`PwnDoc Importer: could not read template "${tpl.path}"`);
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
            `pwndoc_id: "${vuln.id}"`,
            `locale: "${vuln.locale}"`,
            `category: "${vuln.category}"`,
            `assets: "INSERT_ASSET"`,
            ...(auditId ? [`pwndoc_audit_id: "${auditId}"`] : []),
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
            await this.app.workspace.getLeaf().openFile(file);
            new Notice(`Created: ${noteName}`);
        } catch (e) {
            new Notice(`PwnDoc Importer: failed to create note — ${e.message}`);
            console.error(e);
        }
    }
}

module.exports = PwnDocImporterPlugin;
module.exports.__test = { pwndocApi, migratePassword, SECRET_ID, SECTION_DEFS, DEFAULT_SYNC_SECTIONS, parseSections, replaceSection, serializeWhitelist, imgToken, expandImgTokens, resolveAuditId, renameFolderKeys, titleFromBasename, rankFindings,
    extractImageRefs, replaceImageRefs, uploadImage, tokenizeImages, downloadImage, pullImages,
    lineDiff, buildComparison, renderCustomFields };
