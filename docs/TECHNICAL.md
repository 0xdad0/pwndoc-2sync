# PwnDoc 2Sync: technical documentation

For users: see the [README](../README.md). This document describes how the plugin works, what it assumes about PwnDoc, and what has and has not been verified.

## 1. Architecture

- **One file, no build**: `main.js` (CommonJS, about 3800 lines) plus `manifest.json`. The plugin is the file you copy. Desktop only (uses Node `http`/`https`, `crypto`, `electron.clipboard`).
- **Obsidian API used**: `secretStorage` and `SecretComponent`, `MarkdownRenderer.render`, `htmlToMarkdown`, `fileManager.processFrontMatter`, `metadataCache`, `Menu`, `MarkdownView.addAction`, status bar item, vault events (`create`, `rename`), `Modal`, `SuggestModal`, `FuzzySuggestModal`.
- **Layering**: pure functions (no Obsidian objects) hold the logic; the plugin class and the modals are thin glue. Pure functions take a `ctx` object (see 1.2) so the pipelines run in tests with fakes.
- **Order of `main.js`**: CSV parser, CVSS 3.1 calculator, section definitions (`SECTION_DEFS`) and codecs, HTML/Markdown converters, engagement association, images, diff and comparison, history store, push/pull pipeline, rollback, title and CVSS, three-way merge, create finding, engagement attribute helpers, side-by-side and import helpers, lint, dashboard and bulk plan, create engagement, report template and generation, delete finding, HTTP client and API helpers, settings, modals, plugin class. Pure helpers are exported through `module.exports.__test`.

### 1.1 Tests

`node --test test/pure.test.js` (Node 22: pass the file, not the directory). `test/obsidian-stub.js` stubs the `obsidian` module. Network tests start a local `http` server and close it with `closeAllConnections()` (keep-alive sockets otherwise hang the run). There are no UI tests: modals and event glue were exercised only against fake objects.

### 1.2 The `ctx` object

Built by `syncCtx(file, findingId, auditId)`:

| Member | Purpose |
|---|---|
| `api(method, path, opts)` | authenticated PwnDoc call (one re-login on HTTP 401) |
| `mdToHtml(md)` | strict Markdown to PwnDoc HTML (Obsidian renderer + whitelist) |
| `htmlToMd(html)` | PwnDoc HTML to Markdown (sanitise, `htmlToMarkdown`, demote headings) |
| `normalize(md)` | comparison form of a Markdown text (render, convert back, images by canonical key) |
| `resolvePath`, `readBinary`, `writeBinary`, `exists` | vault access for images |
| `imageCache`, `save` | persisted `{ [auditId]: { [sha256]: imageId } }` |
| `adapter`, `historyDir`, `historyLimit` | history store |
| `noteInfo` | `{ basename, fm }` of the note, used by frontmatter-backed fields |
| `cfLabels`, `cfTypes` | custom field `_id` to label and field type |
| `confirmEmpty(key, direction)` | prompt before blanking a populated section |

## 2. Data model

### 2.1 Frontmatter

| Key | Written by | Meaning |
|---|---|---|
| `pwndoc_audit_id`, `pwndoc_audit` | folder association, import, send | engagement id and name |
| `pwndoc_finding_id` | send, associate, import | the link to a finding |
| `pwndoc`, `pwndoc_id` | import | note comes from the library, library vulnerability id |
| `cvss_vector`, `cvss_score`, `cvss_severity`, `severity`, `cvss_link` | import, pull of CVSS | CVSS 3.1 data, recomputed on pull |
| `category`, `priority`, `remediation_complexity`, `status`, `locale` | import, pulls | synced fields and note language |

The audit of a note is resolved by `resolveAuditId`: `pwndoc_audit_id`, else the nearest associated folder (`folderAuditFor`).

### 2.2 Settings (`data.json`)

`folderAudits` (`{ [folder]: { auditId, name } }`, renamed with the folder), `imageCache`, `historyLimit`, `attachmentsFolder`, `reportsFolder`, `watchRemote`, `watchIntervalMin`, `generalRequired`, `lastAuditType`, `lastLanguage`, `apiUrl`, `apiUsername`, `lintRulesFile`, `apiPasswordSecret` (the secret id; the password itself is in Obsidian secret storage, a legacy plain `apiPassword` is migrated on load), `apiIgnoreSsl`, plus the import settings (`csvPath`, `locale`, `quickImport*`, `csvOutputFolder`, `templates`, `debugMode`). `data.json` holds the PwnDoc address and engagement names: do not share it.

### 2.3 History store

`<plugin dir>/history/<findingId>/<ts>-<op>-<rand>.json`:

```json
{ "id": "...", "ts": "ISO", "op": "push|pull|merge|rollback|create|status|delete",
  "forced": false, "auditId": "...", "findingId": "...", "notePath": "...",
  "sections": ["poc"], "remoteBefore": { /* whole finding */ }, "localBefore": "note text" }
```

`base.json` in the same folder: `{ ts, sections: { [key]: "comparison form last synced" } }`, merged on every successful sync (`saveBase`). Entries are pruned to `historyLimit`. Corrupt files are skipped on read. The folder is git-ignored.

## 3. Fields

`SECTION_DEFS` describes every synced item: `key`, PwnDoc `field`, `kind`, heading `aliases`, and for non-heading items `source` and `fmKey`.

| key | field | kind | source |
|---|---|---|---|
| description, observation, poc | same | html | heading |
| scope | `scope` | text | heading `Assets` |
| remediation | `remediation` | html | heading |
| references | `references` | list (`string[]`) | heading, one per line |
| customFields | `customFields` | custom | heading `Custom Fields` |
| title | `title` | text | file name after `VT-NN - ` |
| cvssv3 | `cvssv3` | text | `cvss_vector` |
| vulnType | `vulnType` | text codec | `category` |
| priority | `priority` | enum codec (1 to 4) | `priority` |
| remediationComplexity | `remediationComplexity` | enum codec (1 to 3) | `remediation_complexity` |
| status | `status` | status codec | `status` |

**Codecs** (`cmpLocal`, `cmpRemote`, `toRemote`, `toFm`) map a frontmatter value and a finding value to one comparison string. Rules: an empty frontmatter value is never pushed (`toRemote` is skipped, otherwise a missing `status` would reopen a finding); an unrepresentable value (`priority: banana`, `1.5`) throws `invalid <label>`; `toFm` decides what a pull writes back (`status` writes `COMPLETED`, writes `DRAFT` only if the note said completed, leaves other workflow values alone).

**Custom fields** are shown field by field: `compareCustomFields` pairs the `**label**` blocks of the note with the finding's fields (labels compared ignoring case, spacing and a trailing colon) and reports `same`, `changed`, `note only` or `PwnDoc only`; the compare dialog lists them above the diff. A PwnDoc field whose label cannot be resolved is shown as `cf_<id>`, never dropped. The importer writes every non-empty custom field, OWASP and CWE included (they used to be left out of the note, so the compare saw them only on the PwnDoc side). `customFieldsPatch`: the note text is parsed into `**label**` blocks; the PUT array is the finding's own entries with the text replaced **only for the labels whose text differs from the rendered PwnDoc value** (so untouched fields keep their exact stored value). Rich `text` fields go through the Markdown to HTML path; `input`, `date`, `radio`, `select` stay plain; other types or array values are refused. Unknown labels are looked up in `cfLabels`, else rejected.

## 4. Sync model

### 4.1 Comparison form

Both sides are reduced to a comparable string (`buildComparison`): `html` through the Obsidian renderer on both sides (`normalizeMd`, so formatting noise cancels), `list` as trimmed lines, `custom` through `canonCustom` / `renderCustomFields`, codec fields through their codecs, the rest trimmed text. A row carries `local`, `remote`, `base`, `status`, `changed`, `localEmpty`, `remoteEmpty`, `diff`, and a three-way `merge` when status is `conflict`.

### 4.2 Status and merge

`classify(base, local, remote)`: `same` if equal; `unknown` without a base; `remote` if local equals base; `local` if remote equals base; else `conflict`. `merge3` is a line-level diff3 built on an LCS alignment of each side with the base: changes on non-adjacent lines combine, changes on the same or adjacent lines (like git) become `<<<<<<< local / ======= / >>>>>>> pwndoc` blocks; `applyMerged` refuses text that still contains markers.

### 4.3 Push (`pushSections`)

1. `fetchFinding` (one `GET /api/audits/:id`, finding taken from `findings[]`).
2. `assertEditable(audit, force)`: state must be `EDIT` or `force`.
3. `assertUnchanged`: SHA-256 of the selected fields of the snapshot taken at compare time must equal the same hash of the fresh finding (the finding has no `updatedAt`).
4. Per section: local value to remote form (`localToRemote`), then the **empty guard** (`isEmptyValue`: no text and no image) asks before blanking a populated field. A codec returning `undefined` skips the field.
5. `recordHistory` (before the write).
6. `PUT /api/audits/:id/findings/:fid` with only the selected fields (PwnDoc merges at field level). An empty patch sends nothing.
7. `saveBase` with the comparison form of what was written.

Nothing is written if any step throws; steps 1 to 4 have no side effect except image uploads (cached by content hash; orphan uploads are possible and harmless).

### 4.4 Pull (`pullSections`)

Local only: fetches the finding, guards against blanking a populated note section, converts remote to Markdown (images downloaded), replaces the section (`replaceSection`), records history and base, returns the new note text and `meta` (title, CVSS and codec fields) for the caller to apply (`applyPullMeta`: rename keeping the `VT-NN` prefix, rewrite frontmatter via `metaToFrontmatter`). Pulled headings are demoted to `###` so a remote text can never create a note section boundary.

### 4.5 Rollback

`buildRollbackComparison` compares the current state with the snapshot of an entry, per side; `rollbackSections` restores the chosen sections on PwnDoc (`restoreRemotePatch`, same guards) or in the note (`restoreLocal`). A rollback is recorded as an entry itself. Frontmatter-backed fields are restorable on the remote side only.

## 5. Images

- **Push**: `extractImageRefs` finds `![alt](path)` and `![[path|alt]]` outside code fences. Each file is read, checked (type png/jpg/gif/webp, at most 12 MB, no remote URLs), hashed, and uploaded with `POST /api/images { value: "data:...;base64,...", name, auditId }`, cached in `imageCache`. The ref becomes an inert token `⟦pwimg:<id>:<hex alt>⟧` so the Markdown renderer never sees vault paths; after rendering the tokens expand to `<img src="<id>" alt="<alt>">`. Any `<img>` not produced from a token is an error (`strictImageResolver`), never silently dropped.
- **Pull**: ids in `<img src>` are downloaded (`GET /api/images/:id`, a JSON with a data URI) into `<attachments>/<id>.<ext>` unless already there, and the ref becomes `![alt](path)`.
- **Comparison**: the renderer drops images, so `withImagesPreserved` parks them as tokens and restores them as `![alt](key)`, where `canonicalImageKey` maps a path to its PwnDoc id (file name pattern, or the content hash in `imageCache`).
- **Captions**: `*Figura N – text*` is an ordinary paragraph (`<p><em>`). The alt text is the PwnDoc caption. They are independent.

## 6. HTML and Markdown

`mdToHtml` renders into a detached element with `MarkdownRenderer.render` and serialises through a whitelist (`serializeWhitelist`: paragraphs, emphasis, code, `pre`, lists, tables, links, images, line breaks). `htmlToMd` first sanitises PwnDoc HTML with the same whitelist (it is untrusted on its way into the vault), then `htmlToMarkdown`.

## 7. Lint (`lintNote`)

Runs on the sections about to be pushed (compare dialog and bulk push) and on demand. Fence-aware (`linesWithFence`): nothing inside a code fence counts.

| Level | Rule |
|---|---|
| error | missing image file, remote image, conflict markers, unclosed fence, invalid CVSS 3.1 vector, unrepresentable priority or complexity, empty title |
| warn | empty section, image not followed by a caption line, caption number not progressive across the whole note (document order), caption word not matching the audit language (`IT` is `Figura`, `EN` is `Figure`), caption separator not an en dash |

Not linted: sections resolved with *Merge both* (their text carries PwnDoc image ids, not vault paths).

### 7.1 Custom rules

`loadLintRules` reads the rules note (setting `lintRulesFile`), `extractRulesText` takes its first ```` ```yaml ```` block (or the whole text), `parseLintRules(text, parseYaml)` (Obsidian's `parseYaml`) validates and compiles it. A rule that fails to compile is reported (`rule N (id): reason`) and skipped; the report becomes a `warn` issue so a typo is never silent. `lintIssues` merges built-in issues, custom issues and rule-file errors; `lintGate`, `lintCurrentNote` and `bulkSync` all go through it.

Evaluation (`runCustomLint(rules, ctx)`), `ctx = { path, folder, basename, title, fm, md, engagement }`: skip the rule if `when` does not hold or `unless` holds (each is a map of conditions that must all hold: `folder`, `file`, `path`, `title`, `engagement`, `fm.<key>`, each a regex tested on the value, frontmatter arrays joined with `, `); then for every target in `in` take its text (`note` without frontmatter, `filename`, `title`, `path`, `frontmatter` as `key: value` lines, `fm:<key>`, `section:<name>` via the section aliases, an absent section is `''`) and test the regex: `match` is a violation when it matches (first match, line number for multi-line targets), `missing` when it does not. Regexes: `/re/flags` literal (the `g` and `y` flags are dropped, they make `test` stateful), otherwise the text compiled case-insensitive. Issues are `{ level, section: 'rule', where, message }` with an optional `[id]` prefix. The rules run on the whole note regardless of which sections are being pushed.

## 8. Engagement dashboard

- `buildDashboard(ctxFor, { audit, notes, linkedIds, loadBase })` returns `rows` (linked notes), `orphans` (`orphanReason`), `unlinked` and `missing` (`missingFindings`). Each row has a state (the worst of its watched sections), the differing keys and per-section `{ status, localEmpty, remoteEmpty }`.
- **Watched sections** (`watchedRows`): the default sections always, plus any with content in the note or a sync base. This keeps a note where only Evidenza was written from showing every other section as different.
- **`bulkPlan(row, direction, keys)`**:

| status | push | pull |
|---|---|---|
| same | skipped | skipped |
| local | runs | blocked |
| remote | blocked | runs |
| conflict | blocked | blocked |
| unknown (no base) | runs only if the note is not empty and PwnDoc is empty | runs only if the note is empty |

  Blocked sections are reported, never forced. `bulkSummary` feeds the preview in the footer.
- `bulkSync` runs each note through `pushSections` / `pullSections` (all guards apply), lint errors skip a note, failures are collected and reported at the end.

## 9. Background check

`checkRemote(file)` runs on `file-open` and on an interval for the active note. It needs credentials already stored (`hasCredentials`), a link and a base; it builds the comparison and keeps the sections whose status is `remote` or `conflict`. It shows them in the status bar and notifies once per change signature. It never writes, never prompts, and after any error pauses itself for 10 minutes (`remoteBackoff`) so a wrong password cannot lock the account.

## 10. Engagement, report, deletion

- **Create engagement** (`createAudit`): validates, `POST /api/audits { name, language, auditType }`, takes the id from `datas.audit._id` (or finds the newest audit with that name), then `PUT /api/audits/:id/general` with `template`, `date_start`, `date_end` if given. Company and client are not set.
- **Report template** (`setAuditTemplate`): `PUT .../general { template }` under the state guard. **Generate** (`generateReport`): `GET .../generate` as raw bytes, extension from the template.
- **General Information check** (`missingGeneralFields`): blank values among the configured keys (`isBlankValue`: empty string, empty list, object with no value) plus custom fields with `required` and `display: general`.
- **Delete** (`deleteFinding`): fetch, `assertEditable`, history entry with the whole finding, `DELETE /api/audits/:id/findings/:fid`. The UI adds the typed-title confirmation.

## 11. PwnDoc API surface

Auth: `POST /api/users/token { username, password, totpToken: "" }`, then every call carries the cookie `token= JWT <token>`. Responses are `{ status, datas }`. Requests time out after 60 s.

| Call | Used for | Status |
|---|---|---|
| `GET /api/audits`, `GET /api/audits/:id` | pick engagement, findings, state, language, template | verified live |
| `PUT /api/audits/:id/findings/:fid` | push (merges fields) | verified live |
| `POST /api/audits/:id/findings` | create finding; the reply carries no id, it is found as the finding absent before | verified live |
| `DELETE /api/audits/:id/findings/:fid` | delete finding | verified live (cleanup of test findings) |
| `POST /api/images`, `GET /api/images/:id` | image upload and download | verified live |
| `GET /api/vulnerabilities`, `.../detail/:id`, `GET /api/data/custom-fields` | library import, custom field labels | verified live |
| `GET /api/data/audit-types`, `GET /api/data/languages` | engagement form | **not verified** |
| `POST /api/audits` | create engagement; id in the reply assumed | **not verified** |
| `PUT /api/audits/:id/general` | template and dates, with a partial body | **not verified** |
| `GET /api/templates`, `GET /api/audits/:id/generate` | report | **not verified** |
| finding `status` 0 = completed, 1 = in progress | completion | **not verified** (from PwnDoc source) |
| finding `priority`, `remediationComplexity` | enum fields | **not verified** |
| write shape of `customFields` (`{ customField: id, text }`) | custom field push | **not verified** |
| audit states `REVIEW`, `APPROVED` | state guard | **not verified** (reviews are disabled on the test instance; only `EDIT` was observed) |

Observed facts the code relies on: the finding has no `updatedAt`; `PUT` merges; the body limit is about 17.8 MB (hence 12 MB per image); the server de-duplicates identical images; the editor stores `<img src="<id>" alt>` and `<pre><code>` verbatim. The raw findings of the spike are in `docs/superpowers/spikes/pwndoc-api-formats.md`.

## 12. Security notes

- The password lives in Obsidian secret storage, never in `data.json`.
- `Ignore SSL certificate errors` disables certificate validation for every call of the plugin; use it only for a known self-signed server.
- Every write to PwnDoc is explicit (Apply, a confirmed prompt, a typed title) and passes the state guard. Writes were only ever tried on a throwaway audit.
- `history/` and `data.json` contain client data.
- PwnDoc content entering the vault is sanitised; content leaving the vault is rendered from a whitelist, and unknown image syntax aborts the push.

## 13. Known limitations

- Line-level merge: two edits on adjacent lines conflict. Merging by word is not implemented.
- A cached image id is trusted: an image deleted on PwnDoc is not re-uploaded until its cache entry is removed.
- Orphan uploads are not cleaned up.
- A custom field value line consisting only of `**bold**` reads as a new label.
- `nextFigureNumber` is the highest number plus one, not the position in the note.
- Restoring a snapshot with a null numeric field, or populated custom field objects, sends them as stored (shape not verified).
- Deleted findings are recoverable only by hand from the history.
- Fences of four or more backticks and an unclosed fence at the end of a section are only partly handled by the section scanner.

## 14. Release

`manifest.json` carries the version; the workflow `.github/workflows/release.yml` publishes a release on push to `master` from that version. There is no CI for other branches: run the tests locally before merging.
