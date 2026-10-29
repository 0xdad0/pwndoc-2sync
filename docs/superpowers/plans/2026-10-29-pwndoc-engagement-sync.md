# PwnDoc Engagement Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Associare note locali (singole o per cartella) a un audit PwnDoc, confrontarle con il finding corrispondente e fare merge per sezione in entrambe le direzioni (default: solo Evidenza), con upload/download immagini e formattazione preservata.

**Architecture:** Resta un solo `main.js` CommonJS senza build (Obsidian non risolve `require('./x')` nei plugin), organizzato a sezioni. La logica pura (parser sezioni, diff, estrazione immagini, assemblaggio push) riceve i converter e il client HTTP come parametri, così si testa in Node con `node --test` e uno stub di `obsidian`. I converter reali (`htmlToMarkdown`, `MarkdownRenderer`) e l'UI si verificano a mano nel vault.

**Tech Stack:** Obsidian API (>= 1.11.5: `secretStorage`, `SecretComponent`, `htmlToMarkdown`, `MarkdownRenderer`, `processFrontMatter`), Node `http`/`https`, `node:test`. Nessuna dipendenza npm.

**Spec:** nessun design doc separato; le decisioni sono nella sezione "Decisioni" sotto (concordate in chat il 2026-10-29).

## Decisioni

- Engagement = **audit** PwnDoc. La nota si collega a un **finding** dell'audit (`PUT /api/audits/:auditId/findings/:findingId`), non alla vuln di libreria.
- Associazione: frontmatter `pwndoc_audit_id`, `pwndoc_finding_id`. Per cartella: `settings.folderAudits = { [folderPath]: { auditId, name } }`, risolto dall'antenato più vicino; la nota sovrascrive la cartella.
- Mapping sezione nota -> campo finding (heading riconosciuti per alias):

| key | alias heading | campo finding | kind |
|---|---|---|---|
| `description` | Descrizione, Description | `description` | html |
| `observation` | Impatto, Impact, Observation | `observation` | html |
| `poc` | Evidenza, Evidenze, Evidence, Proof | `poc` | html |
| `scope` | Assets | `scope` | text |
| `remediation` | Remediation | `remediation` | html |
| `references` | References | `references` | list |
| `customFields` | Custom Fields | `customFields[]` | custom |
| `title` | nome file dopo `PREFIX-NN - ` | `title` | text, sorgente filename |
| `cvssv3` | frontmatter `cvss_vector` | `cvssv3` | text, sorgente frontmatter |

- Default delle sezioni selezionate nel merge: `['poc']`. Direzione: push e pull, stessa UI, scelta per sezione. `title` e `cvssv3` sono sempre deselezionate di default.
- **Merge a tre vie:** la base è lo stato normalizzato di ogni sezione all'ultimo sync riuscito (`history/<findingId>/base.json`). Classificazione per sezione: `same | local | remote | conflict | unknown` (nessuna base = `unknown`, confronto a due vie). Se ha cambiato solo un lato la direzione è preimpostata; se hanno cambiato entrambi il testo viene unito con `merge3` a righe (diff3), e con conflitti l'utente li risolve a mano in un campo di testo con marcatori prima di poter applicare.
- **Guard sullo stato dell'audit:** ogni scrittura su PwnDoc (push, merge, rollback, create finding) richiede audit in stato `EDIT`. Altrimenti viene bloccata, salvo che l'utente spunti `Enforce` per quella singola operazione (non persistito, spento di default); l'entry di history registra `forced: true`. Il pull è solo locale e non è soggetto al guard.
- **Crea finding:** se una nota associata a un audit non ha un finding, si crea da una vuln di libreria (suggerita quella con `pwndoc_id` della nota, scelta libera su tutta la libreria) oppure da zero con titolo e CVSS della nota; poi si apre il merge con Evidenza preselezionata.
- Conversione: HTML->MD con `htmlToMarkdown`; MD->HTML con `MarkdownRenderer.render` su div detached e serializzazione whitelist. Il confronto avviene sulla forma normalizzata (entrambi i lati passati da MD->HTML->MD).
- Immagini: `alt` PwnDoc = didascalia; cache `sha256 -> imageId` per audit in `settings.imageCache`; download in `settings.attachmentsFolder`.
- Push sicuro (aggiornato dallo spike, vedi `docs/superpowers/spikes/pwndoc-api-formats.md`): GET fresco del finding, PUT del **solo patch** dei campi scelti (il PUT di PwnDoc fa merge), abort se l'hash dei campi scelti è cambiato dallo snapshot del diff (il finding non ha `updatedAt`), entry di history scritta prima del PUT.
- History: ogni push, pull e rollback scrive un'entry JSON in `<plugin-dir>/history/<findingId>/<ts>-<op>.json` con il finding remoto e la nota locale **prima** dell'operazione. Retention `settings.historyLimit` (default 50 per finding). Il rollback ripristina le sezioni scelte lato PwnDoc o lato nota, passa dalla stessa UI di diff e scrive a sua volta una entry (quindi è annullabile). Le immagini caricate non vengono mai cancellate, quindi gli snapshot restano validi.
- Password API in `app.secretStorage`, id `pwndoc-importer-api-password`; `data.json` non la contiene più. Il token JWT resta solo in memoria.

## Global Constraints

- `manifest.json`: `minAppVersion` = `1.11.5`, `version` = `1.3.0`, `isDesktopOnly` = `true`.
- Un solo file di codice: `main.js`. Nessun bundler, nessuna dipendenza npm.
- Testi UI e messaggi in inglese (come l'esistente); prefisso `PwnDoc Importer:` nei `Notice`.
- Heading della nota in italiano come da `createVulnNote` (`## Descrizione`, `## Impatto`, `## Evidenza`, `## Assets`, `## Remediation`, `## References`, `## Custom Fields`).
- Frontmatter scritto solo via `app.fileManager.processFrontMatter`.
- `history/` contiene dati del cliente: deve restare fuori da git (`.gitignore`, Task 1).

## Review Focus

1. Sezione locale Evidenza vuota/assente con remoto non vuoto: il push non deve cancellare il remoto senza conferma esplicita; il pull non deve svuotare il locale senza conferma.
2. Heading `## ` dentro un code fence (tipico negli output di tool in Evidenza): non deve spezzare la sezione.
3. Immagine locale mancante, con spazi o unicode nel path: errore prima di qualunque PUT, nessuna sostituzione parziale.
4. Finding modificato in PwnDoc tra compare e push, oppure audit non in `EDIT`: abort senza scrittura, a meno di `Enforce` esplicito per quella operazione.
5. HTML remoto con tag non supportati o `<script>`, e MD locale con HTML grezzo: la serializzazione whitelist li scarta, il pull non inserisce HTML eseguibile nella nota.

---

### Task 0: Spike sui formati PwnDoc (nessun codice di prodotto) — FATTO, risultati in `docs/superpowers/spikes/pwndoc-api-formats.md`

**Files:**
- Create: `docs/superpowers/spikes/pwndoc-api-formats.md`

**Interfaces:**
- Produces: il documento fissa i valori usati dai Task 1, 4, 6, 9, 10: `FORMATS = { imgTag, codeBlockTag, imageUploadBody, imageDownloadShape, putSemantics, updatedAtField, auditsListPath, auditDetailPath, auditStateField, auditStateValues, auditLanguageField, createFindingPath, createFindingBody }`.

- [ ] **Step 1:** Su una istanza PwnDoc di test (docker `pwndoc` o la tua), crea un audit con un finding il cui PoC contiene grassetto, lista, tabella, code block e 2 immagini con didascalia. Cattura con Burp o DevTools: il PUT del finding, il POST `/api/images`, il GET `/api/images/download/:id`, `GET /api/audits`, `GET /api/audits/:id`.
- [ ] **Step 2:** Scrivi nel doc, per ciascun voce di `FORMATS`, il valore osservato (HTML esatto di `<img>` e `<pre>`, body JSON dell'upload, forma della risposta, nome del campo `updatedAt`, se il PUT sostituisce l'intero finding o fa merge parziale).
- [ ] **Step 3:** Verifica il limite di body: carica una PNG da ~5 MB e annota l'esito.
- [ ] **Step 4:** Commit del doc.

```bash
git add docs/superpowers/spikes/pwndoc-api-formats.md
git commit -m "docs: record PwnDoc API formats from spike"
```

---

### Task 1: Harness di test e client API generico

**Files:**
- Create: `test/pure.test.js`, `test/obsidian-stub.js`
- Modify: `main.js` (sezione "PwnDoc API client", righe ~108-240; coda del file riga ~1065)

**Interfaces:**
- Produces:
  - `pwndocApi(baseUrl, token, method, path, { body, ignoreSsl, rawResponse })`: `Promise<any>`; usa `http` o `https` secondo lo schema dell'URL; `body` oggetto serializzato JSON; ritorna `datas` della risposta (o il `Buffer` con `rawResponse: true`).
  - `module.exports.__test = { ... }`: oggetto a cui ogni task aggiunge le funzioni pure.
- Le 4 funzioni `pwndocFetch*` esistenti diventano wrapper di `pwndocApi` (comportamento invariato).

- [ ] **Step 1: Test** in `test/pure.test.js`, con `test/obsidian-stub.js` che registra un hook `Module._load` restituendo `{ Plugin: class {}, PluginSettingTab: class {}, Setting: class {}, FuzzySuggestModal: class {}, SuggestModal: class {}, Modal: class {}, Notice: class {}, normalizePath: p => p }` per `'obsidian'`:
  - `pwndocApi` contro un `http.createServer` locale: `GET /api/x` ritorna `datas`; `PUT /api/x` riceve il body JSON e il cookie `token= JWT T`; status 500 rigetta con `HTTP 500`.
- [ ] **Step 2:** `node --test test/pure.test.js` e verifica FAIL (`pwndocApi` non definita).
- [ ] **Step 3:** Implementa `pwndocApi` in `main.js`; riscrivi `httpsRequest` come `httpRequest` che sceglie `http`/`https` e supporta `method`/`body`; riesporta via `module.exports.__test`.
- [ ] **Step 4:** `node --test test/pure.test.js` PASS; verifica a mano che l'import da API esistente funzioni ancora (Notice di successo).
- [ ] **Step 5:** Crea `.gitignore` con `history/` e `data.json`, ed esegui `git rm --cached data.json`. Motivo: `data.json` è tracciato e da questo piano in poi conterrà `folderAudits` (nomi di engagement) e `imageCache`. Se la cartella di sviluppo non coincide con quella del plugin nel vault, il rischio è solo teorico, ma l'untrack è comunque più sicuro. Conferma con l'utente prima di eseguirlo.
- [ ] **Step 6:** Commit.

```bash
git add .gitignore main.js test/
git commit -m "refactor: generic PwnDoc API client with http/https and PUT, add node test harness, ignore local data"
```

---

### Task 2: Password in `secretStorage` e manifest

**Files:**
- Modify: `main.js` (`DEFAULT_SETTINGS` ~243, `loadSettings` ~773, `PwnDocSettingTab` Password ~630, `ApiCredentialsModal` ~402, `quickImport` ~804, `fetchFromApi` ~847), `manifest.json`

**Interfaces:**
- Produces: `const SECRET_ID = 'pwndoc-importer-api-password'`; `getApiPassword(app): string` (`app.secretStorage.getSecret(SECRET_ID) ?? ''`); `setApiPassword(app, value): void`. Dopo il Task 2 `settings.apiPassword` non esiste più.

- [ ] **Step 1:** Test puro `migratePassword(settings, secretStorage)`: con `settings.apiPassword = 'x'` chiama `setSecret(SECRET_ID,'x')` e restituisce settings senza la chiave `apiPassword`; con campo vuoto non chiama `setSecret`. FAIL.
- [ ] **Step 2:** Implementa `migratePassword` e chiamala in `loadSettings` (poi `saveSettings`). PASS.
- [ ] **Step 3:** Sostituisci tutti gli usi di `settings.apiPassword` con `getApiPassword`/`setApiPassword`; il campo Password nelle settings usa `SecretComponent` (firma da `obsidian.d.ts` della 1.11.5); aggiorna `manifest.json` (`minAppVersion` 1.11.5).
- [ ] **Step 4: Verifica manuale:** dopo reload del plugin, `data.json` non contiene `apiPassword` (`grep apiPassword data.json` vuoto) e il quick import API funziona con il secret salvato.
- [ ] **Step 5:** Commit.

```bash
git add main.js manifest.json
git commit -m "feat: store API password in Obsidian secretStorage, require Obsidian 1.11.5"
```

---

### Task 3: Parser e riscrittura delle sezioni della nota

**Files:**
- Modify: `main.js` (nuova sezione "Note sections" dopo `computeCVSS31`)
- Test: `test/pure.test.js`

**Interfaces:**
- Produces:
  - `SECTION_DEFS: Array<{ key, field, kind: 'html'|'text'|'list'|'custom', aliases: string[] }>` (tabella in "Decisioni").
  - `parseSections(md: string): Record<key, { text: string, start: number, end: number }>`: offset del corpo (heading escluso) nel testo completo; ignora `## ` dentro code fence; per heading duplicati vale il primo.
  - `replaceSection(md: string, key: string, newText: string): string`: sostituisce il corpo della sezione; se la sezione manca la aggiunge in fondo con il primo alias.
  - `DEFAULT_SYNC_SECTIONS = ['poc']`.

- [ ] **Step 1: Test:** su una nota di esempio (frontmatter + 6 sezioni generate come in `createVulnNote`):
  - `parseSections(md).poc.text` è il testo tra `## Evidenza` e `## Assets`.
  - heading alias `## Evidence` mappa a `poc`.
  - una sezione `poc` contenente un code fence con riga `## not a heading` resta intera.
  - `replaceSection(md,'poc','X')` cambia solo quella sezione (`md` identico fuori dal range).
  - `replaceSection` su nota senza `## Evidenza` la crea in fondo.
- [ ] **Step 2:** FAIL. **Step 3:** implementa con scansione per righe che tiene traccia dello stato del fence. **Step 4:** PASS.
- [ ] **Step 5:** Commit.

```bash
git add main.js test/pure.test.js
git commit -m "feat: parse and replace note sections by heading alias"
```

---

### Task 4: Converter HTML<->MD e import fedele

**Files:**
- Modify: `main.js` (`stripHtml` ~45, `createVulnNote` ~975-978, nuova sezione "Converters")
- Test: `test/pure.test.js`

**Interfaces:**
- Consumes: `FORMATS` dal Task 0.
- Produces:
  - `htmlToMd(html: string): string`: wrapper di `htmlToMarkdown` di Obsidian.
  - `async mdToHtml(app, md: string, imgResolver: (src: string, alt: string) => string): Promise<string>`: `MarkdownRenderer.render` su `div` detached, poi `serializeWhitelist(el, imgResolver)`.
  - `serializeWhitelist(el: Element, imgResolver): string`: tag ammessi `p ul ol li strong em code pre a img h1..h6 table thead tbody tr th td br`; scarta il resto (testo mantenuto); `<img>` prodotto come da `FORMATS.imgTag`; `<pre>` come `FORMATS.codeBlockTag`.
  - `normalizeMd(app, md): Promise<string>`: `htmlToMd(await mdToHtml(app, md, identity))`, usato solo per il confronto.
- `createVulnNote` usa `htmlToMd` al posto di `stripHtml` per description, observation, remediation e custom fields.

- [ ] **Step 1: Test puro** su `serializeWhitelist` con un DOM minimale (stub `jsdom`-free: fornire un mini-elemento fake con `tagName`, `childNodes`, `getAttribute`): `<script>` scartato, `<strong>` mantenuto, `<img>` passa dal resolver, tag sconosciuto sostituito dal suo testo.
- [ ] **Step 2:** FAIL. **Step 3:** implementa. **Step 4:** PASS.
- [ ] **Step 5: Verifica manuale nel vault** (Obsidian CLI `eval` o console): `await normalizeMd(app, md)` è idempotente (`normalizeMd(normalizeMd(x)) === normalizeMd(x)`) su grassetto, lista, tabella, code block. Annota i casi non idempotenti nel doc dello spike.
- [ ] **Step 6:** Importa una vuln con descrizione formattata e controlla che la nota mantenga grassetto/liste.
- [ ] **Step 7:** Commit.

```bash
git add main.js test/pure.test.js
git commit -m "feat: faithful HTML<->Markdown conversion for import and sync"
```

---

### Task 5: Associazione cartella/nota ad audit e finding

**Files:**
- Modify: `main.js` (`DEFAULT_SETTINGS`, `onload`, nuovi modal, `createVulnNote` frontmatter)
- Test: `test/pure.test.js`

**Interfaces:**
- Produces:
  - `DEFAULT_SETTINGS.folderAudits = {}`.
  - `resolveAuditId(notePath: string, fm: object, folderAudits: object): string | null`: `fm.pwndoc_audit_id` se presente, altrimenti la voce di `folderAudits` per l'antenato più vicino, altrimenti `null`.
  - `renameFolderKeys(folderAudits, oldPath, newPath): object`: riscrive chiavi uguali o discendenti di `oldPath`.
  - `pwndocListAudits(baseUrl, token, ignoreSsl): Promise<Array<{_id,name,...}>>` e `pwndocGetAudit(baseUrl, token, id, ignoreSsl): Promise<{_id, updatedAt, findings: Finding[]}>` (path da `FORMATS`).
  - `AuditPickModal(app, audits, onChoose)` e `FindingPickModal(app, findings, onChoose, suggestedTitle)` (FuzzySuggestModal, il finding con titolo più simile è primo).
  - Comandi: `associate-folder` (sceglie cartella con `FolderModal`, poi audit), `associate-note` (audit risolto + finding, scrive i due campi nel frontmatter), `compare-with-pwndoc` (Task 9).
  - Handler `this.registerEvent(vault.on('rename', ...))` che aggiorna `folderAudits` con `renameFolderKeys`.
  - `createVulnNote` scrive `pwndoc_audit_id` quando la cartella target risolve un audit.

- [ ] **Step 1: Test:** `resolveAuditId` (nota vince su cartella; antenato più vicino vince su più lontano; nessuna voce -> `null`), `renameFolderKeys` (rinomina chiave e figlie, lascia le altre).
- [ ] **Step 2:** FAIL. **Step 3:** implementa pure + modal + comandi + handler. **Step 4:** PASS.
- [ ] **Step 5: Verifica manuale:** associa una cartella, crea una subfolder con una nota, esegui `associate-note`: il frontmatter ha i due id; rinomina la cartella e controlla `data.json`.
- [ ] **Step 6:** Commit.

```bash
git add main.js test/pure.test.js
git commit -m "feat: associate folders and notes to PwnDoc audit and finding"
```

---

### Task 6: Immagini (estrazione, upload con cache, download)

**Files:**
- Modify: `main.js` (nuova sezione "Images", `DEFAULT_SETTINGS`: `imageCache: {}`, `attachmentsFolder: 'attachments'`; settings tab)
- Test: `test/pure.test.js`

**Interfaces:**
- Consumes: `FORMATS.imageUploadBody`, `FORMATS.imageDownloadShape` (Task 0), `pwndocApi` (Task 1).
- Produces:
  - `extractImageRefs(md: string): Array<{ raw: string, src: string, alt: string }>`: sintassi `![alt](src)` e `![[src|alt]]`; ignora i code fence; `src` URL-decoded.
  - `replaceImageRefs(md: string, map: (ref) => string): string`.
  - `async uploadImage(ctx, auditId, vaultPath): Promise<string>` (ritorna `imageId`): legge i byte via `app.vault.readBinary`, calcola `sha256` (`crypto.createHash`), consulta `settings.imageCache[auditId][hash]`, altrimenti POST e salva in cache.
  - `async downloadImage(ctx, imageId, destFolder): Promise<string>` (ritorna il path vault creato; nome `<imageId>.<ext>`; non riscarica se esiste).

- [ ] **Step 1: Test:** `extractImageRefs` su `![Figura 1 – login](img/a b.png)`, `![[shot.png|caption]]`, e su un fence contenente `![x](y.png)` (non estratta); `replaceImageRefs` sostituisce solo i match attesi. FAIL -> implementa -> PASS.
- [ ] **Step 2:** Test con `uploadImage` e client fake (`pwndocApi` iniettato): stessa immagine due volte -> un solo POST; file mancante -> rigetta con `missing image: <path>` senza POST.
- [ ] **Step 3: Verifica manuale:** upload di una PNG vera contro l'istanza di test e visualizzazione nell'UI PwnDoc; download di un'immagine remota nel vault.
- [ ] **Step 4:** Commit.

```bash
git add main.js test/pure.test.js
git commit -m "feat: image extraction, cached upload and download for PwnDoc sync"
```

---

### Task 7: Diff per sezione

**Files:**
- Modify: `main.js` (sezione "Diff")
- Test: `test/pure.test.js`

**Interfaces:**
- Produces:
  - `lineDiff(a: string, b: string): Array<{ op: 'eq'|'add'|'del', line: string }>` (LCS a righe).
  - `async buildComparison(ctx, noteMd: string, finding: Finding, keys: string[]): Promise<Array<{ key, local: string, remote: string, changed: boolean, diff: ReturnType<typeof lineDiff> }>>`: `local` = `normalizeMd` della sezione locale; `remote` = `htmlToMd(finding[field])` normalizzato (per `text` e `list` conversione banale: `scope` testo, `references` una per riga).

- [ ] **Step 1: Test:** `lineDiff('a\nb','a\nc')` = `[eq a, del b, add c]`; stringhe uguali -> tutti `eq`; vuoto vs non vuoto. `buildComparison` con converter finti: `changed=false` quando local e remote coincidono dopo normalizzazione.
- [ ] **Step 2:** FAIL -> implementa -> PASS.
- [ ] **Step 3:** Commit.

```bash
git add main.js test/pure.test.js
git commit -m "feat: per-section line diff between note and PwnDoc finding"
```

---

### Task 8: Store della history

**Files:**
- Modify: `main.js` (sezione "History", `DEFAULT_SETTINGS.historyLimit = 50`)
- Test: `test/pure.test.js`

**Interfaces:**
- Produces:
  - `type HistoryEntry = { id: string, ts: string /* ISO */, op: 'push'|'pull'|'merge'|'rollback'|'create', forced: boolean, auditId: string, findingId: string, notePath: string, sections: string[], remoteBefore: Finding | null, localBefore: string | null /* nota completa */ }`.
  - `historyDir(manifestDir: string, findingId: string): string` = `<manifestDir>/history/<findingId>`.
  - `async recordHistory(adapter, dir: string, entry: HistoryEntry, limit: number): Promise<void>`: scrive `<ts-filename-safe>-<op>.json` e poi elimina le entry oltre `limit`.
  - `async listHistory(adapter, dir: string): Promise<HistoryEntry[]>`: dal più recente; file corrotti saltati con `dbg`.
  - `pruneNames(names: string[], limit: number): string[]`: nomi da eliminare (i più vecchi oltre `limit`), pura.
  - `type Base = { ts: string, sections: Record<string, string> }` (testo MD normalizzato per sezione all'ultimo sync).
  - `async saveBase(adapter, dir, base: Base): Promise<void>` e `async loadBase(adapter, dir): Promise<Base | null>` (file `base.json` nella cartella del finding, non soggetto a `pruneNames`). `saveBase` unisce le sezioni nuove con quelle già presenti.

- [ ] **Step 1: Test** con `adapter` finto in memoria: `recordHistory` poi `listHistory` restituisce l'entry; con `limit=2` e 3 record resta solo il più vecchio escluso; `listHistory` salta un file con JSON non valido; `pruneNames(['a','b','c'], 2)` = `['a']`; `loadBase` senza file = `null`; due `saveBase` successivi con sezioni diverse restituiscono l'unione e `pruneNames` non elimina mai `base.json`.
- [ ] **Step 2:** FAIL -> implementa (adapter = `app.vault.adapter`, `mkdir`/`write`/`list`/`read`/`remove`) -> PASS.
- [ ] **Step 3:** Commit.

```bash
git add main.js test/pure.test.js
git commit -m "feat: per-finding history store with retention"
```

---

### Task 9: Modal di merge, push e pull

**Files:**
- Modify: `main.js` (nuovo `MergeModal`, metodi `compareWithPwndoc`, `pushSections`, `pullSections`; comando `compare-with-pwndoc`)
- Test: `test/pure.test.js`

**Interfaces:**
- Consumes: Task 3 (`parseSections`, `replaceSection`), 4 (`mdToHtml`, `htmlToMd`), 5 (`resolveAuditId`, `pwndocGetAudit`), 6 (`uploadImage`, `downloadImage`, `extractImageRefs`, `replaceImageRefs`), 7 (`buildComparison`), 8 (`recordHistory`, `historyDir`).
- Produces:
  - `buildPushPayload(finding: Finding, htmlBySection: Record<key,string>, sections: string[]): Finding`: copia di `finding` con i soli campi mappati (`SECTION_DEFS`) sostituiti. Per `customFields` i blocchi `**label**` della nota si mappano a `customField` id tramite il reverse di `this.cfLabels` (caricato da API se assente); label sconosciute sono ignorate con `Notice`.
  - `findingHash(finding: Finding, sections: string[]): string`: sha256 del JSON ordinato dei campi mappati dalle `sections` (il finding non ha `updatedAt`).
  - `assertUnchanged(snapshotHash: string, fresh: Finding, sections: string[]): void`: lancia `Error('finding changed on PwnDoc since compare')` se `findingHash(fresh, sections) !== snapshotHash`.
  - `assertEditable(audit: { state: string }, force: boolean): void`: lancia `AuditLockedError(state)` se `state !== 'EDIT'` e `!force` (valore da `FORMATS.auditStateValues`).
  - `MergeModal(app, comparison, defaultKeys, onApply)`: una riga per sezione con checkbox (solo `defaultKeys`, cioè `['poc']`, spuntata), diff colorato, scelta direzione per sezione (`push` | `pull`), pulsanti "Tutte"/"Nessuna"; `onApply({ push: key[], pull: key[], force: boolean })`. Se l'audit non è in `EDIT` la modale mostra un banner con lo stato e la checkbox `Enforce write on non-EDIT audit` (non persistita, spenta di default); senza spunta i pulsanti di push restano disabilitati, il pull resta ammesso.
  - Push: per ogni sezione scelta -> `replaceImageRefs` con `uploadImage` -> `mdToHtml` -> `buildPushPayload` -> `assertEditable` e `assertUnchanged` su GET fresco -> `recordHistory` (op `push`, `forced`, `remoteBefore` = finding fresco, `localBefore` = nota) -> PUT.
  - Pull: `htmlToMd` della sezione remota -> immagini `<img src=id>` scaricate con `downloadImage` e riscritte in `![alt](path)` -> `recordHistory` (op `pull`) -> `replaceSection`.
  - Se `recordHistory` fallisce l'operazione non procede.
  - Sezione locale vuota con remota non vuota (push) o l'inverso (pull): `confirm` esplicito prima di procedere.

- [ ] **Step 1: Test:** `buildPushPayload` cambia solo `poc` quando `sections=['poc']` e lascia identici tutti gli altri campi (deep equal con l'originale); `assertUnchanged` lancia se un campo selezionato è cambiato e non lancia se cambia solo un campo non selezionato; `assertEditable({state:'REVIEW'}, false)` lancia, con `force=true` o `{state:'EDIT'}` no.
- [ ] **Step 2:** FAIL -> implementa -> PASS.
- [ ] **Step 3: Verifica manuale end to end** sull'istanza di test: (a) nota con Evidenza contenente testo formattato e 2 immagini: push, apri il finding in PwnDoc e controlla formattazione e immagini; (b) ripeti il push: diff vuoto, nessun nuovo upload; (c) modifica il PoC in PwnDoc e fai pull: la nota si aggiorna e le immagini compaiono in `attachments`; (d) modifica il finding in PwnDoc tra compare e push: il push abortisce con il messaggio atteso; (e) selezione "Tutte": le altre sezioni si aggiornano; (f) Evidenza locale vuota, push: richiede conferma; (g) porta l'audit in REVIEW: il push è bloccato, con `Enforce` spuntato passa e l'entry di history ha `forced: true`, il pull funziona comunque.
- [ ] **Step 4:** Commit.

```bash
git add main.js test/pure.test.js
git commit -m "feat: merge modal with bidirectional per-section push and pull"
```

---

### Task 10: History viewer e rollback

**Files:**
- Modify: `main.js` (`HistoryModal`, comando `rollback-from-history`, riuso di `MergeModal`)
- Test: `test/pure.test.js`

**Interfaces:**
- Consumes: Task 8 (`listHistory`, `recordHistory`), Task 9 (`MergeModal`, `buildPushPayload`, `assertUnchanged`), Task 7 (`lineDiff`), Task 3 (`parseSections`, `replaceSection`).
- Produces:
  - `HistoryModal(app, entries, onChoose)`: elenco con data, operazione, sezioni toccate; scelta di un'entry e di una **destinazione**: `Restore PwnDoc` (usa `remoteBefore`) o `Restore note` (usa `localBefore`).
  - `buildRollbackComparison(entry, side: 'remote'|'local', currentFinding: Finding, currentNoteMd: string): Array<{ key, current: string, snapshot: string, changed: boolean, diff }>`: confronto tra stato attuale e snapshot, una riga per sezione di `SECTION_DEFS`; sezioni preselezionate = `entry.sections`.
  - `restoreRemote(finding: Finding, snapshot: Finding, sections: string[]): Finding`: come `buildPushPayload` ma con l'HTML dello snapshot (nessuna conversione né upload).
  - `restoreLocal(noteMd: string, snapshotMd: string, sections: string[]): string`: `replaceSection` ripetuto con il testo delle sezioni dello snapshot.
  - Ogni rollback passa da `assertEditable` e `assertUnchanged` (lato remoto, con lo stesso banner e la checkbox `Enforce`), scrive una entry `op: 'rollback'` e quindi è annullabile con un secondo rollback.

- [ ] **Step 1: Test:**
  - `restoreRemote(current, snapshot, ['poc'])` ha `poc` uguale a quello dello snapshot e tutti gli altri campi uguali a `current` (deep equal).
  - `restoreLocal` cambia solo le sezioni richieste.
  - Rollback di un rollback: applicare `restoreRemote` due volte con gli snapshot incrociati riporta al finding originale.
  - `buildRollbackComparison` segna `changed=false` per le sezioni identiche.
- [ ] **Step 2:** FAIL -> implementa -> PASS.
- [ ] **Step 3: Verifica manuale:** (a) push di Evidenza, poi rollback `Restore PwnDoc`: il PoC in PwnDoc torna com'era, immagini incluse; (b) pull che sovrascrive il locale, poi `Restore note`: la sezione locale torna com'era; (c) modifica il finding in PwnDoc dopo lo snapshot e prova il rollback: il diff mostra la modifica e, se il finding cambia durante la modale, `assertUnchanged` blocca; (d) rollback del rollback; (e) superato `historyLimit` le entry più vecchie spariscono.
- [ ] **Step 4:** Commit.

```bash
git add main.js test/pure.test.js
git commit -m "feat: history viewer and per-section rollback for PwnDoc and note"
```

---

### Task 11: Sync di titolo e CVSS

**Files:**
- Modify: `main.js` (`SECTION_DEFS`, `buildComparison`, `pushSections`, `pullSections`)
- Test: `test/pure.test.js`

**Interfaces:**
- Consumes: `SECTION_DEFS` (Task 3), `computeCVSS31` (esistente), `buildPushPayload` e `pullSections` (Task 9).
- Produces:
  - `SECTION_DEFS` con due voci in più: `{ key: 'title', field: 'title', kind: 'text', source: 'filename' }` e `{ key: 'cvssv3', field: 'cvssv3', kind: 'text', source: 'frontmatter', fmKey: 'cvss_vector' }`. `parseSections` le ignora (non sono heading).
  - `titleFromBasename(basename: string): string`: toglie `^(VT|M)-\d+ - `.
  - `isValidCvss31(v: string): boolean`: regex sul vettore completo `CVSS:3.1/AV:./AC:./PR:./UI:./S:./C:./I:./A:.` con valori ammessi per metrica.
  - `cvssFrontmatter(vector: string): { cvss_vector, cvss_link, cvss_score, cvss_severity, severity }`: stessi campi e formati di `createVulnNote`.
  - `localValue({ basename, fm, md }, def: SectionDef): string`: sorgente locale di una chiave (heading, filename o frontmatter).
  - Push: `title` sanitizzato come in `createVulnNote` (`[\\/:*?"<>|]` -> `-`); `cvssv3` con vettore non valido blocca l'operazione prima del PUT. Pull: `title` rinomina la nota con `app.fileManager.renameFile` mantenendo `PREFIX-NN - ` (rifiuta se il path esiste già); `cvssv3` aggiorna il frontmatter con `cvssFrontmatter` via `processFrontMatter`.

- [ ] **Step 1: Test:** `titleFromBasename('VT-03 - SQL Injection')` = `SQL Injection`, `M-12 - A - B` = `A - B`; `isValidCvss31` vero per il vettore di esempio del README, falso per `CVSS:3.0/...`, per metriche mancanti e per valori fuori set; `cvssFrontmatter` su `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` dà `cvss_score` 9.8 e `cvss_severity` `CRITICAL`; `localValue` legge titolo da filename e CVSS da frontmatter.
- [ ] **Step 2:** FAIL -> implementa -> PASS.
- [ ] **Step 3: Verifica manuale:** cambia il CVSS nella nota, push solo `cvssv3`: PwnDoc mostra il nuovo vettore e punteggio; cambia il titolo in PwnDoc e fai pull: la nota si rinomina e i wikilink che la puntano restano validi; vettore invalido: blocco con Notice, nessun PUT.
- [ ] **Step 4:** Commit.

```bash
git add main.js test/pure.test.js
git commit -m "feat: sync title and CVSS vector between note and PwnDoc finding"
```

---

### Task 12: Merge a tre vie

**Files:**
- Modify: `main.js` (sezione "Merge3", `MergeModal`, `compareWithPwndoc`, `pushSections`, `pullSections`)
- Test: `test/pure.test.js`

**Interfaces:**
- Consumes: `lineDiff` (Task 7), `loadBase`/`saveBase`/`recordHistory` (Task 8), `MergeModal`, push e pull (Task 9).
- Produces:
  - `classify(base: string | undefined, local: string, remote: string): 'same' | 'local' | 'remote' | 'conflict' | 'unknown'`: `same` se local = remote; `unknown` se `base` è `undefined` e local ≠ remote; `local` se solo local ≠ base; `remote` se solo remote ≠ base; altrimenti `conflict`.
  - `merge3(base: string, local: string, remote: string): { text: string, conflicts: number }`: diff3 a righe (due `lineDiff` contro la base, blocchi non sovrapposti uniti, sovrapposti con modifiche diverse emessi con marcatori `<<<<<<< local` / `=======` / `>>>>>>> pwndoc`). // ponytail: granularità a riga, per parole se serve.
  - `hasConflictMarkers(text: string): boolean`: vero se esiste una riga che inizia per `<<<<<<< local`, `=======` o `>>>>>>> pwndoc`.
  - `buildComparison` restituisce anche `base` e `status` per riga; `MergeModal` mostra un badge di stato, preimposta la direzione (`local` -> push, `remote` -> pull, `conflict` -> riga con textarea precompilata da `merge3`, `unknown` -> due vie come ora) e disabilita Apply finché una riga selezionata ha `hasConflictMarkers`.
  - `onApply` riceve anche `merged: Record<key, string>`: per queste sezioni il testo risolto va **sia** al remoto (stessa pipeline di push: upload immagini, `mdToHtml`, un solo PUT) **sia** alla nota (`replaceSection`); history con `op: 'merge'`.
  - Dopo ogni push, pull o merge riuscito `saveBase` aggiorna le sezioni scambiate con il testo normalizzato finale.

- [ ] **Step 1: Test:**
  - `classify`: tabella completa (`same`, `local`, `remote`, `conflict`, `unknown` con base mancante).
  - `merge3('a\nb\nc','a\nB\nc','a\nb\nC')` = `a\nB\nC`, 0 conflitti (modifiche su righe diverse).
  - `merge3('a\nb\nc','a\nX\nc','a\nY\nc')` = 1 conflitto, `hasConflictMarkers` vero.
  - modifica identica su entrambi i lati: 0 conflitti, nessuna duplicazione.
  - solo local cambiato: `merge3` = local; solo remote: = remote.
  - `hasConflictMarkers('a\n=======\nb')` vero, `hasConflictMarkers('a = b')` falso.
- [ ] **Step 2:** FAIL -> implementa -> PASS.
- [ ] **Step 3: Verifica manuale:** (a) push di Evidenza, poi modifica solo la nota: badge `local`, direzione push preimpostata; (b) modifica solo PwnDoc: badge `remote`, pull preimpostato; (c) modifica su righe diverse da entrambi i lati: merge automatico senza conflitti, applicato a entrambi i lati con un solo PUT; (d) stessa riga modificata in entrambi: textarea con marcatori, Apply disabilitato finché non li rimuovi; (e) cancella `base.json`: la sezione torna `unknown` e funziona a due vie.
- [ ] **Step 4:** Commit.

```bash
git add main.js test/pure.test.js
git commit -m "feat: three-way merge with per-section status and line-level diff3"
```

---

### Task 13: Crea finding in PwnDoc (da libreria o da zero)

**Files:**
- Modify: `main.js` (`LibraryVulnPickModal`, comando `create-finding-in-pwndoc`, `associate-note` esteso)
- Test: `test/pure.test.js`

**Interfaces:**
- Consumes: `FORMATS.createFindingPath`/`createFindingBody` (Task 0), `pwndocFetchVulns` e `pwndocFetchVulnDetail` (esistenti, riusati per la libreria), `pwndocGetAudit` (Task 5), `assertEditable` e `MergeModal` (Task 9), `recordHistory` (Task 8), `cvssFrontmatter`/`isValidCvss31`/`titleFromBasename` (Task 11).
- Produces:
  - `matchFinding(title: string, findings: Finding[]): Finding | null`: uguaglianza case-insensitive e a spazi normalizzati sul titolo, `null` se assente o ambigua (due match).
  - `buildFindingFromLibrary(vuln: LibraryVuln, locale: string): CreateFindingBody`: sceglie il `detail` con `locale` uguale a quello dell'audit (fallback al primo) e copia titolo, tipo, description, observation, remediation, references, cvssv3 e custom fields nel formato di `FORMATS.createFindingBody`.
  - `buildFindingFromNote(title: string, cvssVector: string, locale: string): CreateFindingBody`: finding minimale; `cvssv3` omesso se il vettore non è valido.
  - `LibraryVulnPickModal(app, vulns, suggestedId, onChoose)`: ricerca fuzzy sull'intera libreria, `suggestedId` (il `pwndoc_id` del frontmatter) in testa e con etichetta `suggested`, ultima voce `New blank finding`.
  - `async createFinding(ctx, auditId, body: CreateFindingBody, force: boolean): Promise<string>`: `assertEditable` su GET fresco dell'audit, POST (la risposta non contiene l'id), poi GET dell'audit e `_id` del finding con `identifier` più alto, ritornato.
  - Flusso del comando: (1) risolve l'audit (Task 5); (2) cerca il finding con `matchFinding`: se c'è propone di associarlo e termina; (3) altrimenti apre `LibraryVulnPickModal` con `pwndoc_id` suggerito; (4) `createFinding` (con checkbox `Enforce` come nel merge se l'audit non è `EDIT`); (5) scrive `pwndoc_audit_id` e `pwndoc_finding_id` nel frontmatter; (6) `recordHistory` con `op: 'create'`, `remoteBefore: null`; (7) apre `MergeModal` con `['poc']` preselezionato.
  - `associate-note` (Task 5): se `matchFinding` non trova nulla offre `Create finding` e passa dal flusso sopra.

- [ ] **Step 1: Test:**
  - `matchFinding`: match esatto ignorando maiuscole e spazi doppi; nessun match; due finding con lo stesso titolo -> `null`.
  - `buildFindingFromLibrary`: sceglie il `detail` del locale dell'audit, altrimenti il primo; copia i campi attesi.
  - `buildFindingFromNote` omette `cvssv3` per un vettore non valido.
  - `createFinding` con client finto: audit in `REVIEW` e `force=false` rigetta senza POST; con `force=true` esegue un solo POST e ritorna l'id.
- [ ] **Step 2:** FAIL -> implementa -> PASS.
- [ ] **Step 3: Verifica manuale:** (a) nota importata dalla libreria in una cartella associata, senza finding: il comando suggerisce la vuln di libreria corretta, il finding compare nell'audit con titolo, CVSS e testi di libreria, poi il merge propone Evidenza; (b) scegli una vuln di libreria diversa da quella suggerita: viene usata quella scelta; (c) `New blank finding`: finding con titolo e CVSS della nota; (d) audit in REVIEW: la creazione è bloccata senza `Enforce`; (e) titolo già presente come finding: il comando propone di associarlo e non crea duplicati.
- [ ] **Step 4:** Commit.

```bash
git add main.js test/pure.test.js
git commit -m "feat: create PwnDoc finding from library vuln or note, with audit state guard"
```

---

### Task 14: Documentazione e release

**Files:**
- Modify: `README.md`, `manifest.json` (`version` 1.3.0), eventualmente `.github/workflows/release.yml` se elenca file fissi

- [ ] **Step 1:** README: sezioni "Engagement sync" (associazione, mapping sezioni, default Evidenza, push/pull, immagini, history e rollback, `historyLimit`, merge a tre vie, sync di titolo e CVSS, creazione finding da libreria o da zero, guard sullo stato dell'audit con `Enforce`), aggiornare "Requirements" (Obsidian 1.11.5), rimuovere "stored in plain text" per la password, documentare `attachmentsFolder`.
- [ ] **Step 2:** Controlla che `release.yml` includa `main.js` e `manifest.json` senza elencare file nuovi (nessun file nuovo di runtime è previsto).
- [ ] **Step 3:** `node --test test/pure.test.js` PASS completo; commit.

```bash
git add README.md manifest.json
git commit -m "docs: document engagement sync, bump to 1.3.0"
```
