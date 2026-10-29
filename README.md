# PwnDoc Importer

An [Obsidian](https://obsidian.md) plugin that imports vulnerabilities from a [PwnDoc](https://github.com/pwndoc/pwndoc) instance — either from a local CSV export or directly via the PwnDoc API — and automatically creates structured notes in your vault.

## Features

- Import vulnerabilities from a PwnDoc CSV export via fuzzy-search modal
- Fetch vulnerabilities directly from the PwnDoc API without a pre-exported file
- API credentials can be saved in plugin settings or entered in a popup at import time
- Optionally save the fetched API data as a local CSV for future offline use, with a configurable default output folder
- Automatically calculate CVSS 3.1 scores and severity ratings
- Convert HTML-formatted PwnDoc fields to Markdown, keeping bold, lists, tables and code blocks
- Generate pre-structured notes with YAML frontmatter (severity, platform, CVSS data, OWASP category, CWE)
- Automatically fetch custom field definitions from the API and append all non-empty custom fields as a **Custom Fields** section at the end of the note, using human-readable labels (`displaySub`)
- Filter vulnerabilities by locale (`EN-en`, `IT-it`, or all)
- **Quick import command** with a default source (CSV/API) and default language, ready to be bound to a hotkey
- Choose between **VT** (Vulnerability Ticket) or **M** (Mobile) note prefixes
- Auto-number notes sequentially (`VT-01`, `VT-02`, …)
- Select the target vault folder interactively on each import
- **Engagement sync**: link notes or folders to a PwnDoc audit, compare with the finding and merge per section (push, pull or three-way), with image upload, history and rollback, title/CVSS sync and finding creation (see below)

## Requirements

- Obsidian 1.11.5 or later (uses Obsidian secret storage)
- Desktop only (not supported on mobile)

## Installation

1. Download or clone this repository into your vault's plugin folder:
   ```
   <your-vault>/.obsidian/plugins/pwndoc-importer/
   ```
2. Ensure the folder contains `manifest.json` and `main.js`.
3. In Obsidian, go to **Settings → Community plugins**, disable Safe Mode, and enable **PwnDoc Importer**.

## Configuration

Open **Settings → PwnDoc Importer** to configure the plugin.

### General

| Setting | Default | Description |
|---|---|---|
| **CSV file path** | *(empty)* | Absolute or vault-relative path to a PwnDoc vulnerabilities CSV export |
| **Locale filter** | `EN-en` | Filter vulnerabilities by language (`EN-en`, `IT-it`, or `All`) |

### Quick import

Options for the **Quick import vulnerability** command (bind it to a hotkey in *Settings → Hotkeys*). It skips the source and language pickers by using the defaults below; the VT/M prefix and target folder are still asked per import.

| Setting | Default | Description |
|---|---|---|
| **Default source** | `CSV — local file` | Where the quick import fetches vulnerabilities from (CSV or PwnDoc API) |
| **Default language** | `All locales` | Locale filter applied before opening the vuln list |

Notes:
- With the **API** source, the quick import connects with the credentials saved in settings (it won't prompt for them) and silently saves `vulnerabilities.csv` to the *Default CSV output folder* when that folder is set — otherwise it skips saving. It also skips the CSV-output popup.
- If the configured language isn't present in the data, the quick import falls back to showing all locales with a notice.

### Custom field IDs

| Setting | Default | Description |
|---|---|---|
| **OWASP field column** | `cf_62d92f1597c7c5001833273f` | Field ID for OWASP category (matches the `_id` in PwnDoc custom fields) |
| **CWE field column** | `cf_63ab317fafe66f0011b89881` | Field ID for CWE identifier |

These values must match the `_id` of the corresponding custom fields in your PwnDoc instance.

### API credentials

| Setting | Description |
|---|---|
| **PwnDoc URL** | Base URL of the PwnDoc instance (e.g. `https://localhost:8443`) |
| **Username** | PwnDoc username |
| **Password** | PwnDoc password, kept in Obsidian secret storage (pick or create the secret in the settings). An old plain-text password in `data.json` is moved there automatically on first load. |
| **Ignore SSL certificate errors** | Enable for self-signed certificates |

If any credential field is left blank, the plugin will prompt for credentials at import time. Credentials can also be saved from the import popup by checking **Save credentials in plugin settings**.

### CSV output

| Setting | Description |
|---|---|
| **Default CSV output folder** | Absolute path to the folder where `vulnerabilities.csv` will be saved after an API fetch. Leave blank to be prompted each time. |

### Debug

| Setting | Default | Description |
|---|---|---|
| **Debug mode** | `off` | When enabled, logs detailed information to the browser console during API imports. Open the developer tools with `Ctrl+Shift+I` and filter by `[PwnDoc Importer]` in the Console tab. |

## Usage

Three import commands are available from the command palette (`Ctrl+P` / `Cmd+P`); any of them can be assigned a hotkey in *Settings → Hotkeys*.

### Quick import

1. Run **Quick import vulnerability** (or its hotkey).
2. The plugin fetches the vuln list from the default source (CSV or API) and applies the default language filter — no source or language picker.
3. Search for the vulnerability in the fuzzy-search modal, then continue with the usual prefix → folder → note flow.

### From CSV

1. Run **Import vulnerability from CSV**.
2. Search for the vulnerability using the fuzzy-search modal (shows title, locale, category, and priority).
3. Choose the note prefix: **VT** (Vulnerability Ticket) or **M** (Mobile).
4. Choose the target vault folder (current folder or custom path).
5. The note is created and opened automatically.

### From PwnDoc API

1. Run **Fetch and import vulnerability from PwnDoc API**.
2. A **credentials popup** appears, pre-filled with any values saved in settings. Adjust if needed, enable **Ignore SSL** for self-signed certs, and optionally check **Save credentials in plugin settings** to persist them.
3. The plugin logs in, fetches the vulnerability list (`GET /api/vulnerabilities`) and custom field definitions in parallel, then fetches full detail (`GET /api/vulnerabilities/detail/:id`, 5 at a time) for every listed vuln — the list endpoint only returns metadata (id, cvss, category, title per locale), not description/observation/remediation. A progress notice shows `fetching details N/M…`. Once all details are in, it shows a **CSV output popup** pre-filled with the default output folder from settings:
   - Confirm the folder path to save the fetched data as `vulnerabilities.csv` for future offline use.
   - Click **Skip** to import without saving.
4. The locale filter from settings is applied, then the usual fuzzy-search → prefix → folder → note flow continues.

## Engagement sync

Link notes to a PwnDoc **engagement (audit)**, compare them with the matching **finding** and merge section by section, in both directions. By default only the **Evidenza / proof of concept** section is selected, so evidence written in Obsidian can be pushed into a finding that is already populated on PwnDoc without touching the rest.

### Associating notes

| Command | What it does |
|---|---|
| **Associate folder to PwnDoc engagement** | Pick a vault folder (or right-click a folder in the file explorer) and an audit. Subfolders inherit it (nearest folder wins). Renaming the folder keeps the association. Every note the folder owns gets `pwndoc_audit_id` and `pwndoc_audit` (the engagement name) in its frontmatter, so it shows in the Properties panel and can be searched or used in Bases. Notes created or moved into the folder get it too; notes already linked to a finding of another engagement are left alone. |
| **Associate note to PwnDoc finding** | Picks the finding of the audit (best title match first) and writes `pwndoc_audit_id` and `pwndoc_finding_id` in the frontmatter. If the audit has no finding with the note title it offers to create one. |
| **Create PwnDoc finding for this note** | Links an existing finding with the same title, otherwise creates one from a **library vulnerability** (the one in `pwndoc_id` is suggested, any other can be picked) or a **blank** finding with the note title and CVSS. Then opens the compare with Evidenza selected. |

### Quick actions

- **Status bar:** for a note that belongs to an engagement it shows `PwnDoc: <engagement>` (with `· no finding` until the note is linked). Click it for a menu with compare, associate note, create finding, history, associate folder and refresh.
- **Note header buttons:** compare/merge and history appear once the note is linked to a finding; link and create-finding appear while it is not.
- **Refresh engagement attribute on notes** (command or status-bar menu) re-reads the engagement names from PwnDoc and rewrites the attribute on every associated folder, for example after renaming an audit.

### Compare and merge

**Compare with PwnDoc and merge sections** opens one row per section with its status, a diff and a direction (`note → PwnDoc`, `PwnDoc → note`, or `merge both`).

| Section in the note | PwnDoc field |
|---|---|
| Descrizione | `description` |
| Impatto | `observation` |
| **Evidenza** (default) | `poc` |
| Assets | `scope` |
| Remediation | `remediation` |
| References | `references` |
| Title (file name after `VT-NN - `) | `title` |
| CVSS vector (`cvss_vector`) | `cvssv3` |
| Custom Fields | shown in the diff only, never written |

- **Three-way status.** After every successful sync the plugin stores the synced text of each section as a base. A section is then `changed in the note`, `changed on PwnDoc`, `changed on both sides` or `identical`; the direction is preselected accordingly. When both sides changed, a line-level three-way merge is proposed in an editable box: changes on different lines are combined, changes on the same or adjacent lines produce `<<<<<<< local / ======= / >>>>>>> pwndoc` markers that must be resolved before **Apply** works. Without a base (first sync) the comparison is two-way.
- **Images.** Images in the section (`![alt](path)` and `![[path|alt]]`) are uploaded to PwnDoc and referenced as `<img src="<id>" alt="<alt>">`; the alt text is the caption. Uploads are cached by content hash, so repeating a push does not re-upload. Pulling downloads PwnDoc images into the **attachments folder** and rewrites them to vault links. Images above 12 MB, remote `http(s)` images and unsupported types are rejected before anything is written.
- **Formatting.** Notes are converted to the HTML subset PwnDoc stores (paragraphs, bold/italic, lists, tables, code blocks, links, images); PwnDoc HTML is converted to Markdown on pull.
- **Empty sections.** Overwriting a populated section with an empty one (either direction) asks for confirmation.
- **Only the selected fields are written** (the finding update is a patch), and a push is aborted if the selected fields changed on PwnDoc after you opened the compare.
- **Audit state guard.** Writing to PwnDoc requires the audit to be in state `EDIT`. Otherwise the dialog shows the state and an **Enforce** checkbox (off by default, valid for that operation only); forced operations are marked in the history. Pulling is local and is never blocked.

### History and rollback

Every push, pull, merge, rollback and finding creation stores the finding and the note as they were **before** the operation in `<vault>/.obsidian/plugins/pwndoc-importer/history/<findingId>/` (the last *History entries per finding* are kept). **Restore from PwnDoc sync history (rollback)** lets you pick an entry and restore chosen sections either on PwnDoc or in the note, through the same diff dialog and guards. A rollback is itself recorded, so it can be rolled back. Uploaded images are never deleted, so restored evidence keeps its pictures.

The history folder contains client data: do not commit it (`history/` is git-ignored in this repository). `data.json` also stores the engagement names you associate and the API address, so keep it out of version control if you share this folder.

### Settings

| Setting | Default | Description |
|---|---|---|
| **Attachments folder** | `attachments` | Vault folder where images pulled from PwnDoc are saved |
| **History entries per finding** | `50` | Older history entries are pruned |

## Generated Note Structure

Notes are named `<PREFIX>-<NN> - <Title>.md` (e.g. `VT-03 - SQL Injection.md`) and contain:

**YAML frontmatter**
```yaml
severity: CRITICAL
platform: WEB
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
cvss_link: "https://www.first.org/cvss/calculator/3-1#CVSS:3.1/..."
cvss_score: 9.8
cvss_severity: CRITICAL
status: "DRAFT"
pwndoc: true
pwndoc_id: "<original_pwndoc_id>"
locale: "EN-en"
category: "WAPT"
assets: "INSERT_ASSET"
```

**Content sections**
- Metadata table (Severity, CVSS 3.1 vector + score, OWASP category, CWE)
- Description
- Impact
- Evidence *(blank — to be filled during the assessment)*
- Assets *(blank — to be filled during the assessment)*
- Remediation
- References *(included only when present in the source data)*
- Custom Fields *(included only when the vulnerability has non-empty custom fields beyond OWASP and CWE; each field is rendered as a bold label followed by its plain-text value)*

**Custom field resolution** — when importing via API, the plugin calls `GET /api/data/custom_fields` in parallel with the vulnerability fetch and builds a map of `_id → displaySub`. This label is used as the column name in the saved CSV and as the section header in the note. When importing from a CSV saved without API metadata, the raw `cf_<id>` key is used as fallback.

Platform is inferred automatically from the PwnDoc category:
- `WAPT` → `WEB`
- `Android` → `Android`
- `iOS` → `iOS`
- `Mobile` / anything else → `Mobile`

## CSV Format

The plugin expects a CSV with (at minimum) the following columns. This is the format produced by both the PwnDoc API import (when saving) and any companion export script.

| Column | Description |
|---|---|
| `id` | PwnDoc vulnerability ID |
| `title` | Vulnerability title |
| `locale` | Language code (e.g. `EN-en`) |
| `category` | Category (e.g. `WAPT`, `Android`) |
| `priority` | Priority level |
| `cvssv3` | CVSS 3.1 vector string |
| `description` | HTML-formatted description |
| `observation` | HTML-formatted impact/observation |
| `remediation` | HTML-formatted remediation steps |
| `references` | Reference links |
| *custom field columns* | Named after the `displaySub` label from PwnDoc (or `cf_<id>` if label is unavailable) |

## Author

davide.caputo
