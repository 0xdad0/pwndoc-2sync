# PwnDoc 2Sync

An [Obsidian](https://obsidian.md) plugin that keeps your finding notes and a [PwnDoc](https://github.com/pwndoc/pwndoc) engagement in sync, in both directions. Write the finding in Obsidian, send it to the engagement, pull what changed on PwnDoc, generate the report. It also imports library vulnerabilities into structured notes.

> Formerly *PwnDoc Importer*. The plugin id is still `pwndoc-importer`, so the folder, settings, history and stored password of an existing installation keep working.

Technical details (architecture, data model, algorithms, API calls, tests) are in [docs/TECHNICAL.md](docs/TECHNICAL.md).

## What it does

- **Send a note to PwnDoc**: pick the finding of the engagement (or create it), compare side by side, push only what you choose. By default only the **Evidenza** section, images included.
- **Pull** what changed on PwnDoc, section by section, with a three-way merge when both sides changed.
- **Dashboard** of the whole engagement: sync state of every note, bulk push and pull, orphans, findings without a note.
- **Safety net**: lint before pushing, audit state guard, history of every write with rollback, warning when PwnDoc changed under you.
- **Engagement and report**: create an engagement, choose its report template, generate the docx, mark findings completed, delete findings.
- **Import** library vulnerabilities from a CSV export or the PwnDoc API into `VT-NN` / `M-NN` notes.

## Requirements and installation

- Obsidian 1.11.5 or later (uses Obsidian secret storage). Desktop only.
- Copy `main.js` and `manifest.json` into `<vault>/.obsidian/plugins/pwndoc-importer/`, then enable **PwnDoc 2Sync** in *Settings, Community plugins*.
- In *Settings, PwnDoc 2Sync* set the PwnDoc URL and username, and pick or create the secret that holds the password. Enable *Ignore SSL certificate errors* for self-signed certificates.

## Quick start

1. **Once per engagement**: right-click the folder that holds its notes, *Associate to PwnDoc engagement* (or *Create a new engagement for this folder*). Every note in it gets `pwndoc_audit` in its properties.
2. **Write the note** (`VT-NN - Title`, from a library import or by hand). Put the evidence under `## Evidenza`. Paste screenshots with *Paste clipboard image with numbered caption*.
3. **Send it**: run *Send note to PwnDoc* (command, header button, or status-bar menu). Pick the finding of the engagement, best title match first, or choose *+ Create a new finding*. The compare opens with Evidenza selected: check it, press **Apply**. Lint runs, then the section is pushed.
4. **Next times** the same command opens the compare directly. Use the **dashboard** to see all the notes at once.
5. **Close up**: *Mark PwnDoc finding as completed*, *Choose the report template of the engagement*, *Generate PwnDoc report*.

Nothing is written to PwnDoc before you press Apply or confirm a prompt. Every write is recorded in the history and can be rolled back.

## Commands

Everything is in the command palette; the status-bar menu (click the `PwnDoc: <engagement>` text) has the most used ones.

| Area | Command | What it does |
|---|---|---|
| Sync | **Send note to PwnDoc** | Linked note: opens the compare. Otherwise asks for the finding or creates it, links the note, opens the compare |
| | **Compare with PwnDoc and merge sections** | Side-by-side view per section: Skip, Use PwnDoc, Use note, Merge both |
| | **Restore from PwnDoc sync history (rollback)** | Restore sections of a past push, pull or merge, on PwnDoc or in the note |
| | **Lint this note before pushing** | Same checks that run before every push, built-in and custom |
| | **Open (or create) the custom lint rules note** | Your own rules, see below |
| Engagement | **Engagement dashboard** | Tabs: Notes, No finding yet, Orphans, Only on PwnDoc. Bulk push and pull with a preview |
| | **Create a new engagement on PwnDoc** | Name, audit type, language, template, dates. Associates the folder |
| | **Associate folder to PwnDoc engagement** | Subfolders inherit it. Notes get the engagement in their properties |
| | **Refresh engagement attribute on notes** | Re-reads engagement names, rewrites the attribute |
| Findings | **Associate note to PwnDoc finding**, **Create PwnDoc finding for this note** | The two steps of *Send note to PwnDoc*, available on their own |
| | **Import findings that exist only on PwnDoc** | Creates notes from findings that have none. Never writes to PwnDoc |
| | **Mark PwnDoc finding as completed**, **Reopen PwnDoc finding** | Changes the finding status |
| | **Unlink note from its PwnDoc finding**, **Find orphan notes** | Removes the link; lists notes whose finding or engagement is gone |
| | **Delete this note's finding from PwnDoc** | Removes it for everyone. Needs `EDIT` (or Enforce) and typing the title; a copy is kept in the history |
| Report | **Choose the report template of the engagement** | Stored on the audit |
| | **Generate PwnDoc report** | Renders with the engagement template, saves the file in the reports folder. If it fails, lists the blank mandatory General Information fields |
| | **Check the General Information of the engagement** | Same check on demand |
| Images | **Paste clipboard image with numbered caption** | Saves the image, inserts `![](path)` and `*Figura N – text*` |
| Import | **Import vulnerability from CSV / from PwnDoc API / Quick import** | Library vulnerability to a new note (see below) |

## Guarantees

- **Only the selected fields are written** (the finding update is a patch). An empty value is never pushed over a populated one without asking.
- **A push is aborted** if the selected fields changed on PwnDoc after you opened the compare.
- **Audit state**: writing needs state `EDIT`. Otherwise an **Enforce** tick, valid for that operation only, is required and recorded in the history.
- **Bulk actions** never overwrite a side that changed on its own, and never write a section that differs with no sync base: that goes through the compare.
- **Lint**: errors block the push (missing image, conflict markers, invalid CVSS...), warnings ask (missing caption, wrong numbering...).
- **History**: each write stores the finding and the note as they were before, in the plugin folder. It contains client data, do not commit it.
- **Background check** of the open note against PwnDoc only reads, never prompts for the password, and pauses for 10 minutes after a failure.

## Custom lint rules

Besides the built-in checks you can write your own rules in a vault note (*Open (or create) the custom lint rules note* creates `pwndoc-lint-rules.md` with commented examples, all switched off). The rules are a yaml list in the first yaml block of the note and run wherever the lint runs: before a push, *Lint this note*, bulk push from the dashboard.

```yaml
# 1. everywhere: a credential in the text is an error
- id: no-credentials
  level: error
  in: note
  match: '(password|passwd|pwd)\s*[:=]\s*\S+'
  message: 'Possible credential: {match}'

# 2. only for one client: the folder contains "Generali", then the file name must not contain "Test"
- id: generali-no-test
  level: error
  in: filename
  match: test
  message: 'No "Test" in the file name for this client'
  when:
    folder: Generali

# 3. a required text: the evidence must show a request, except for mobile notes
- in: section:evidenza
  missing: '(GET|POST|PUT|DELETE) /'
  message: 'Show the request in the evidence'
  unless:
    fm:
      platform: 'Android|iOS'
```

| Key | Meaning |
|---|---|
| `level` | `error` blocks the push, `warn` (default) asks for confirmation |
| `in` | Where to look, one or a list: `note` (text without frontmatter), `filename`, `title` (file name without `VT-NN - `), `path`, `frontmatter`, `fm:<key>`, `section:<name>` (evidenza, description, remediation...) |
| `match` | A violation if the text matches |
| `missing` | A violation if the text does **not** match (a required text). Give exactly one of `match` and `missing` |
| `message` | What to tell. `{match}` is the text found; for note and section targets the line number is added |
| `when` / `unless` | Apply the rule only when (or not when) the conditions hold. Keys: `folder`, `file`, `path`, `title`, `engagement` (regex each) and `fm` (a map from frontmatter key to regex). Every key of the block must hold |
| `id`, `enabled` | Optional label shown in the message; `enabled: false` switches a rule off |

A pattern is a regular expression: plain text is case-insensitive, `/re/flags` is exact. A rule with a mistake (bad regex, unknown key or target) is reported as a lint warning and skipped; the other rules still run. If the note does not exist there are no custom rules.

## Note format

Sections are matched by heading, in Italian or English. Frontmatter keys written or read by the plugin:

| Note | PwnDoc field | Notes |
|---|---|---|
| `## Descrizione` / `Description` | `description` | |
| `## Impatto` / `Impact` | `observation` | |
| `## Evidenza` / `Evidence` | `poc` | default section |
| `## Assets` | `scope` | |
| `## Remediation` | `remediation` | |
| `## References` | `references` | one per line |
| `## Custom Fields` | `customFields` | `**label**` blocks, one per field (OWASP and CWE included), compared field by field, each with its own Skip / Use PwnDoc / Use note |
| file name after `VT-NN - ` | `title` | |
| `cvss_vector` | `cvssv3` | CVSS 3.1 |
| `category` | `vulnType` | |
| `priority` | `priority` | low, medium, high, urgent or 1 to 4 |
| `remediation_complexity` | `remediationComplexity` | easy, medium, hard or 1 to 3 |
| `status` | `status` | `COMPLETED` or `DONE` = completed, anything else = in progress |
| `pwndoc_audit_id`, `pwndoc_audit`, `pwndoc_finding_id` | | written by the plugin: the link |

Captions: `*Figura X – description*` (IT) or `*Figure X – description*` (EN) on the line after the image. They are pushed as an italic paragraph; the image alt text, if any, becomes the PwnDoc caption.

## Settings

| Setting | Default | Description |
|---|---|---|
| PwnDoc URL, Username, Password, Ignore SSL | | Password is kept in Obsidian secret storage |
| Attachments folder | `attachments` | Images pulled from PwnDoc, pasted images |
| Reports folder | `reports` | Generated reports |
| History entries per finding | `50` | Older entries are pruned |
| Warn about changes on PwnDoc | on | Check the open note against PwnDoc |
| Check interval (minutes) | `5` | `0` = only when a note is opened. Reload the plugin to apply |
| Custom lint rules note | `pwndoc-lint-rules.md` | Vault note with your lint rules in a yaml block |
| Mandatory General Information fields | `name,auditType,language,template,company,client,date_start,date_end` | Checked when an export fails |
| CSV file path, Locale filter, Quick import source and language | | Library import |
| Default CSV output folder | | Where an API fetch saves `vulnerabilities.csv` |
| Note templates | | Notes prepended or appended to imported notes |
| Debug mode | off | Logs to the console, filter by `[PwnDoc 2Sync]` |

## Importing library vulnerabilities

Run **Import vulnerability from CSV**, **Fetch and import vulnerability from PwnDoc API**, or **Quick import** (default source and language from the settings, bind it to a hotkey). Search the vulnerability, choose `VT` (web) or `M` (mobile) and the folder: the note `<PREFIX>-<NN> - <Title>.md` is created with frontmatter (severity, platform, CVSS vector, score, link, `locale`, `category`, `pwndoc_id`), sections Descrizione, Impatto, Evidenza, Assets, Remediation, References, and the non-empty custom fields at the end. CVSS 3.1 score and severity are computed. Platform comes from the category: `WAPT` is `WEB`, `Android` and `iOS` stay, anything else is `Android` for `M` and `WEB` for `VT`.

An API fetch can save the data as `vulnerabilities.csv` for offline use. The CSV needs the columns `id`, `title`, `locale`, `category`, `priority`, `cvssv3`, `description`, `observation`, `remediation`, `references`, plus one column per custom field named after its label (or `cf_<id>`).

## Author

davide.caputo
