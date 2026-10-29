# PwnDoc API formats (spike, 2026-10-29)

Instance: `https://pwndoc.horizon.local:8443` (self-signed cert, frontend is Vue + TipTap/ProseMirror, no Quill). Writes only on audit `Test Obsidian`.
Auth: `POST /api/users/token {username,password,totpToken:''}` -> `datas.token`; sent as `Cookie: token= JWT <token>`.

## FORMATS (values observed)

| Key | Observed |
|---|---|
| `auditsListPath` | `GET /api/audits` -> `datas[]` with `_id, name, language, auditType, company{name}, state, createdAt` (no `updatedAt`, no findings). 933 audits on this instance. |
| `auditDetailPath` | `GET /api/audits/:id` -> `datas` with `findings[]`, `state`, `language`, `updatedAt`, `customFields`, `name`. |
| single finding | `GET /api/audits/:id/findings/:fid` -> finding object directly. |
| finding keys | `identifier, title, vulnType, description, observation, remediation, references (string[]), cvssv3, poc, scope (string), status (number), customFields [], _id, paragraphs []`. **No `updatedAt` on the finding.** |
| `updatedAtField` | Only `audit.updatedAt`, which changes on any change in the audit. It cannot detect a change to one finding without false positives. |
| `putSemantics` | `PUT /api/audits/:id/findings/:fid` is a **merge**: sending `{title}` keeps all other fields. Response `datas` is a message string. |
| `createFindingPath` | `POST /api/audits/:id/findings` with `{title, vulnType, cvssv3, description, observation, remediation, poc, scope, references, customFields}`. Response is only a message, **the new `_id` is not returned**. The new finding is appended to `findings[]` and gets an incrementing `identifier`. |
| `auditStateField` | `audit.state`, observed value `EDIT`. `PUT /api/audits/:id/updateReadyForReview` answers 403 `Audit reviews are not enabled.` here, so `REVIEW`/`APPROVED` could not be exercised and the server did not block writes in the states available. Values `REVIEW`/`APPROVED` are from PwnDoc source, not observed. |
| `auditLanguageField` | `audit.language`, e.g. `EN-en`. Library `details[].locale` uses the same codes (`IT-it`, `EN-en`). |
| `imageUploadBody` | `POST /api/images {value: "data:image/png;base64,...", name, auditId}` -> 201 `datas._id`. |
| `imageDownloadShape` | `GET /api/images/download/:id` returns the raw bytes with `Content-Type: image/png`; `GET /api/images/:id` returns `{_id, auditId, value (data URI), name}`. |
| upload limit | 5 MB raw OK. 15 MB raw fails (HTTP 500, `offset out of range ... 17825792`): total body limit about 17.8 MB, so the raw image limit is about 12.7 MB. |
| `imgTag` | `<img src="<imageId>" alt="<caption>">`, stored verbatim. |
| `codeBlockTag` | `<pre><code>text</code></pre>`, stored verbatim. |
| rich HTML | `<p> <strong> <em> <code> <ul><li> <table><tbody><tr><td>` all stored verbatim by the API. |

## Consequences for the plan

- **Concurrency check (Task 9):** use a hash of the target finding fields (fetched fresh with `GET .../findings/:fid`) instead of `updatedAt`. `assertUnchanged(snapshotHash, fresh)`.
- **Push:** partial `PUT` of only the selected fields is safe (merge), so there is no need to send the whole finding.
- **Create finding (Task 13):** after the POST, `GET` the audit and take the finding with the highest `identifier` (or matching `title`) to get its `_id`.
- **Images:** reject files above 12 MB before uploading.
- **State guard:** keep `assertEditable` on `audit.state !== 'EDIT'`; on this instance it is always `EDIT`, so the guard cannot be exercised end to end here.

## Left on the instance

Audit `Test Obsidian` (`6ae341c72f6b9b3e849af2fe`): finding `Spike finding` (`6ae342352f6b9b3e849af40e`) with rich PoC, and 3 uploaded images (1x1 PNG, 5 MB filler). They can be deleted from the UI.
