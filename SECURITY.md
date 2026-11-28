# Posture.ai security overview

This document describes how Posture.ai protects customer data. It is written for customers' security and procurement teams and reflects the controls implemented in this repository. Items marked **Planned** are on the roadmap and not yet in place.

To report a vulnerability, email the address in [`/.well-known/security.txt`](.well-known/security.txt). We aim to acknowledge reports within two business days.

## Architecture

| Layer | Technology | Notes |
|---|---|---|
| Web app | Static HTML/JS served by Cloudflare Pages | No server-side rendering; all data access goes through authenticated APIs |
| Authentication | Supabase Auth | Email + password with mandatory TOTP multi-factor authentication |
| Database | Supabase PostgreSQL | Row-level security on every table; encrypted at rest (AES-256) by the provider |
| AI | Supabase Edge Function calling Anthropic's Claude API | The API key is a server-side secret; the browser never sees it |

All traffic is encrypted in transit with TLS 1.2+, and HSTS is enforced with preload.

## Identity and access

- **Mandatory MFA.** Every user must enrol an authenticator app. The database grants no access to any data unless the session has completed MFA (`aal2`); this is enforced in the row-level security policies themselves, not only in the user interface.
- **Password policy.** Minimum 12 characters with upper and lower case letters, digits and symbols. Email addresses must be verified. Sign-in, sign-up and verification endpoints are rate-limited. Password-reset responses don't reveal whether an account exists.
- **Sessions.** Access tokens expire after one hour; refresh tokens rotate and are single-use. Users are signed out automatically after 30 minutes of inactivity.
- **Vendor questionnaire links.** Each vendor has one link at a time, stored only as a hash. It lasts 14 days, ends after submission and can be turned off. Claude requests are built on the server, so a link can't send Claude anything else. Audit entries are recorded as coming from an outside link. Removing a vendor removes its link, response and documents.
- **Threat posture assessment links.** Someone without an account can open a link an analyst created. Its token is stored only as a hash, expires after 14 days and ends after one submission. The form starts from the assessment's asset profile choices (asset type, sign-in methods and the Yes/No exposure questions), so it lists the same controls. Impact ratings are the one rating the person can set: they're kept with the rest of the response and applied when an analyst applies it. The link still can't set owners, gaps or scores. The description, free-text details, control answers and evidence are sent only if the analyst shares them, and contact details are never sent back to it. What it saves stays apart from the assessment until an analyst reviews every change and applies it. Audit entries are recorded as coming from an outside link, with the typed name and email kept only as details.
- **Posture snapshot intake links.** Someone in the business without an account can open a link an analyst created to answer the intake questions for a request. Its token is stored only as a hash, expires after 14 days and ends after one submission, and a new link replaces the old one. The form receives only the workspace's name and logo, the request name and which question sets to ask (from the assessment type): nothing else from the assessment, and contact details are never sent back to it. What it saves is limited to the typed name, email and answers, and stays apart from the assessment until an analyst adds it. A final report refuses answers. Audit entries are recorded as coming from an outside link, with the typed name and email kept only as details.
- **Role-based access control.** Each workspace member has one role:

  | Role | Permissions |
  |---|---|
  | Viewer | Read risks and posture snapshots, plus threat posture assessments naming them as asset or risk owner |
  | Analyst | + create, edit and delete risks and vendors; run AI reviews and document fill |
  | Approver | + approve, reject and revoke risk exceptions (see Risk exceptions) |
  | Admin | + invite and manage viewers, analysts and approvers; view the audit log and AI usage |
  | Owner | + manage admins and owners; rename the workspace; delete all workspace data; delete the workspace |

  Role changes are made through database functions that enforce these rules: admins can't grant or remove admin or owner rights, and a workspace always keeps at least one owner.
- **Invitations** are tied to an email address, expire after 7 days and can only be accepted by a user whose email address is verified and who has completed MFA.

## Tenant isolation

Each customer organisation is a separate workspace. Every business record carries its workspace ID, and PostgreSQL row-level security restricts every read and write to members of that workspace. Records cannot be moved between workspaces, and authorship fields (`created_by`, `updated_by`, timestamps) are set by the database, not the client. Clients can only write the specific columns they need. Anonymous users have no table access at all.

These rules are verified by an automated suite of more than 300 tests (`supabase/tests/`) covering cross-tenant reads and writes, MFA enforcement, every role boundary, invitation handling, input limits, audit-log immutability and workspace deletion. The suite runs on every change in GitHub Actions.

## Data deletion

- **Workspace deletion.** An owner can delete a whole workspace in Settings (hosted mode). They must type the workspace name, and the app offers a JSON backup first. The database function `delete_workspace` checks that the caller is an owner on an MFA session and that the exact workspace name was passed, then deletes the workspace and everything tied to it: risks and their evidence files, vendors, assessments, threat posture assessments, the people directory, the saved briefing and settings, members, invitations, AI usage, and questionnaire links, responses and documents. The deletion is immediate and can't be undone. An automated test fails if a table that holds workspace data is added without being deleted with the workspace.
- **What is kept.** The audit log is not tied to the workspace and is append-only, so it is kept: the changes it recorded (including the deletion of each record) remain, with a final entry saying who deleted the workspace and when. The log holds user email addresses. People's sign-in accounts are not deleted. Any backups held by the database provider follow the provider's own retention schedule and are outside the application's control.
- **Delete all data** (Settings, owners) clears the records and the people directory but keeps the workspace, its settings and its members.

## Risk exceptions

A risk's exception is requested and approved, not set by hand (hosted mode). An analyst or above requests it with a reason and an end date (in the future, within two years), and the request waits. Someone with the approver role or above approves or rejects it; a rejection needs a note. A renewal is another request, and the earlier approval stands until its own end date unless it is revoked. Approvers and above can revoke an approved exception, with a note. Roles rank viewer, analyst, approver, admin, owner, so admins and owners can approve without being given the approver role, and admins can grant it (they manage viewers, analysts and approvers).

The database enforces this, whatever the client does:

- **Nobody decides their own request**, whatever their role. A request is decided once. Only the person who made a request, or an admin or owner, can withdraw it.
- **The approval fields can only be changed by those functions** (`exceptionApproved`, `exceptionExpiry`, `exceptionApprovedBy`, `exceptionApprovedDate` and `exceptionPending` on the risk). A client that writes them, such as an analyst saving a risk, an import or an out-of-date copy of the risk, has them put back as they were, and a new risk starts without them. Imported exception approvals are therefore not kept in hosted mode.
- **The requests table** (`risk_exceptions`) is read-only to everyone who can read the risks; only the functions write it. It is closed to anonymous callers and to other workspaces, and a deleted risk takes its requests with it.
- **Audit.** Each request, decision, withdrawal and revoke (with its note) is in the audit log, and the changes to the approval fields appear in the risk's history.
- **Exceptions approved before this feature** keep their approval and end date, and are shown as recorded before approvals were tracked.

## Evidence files

Analysts and above can attach evidence to a risk (hosted mode): a PDF, a text file or a PNG or JPEG image, at most 5 MB each and 10 per risk. Files are stored in the database as base64 text, in `risk_evidence`, and the database enforces every rule, so they hold whatever the client does:

- **What is accepted.** Only those four types (not SVG, HTML or Office files). The data must be valid base64 and must start the way its declared type does, so a web page can't be stored as an image or PDF; a text file can't contain binary bytes. The size is worked out from the data, not taken from the client.
- **Who can reach them.** Anyone who can read the risks (viewers and up, on an MFA session) can read and download a risk's files. Only analysts and up can add or remove them. Files can't be changed once added, and the table is closed to anonymous callers. Another workspace can't see them.
- **How they are served.** A file is downloaded, or previewed, as a blob of its declared type. An image is shown in an image element in a dialog (the policy already allows blob images). A text file is shown with `textContent`, as plain text, never as markup, and only its first 100 KB. A PDF is opened in a new browser tab, so the browser's own viewer shows it; the tab is opened with no link back to the app, and the app's strict Content Security Policy (no frames or objects) is unchanged. The app never puts an uploaded file into the page as markup or runs one.
- **Audit and deletion.** Adding and removing a file are audited against the risk (name, size and type; never the content). A file is removed with its risk, so it can't appear on a new risk given the same number, and with the workspace. The JSON backup does not include evidence files.

## Audit logging

Every create, update and delete of risks, vendors, members, invitations and workspace settings is recorded by database triggers with the time, user, action, record and the list of changed fields. The audit log is **append-only**: updates and deletes are rejected by the database even for its owner. Admins can view and export the log.

**Risk history.** For a risk's key fields (title, stage, category, owner, likelihood and impact, residual likelihood and impact, treatment, treatment due date, next review and the exception fields) an update also records the old and new value, each cut to 200 characters. Nothing else is recorded with values: comments, the AI review and other fields appear only in the list of changed fields. The audit log stays admin-only; a `risk_history` function lets anyone who can read the risks (viewers, analysts, admins and owners, with MFA) read one risk's entries, which show the time, the action, the email of the person who made the change and those values. Entries from before the risk was last deleted are left out, because a risk number can be reused. Risks changed before this feature have no old values in their history.

## AI and data handling

- AI requests go to a server-side function that verifies the user's session, MFA status and workspace role, applies a per-user rate limit and a monthly per-workspace quota, and records token usage.
- The function only runs a fixed set of tasks. Their system prompts, output schemas, models and token limits are defined server-side, so a user can't repurpose it as a general AI proxy or change the instructions.
- **Vendor documents.** Documents a vendor attaches through their questionnaire link (PDF, Excel, text, Markdown or CSV; at most 5 files and 20 MB in total) are validated for type, count and size and stored in the workspace's database. Only analysts and above can read them, and they are deleted with the vendor or the workspace. Their content is sent to Anthropic only to answer an AI request, such as filling in answers from them, and is treated as untrusted data in prompts. Stored documents are protected by the database provider's encryption at rest, the same as other workspace data.
- **Documents an analyst adds in the vendor editor** (Fill from documents) are held in the browser's memory only and are not saved by Posture.ai. They are sent to Anthropic only when the analyst runs the fill: through the server-side AI function in hosted mode, which records only token counts, or directly with the analyst's own key in demo mode.
- Under Anthropic's commercial terms, API inputs and outputs are not used to train models. Anthropic is a subprocessor (see below).
- Errors returned to users never include upstream details or secrets.

## Application security

- **Content Security Policy:** scripts only from Posture.ai's own origin (no third-party CDNs and no inline scripts), connections only to Posture.ai and its database, no plug-ins, frames or form posts elsewhere. Automated tests confirm that injected inline scripts, external scripts and data exfiltration attempts are blocked.
- **Clickjacking:** `frame-ancestors 'none'`, `X-Frame-Options: DENY`, plus a script guard for hosts that can't send headers.
- **Other headers:** `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`, and cross-origin opener and resource policies.
- **Output encoding:** all user- and AI-supplied text is HTML-escaped before display.
- **Input validation:** imported files and records are restricted to known fields, with length, size and count limits; the database enforces size limits and ID formats. The database also checks the shape of the answers sent through threat posture and intake links: unknown questions or controls, out-of-scale ratings and unexpected fields are refused, and over-long text is cut to its limit.
- **Supply chain:** third-party libraries are pinned to exact versions, served from Posture.ai's own origin, and checked against recorded SHA-256 hashes in CI. Neither library uses `eval`.

## Subprocessors

| Subprocessor | Purpose | Data |
|---|---|---|
| Supabase, Inc. | Authentication, database, server functions | Account details and all workspace data |
| Cloudflare, Inc. | Web hosting and content delivery | Request metadata (no customer content is stored) |
| Anthropic, PBC | AI analysis | Content sent with AI requests, processed transiently |

The hosting region is chosen when the Supabase project is created (for example EU or US) and should match customers' data-residency requirements.

## Backups and resilience

Supabase takes daily database backups; point-in-time recovery is available on paid plans and should be enabled for production. Customers can export their risks and vendors at any time as JSON or CSV, and the audit log as CSV.

## Roadmap (planned controls)

- **Planned:** SAML single sign-on for enterprise customers (Supabase SSO), with optional enforcement per workspace.
- **Planned:** encrypting vendor documents with a separate key for each workspace, on top of the database provider's encryption at rest. Vendors already submit questionnaires and documents through expiring, single-use links.
- **Planned:** self-service account deletion (a user deleting their own sign-in account). Owners can already delete a whole workspace, see Data deletion.
- **Planned:** independent penetration test before general availability, then annually.
- **Planned:** SOC 2 Type I, followed by Type II.
- **Planned:** security monitoring and alerting on authentication anomalies and quota abuse.
