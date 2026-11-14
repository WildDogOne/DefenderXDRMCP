# Project rules

## Never commit tenant / live-environment data

This project is developed and verified against a **real Defender tenant**. Behavioral findings
("Graph ignores `$search` here", "the hunting endpoint rejects `eq`") belong in docstrings,
CHANGELOGs and READMEs; the data they were observed on does **not**.

Never put any of these into a tracked file (code, docstrings, docs, commit messages):

- **Tenant identifiers** - tenant IDs or GUIDs, *including truncated ones* (an 8-char prefix like
  `tenant 01234567-...` is still a fingerprint). Say "verified live (YYYY-MM-DD)" with no tenant
  reference.
- **Identity data** - user principal names, display names, email addresses, group names.
- **Endpoint data** - device / host names (including internal naming patterns like a device-name
  prefix), IP addresses, serial numbers.
- **Resource ids** - incident / alert / case / rule ids from the tenant.
- **Tenant observations** - counts (incident totals, per-bucket counts), file names + hashes seen
  in alerts, saved-function names, anything that only makes sense inside this tenant.
- **Credentials** - `.env` is gitignored and stays that way; docs and script usage lines use the
  dummies (`AZURE_TENANT_ID=common`, `AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000`,
  `AZURE_CLIENT_SECRET=dummy`).

Write verification notes with placeholders instead: "a user", "device A", "one incident",
"~N open incidents", "a MalwareBazaar IOC sample". The *behavioral* fact must survive
anonymization; the specific row should not.

Self-check before committing - the staged diff must come back empty:

    git diff --cached | grep -inE "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-|@<your-org-domain>|<your-device-name-prefix>|onmicrosoft\.com|AZURE_CLIENT_SECRET=[^d]"

(Replace the two `<...>` placeholders with the tenant's actual domain and device-name prefix;
keep that mapping out of the repo.)

## Git

- Staging and preparing changes is fine; only commit when explicitly asked.
