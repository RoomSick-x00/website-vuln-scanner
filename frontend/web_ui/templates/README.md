# Web UI Templates

This folder contains Jinja templates rendered by `frontend/web_ui/app.py`.

## Files

- `index.html` is the first screen. It contains the URL input, Quick/Full/Custom
  scan mode controls, custom module selection, client-side URL validation, and
  form submission behavior.
- `verify.html` shows DNS TXT verification instructions for scans that include
  XSS. It copies record values, checks `/api/verify-domain`, and submits the
  hidden scan form when verification succeeds.
- `status.html` displays animated progress while polling `/api/status/<scan_id>`
  until the backend marks the scan complete or failed.
- `results.html` renders the report view: risk grade, severity pills, skipped
  module links, priority actions, module tabs, finding cards, copy-fix buttons,
  and PDF download links.

## Template Logic

Templates keep most UI state in browser JavaScript but use server-rendered
values from Flask for scan IDs, target display names, grouped findings, module
labels, risk summaries, and CSP nonces.

Inline scripts use the per-request nonce generated in `app.py`, matching the
Content Security Policy applied to every Flask response.
