# Scanner Modules

This folder contains the scanner implementations. Each scanner subclasses
`BaseScanner` and returns a list of normalized finding dictionaries.

## Files

- `base.py` defines the `Finding` shape, severity levels, `BaseScanner.scan()`,
  `_finding()`, and `safe_scan()`.
- `tls.py` checks TLS certificate state, hostname/SAN coverage, public-key
  strength, chain trust, negotiated cipher, TLS version support, and forward
  secrecy.
- `https_headers.py` checks security headers, dangerous fingerprinting headers,
  HSTS strength, CSP weaknesses, and `Clear-Site-Data` on logout-like paths.
- `dns.py` checks domain existence, managed platform domains, SPF, DMARC,
  DNSSEC, CAA, and MX records.
- `xss.py` performs authorized reflected-XSS probes against URL parameters and
  forms.
- `dir_listing.py`, `open_ports.py`, and `sqli.py` are placeholders for future
  scanners and are not currently registered in `workers/processor.py`.
- `test_tls.py`, `test_headers.py`, `test_dns.py`, and `test_xss.py` are manual
  smoke scripts for individual scanners.
- `SCANNER_RULES.md` documents scanner behavior/rules.
- `__init__.py` marks this directory as a package.

## Scanner Contract

Every active scanner should:

- set `name`, `display_name`, and `tier`;
- implement `scan(target, timeout)`;
- use `self._finding(...)` to return consistent fields;
- avoid writing to the database directly;
- let `safe_scan()` convert unexpected exceptions into medium-severity scanner
  bug findings.

## Active Logic

Quick scans run `tls`, `http_headers`, and `dns`. Full scans add `xss`. The XSS
scanner is treated as intrusive, so the backend requires DNS ownership
verification before queueing it.

## Finding Shape

Findings include:

- `module_name`
- `issue`
- `evidence`
- `severity`
- `score_penalty`
- `remediation`

The worker processor later adds `scan_id` and `task_type` before storing the
finding in PostgreSQL.
