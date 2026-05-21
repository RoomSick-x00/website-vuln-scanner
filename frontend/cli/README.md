# CLI Frontend

This folder contains the command-line client for the scanner. It is useful for
smoke checks, automation, and quick status/result inspection without opening the
web UI.

## Files

- `main.py` defines the `argparse` commands and maps them to handler functions.
- `commands_cli.py` contains resilient HTTP client functions used by both the
  CLI and Flask UI.
- `api.py` is an older/simple HTTP wrapper kept for compatibility.
- `formatter.py` formats backend responses for terminal output.

## Commands

Run from the repository root:

```powershell
python -m frontend.cli.main submit --url https://example.com
python -m frontend.cli.main status --id <scan_id>
python -m frontend.cli.main results --id <scan_id>
```

Set `BACKEND_URL` if the API is not running at `http://localhost:8000`.

## Logic

`main.py` only parses commands. `commands_cli.py` owns HTTP behavior, including
payload construction for quick/custom scans and basic backend error handling.
`formatter.py` keeps presentation separate from request logic.
