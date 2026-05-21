# Static Assets

This folder contains browser assets served directly by Flask.

## Folders

- `css/` contains the stylesheet used by all web UI templates.

## Logic

Static files are referenced from templates through Flask's `url_for('static',
filename=...)` helper so paths work consistently in local development and in the
Docker/Railway frontend service.
