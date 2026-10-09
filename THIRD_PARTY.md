# Third-party components

Incident Analyst is MIT licensed (see `LICENSE`). It bundles the following assets so that the web UI makes no requests to third-party servers. Versions, origins and SHA-256 sums are recorded in `src/tia/web/static/SOURCES.md` (written by `tools/vendor-assets.py`; verify with `--verify`).

| Component | Files | License |
|---|---|---|
| [htmx](https://htmx.org/) 2.0.11 | `src/tia/web/static/htmx.min.js` | Zero-Clause BSD (`src/tia/web/static/LICENSE-htmx.txt`) |
| [Bricolage Grotesque](https://github.com/ateliertriay/bricolage) | `src/tia/web/static/fonts/bricolage-grotesque-*.woff2` | SIL Open Font License 1.1 (`LICENSE-bricolage-grotesque.txt`) |
| [IBM Plex Mono](https://github.com/IBM/plex) | `src/tia/web/static/fonts/ibm-plex-mono-*.woff2` | SIL Open Font License 1.1 (`LICENSE-ibm-plex-mono.txt`) |
| [Zen Kaku Gothic New](https://github.com/googlefonts/zen-kakugothic) | `src/tia/web/static/fonts/zen-kaku-gothic-new-*.woff2` | SIL Open Font License 1.1 (`LICENSE-zen-kaku-gothic-new.txt`) |

Python dependencies (FastAPI, Starlette, Jinja2, httpx, PyYAML, uvicorn, python-multipart, tzdata and their transitive dependencies) are installed from PyPI under their own licenses (MIT, BSD-3-Clause, Apache-2.0) and are not redistributed in this repository; `deploy/requirements.txt` lists the exact versions and hashes used in the container image.

The container image is based on `python:3.13-slim` (Debian), which carries its own licenses.
