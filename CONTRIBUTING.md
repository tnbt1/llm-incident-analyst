# Contributing

Thanks for your interest. This project is small and opinionated; the notes below keep it that way.

## Development setup

```bash
uv sync
uv run pytest -W error -p no:cacheprovider        # full suite, ~2.5 min
uv run pytest -m "not docker and not browser"    # what CI runs
```

* Python 3.12+ (CI uses 3.13). Dependencies are managed with `uv`; commit `uv.lock` changes together with `pyproject.toml`.
* Tests marked `docker` need a Docker daemon (they build a small Ubuntu stand-in VM); tests marked `browser` need headless Chromium. Both skip automatically when the tool is missing.
* Warnings are errors (`-W error`). Keep it that way.

## Language

Comments, log messages, UI strings and LLM prompts are in Japanese; identifiers, config keys and documentation under `docs/` are in English. Match the surrounding file. An English UI (templates + a `web.language` setting) would be a welcome contribution — please open an issue first to agree on the approach.

## What a change needs

1. **A test.** Behaviour is specified by the test suite; new behaviour comes with tests, bug fixes with a regression test.
2. **No new network calls from the browser.** Static assets are vendored with `tools/vendor-assets.py` and listed in `src/tia/web/static/SOURCES.md`.
3. **Safety invariants stay.** Anything that could make the analyser *change* a system (new probe commands, new sudo lines, relaxed command validation) must be read-only and must extend `tests/test_probe_executor.py` / `tests/test_analysis_commands.py`.
4. **Config keys are validated.** Add new keys to `Config` with a default, a range or a check in `src/tia/config.py`, and to `config/analyzer.yaml` with a comment.
5. **No secrets, no real hosts.** Use the `example-*` host names, RFC 5737 addresses (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) and throwaway keys in tests and docs.

## Pull requests

* One topic per PR; describe *why*, not only *what*.
* Run the full suite locally (including Docker tests if you can) before opening the PR.
* Update `CHANGELOG.md` under *Unreleased*.

## Reporting bugs

Open an issue with the version (`uv run tia --help` header / `pyproject.toml`), the relevant log lines (redact hosts and tokens) and, if possible, a failing test.

Security issues: see [SECURITY.md](SECURITY.md).
