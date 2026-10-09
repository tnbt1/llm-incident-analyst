# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] — 2026-10-09

Initial public release.

### Added
- Collectors for Zabbix (`problem.get`) and the Wazuh indexer with watermarks, overlap and back-off.
- Intake, type rules, recurrence/follow-up handling, storm and root-host grouping; SQLite storage with migrations.
- Knowledge bundle: Markdown → sections, environment card, per-incident section selection, secret scanning with hash allow-list, token estimation.
- Analysis worker with budgeted context, JSON-schema validation, single retry, destructive-command exclusion and documented-command matching.
- Read-only probes: VM executor behind sshd `ForceCommand`, role-restricted sudoers, Zabbix/Wazuh probes, stage-1 execution before inference and on-demand execution from the UI.
- Web UI (FastAPI, Jinja2, HTMX, SSE) with health chips, feedback, case registration, light/dark theme; vendored HTMX and fonts.
- `tia run` single-process service, `/healthz`, nightly backup, retention housekeeping, `backup`/`restore`.
- Hardened container image (uid 10001, read-only FS, `cap_drop: ALL`), Compose with file secrets, Caddy snippet, local stack with fake sources and a stand-in VM.
- `web.system_name` setting for the name shown in the UI.
