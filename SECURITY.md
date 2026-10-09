# Security policy

## Supported versions

Only the latest release on `main` receives fixes.

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Use GitHub's *Report a vulnerability* (Security → Advisories) on this repository, or e-mail the maintainer listed in `pyproject.toml` / the repository profile. Include the version, a description, and reproduction steps. You should get an acknowledgement within 7 days.

## Scope — what we consider a vulnerability

* Any way for the analyser, its probes or its recommendations to **change** a monitored system.
* Escaping the probe executor (`deploy/remote-host/analyst-probe`): running anything other than the fixed argv of a catalogued probe, obtaining a shell, a TTY or a forwarded port as `analyst-probe`, or exceeding the `sudo -n` allow-list.
* Prompt-injection paths that let alert or probe content turn into executed actions (the LLM has no tools, so this means influencing the *validated* output in a way that bypasses the destructive-command checks).
* The knowledge build shipping secrets despite the scanner.
* Web UI: authentication bypass of state-changing routes (CSRF/origin checks), information disclosure to unauthenticated clients, SSE abuse.
* Container hardening regressions (running as root, writable root FS, added capabilities).

Out of scope: weaknesses of Zabbix, Wazuh, Open WebUI, Caddy or the LLM itself; configurations that deviate from `docs/deployment.md` (e.g. exposing port 38090 directly).

## Hardening checklist for operators

* Keep the container on `127.0.0.1:38090`; expose only through the reverse proxy with TLS and authentication on a management network.
* Give Zabbix and Wazuh users read-only roles; rotate the API token / password when staff changes.
* Pin probed hosts' keys in `probes_known_hosts`; keep the probe private key only in the `probe_ssh_key` secret (`root:10001 0440`).
* Re-run `tia knowledge build` instead of editing a bundle by hand so the secret scan always runs.
* Review `deploy/sudoers/analyst-probe` after every update; it is the whole privilege surface on the VMs.
