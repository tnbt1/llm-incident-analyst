# Deployment

This guide deploys Incident Analyst as one container on the host that already runs your Zabbix and Wazuh containers (the *monitoring host*). All addresses in the repository (`192.0.2.x`, `172.28.40.x`, `203.0.113.x`) are **documentation examples** — replace them.

## 1. Prerequisites on the monitoring host

* Docker with Compose v2; the monitoring stack's network name (e.g. `monitoring_default`) and the Zabbix frontend network (e.g. `zabbix_frontend`).
* Caddy (or another reverse proxy) that can terminate TLS and do basic auth on a management-only address.
* A read-only Zabbix API user with an API token, and a read-only Wazuh indexer user (e.g. `analyzer_ro` with `read` on `wazuh-alerts-*`). Keep the indexer's root CA file.
* An OpenAI-compatible LLM endpoint reachable from the container. Record for your own setup: the base URL the container uses (`TIA_LLM_URL`, ending in `/openai` for Open WebUI; otherwise set `llm.allow_other_route: true`), how the endpoint is reached from the monitoring host (direct network, VPN, or a tunnel), who owns that path and how it restarts, where the API key lives (`secrets/openwebui_api_key`), the model name (`TIA_LLM_MODEL`), and the upstream timeout of the endpoint (keep `llm.timeout_sec` below it).

## 2. Build the image (on your workstation)

```bash
tools/image-build.sh            # uv export → deploy/requirements.txt (hashed), uv build → wheel, docker build
docker save llm-incident-analyst:0.2.0 | gzip > llm-incident-analyst-0.2.0.tar.gz
scp llm-incident-analyst-0.2.0.tar.gz <monitoring host>:
```

The image is two-stage, pinned to `python:3.13-slim` by digest, runs as uid 10001, contains only `openssh-client` on top of the base image.

## 3. Build the knowledge bundle (on your workstation)

```bash
uv run tia knowledge build --source <your docs> --out deploy/config/knowledge --recipe config/knowledge.yaml
```

The bundle directory is copied to the host read-only; the container never needs the source documents. Rebuild and re-copy whenever the documents change (the UI warns when the bundle is older than `knowledge.stale_after_days`).

## 4. Lay out `/opt/llm-incident-analyst` on the monitoring host

```
/opt/llm-incident-analyst/
  compose.yaml                 ← deploy/compose.yaml, edited
  config/
    analyzer.yaml              ← deploy/config/analyzer.yaml (container paths)
    type-rules.yaml, knowledge.yaml, probes.yaml
    knowledge/                 ← the bundle from step 3
    probes_known_hosts         ← ssh-keyscan output of the probed VMs (see docs/probes.md)
    ca/wazuh-root-ca.pem       ← Wazuh indexer root CA
  secrets/                     ← root:root 0700, files root:10001 0440 (deploy/secrets/README.md)
  data/  backups/              ← owned by 10001:10001
```

```bash
sudo install -d -m 755 /opt/llm-incident-analyst/config
sudo install -d -o 10001 -g 10001 -m 750 /opt/llm-incident-analyst/data /opt/llm-incident-analyst/backups
sudo install -d -m 700 /opt/llm-incident-analyst/secrets
docker load < llm-incident-analyst-0.2.0.tar.gz
```

Edit `compose.yaml`:

| Key | Set to |
|---|---|
| `TIA_LLM_URL` | your LLM base URL, e.g. `http://<tunnel ip>:18080/openai` |
| `TIA_ZABBIX_URL` | the Zabbix web container, e.g. `http://zabbix-web-apache-mysql:8080/api_jsonrpc.php` |
| `TIA_WAZUH_URL` / `TIA_WAZUH_USER` | the indexer container and the read-only user |
| `networks.monitoring.name`, `networks.zabbix_frontend.name` | your real external network names |
| `services.analyzer.networks.monitoring.ipv4_address` | a free fixed address in that network (used by firewall rules); remove if you do not need it |

Instead of editing `compose.yaml`, you can put these endpoints and any analyser setting into `/opt/llm-incident-analyst/.env` (`TIA_SECTION_KEY=value`; template: `.env.example` in the repository, or `tia config env-template`). Compose passes the file to the container through `env_file` (it is optional) and reads `TIA_IMAGE_TAG` from it itself. Precedence inside the container: environment > `.env` > `config/analyzer.yaml` > defaults.

Place the four secrets as described in `deploy/secrets/README.md`, then:

```bash
cd /opt/llm-incident-analyst && sudo docker compose up -d
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:38090/healthz   # 200 when ready, 503 while starting
```

## 5. Caddy

Append `deploy/caddy/site.caddy` to your Caddyfile, replacing `<MONITORING_VM_IP>`, `<USER>` and the bcrypt hash (`caddy hash-password`). The snippet binds to the management address only, uses `tls internal`, keeps `Host` unchanged (the app compares `Origin` and `Host`), and sets long read timeouts for SSE. Then `caddy reload` and open `https://<MONITORING_VM_IP>:11443/`.

If the host has a guest firewall with default drop, allow TCP 11443 from your management network only, and allow the container's fixed address to reach the LLM tunnel port.

## 6. Monitoring the analyser itself

Add an HTTP monitor on `http://127.0.0.1:38090/healthz` expecting status 200 (e.g. Uptime Kuma on the same host). Container health is also reported by Docker (`HEALTHCHECK`).

## 7. Updating

```bash
tools/image-build.sh <new version>; docker save … | scp …
# on the host
docker load < llm-incident-analyst-<new>.tar.gz
sudo docker compose -f /opt/llm-incident-analyst/compose.yaml exec analyzer tia backup --db /data/tia.sqlite --out /backups --config-dir /config
TIA_IMAGE_TAG=<new> sudo docker compose -f /opt/llm-incident-analyst/compose.yaml up -d
```

Schema migrations run at start-up. To roll back, restore the previous tag and, if the schema changed, `tia restore` the backup taken before the update (with the service stopped).

### Changing one setting

```bash
cd /opt/llm-incident-analyst
printf 'TIA_ZABBIX_MIN_SEVERITY=3\n' | sudo tee -a .env
sudo docker compose up -d analyzer     # `restart` does not re-read env_file; `up -d` recreates the container
sudo docker compose exec analyzer tia config show --config /config/analyzer.yaml | grep -v 'default$'   # non-default values and where they come from
```

A wrong value stops the container with `設定の誤り: <VARIABLE> ...` in `docker compose logs analyzer`.

## 8. Local stack

`tools/local-stack.sh up` reproduces the whole thing on your workstation with fake sources (`tools/fake-sources.py`), a stand-in VM (`deploy/local/Dockerfile.vm`) and the real image, using the sample knowledge in `examples/`. No real system is contacted.
