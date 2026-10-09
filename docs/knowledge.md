# Knowledge bundle

The LLM is only as good as what it knows about *your* environment. Incident Analyst takes your existing operations manual (Markdown) and turns it into a **bundle** that is shipped to the monitoring host and injected into every prompt in two ways:

1. **Environment card** (`<env_card>`): a fixed list of sections — topology summary, VM register, firewall scope, open issues, port registers — always present (budget `knowledge.card_budget_tokens`).
2. **Selected sections** (`<doc>`): for each incident, up to `knowledge.max_sections` sections chosen by host alias, incident type words, title terms and preferred headings (budget `knowledge.section_budget_tokens`). `knowledge.mode: full` sends the whole document instead.

## Recipe (`config/knowledge.yaml`)

| Key | Meaning |
|---|---|
| `files` | Markdown files to read, in order (also the tie-break order) |
| `card.sections` | `{file, heading}` pairs; the heading is matched by prefix and must be unique |
| `card.recent_changes` | optional: rows of a change-log table newer than N days (not used by default — it assumes the docs are updated in real time) |
| `hosts` | canonical host name (as Zabbix/Wazuh report it) → aliases used in the documents (IPs, nicknames, "監視VM", "Zabbix server"…) |
| `types` | incident type → words in the documents |
| `prefer_headings` | words in headings that mark "status / check / troubleshoot" sections |
| `allow_secrets` | lines (by SHA-256) that the secret scanner flagged but you verified are not secrets, with a reason |

The sample recipe matches `examples/knowledge-source/` — four short documents about a fictional site (router, monitoring VM, two application VMs). Replace both with your own.

## Building and inspecting

```bash
uv run tia knowledge build --source <docs dir> --out config/knowledge --recipe config/knowledge.yaml
uv run tia knowledge show --bundle config/knowledge
uv run tia knowledge select --bundle config/knowledge --host example-monitor01 --type disk --title "Disk space is critically low"
```

`build` writes a new versioned directory and moves the `current` pointer atomically; the running service notices within `knowledge.reload_check_sec`. The source directory is never written to.

## Secret scanning

Every line of every file is scanned for private keys, API tokens, passwords in URLs and arguments, bcrypt/apr1 hashes, cloud credentials and similar. A finding fails the build. If a line is a false positive, run `tia knowledge build --line-hashes` to get its hash and add it to `allow_secrets` with a reason. Private key blocks can never be allow-listed.

## Writing documents that work well

* One topic per heading; keep status/check procedures under headings containing words like 状態, 確認, 点検, 切り分け (or add your own to `prefer_headings`).
* Name hosts consistently and list every alias in `hosts`, including the IP and the name monitoring uses.
* Put *read-only* commands in fenced `bash` blocks — they become the pool of *documented commands* that the validator trusts in recommendations. Commands that change state are detected and excluded from recommendations (see `tests/test_analysis_commands_example.py`).
* Keep secrets out of the manual; the scanner will stop the build otherwise.
