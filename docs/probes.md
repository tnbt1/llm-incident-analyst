# Probes (read-only checks)

Before inference, and on demand from the UI, Incident Analyst runs *probes*: a fixed catalogue of read-only commands on the affected VM and read-only queries to Zabbix and Wazuh. The output is given to the LLM as `<probe_data>` so it can reason from facts instead of guessing.

## Design

| Layer | Control |
|---|---|
| Who may connect | a dedicated user `analyst-probe` on each VM; `publickey` only, key installed with `restrict` |
| What runs | `ForceCommand /usr/local/lib/analyst-probe/run` — the executor (`deploy/remote-host/analyst-probe`) |
| What the executor accepts | exactly **one probe name** (`[a-z][a-z0-9_]{0,39}`) in `SSH_ORIGINAL_COMMAND`; anything else exits 2 without running |
| How it runs | a fixed argv per name, no shell, stages piped left to right, timeout 15 s, output capped |
| Privileges | `sudo -n` only for the exact argv listed in `deploy/sudoers/analyst-probe`, filled per VM |
| Session | no TTY, no TCP/agent/stream forwarding, no tunnel, no X11, no user RC, `MaxSessions 2` |
| Per-VM differences | `/etc/analyst-probe.conf`: `ROLES=docker,frr`, `GUARD_TABLE=<nft table>`, `COMPOSE=<compose file>` |
| On the analyser side | `config/probes.yaml` lists hosts (ip, roles, guard table, compose) and the same probe names; `probes_known_hosts` pins host keys; `StrictHostKeyChecking=yes`, `IdentitiesOnly=yes`, no agent |

Exit codes of the executor: 0 ok, 2 refused (unknown name or not for this VM's roles), 3 timeout, 4 command failed.

## Catalogue (`config/probes.yaml`)

| Probe | Where | Command | When |
|---|---|---|---|
| `uptime_load` | host | `uptime` | always |
| `disk` | host | `df -h / /var/lib/docker /home` | always |
| `memory` | host | `free -m` | always |
| `failed_units` | host | `systemctl --failed --no-pager --plain` | always |
| `warnings_1h` | host | `sudo -n journalctl -p warning --since -1h` (last 30 lines) | always |
| `compose_ps` | host (docker) | `sudo -n docker compose -f <compose> ps -a` | type container / service / disk |
| `docker_events_1h` | host (docker) | `sudo -n docker events --since 1h --until 1s` | type container / service |
| `logins` | host | `sudo -n journalctl _COMM=sshd _COMM=sshd-session --since -24h`, Accepted/Failed/Invalid only, probe users excluded | type auth / user / file |
| `listening` | host | `sudo -n ss -ltnup` | type service / net |
| `guard_counters` | host | `sudo -n nft list chain inet <guard_table> input` | type net / auth |
| `accounts` | host | `getent passwd` (uid ≥ 1000 or 0) | type user / file / auth |
| `ipsec_status` | host (frr) | `sudo -n swanctl --list-sas` | type net / service |
| `routes` | host (frr) | `sudo -n vtysh -c 'show ip route summary'` | type net |
| `zabbix_trigger`, `zabbix_history_60m` | zabbix | trigger details, 60 minutes of item history | source zabbix |
| `zabbix_host_problems` | zabbix | other open problems of the same host | always |
| `wazuh_recent_events` | wazuh | recent events of the agent | source wazuh / type auth / file / user |

Add a probe by adding the same name to **both** the catalogue and the executor's `TABLE` (and to sudoers if it needs root). `tests/test_probe_executor.py` checks that the two stay consistent.

## Installing the probe user on a VM

1. On the monitoring host generate the key pair once (no passphrase) and store the private key as the `probe_ssh_key` secret; keep only the public key for the VMs.
2. On each VM, as root:

```bash
install -d -m 755 /usr/local/lib/analyst-probe
install -m 755 analyst-probe /usr/local/lib/analyst-probe/run                      # deploy/remote-host/analyst-probe
install -m 644 analyst-probe-sshd.conf /etc/ssh/sshd_config.d/61-analyst-probe.conf  # deploy/remote-host/analyst-probe-sshd.conf
sed -e 's#@GUARD_TABLE@#<your nft table>#' -e 's#@COMPOSE@#<your compose file>#' analyst-probe.sudoers \
  | install -m 440 /dev/stdin /etc/sudoers.d/analyst-probe                          # deploy/sudoers/analyst-probe
#   drop the ANALYST_PROBE_DOCKER lines on hosts without docker, the ANALYST_PROBE_FRR lines on hosts without FRR
visudo -c -q -f /etc/sudoers.d/analyst-probe
useradd --system --user-group --home-dir /var/lib/analyst-probe --create-home --shell /bin/sh analyst-probe
install -d -o analyst-probe -g analyst-probe -m 700 /var/lib/analyst-probe/.ssh
{ printf 'restrict '; cat probe_ssh_key.pub; } | install -o analyst-probe -g analyst-probe -m 600 /dev/stdin /var/lib/analyst-probe/.ssh/authorized_keys
printf 'ROLES=docker\nGUARD_TABLE=<your nft table>\nCOMPOSE=<your compose file>\n' > /etc/analyst-probe.conf
sshd -t && systemctl reload ssh
```

   If sshd uses `AllowUsers`, add `analyst-probe`. If the guest firewall restricts SSH by source, allow the monitoring host's address.
3. On the monitoring host, record the host key and test:

```bash
ssh-keyscan -t ed25519 <vm ip> >> /opt/llm-incident-analyst/config/probes_known_hosts
ssh -i probe_ssh_key -o IdentitiesOnly=yes -o UserKnownHostsFile=/opt/llm-incident-analyst/config/probes_known_hosts analyst-probe@<vm ip> uptime_load
ssh … analyst-probe@<vm ip> 'cat /etc/shadow'     # must print nothing and exit 2
```

4. Add the VM to `config/probes.yaml` → `hosts` (name = Zabbix host name).

`tests/deploy_standin.py` + `tests/test_probe_executor.py` reproduce this installation in an Ubuntu container and verify that forwarding is refused, that unknown commands never run, and that another user's key cannot log in as `analyst-probe`.
