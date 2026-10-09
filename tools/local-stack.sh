#!/usr/bin/env bash
# 手元の通し。偽の系統に対して、配置用と同じ画像で司令塔を動かす。本物の監視 VM にも LLM にもつながない。
#
#   tools/local-stack.sh up        束を作り、画像を作り、起動して、生きるまで待つ
#   tools/local-stack.sh inject N  偽の Zabbix と Wazuh に N 件ずつアラートを足す
#   tools/local-stack.sh check     /healthz が 200 になるまで待ち、インシデントの一覧を出す。done が 1 件以上で 0
#   tools/local-stack.sh probes    代役の VM に対する確認の結果（probes 表）を出す
#   tools/local-stack.sh backup    コンテナの中で tia backup を行い、世代を一覧する
#   tools/local-stack.sh logs      司令塔の記録
#   tools/local-stack.sh down      止めて、volume と手元の画像を消す
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose=(docker compose -f "$here/deploy/local/compose.yaml")
knowledge="$here/deploy/local/config/knowledge"

keys() {
    # 確認の鍵と代役の VM のホスト鍵。本物の値ではない。git には入らない（.gitignore）
    local dir="$here/deploy/local/secrets"
    [ -f "$dir/probe_ssh_key" ] || ssh-keygen -q -t ed25519 -N '' -C tia-local-probe -f "$dir/probe_ssh_key"
    [ -f "$dir/vm_host_key" ] || ssh-keygen -q -t ed25519 -N '' -C tia-local-vm -f "$dir/vm_host_key"
    printf '172.28.41.6 %s\n' "$(cut -d' ' -f1,2 "$dir/vm_host_key.pub")" > "$dir/probes_known_hosts"
    chmod 644 "$dir/probe_ssh_key" "$dir/probes_known_hosts"  # コンテナの uid 10001 が読む。手元の通しだけ
}

up() {
    keys
    if [ ! -f "$knowledge/current" ]; then
        (cd "$here" && uv run tia knowledge build --source examples/knowledge-source --out "$knowledge" \
            --recipe config/knowledge.yaml >/dev/null)
        chmod -R a+rX "$knowledge"
    fi
    "${compose[@]}" up -d --build --wait --wait-timeout 180
    "${compose[@]}" ps
}

inject() {
    local n="${1:-1}" i
    for ((i = 1; i <= n; i++)); do
        curl -fsS -X POST http://127.0.0.1:18079/zabbix/problem -H 'Content-Type: application/json' \
            -d "{\"name\": \"Disk space is low ($i)\", \"host\": \"example-app01\", \"severity\": 3, \"keys\": [\"vfs.fs.size[/,pused]\"], \"tags\": [[\"component\", \"storage\"]]}" >/dev/null
        curl -fsS -X POST http://127.0.0.1:18079/wazuh/alert -H 'Content-Type: application/json' \
            -d "{\"description\": \"sshd: brute force ($i)\", \"host\": \"example-monitor01\", \"srcip\": \"192.0.2.$((10 + i))\"}" >/dev/null
    done
    curl -fsS http://127.0.0.1:18079/stats
    echo
}

check() {
    local limit=$(( $(date +%s) + 180 )) code body
    while :; do
        code="$(curl -s -o /tmp/tia-local-healthz.json -w '%{http_code}' http://127.0.0.1:38090/healthz || true)"
        if [ "$code" = "200" ]; then break; fi
        if (( $(date +%s) > limit )); then
            echo "/healthz が 200 にならない（最後は $code）"; cat /tmp/tia-local-healthz.json; echo; return 1
        fi
        sleep 2
    done
    echo "/healthz 200"
    local list
    list="$("${compose[@]}" exec -T analyzer tia list --db /data/tia.sqlite)"
    printf '%s\n' "$list"
    grep -q ' done ' <<<"$list" || { echo "done のインシデントがない"; return 1; }
}

backup_() {
    "${compose[@]}" exec -T analyzer tia backup --db /data/tia.sqlite --out /backups --config-dir /config
    "${compose[@]}" exec -T analyzer sh -c 'ls -la /backups && cat /backups/*/manifest.json | head -20'
}

case "${1:-}" in
    up) up ;;
    inject) inject "${2:-1}" ;;
    check) check ;;
    probes) "${compose[@]}" exec -T analyzer python -c "import sqlite3; c = sqlite3.connect('/data/tia.sqlite'); [print(r) for r in c.execute('SELECT incident_id, name, target, status, duration_ms, substr(output, 1, 60), error FROM probes ORDER BY id')]" ;;
    backup) backup_ ;;
    logs) "${compose[@]}" logs --tail 100 analyzer ;;
    down) "${compose[@]}" down -v --rmi local ;;
    *) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
