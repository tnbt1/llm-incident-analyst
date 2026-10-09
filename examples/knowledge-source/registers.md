# 運用台帳（見本）

## 公開ポート台帳

| 公開 | 転送先 | 用途 |
|---|---|---|
| UDP 26900-26902 | `192.0.2.6` | アプリ 01 |
| UDP 7777 | `192.0.2.8` | アプリ 02 |

## 管理・内部通信台帳

| 経路 | 宛先 | 用途 |
|---|---|---|
| 管理経路 192.0.2.5 → 全 VM | TCP 22 | SSH |
| 管理経路 192.0.2.5 → `example-monitor01` | TCP 443、8443、9443、10443、11443 | Wazuh、Uptime Kuma、Netdata、Zabbix、Incident Analyst の画面 |
| `example-monitor01` → 全 VM | TCP 10050 | Zabbix passive agent |
| 全 VM → `example-monitor01` | TCP 1514、1515 | Wazuh agent |
| `example-monitor01` → LLM の中継 | TCP 18080 | Open WebUI（SSH の逆トンネル） |

## 設定ファイルの所在

| 対象 | 場所 |
|---|---|
| ルーター VM の FW | `/etc/nftables.conf` |
| 監視 VM の Compose | `/opt/monitoring-stack/compose.yaml` |
| アプリ 01 の Compose | `/opt/app01/docker-compose.yml` |
| アプリ 02 の Compose | `/opt/app02/docker-compose.yml` |
