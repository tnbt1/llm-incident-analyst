# 保守手順（見本）

## 日常点検ではサービス・経路・容量を確認する

### ルーターVMの状態

```bash
# 経路と BGP、nftables の表
ip route show table main
sudo -n vtysh -c 'show ip route'
sudo -n nft list table inet example_router_fw
```

既定の経路があり、公開ポートの DNAT の規則が残っていれば正常。

### 監視VMの状態

```bash
# コンテナの状態と容量
sudo -n docker compose -f /opt/monitoring-stack/compose.yaml ps
df -h / /var/lib/docker
free -m
```

Zabbix と Wazuh のコンテナが healthy で、ディスクの使用率が 80% 未満なら正常。容量が足りないときは、まず古いバックアップを減らす。

### アプリVMの状態

```bash
sudo -n docker compose -f /opt/app01/docker-compose.yml ps
sudo -n docker stats --no-stream
systemctl status docker
uptime
```

コンテナが Up で、負荷平均がコア数を超えていなければ正常。

## ログを読む場所

| 対象 | 場所 |
|---|---|
| FRR | `journalctl -u frr` |
| SSH のログイン | `journalctl -u ssh` |
| Docker | `docker logs <コンテナ>` |
| パッケージの更新 | `cat /var/log/dpkg.log` |

## バックアップを取得する

監視 VM のコンテナを止めてから、volume を複製する。

```bash
sudo -n docker compose -f /opt/monitoring-stack/compose.yaml stop
sudo -n tar -C /var/lib/docker/volumes -czf /backups/volumes.tgz .
sudo -n docker compose -f /opt/monitoring-stack/compose.yaml start
```

## 症状から切り分ける

### 疎通を切り分ける

疎通がないときは、ルーター VM の経路、FW、アプリ VM の待受の順に見る。先に見た層で原因が見つかれば、後の層は確認しなくてよい。

```bash
ping -c 3 192.0.2.4
sudo -n ss -lntup
```

### ディスクを切り分ける

```bash
sudo -n du -xsh /var/lib/docker/* | sort -h | tail
sudo -n docker system df
```

### サービスの再起動

点検で直らないときだけ行い、変更記録を書く。

```bash
sudo systemctl restart docker
```
