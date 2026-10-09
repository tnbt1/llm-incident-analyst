# 保守手順

## 日常点検ではサービス・経路・容量を確認する

### FRRの状態

```bash
# IPsec の SA と経路を見る
sudo swanctl --list-sas
ip route show table main
```

IPsec の SA が 2 本あること。経路に拠点の宛先があること。

### 監視VMの状態

```bash
# コンテナの状態
sudo docker compose ps
df -h / /var/lib/docker
```

Zabbix と Wazuh のコンテナが healthy であること。ディスクの使用率が 80% 未満であること。容量が足りない場合は、古いバックアップを減らす。

## ログを読む場所

| 対象 | 場所 |
|---|---|
| FRR | `journalctl -u frr` |
| SSH のログイン | `journalctl -u ssh` |
| Docker | `docker logs <コンテナ>` |

## バックアップを取得する

監視VM のコンテナを止めてから、volume を複製する。Docker の volume は 4 つある。

## 症状から切り分ける

### IPsecを切り分ける

疎通がない場合は、IPsec の SA、経路、FW の順に確認する。IPsec の再接続は FRR で行う。

### ゲームに参加できない

ゲームVM の待受と、FRR の転送を確認する。
