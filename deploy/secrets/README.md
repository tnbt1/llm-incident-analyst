# 秘密のファイル

`/opt/llm-incident-analyst/secrets/`（フォルダは `root:root`、`0700`）に 4 つ。Compose がコンテナの `/run/secrets/<名前>` に置く。

| ファイル | 中身 | 作る人 |
|---|---|---|
| `zabbix_api_token` | Zabbix の読み取り専用の利用者の API トークン | 運用者（Zabbix の画面で発行） |
| `wazuh_indexer_password` | インデクサーの読み取り専用の利用者（例 `analyzer_ro`）のパスワード | 運用者（Wazuh の内部利用者として作る） |
| `openwebui_api_key` | Open WebUI の API キー | 運用者（Open WebUI の画面で発行） |
| `probe_ssh_key` | 確認専用の利用者 `analyst-probe` の SSH 秘密鍵（ed25519、パスフレーズなし） | 運用者（監視 VM の中で生成し、公開鍵だけを対象の VM に置く。`docs/probes.md`） |

コンテナは uid 10001 で動く。Compose のファイルの秘密はホストの権限のまま見えるので、所有を `root:10001`、権限を `0440` にする。値の末尾の改行は読む側が落とす。

監視 VM で次のようにして置く。値は引数にも記録にも残らない。

```bash
umask 077
read -rs -p 'value: ' value && printf '%s\n' "$value" | sudo install -o root -g 10001 -m 0440 /dev/stdin /opt/llm-incident-analyst/secrets/<名前>
unset value
```

値を変えたら `docker compose -f /opt/llm-incident-analyst/compose.yaml restart analyzer`。収集と解析は秘密を要求のたびに読むが、Compose の秘密は起動時に写されるため。

このフォルダに本物の値を置かない。git には README だけを入れる。
