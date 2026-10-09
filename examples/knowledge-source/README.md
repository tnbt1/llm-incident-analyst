# 運用マニュアル（見本）

この文書は Incident Analyst に渡す「環境の資料」の見本である。架空の小さな環境（ルーター 1 台、監視 VM 1 台、アプリ VM 2 台）を説明する。自分の環境では、この 4 つの文書を自分の運用文書に置き換え、`config/knowledge.yaml` の `files`、`card`、`hosts` を合わせる。

## 目的から読む場所を選ぶ

| 目的 | 読む文書 |
|---|---|
| 構成を知る | architecture.md |
| ポートと経路を調べる | registers.md |
| 点検と切り分けをする | maintenance.md |

## 文書を更新する

構成を変えたら、台帳と図を同時に直す。束は `tia knowledge build` で作り直す。
