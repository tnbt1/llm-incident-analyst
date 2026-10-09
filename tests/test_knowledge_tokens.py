import pytest

from tia.knowledge.tokens import ESTIMATOR, estimate_tokens

# 見本の文と、利用するモデルのトークナイザーで数えた正解。係数を合わせ直したら、ここも数え直す。
SAMPLES = {
    "prose": (99, (
        '監視 VM は Zabbix と Wazuh を動かしている。管理 PC からは Cloud VPN の Connector を経由して入る'
        '。再起動の後は、ゲスト FW、Docker、コンテナの順に立ち上がる。収集が止まった場合は、まず経路と容量を確認する。ディスクの使用率が 8'
        '0% を超えたら、古いバックアップの世代を減らす。'
    )),
    "table": (121, (
        '| VM | VPC 内 IP | 役割 |\n'
        '|---|---|---|\n'
        '| `vm-router01` | `10.20.0.4` | ルーター、NAT、FW |\n'
        '| `vm-monitor01` | `10.20.0.7` | 監視。Zabbix 7.0、Wazuh 4.9 |\n'
        '| `vm-game01` | `10.20.0.8` | ゲーム。UDP 7777 を公開 |\n'
    )),
    "commands": (67, (
        '```bash\n'
        'sudo systemctl status docker --no-pager\n'
        'sudo docker compose ps\n'
        'df -h / /var/lib/docker\n'
        "journalctl -u ssh --since '1 hour ago' --no-pager | tail -n 50\n"
        "ss -Hltn 'sport = :10051'\n"
        '```\n'
    )),
    "list": (95, (
        '## 日常点検ではサービス・経路・容量を確認する\n'
        '\n'
        '- FRR の状態を確認する。IPsec の SA が 2 本あること。\n'
        '- 監視 VM のコンテナがすべて healthy であること。\n'
        '- ルートファイルシステムの使用率が 80% 未満であること。\n'
        '- バックアップの最新の世代が 24 時間以内であること。\n'
    )),
    "json": (87, (
        '{"host": "vm-monitor01", "severity": "Warning", "title": "Disk space i'
        's low (used > 80%)", "started_at": "2026-09-29T05:57:00+00:00", "items'
        '": [{"key": "vfs.fs.size[/,pused]", "last": 81.4}]}'
    )),
}


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_estimate_is_close_to_the_real_tokenizer(name):
    truth, text = SAMPLES[name]
    assert abs(estimate_tokens(text) - truth) <= truth * 0.15


def test_total_of_the_samples_is_within_five_percent():
    truth = sum(count for count, _ in SAMPLES.values())
    estimate = sum(estimate_tokens(text) for _, text in SAMPLES.values())
    assert abs(estimate - truth) <= truth * 0.05


def test_empty_text_is_zero():
    assert estimate_tokens("") == 0


def test_any_text_counts_at_least_one():
    assert estimate_tokens("a") == 1
    assert estimate_tokens(" ") == 1


def test_result_is_an_integer_and_repeatable():
    text = SAMPLES["prose"][1]
    assert isinstance(estimate_tokens(text), int)
    assert estimate_tokens(text) == estimate_tokens(text)


def test_longer_text_never_counts_less():
    text = SAMPLES["list"][1]
    counts = [estimate_tokens(text[:size]) for size in range(0, len(text) + 1, 7)]
    assert counts == sorted(counts)


def test_characters_outside_the_known_classes_are_counted():
    """絵文字やハングルなど、較正に使っていない文字も 0 にはしない。"""
    assert estimate_tokens("한국어 텍스트") >= 4
    assert estimate_tokens("🙂🙂🙂") >= 3


def test_estimator_has_a_name_for_the_manifest():
    assert ESTIMATOR == "tia-chars-v1"
