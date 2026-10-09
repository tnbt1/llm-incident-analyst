"""同梱の見本 examples/knowledge-source のコマンドに対する検査と照合。"""
from datetime import date

import pytest
from test_knowledge_example_source import RECIPE, SOURCE

from tia.analysis.commands import destructive_reason, matches_template, templates_in
from tia.knowledge import build_bundle, full_document, load_bundle, load_recipe

# 見本にある変更の手順。推奨の「確認」に入れてはいけないので、検出されるのが正しい
CHANGE_REASONS = {"コンテナの操作", "サービスの操作", "ファイルの書き換え", "権限と所有者の変更", "仮想マシンの操作",
                  "ウェブサーバーの操作", "ファイアウォールの変更", "ネットワークの変更", "再起動と停止", "インラインのコード"}
# 見本が勧める読み取りの確認。誤って破壊的と判定してはいけない
MUST_PASS = ["cat /var/log/dpkg.log", "sudo -n cat /etc/passwd", "vmctl vm exec example-app01 -- sudo -n cat /etc/passwd",
             "systemctl status docker", "sudo -n docker compose -f /opt/app01/docker-compose.yml ps", "free -m",
             "df -h / /var/lib/docker", "sudo -n nft list table inet example_router_fw", "journalctl -u ssh",
             "sudo -n docker system df", "ping -c 3 192.0.2.4"]


@pytest.fixture(scope="module")
def templates(tmp_path_factory):
    result = build_bundle(SOURCE, tmp_path_factory.mktemp("bundles"), load_recipe(RECIPE), date(2026, 10, 3))
    text, _ = full_document(load_bundle(result.path))
    return templates_in([text])


def test_documented_read_only_commands_are_not_called_destructive(templates):
    for command in MUST_PASS:
        assert destructive_reason(command) is None, command
    hits = {command: destructive_reason(command) for command in templates if destructive_reason(command)}
    # 当たるのは変更の手順だけ。読み取りの確認が混ざっていないこと、読めない断片がないことを確かめる
    unexpected = {command: reason for command, reason in hits.items() if reason not in CHANGE_REASONS}
    assert not unexpected, unexpected
    assert hits, "見本には停止と再起動の手順があるので、検出が 0 件ではおかしい"
    assert "systemctl restart docker" in hits


def test_most_documented_commands_verify_themselves(templates):
    matched = [template for template in templates if matches_template(template, templates)]
    assert len(templates) >= 15
    assert len(matched) / len(templates) >= 0.8, f"{len(matched)} / {len(templates)}"
