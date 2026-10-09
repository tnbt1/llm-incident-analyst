from datetime import date

import pytest

from tia.knowledge.index import build_index, confirmed_on, detect_hosts, detect_types, extract_terms
from tia.knowledge.recipe import Recipe
from tia.models import IncidentType

RECIPE = Recipe(
    files=("a.md",),
    hosts={
        "vm-router01": ("vm-router01", "FRR", "10.20.0.4"),
        "vm-game02": ("vm-game02", "APP01", "APP"),
        "vm-game03": ("vm-game03", "APP03", "APP"),
        "vm-monitor01": ("vm-monitor01", "監視VM", "Zabbix"),
    },
    types={
        IncidentType.DISK: ("ディスク", "容量"),
        IncidentType.NET: ("IPsec", "経路"),
        IncidentType.IO: ("I/O", "iowait"),
    },
)


@pytest.mark.parametrize(("heading", "text", "expected"), [
    ("FRRの状態", "本文", {"vm-router01": 2}),
    ("frr の設定", "本文", {"vm-router01": 2}),
    ("状態", "FRR を確認する。FRR のログを見る。", {"vm-router01": 1}),
    ("状態", "FRR を 1 回だけ書いた文。", {}),
    ("状態", "10.20.0.4 へ ping。10.20.0.4 の経路。", {"vm-router01": 1}),
    ("状態", "10.20.0.40 と 110.20.0.4 と 10.20.0.41 は別の機械。", {}),
    ("状態", "vm-router01 と vm-router01 を比べる", {"vm-router01": 1}),
    ("監視VMの状態", "Zabbix の画面", {"vm-monitor01": 2}),
    ("APP01を止める", "本文", {"vm-game02": 2}),
    ("APP VMの状態", "本文", {"vm-game02": 2, "vm-game03": 2}),
    ("状態", "OFFRRAMP や FRRX は別の言葉。", {}),
    ("なし", "関係のない文", {}),
])
def test_hosts_are_found_by_name_and_alias(heading, text, expected):
    assert detect_hosts(RECIPE, heading, f"## {heading}\n\n{text}") == expected


@pytest.mark.parametrize(("heading", "text", "expected"), [
    ("ディスクの空きを確認する", "本文", {"disk": 2}),
    ("確認", "容量を見る。容量が足りない。", {"disk": 1}),
    ("確認", "容量を 1 回だけ。", {}),
    ("IPsecを切り分ける", "経路を見る。経路を直す。", {"net": 2}),
    ("確認", "iowait が高い。I/O の待ち。", {"io": 1}),
    ("確認", "ipsec と IPSEC", {"net": 1}),
    ("確認", "関係のない文", {}),
])
def test_types_are_found_by_their_words(heading, text, expected):
    assert detect_types(RECIPE, heading, f"## {heading}\n\n{text}") == expected


def test_result_is_sorted_by_name():
    found = detect_hosts(RECIPE, "監視VMとFRRとAPP", "本文")
    assert list(found) == sorted(found)


@pytest.mark.parametrize(("text", "expected"), [
    ("2026-09-21 に確認。2026-09-28 に再確認。", "2026-09-28"),
    ("| 2026-09-22〜23 | 変更 |", "2026-09-22"),
    ("確認日の記載なし。9月29日JST。", None),
    ("2026-13-01 と 2026-02-30 は日付ではない", None),
    ("版 12026-09-010 は日付ではない", None),
    ("2026-10-05 は先の日付。2026-09-01 は過去。", "2026-09-01"),
])
def test_confirmed_on_is_the_latest_date_not_after_today(text, expected):
    assert confirmed_on(text, date(2026, 9, 29)) == expected


@pytest.mark.parametrize(("text", "expected"), [
    ("High CPU utilization (over 90% for 5m)", {"cpu", "utilization"}),
    ("Disk space is low on /var/lib/docker", {"disk", "space", "var", "lib", "docker"}),
    ("sshd: authentication failed", {"sshd", "authentication", "failed"}),
    ("メモリ使用率が 90% を超過", {"メモ", "モリ", "リ使", "使用", "用率", "超過"}),
    ("IPsecを切り分ける", {"ipsec"}),
    ("障害の切り分けと復旧手順", {"障害", "復旧", "旧手", "手順"}),
    ("コンテナーの再起動", {"コン", "ンテ", "テナ", "ナー", "再起", "起動"}),
    ("する これ の は", set()),
    ("", set()),
])
def test_terms_are_words_and_pairs_of_characters(text, expected):
    assert extract_terms(text) == expected


def _section(identifier, heading, body):
    return {"id": identifier, "heading": heading, "text": f"## {heading}\n\n{body}"}


def test_index_lists_sections_by_host_type_and_term():
    sections = [
        {**_section("a-1", "FRRの状態", "IPsec の SA を見る。経路を確認する。"), "hosts": {"vm-router01": 2},
         "types": {"net": 2}},
        {**_section("a-2", "ディスクの空き", "容量を確認する。"), "hosts": {}, "types": {"disk": 2}},
        {**_section("a-3", "ログ", "FRR のログ。FRR の設定。確認する。"), "hosts": {"vm-router01": 1}, "types": {}},
        {**_section("a-4", "公開", "確認する。"), "hosts": {}, "types": {}},
    ]
    index = build_index(sections)
    assert index["hosts"] == {"vm-router01": {"a-1": 2, "a-3": 1}}
    assert index["types"] == {"disk": {"a-2": 2}, "net": {"a-1": 2}}
    assert index["terms"]["ipsec"] == {"weight": 3, "heading": [], "body": ["a-1"]}
    assert index["terms"]["frr"] == {"weight": 2, "heading": ["a-1"], "body": ["a-3"]}
    assert index["terms"]["状態"]["heading"] == ["a-1"]
    assert "確認" not in index["terms"], "全部の節にある言葉は、選ぶ手がかりにならない"


def test_index_of_nothing_is_empty():
    assert build_index([]) == {"aliases": {}, "hosts": {}, "types": {}, "terms": {}}


def test_index_does_not_depend_on_the_order_of_keys():
    sections = [
        {**_section("b-2", "経路", "IPsec"), "hosts": {"z": 1, "a": 2}, "types": {}},
        {**_section("b-1", "経路", "IPsec"), "hosts": {"a": 1}, "types": {}},
    ]
    index = build_index(sections)
    assert list(index["hosts"]) == ["a", "z"]
    assert list(index["hosts"]["a"]) == ["b-1", "b-2"]
    assert index["terms"]["経路"]["heading"] == ["b-1", "b-2"]
