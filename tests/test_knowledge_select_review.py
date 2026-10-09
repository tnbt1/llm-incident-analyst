"""節の選択と索引。細かな境界を固定するテスト。"""
import hashlib
import json
from datetime import date
from pathlib import Path

import pytest
from knowledge_helpers import FIXTURES, build_fixture

from tia.cli import main
from tia.knowledge.bundle import Bundle, Section, load_bundle
from tia.knowledge.index import build_index, detect_types, extract_terms
from tia.knowledge.recipe import load_recipe
from tia.knowledge.select import resolve_hosts, select_sections

HOSTS = {"vm-a": ("vm-a", "監視VM", "mon-a", "10.20.0.7"), "vm-b": ("vm-b", "ゲーム", "10.20.0.8"),
         "vm-c": ("vm-c", "ゲーム")}


def make_bundle(*specs: dict) -> Bundle:
    sections = []
    for order, spec in enumerate(specs):
        text = f"## {spec['heading']}\n\n{spec.get('body', '本文')}"
        sections.append(Section(
            id=f"a-{order:010x}", file="a.md", heading=spec["heading"], level=2, parent="", order=order,
            line=order + 1, text=text, hosts=spec.get("hosts", {}), types=spec.get("types", {}), confirmed_on=None,
            tokens=spec.get("tokens", 100), sha256=hashlib.sha256(text.encode()).hexdigest(),
            in_card=False, preferred=spec.get("preferred", False)))
    index = build_index([{"id": s.id, "heading": s.heading, "text": s.text, "hosts": s.hosts, "types": s.types}
                         for s in sections], HOSTS)
    return Bundle(version="20260929-000000000000", built_on=date(2026, 9, 29), path=Path("."),
                  sections=tuple(sections), card="", card_tokens=0, tokens=sum(s.tokens for s in sections),
                  index=index, source_hashes={}, notices=(), estimator="test")


def _headings(selected):
    return [item.section.heading for item in selected]


FILLER = ({"heading": "埋め草 1"}, {"heading": "埋め草 2"}, {"heading": "埋め草 3"})


# --- ホストだけでは選ばない


def test_host_alone_does_not_choose_a_section():
    bundle = make_bundle({"heading": "バックアップを取る", "hosts": {"vm-a": 2}},
                         {"heading": "状態を見る", "hosts": {"vm-a": 1}, "types": {"disk": 1}})
    selected = select_sections(bundle, hosts=["vm-a"], incident_type="disk", title="")
    assert [(item.section.heading, item.score) for item in selected] == [("状態を見る", 30 + 20)]


def test_host_and_a_word_of_the_title_choose_a_section():
    bundle = make_bundle({"heading": "節", "body": "swanctl の使い方", "hosts": {"vm-a": 2}}, *FILLER)
    assert _headings(select_sections(bundle, hosts=["vm-a"], incident_type="other", title="swanctl failed")) \
        == ["節"]


def test_section_about_another_host_is_left_out():
    bundle = make_bundle({"heading": "ゲームのディスク", "hosts": {"vm-b": 2}, "types": {"disk": 2}},
                         {"heading": "両方のディスク", "hosts": {"vm-a": 2, "vm-b": 2}, "types": {"disk": 2}},
                         {"heading": "ディスクの一般", "types": {"disk": 2}},
                         {"heading": "本文にだけ出る", "hosts": {"vm-b": 1}, "types": {"disk": 2}})
    assert _headings(select_sections(bundle, hosts=["vm-a"], incident_type="disk", title="", max_sections=9)) \
        == ["両方のディスク", "ディスクの一般", "本文にだけ出る"]
    assert _headings(select_sections(bundle, hosts=[], incident_type="disk", title="", max_sections=9)) \
        == ["ゲームのディスク", "両方のディスク", "ディスクの一般", "本文にだけ出る"]
    assert "ゲームのディスク" in _headings(
        select_sections(bundle, hosts=["ghost01"], incident_type="disk", title="", max_sections=9))


# --- 題名のホスト名と場所は、言葉にしない


def test_host_name_and_path_in_the_title_are_not_words():
    bundle = make_bundle(
        {"heading": "復元する", "body": "var lib docker を戻す。example monitor01 の手順", "hosts": {"vm-a": 2}},
        {"heading": "空きを見る", "body": "critically low のとき space を調べる", "hosts": {"vm-a": 1}},
        *FILLER)
    selected = select_sections(bundle, hosts=["vm-a", "example-monitor01"], incident_type="other",
                               title="Disk space is critically low on /var/lib/docker (example-monitor01)")
    assert _headings(selected) == ["空きを見る"]
    assert "var" not in selected[0].reasons[1] and "monitor01" not in selected[0].reasons[1]


def test_words_next_to_a_path_are_kept():
    bundle = make_bundle({"heading": "節", "body": "overlay2 の掃除", "hosts": {"vm-a": 2}}, *FILLER)
    selected = select_sections(bundle, hosts=["vm-a"], incident_type="other",
                               title="overlay2 is full: /var/lib/docker/overlay2")
    assert _headings(selected) == ["節"]


# --- 種類の言葉は、コードブロックの外で数える


def test_type_words_inside_code_blocks_do_not_count():
    recipe = load_recipe(FIXTURES / "recipe.yaml")
    in_code = "## 手順\n\n```bash\nsudo systemctl restart docker\nsudo systemctl status docker\n```\n"
    in_text = "## 手順\n\nsystemd のサービスを確かめる。サービスが止まっていたら起動する。\n"
    tilde = "## 手順\n\n~~~\nsystemd サービス サービス\n~~~\n"
    assert detect_types(recipe, "手順", in_code) == {}
    assert detect_types(recipe, "手順", tilde) == {}
    assert detect_types(recipe, "手順", in_text) == {"service": 1}
    assert detect_types(recipe, "Docker の手順", in_code) == {"container": 2}


# --- 1 節は予算の半分まで


def test_one_section_takes_at_most_half_of_the_budget():
    bundle = make_bundle({"heading": "大きい", "hosts": {"vm-a": 2}, "types": {"disk": 2}, "tokens": 1501},
                         {"heading": "半分", "hosts": {"vm-a": 1}, "types": {"disk": 1}, "tokens": 1500},
                         {"heading": "小さい", "hosts": {"vm-a": 1}, "types": {"disk": 1}, "tokens": 300})
    selected = select_sections(bundle, hosts=["vm-a"], incident_type="disk", title="", budget=3000)
    assert _headings(selected) == ["半分", "小さい"]


def test_large_section_is_chosen_when_nothing_else_qualifies():
    bundle = make_bundle({"heading": "大きい", "hosts": {"vm-a": 2}, "types": {"disk": 2}, "tokens": 2600},
                         {"heading": "関係ない", "tokens": 300})
    selected = select_sections(bundle, hosts=["vm-a"], incident_type="disk", title="", budget=3000)
    assert _headings(selected) == ["大きい"]


# --- ホストの書き方


@pytest.mark.parametrize("name", ["vm-a", "VM-A", "  vm-a \t", "ｖｍ－ａ", "vm-a.local", "VM-A.example.internal",
                                  "監視VM", "mon-a", "MON-A", "10.20.0.7"])
def test_host_is_found_in_other_spellings(name):
    bundle = make_bundle({"heading": "状態", "hosts": {"vm-a": 2}, "types": {"disk": 1}})
    selected = select_sections(bundle, hosts=[name], incident_type="disk", title="")
    assert [item.reasons[0] for item in selected] == ["ホスト vm-a が見出しにある"]
    assert resolve_hosts(bundle, [name]) == (("vm-a",), ())


def test_name_shared_by_two_hosts_means_both():
    bundle = make_bundle({"heading": "状態"})
    assert resolve_hosts(bundle, ["ゲーム"]) == (("vm-b", "vm-c"), ())


def test_host_that_matches_nothing_is_named_in_the_reasons():
    bundle = make_bundle({"heading": "状態", "hosts": {"vm-a": 2}, "types": {"disk": 2}})
    selected = select_sections(bundle, hosts=["ghost01", "vm-a"], incident_type="disk", title="")
    assert selected[0].reasons == ("ホスト vm-a が見出しにある", "種類 disk の言葉が見出しにある",
                                   "ホスト ghost01 は束のホストに当たらない")
    assert resolve_hosts(bundle, ["ghost01", "vm-a", None, 3]) == (("vm-a",), ("ghost01",))


def test_reason_does_not_depend_on_the_order_of_the_hosts():
    bundle = make_bundle({"heading": "節", "hosts": {"vm-b": 2, "vm-c": 2}, "types": {"disk": 1}})
    first = select_sections(bundle, hosts=["vm-b", "vm-c"], incident_type="disk", title="")
    second = select_sections(bundle, hosts=["vm-c", "vm-b"], incident_type="disk", title="")
    assert first == second
    assert first[0].reasons[0] == "ホスト vm-b が見出しにある"


# --- 数字と、英字と数字の混ざった言葉


def test_numbers_and_mixed_words_are_terms():
    assert extract_terms("Wazuh rule 100101 on port 10050 by appserver in 5m over 90% at 10.20.0.7") \
        == {"wazuh", "rule", "100101", "port", "10050", "appserver"}
    assert extract_terms("rule 550 と 5715") == {"rule", "550", "5715"}


def test_rule_number_finds_its_section():
    bundle = make_bundle(
        {"heading": "検知の一覧", "body": "100101 は Docker の操作。5715 は SSH の成功。", "hosts": {"vm-a": 1}},
        {"heading": "別の節", "body": "10050 は Zabbix agent。", "hosts": {"vm-a": 1}}, *FILLER)
    selected = select_sections(bundle, hosts=["vm-a"], incident_type="other", title="Wazuh rule 100101 fired (5715)")
    assert _headings(selected) == ["検知の一覧"]
    assert selected[0].reasons == ("ホスト vm-a が本文にある", "題名の言葉が一致: 100101、5715")


# --- 束と索引


def test_index_carries_the_names_of_the_hosts():
    index = build_index([], HOSTS)
    assert index["aliases"]["vm-a"] == ["vm-a"]
    assert index["aliases"]["監視vm"] == ["vm-a"]
    assert index["aliases"]["ゲーム"] == ["vm-b", "vm-c"]
    assert list(index["aliases"]) == sorted(index["aliases"])
    assert build_index([])["aliases"] == {}


def test_built_bundle_resolves_the_names_of_the_recipe(tmp_path):
    bundle = load_bundle(build_fixture(tmp_path).path)
    assert resolve_hosts(bundle, ["zabbix", "10.20.0.4", "FRR", "nobody"]) \
        == (("vm-monitor01", "vm-router01"), ("nobody",))
    manifest = json.loads((bundle.path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["format"] == 2


def test_command_names_the_hosts_it_does_not_know(tmp_path, capsys):
    build_fixture(tmp_path)
    assert main(["knowledge", "select", "--bundle", str(tmp_path / "bundles"), "--host", "ghost01", "--host",
                 "ZABBIX", "--type", "disk", "--title", "Disk space is low"]) == 0
    out = capsys.readouterr().out
    assert "束にないホスト: ghost01" in out
    assert "ホスト vm-monitor01 が見出しにある" in out


# --- ホストの状態を見る節


def test_status_section_of_the_host_is_a_candidate_for_any_alert():
    bundle = make_bundle({"heading": "監視VMの状態", "hosts": {"vm-a": 2}, "preferred": True},
                         {"heading": "バックアップを取る", "hosts": {"vm-a": 2}, "types": {"disk": 1}},
                         {"heading": "用語を確認する", "types": {"disk": 1}, "preferred": True},
                         {"heading": "本文に出るだけの確認", "hosts": {"vm-a": 1}, "preferred": True})
    selected = select_sections(bundle, hosts=["vm-a"], incident_type="disk", title="", max_sections=9)
    assert [(item.section.heading, item.score) for item in selected] \
        == [("監視VMの状態", 100 + 40), ("バックアップを取る", 100 + 20)]
    assert selected[0].reasons == ("ホスト vm-a が見出しにある", "ホストの状態を見る節")
