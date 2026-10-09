"""同梱の見本 examples/knowledge-source から、config/knowledge.yaml のレシピで束を作れることを確かめる。

確かめるのは緩い性質だけ。見本は直されるので、節の数やトークン数を固定しない。出典には書き込まない。
"""
import hashlib
from datetime import date
from pathlib import Path

import pytest

from tia.knowledge import build_bundle, full_document, load_bundle, load_recipe, select_sections
from tia.knowledge.select import resolve_hosts

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "examples" / "knowledge-source"
RECIPE = ROOT / "config" / "knowledge.yaml"


def _hashes(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    before = _hashes(SOURCE)
    result = build_bundle(SOURCE, tmp_path_factory.mktemp("bundles"), load_recipe(RECIPE), date.today())
    assert _hashes(SOURCE) == before, "出典には書き込まない"
    return result


def test_example_documents_build_without_findings(built):
    assert 10 <= built.sections <= 80
    assert 1000 <= built.tokens <= 20000
    assert 0 < built.card_tokens <= 6000


def test_example_bundle_loads_and_selects(built):
    bundle = load_bundle(built.path)
    assert len({s.id for s in bundle.sections}) == len(bundle.sections)
    assert sum(1 for s in bundle.sections if s.in_card) == 6
    assert full_document(bundle)[1] == built.tokens
    selected = select_sections(bundle, hosts=["example-router01"], incident_type="net",
                               title="Unavailable by ICMP ping")
    assert 1 <= len(selected) <= 3
    assert sum(item.section.tokens for item in selected) <= 3000
    assert all(item.reasons for item in selected)


def test_monitor_disk_alert_gets_the_status_section_of_the_monitor(built):
    """ホストが見出しにあるだけのバックアップの手順が、状態の節を押し出さないこと。"""
    bundle = load_bundle(built.path)
    selected = select_sections(bundle, hosts=["example-monitor01"], incident_type="disk",
                               title="Disk space is critically low (used > 90%) on /var/lib/docker")
    headings = [item.section.heading for item in selected]
    assert "監視VMの状態" in headings
    place = headings.index("監視VMの状態")
    assert not any("バックアップ" in heading for heading in headings[:place])


def test_short_name_of_a_host_gives_the_same_sections(built):
    bundle = load_bundle(built.path)
    arguments = {"incident_type": "disk", "title": "Disk space is critically low"}
    formal = select_sections(bundle, hosts=["example-monitor01"], **arguments)
    assert formal
    for name in ("monitor01", "EXAMPLE-MONITOR01", "example-monitor01.local", " example-monitor01 "):
        assert select_sections(bundle, hosts=[name], **arguments) == formal


def test_zabbix_server_host_resolves_to_the_monitoring_vm(built):
    """Zabbix の既定のホスト「Zabbix server」は監視 VM で動く。節が 0 件になってはいけない。"""
    bundle = load_bundle(built.path)
    for name in ("Zabbix server", "zabbix server", "ZABBIX SERVER"):
        resolved, unknown = resolve_hosts(bundle, [name])
        assert resolved == ("example-monitor01",) and unknown == (), name
    selected = select_sections(bundle, hosts=["Zabbix server"], incident_type="availability",
                               title="Linux: Zabbix agent is not available (for 3m)")
    assert selected and any("監視VM" in item.section.heading for item in selected)
