"""確認のカタログ。名前と固定のコマンドの表を読み、インシデントに合う確認を選ぶ。"""
import re
from pathlib import Path

import pytest
import yaml

from tia.models import IncidentType
from tia.probes.catalog import Catalog, CatalogError

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "config" / "probes.yaml"


@pytest.fixture
def catalog():
    return Catalog.load(CATALOG)


def test_catalog_loads_with_hosts_and_probes(catalog):
    assert set(catalog.hosts) == {"example-router01", "example-app01", "example-app02",
                                  "example-app03"}
    assert catalog.hosts["example-app01"].ip == "192.0.2.6"
    assert catalog.hosts["example-router01"].compose is None
    for name in ("uptime_load", "disk", "failed_units", "zabbix_trigger", "wazuh_recent_events"):
        assert name in catalog.probes, name
    assert all(p.timeout_sec <= 30 and p.cap_bytes <= 65536 for p in catalog.probes.values())


def test_host_probe_commands_are_fixed_read_only_words(catalog):
    for probe in catalog.probes.values():
        if probe.where == "host":
            assert probe.command, probe.name
            assert not re.search(r"\$\(|`|;|&&|[<>](?!=)", probe.command), probe.name


def test_for_incident_picks_by_host_type_and_source(catalog):
    names = {p.name for p in catalog.for_incident("example-router01", "net", "zabbix")}
    assert {"ipsec_status", "routes", "guard_counters", "listening", "zabbix_trigger", "uptime_load"} <= names
    assert "compose_ps" not in names and "docker_events_1h" not in names
    names = {p.name for p in catalog.for_incident("example-app01", "disk", "zabbix")}
    assert {"disk", "compose_ps", "uptime_load", "zabbix_host_problems"} <= names
    assert "ipsec_status" not in names
    names = {p.name for p in catalog.for_incident("example-app03", "auth", "wazuh")}
    assert {"logins", "accounts", "wazuh_recent_events"} <= names
    assert "zabbix_trigger" not in names


def test_unknown_host_gets_only_api_probes(catalog):
    probes = catalog.for_incident("Zabbix server", "service", "zabbix")
    assert probes and all(p.where != "host" for p in probes)


def test_every_condition_names_a_real_incident_type_or_source(catalog):
    """when の type: は models.IncidentType の語彙だけ。存在しない種類（network、availability）は一度も動かない確認になる。"""
    types = {t.value for t in IncidentType}
    for probe in catalog.probes.values():
        for condition in probe.when:
            if condition.startswith("type:"):
                assert condition[5:] in types, f"{probe.name}: {condition}"
            elif condition.startswith("source:"):
                assert condition[7:] in ("zabbix", "wazuh"), f"{probe.name}: {condition}"
            else:
                assert condition == "always", f"{probe.name}: {condition}"
    # FRR の net のインシデントには、FRR 専用の網の確認が段階 1 で付く
    frr = {p.name for p in catalog.for_incident("example-router01", "net", "zabbix")}
    assert {"ipsec_status", "routes"} <= frr


def test_unknown_type_in_a_condition_is_refused(tmp_path):
    data = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    data["probes"] = {"x": {"where": "host", "command": "uptime", "timeout_sec": 5, "cap_bytes": 100,
                            "when": ["type:network"]}}
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    with pytest.raises(CatalogError, match="when"):
        Catalog.load(path)


def test_bad_catalog_values_are_refused(tmp_path):
    data = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    bad = dict(data)
    bad["probes"] = {"x": {"where": "shell", "command": "ls", "timeout_sec": 5, "cap_bytes": 100, "when": ["always"]}}
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(bad, allow_unicode=True), encoding="utf-8")
    with pytest.raises(CatalogError, match="where"):
        Catalog.load(path)
    bad["probes"] = {"x": {"where": "host", "command": "ls", "timeout_sec": 31, "cap_bytes": 100, "when": ["always"]}}
    path.write_text(yaml.safe_dump(bad, allow_unicode=True), encoding="utf-8")
    with pytest.raises(CatalogError, match="timeout_sec"):
        Catalog.load(path)
    bad["probes"] = {"x": {"where": "host", "command": "ls", "timeout_sec": 5, "cap_bytes": 70000, "when": ["always"]}}
    path.write_text(yaml.safe_dump(bad, allow_unicode=True), encoding="utf-8")
    with pytest.raises(CatalogError, match="cap_bytes"):
        Catalog.load(path)
    for command in ("cat /etc/passwd > /tmp/x", "uptime; id", "echo $(id)", "true && reboot", "false || reboot"):
        bad["probes"] = {"x": {"where": "host", "command": command, "timeout_sec": 5, "cap_bytes": 100, "when": ["always"]}}
        path.write_text(yaml.safe_dump(bad, allow_unicode=True), encoding="utf-8")
        with pytest.raises(CatalogError, match="command"):
            Catalog.load(path)


def test_deployed_catalog_matches_the_original_and_the_local_copy_loads():
    original = CATALOG.read_text(encoding="utf-8")
    assert (ROOT / "deploy" / "config" / "probes.yaml").read_text(encoding="utf-8") == original
    local = Catalog.load(ROOT / "deploy" / "local" / "config" / "probes.yaml")
    assert set(local.probes) == set(Catalog.load(CATALOG).probes)
    assert {h.ip for h in local.hosts.values()} == {"172.28.41.6"}
