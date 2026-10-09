"""種類の判定。解析前から一覧に形を出すため、LLM ではなく規則で決める。"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from tia.models import IncidentType


@dataclass(frozen=True)
class TypeRules:
    zabbix_component_tags: dict[str, IncidentType]
    zabbix_item_key_prefixes: tuple[tuple[str, IncidentType], ...]
    wazuh_rule_ids: dict[str, IncidentType]
    wazuh_groups: tuple[tuple[str, IncidentType], ...]


def load_type_rules(path: Path) -> TypeRules:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    zabbix, wazuh = data["zabbix"], data["wazuh"]
    return TypeRules(
        zabbix_component_tags={str(k): IncidentType(v) for k, v in zabbix["component_tags"].items()},
        zabbix_item_key_prefixes=tuple((str(p), IncidentType(t)) for p, t in zabbix["item_key_prefixes"]),
        wazuh_rule_ids={str(k): IncidentType(v) for k, v in wazuh["rule_ids"].items()},
        wazuh_groups=tuple((str(g), IncidentType(t)) for g, t in wazuh["groups"]),
    )


def classify_zabbix(rules: TypeRules, tags: list[dict], item_keys: list[str]) -> IncidentType:
    """component タグを優先し、なければ項目キーの接頭辞で決める。"""
    for tag in tags:
        if tag.get("tag") == "component" and tag.get("value") in rules.zabbix_component_tags:
            return rules.zabbix_component_tags[tag["value"]]
    for prefix, incident_type in rules.zabbix_item_key_prefixes:
        if any(key.startswith(prefix) for key in item_keys):
            return incident_type
    return IncidentType.OTHER


def classify_wazuh(rules: TypeRules, rule_id: str, groups: list[str]) -> IncidentType:
    """ルール番号の指定を優先し、なければ規則の順で最初に当たった group で決める。"""
    if rule_id in rules.wazuh_rule_ids:
        return rules.wazuh_rule_ids[rule_id]
    for group, incident_type in rules.wazuh_groups:
        if group in groups:
            return incident_type
    return IncidentType.OTHER
