import pytest

from tia.models import IncidentType
from tia.type_rules import classify_wazuh, classify_zabbix


@pytest.mark.parametrize("keys, expected", [
    (["system.cpu.util"], IncidentType.CPU),
    (["system.cpu.util[,iowait]"], IncidentType.IO),
    (["vm.memory.utilization"], IncidentType.MEM),
    (["system.swap.size[,pfree]"], IncidentType.SWAP),
    (["vfs.fs.size[/,pused]"], IncidentType.DISK),
    (["vfs.dev.read.rate[sda]"], IncidentType.IO),
    (["net.if.in[enp1s0]"], IncidentType.NET),
    (["icmppingloss"], IncidentType.NET),
    (["agent.ping"], IncidentType.NET),
    (["docker.container_info.state.running"], IncidentType.CONTAINER),
    (["systemd.unit.info[ssh.service]"], IncidentType.SERVICE),
    (["kernel.maxproc"], IncidentType.OTHER),
    ([], IncidentType.OTHER),
])
def test_zabbix_item_keys(rules, keys, expected):
    assert classify_zabbix(rules, [], keys) == expected


def test_zabbix_component_tag_wins_over_item_key(rules):
    tags = [{"tag": "scope", "value": "performance"}, {"tag": "component", "value": "memory"}]
    assert classify_zabbix(rules, tags, ["system.cpu.util"]) == IncidentType.MEM


def test_zabbix_unknown_component_tag_falls_back_to_item_key(rules):
    tags = [{"tag": "component", "value": "application"}]
    assert classify_zabbix(rules, tags, ["vfs.fs.size[/,pused]"]) == IncidentType.DISK


@pytest.mark.parametrize("rule_id, groups, expected", [
    ("5712", ["syslog", "sshd", "authentication_failures"], IncidentType.AUTH),
    ("5716", ["syslog", "sshd", "authentication_failed"], IncidentType.AUTH),
    ("5402", ["syslog", "sudo"], IncidentType.USER),
    ("5902", ["syslog", "adduser"], IncidentType.USER),
    ("550", ["ossec", "syscheck"], IncidentType.FILE),
    ("2902", ["syslog", "dpkg"], IncidentType.PKG),
    ("100101", ["local", "health"], IncidentType.SERVICE),
    ("1002", ["syslog", "errors"], IncidentType.OTHER),
])
def test_wazuh(rules, rule_id, groups, expected):
    assert classify_wazuh(rules, rule_id, groups) == expected
