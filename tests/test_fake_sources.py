"""手元の通しで使う偽の系統の道具。3 系統と制御の経路を立て、注入が効き、CA で TLS が通る。コンテナは使わない。"""
import importlib.util
import json
import ssl
import sys
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def fake_sources():
    spec = importlib.util.spec_from_file_location("fake_sources", ROOT / "tools" / "fake-sources.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["fake_sources"] = module
    spec.loader.exec_module(module)
    return module


def get(url, *, context=None, headers=None, data=None):
    request = urllib.request.Request(url, data=data, headers=headers or {}, method="POST" if data else "GET")
    with urllib.request.urlopen(request, timeout=5, context=context) as response:
        return response.status, json.loads(response.read().decode("utf-8") or "null")


def test_sources_answer_and_injection_adds_alerts(fake_sources, tmp_path):
    ca_out = tmp_path / "wazuh-root-ca.pem"
    stack = fake_sources.build(bind="127.0.0.1", ca_out=ca_out, token="fake-zabbix-token-for-local-test",
                               password="fake-wazuh-password-for-local-test", key="fake-openwebui-key-for-local-test",
                               names=("localhost", "127.0.0.1", "fakes"))
    with stack:
        assert ca_out.is_file()
        context = ssl.create_default_context(cafile=str(ca_out))
        # Zabbix: 起動時の 1 件、注入で 2 件
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "problem.get", "params": {"output": "extend"}}).encode()
        auth = {"Content-Type": "application/json", "Authorization": "Bearer fake-zabbix-token-for-local-test"}
        before = get(stack.zabbix_url + "/api_jsonrpc.php", headers=auth, data=body)[1]["result"]
        status, injected = get(stack.control_url + "/zabbix/problem", data=json.dumps({"name": "Disk space is low"}).encode(),
                               headers={"Content-Type": "application/json"})
        assert status == 200 and injected["event_id"]
        after = get(stack.zabbix_url + "/api_jsonrpc.php", headers=auth, data=body)[1]["result"]
        assert len(after) == len(before) + 1
        # Wazuh: TLS は配った CA で通り、注入で 1 件増える
        basic = {"Content-Type": "application/json", "Authorization": fake_sources.basic("analyzer_ro", "fake-wazuh-password-for-local-test")}
        query = json.dumps({"size": 100, "query": {"bool": {}},
                            "sort": [{"timestamp": {"order": "asc"}}, {"id": {"order": "asc"}}]}).encode()
        before_w = get(stack.wazuh_url + "/wazuh-alerts-*/_search", context=context, headers=basic, data=query)[1]["hits"]["hits"]
        status, _ = get(stack.control_url + "/wazuh/alert", data=json.dumps({"description": "sshd: brute force"}).encode(),
                        headers={"Content-Type": "application/json"})
        assert status == 200
        after_w = get(stack.wazuh_url + "/wazuh-alerts-*/_search", context=context, headers=basic, data=query)[1]["hits"]["hits"]
        assert len(after_w) == len(before_w) + 1
        # LLM: /health は認証なし、/openai/models は鍵が要る
        assert get(stack.llm_url + "/health")[1] == {"status": True}
        with pytest.raises(urllib.error.HTTPError):
            get(stack.llm_url + "/openai/models")
        assert get(stack.llm_url + "/openai/models", headers={"Authorization": "Bearer fake-openwebui-key-for-local-test"})[0] == 200
        stats = get(stack.control_url + "/stats")[1]
        assert stats["zabbix_problems"] == len(after) and stats["wazuh_alerts"] == len(after_w)


def test_fake_server_can_bind_any_address(tmp_path):
    from fakes import FakeServer, Reply

    with FakeServer(lambda request: Reply(body={"ok": True}), host="0.0.0.0") as server:
        assert server.url.startswith("http://127.0.0.1:")
        assert get(server.url + "/")[1] == {"ok": True}
