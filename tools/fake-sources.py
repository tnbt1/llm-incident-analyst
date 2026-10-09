#!/usr/bin/env python3
"""偽の Zabbix、Wazuh のインデクサー、LLM（Open WebUI の中継経路）と、注入のための制御の経路を立てる。

手元の通し（deploy/local）で、監視 VM の代わりに使う。実環境には置かない。

    python tools/fake-sources.py --bind 0.0.0.0 --ca-out /shared/wazuh-root-ca.pem

秘密の値は環境変数 FAKE_ZABBIX_TOKEN、FAKE_WAZUH_PASSWORD、FAKE_LLM_KEY。制御の経路:
    POST /zabbix/problem {"name": ..., "host": ..., "severity": 2}   問題を 1 件足す
    POST /wazuh/alert {"description": ..., "host": ..., "rule_id": "5712", "level": 10}   アラートを 1 件足す
    GET  /stats
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from fakes import FakeLlm, FakeServer, FakeWazuh, FakeZabbix, Reply, Request  # noqa: E402

DEFAULT_NAMES = ("localhost", "127.0.0.1", "fakes")


def basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class Stack:
    """4 つのサーバー。with で立て、抜けると閉じる。"""

    def __init__(self, *, bind: str, ca_out: Path, token: str, password: str, key: str,
                 zabbix_port: int = 0, wazuh_port: int = 0, llm_port: int = 0, control_port: int = 0,
                 names: tuple[str, ...] = DEFAULT_NAMES) -> None:
        import trustme

        self.zabbix = FakeZabbix(token=token)
        self.wazuh = FakeWazuh(password=password)
        self.llm = FakeLlm(key=key)
        self._event = 48300
        self._alert = 0
        ca = trustme.CA()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ca.issue_cert(*names).configure_cert(context)
        ca_out.parent.mkdir(parents=True, exist_ok=True)
        tmp = ca_out.with_suffix(".tmp")
        ca.cert_pem.write_to_path(tmp)
        os.replace(tmp, ca_out)
        self._servers = {
            "zabbix": FakeServer(self.zabbix.handle, port=zabbix_port, host=bind),
            "wazuh": FakeServer(self.wazuh.handle, tls=context, port=wazuh_port, host=bind),
            "llm": FakeServer(self.llm.handle, port=llm_port, host=bind),
            "control": FakeServer(self.control, port=control_port, host=bind),
        }
        self.seed()

    def seed(self) -> None:
        """いま起きたアラートを少し入れる。収集がすぐに何かを取り込めるように。"""
        now = int(time.time())
        self.add_problem({"name": "High CPU utilization", "host": "example-router01", "severity": 2,
                          "clock": now - 300})
        self.add_alert({"description": "sshd: brute force", "host": "example-router01"})
        self.add_alert({"description": "sshd: brute force", "host": "example-router01", "srcip": "192.0.2.6"})

    def add_problem(self, body: dict) -> dict:
        self._event += 1
        event_id = str(body.get("event_id") or self._event)
        severity = int(body.get("severity", 2))
        self.zabbix.add_problem(event_id, trigger_id=str(23000 + self._event), severity=severity,
                                clock=int(body.get("clock") or time.time()), name=str(body.get("name") or "Fake problem"),
                                host=str(body.get("host") or "example-router01"),
                                keys=tuple(body.get("keys") or ("system.cpu.util",)),
                                tags=tuple(tuple(t) for t in body.get("tags") or (("component", "cpu"),)))
        # 確認の zabbix_history_60m が読む 60 分の履歴。1 分ごとに少し上がる値
        clock = int(body.get("clock") or time.time())
        for n in range(1, len(body.get("keys") or ("x",)) + 1):
            if str(n) not in self.zabbix.history:
                self.zabbix.add_history(str(n), [(clock - 3600 + i * 60, round(60 + i * 0.5, 1)) for i in range(60)])
        return {"event_id": event_id}

    def add_alert(self, body: dict) -> dict:
        self._alert += 1
        doc_id = str(body.get("id") or f"local-{self._alert:06d}")
        stamp = body.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime(time.time() - 5))
        self.wazuh.add(doc_id, stamp, rule_id=str(body.get("rule_id") or "5712"), level=int(body.get("level", 10)),
                       host=str(body.get("host") or "example-router01"), srcip=str(body.get("srcip") or "192.0.2.5"),
                       description=str(body.get("description") or "sshd: brute force"))
        return {"id": doc_id}

    def control(self, request: Request) -> Reply:
        if request.method == "GET" and request.path == "/stats":
            return Reply(body={"zabbix_problems": len(self.zabbix.problems), "wazuh_alerts": len(self.wazuh.docs),
                               "llm_requests": len(self.llm.requests), "zabbix_calls": len(self.zabbix.calls),
                               "wazuh_searches": len(self.wazuh.searches)})
        if request.method == "POST" and request.path in ("/zabbix/problem", "/wazuh/alert"):
            try:
                body = json.loads(request.body or b"{}")
            except ValueError:
                return Reply(status=400, body={"error": "JSON で書く"})
            if not isinstance(body, dict):
                return Reply(status=400, body={"error": "対応表で書く"})
            added = self.add_problem(body) if request.path == "/zabbix/problem" else self.add_alert(body)
            return Reply(body=added)
        return Reply(status=404, body={"error": "ない"})

    @property
    def zabbix_url(self) -> str:
        return self._servers["zabbix"].url

    @property
    def wazuh_url(self) -> str:
        return self._servers["wazuh"].url

    @property
    def llm_url(self) -> str:
        return self._servers["llm"].url

    @property
    def control_url(self) -> str:
        return self._servers["control"].url

    def __enter__(self) -> Stack:
        for server in self._servers.values():
            server.__enter__()
        return self

    def __exit__(self, *exc: object) -> None:
        for server in reversed(list(self._servers.values())):
            server.__exit__(*exc)


def build(**kwargs) -> Stack:
    return Stack(**kwargs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--ca-out", type=Path, required=True, help="Wazuh 役の CA を書く場所")
    parser.add_argument("--zabbix-port", type=int, default=18081)
    parser.add_argument("--wazuh-port", type=int, default=19200)
    parser.add_argument("--llm-port", type=int, default=18090)
    parser.add_argument("--control-port", type=int, default=18079)
    args = parser.parse_args()
    env = os.environ
    stack = build(bind=args.bind, ca_out=args.ca_out, token=env.get("FAKE_ZABBIX_TOKEN", "fake-zabbix-token-for-local-test"),
                  password=env.get("FAKE_WAZUH_PASSWORD", "fake-wazuh-password-for-local-test"),
                  key=env.get("FAKE_LLM_KEY", "fake-openwebui-key-for-local-test"), zabbix_port=args.zabbix_port,
                  wazuh_port=args.wazuh_port, llm_port=args.llm_port, control_port=args.control_port)
    with stack:
        print(f"偽の系統: Zabbix {stack.zabbix_url}/api_jsonrpc.php、Wazuh {stack.wazuh_url}、LLM {stack.llm_url}/openai、"
              f"制御 {stack.control_url}（CA は {args.ca_out}）", flush=True)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
