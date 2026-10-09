"""画面の段階 2': 「確認した状態」、推奨する確認の「実行」、「結果を添えて再解析」。"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from web_fixtures import (BASE_URL, NOW, Clock, Probe, bundle_dir, client, ids, make_db, post, probe, token_of,  # noqa: F401
                          web_app, web_clock, web_db)

from tia import db
from tia.probes import store
from tia.probes.catalog import Catalog
from tia.probes.runner import ProbeResult
from tia.web.queries import available_actions, probe_for_check

ROOT = Path(__file__).resolve().parents[1]
CATALOG = Catalog.load(ROOT / "config" / "probes.yaml")


class StubRunner:
    """画面から呼ばれる実行器の代わり。run は決めた結果を返し、呼ばれた名前を残す。"""

    def __init__(self) -> None:
        self.catalog = CATALOG
        self.calls: list[tuple[str, str]] = []
        self.status = "ok"

    def run(self, probes, incident, *, stop=None):
        results = []
        for probe in probes:
            self.calls.append((probe.name, incident["host"]))
            target = incident["host"] if probe.where == "host" else probe.where
            output = f"result of {probe.name} <script>alert(1)</script>" if self.status == "ok" else ""
            error = None if self.status == "ok" else "10 秒で打ち切った"
            results.append(ProbeResult(probe.name, target, self.status, output, error, 42,
                                       datetime(2026, 9, 29, 5, 57, 30, tzinfo=UTC), self.catalog.command_for(probe, incident["host"])))
        return results


@pytest.fixture
def probe_runner():
    return StubRunner()


def _toast(response) -> dict:
    return json.loads(response.headers["hx-trigger"])["tia-toast"]


def _move_to_catalog_host(path, incident_id, host="example-app02"):
    conn = db.connect(path)
    try:
        conn.execute("UPDATE incidents SET host = ? WHERE id = ?", (host, incident_id))
    finally:
        conn.close()


def test_probe_for_check_matches_word_wise_prefixes_only():
    runner = StubRunner()
    host = "example-app01"
    assert probe_for_check(runner, host, "df -h / /var/lib/docker /home") == "disk"
    assert probe_for_check(runner, host, "df -h / /var/lib/docker /home | sort") == "disk"
    assert probe_for_check(runner, host, "sudo df -h / /var/lib/docker /home") == "disk"
    assert probe_for_check(runner, host, "sudo -n systemctl --failed --no-pager --plain") == "failed_units"
    assert probe_for_check(runner, host, "docker compose -f /opt/app01/docker-compose.yml ps -a") == "compose_ps"
    assert probe_for_check(runner, host, "df -h") is None  # 短すぎる（カタログのほうが長い）
    assert probe_for_check(runner, host, "dfx -h / /var/lib/docker /home") is None  # 言葉の途中では合わせない
    assert probe_for_check(runner, host, "rm -rf /") is None
    assert probe_for_check(runner, host, "swanctl --list-sas") is None  # FRR 専用
    assert probe_for_check(runner, "example-router01", "sudo swanctl --list-sas") == "ipsec_status"
    assert probe_for_check(runner, "unknown-host", "uptime") is None
    assert probe_for_check(None, host, "uptime") is None


def test_available_actions_gain_probe_and_reanalyze_with_probes():
    assert "probe" in available_actions("done", True, probes=True)
    assert "probe" not in available_actions("running", True, probes=True)
    assert "probe" not in available_actions("done", True, probes=False)
    assert "reanalyze_with_probes" in available_actions("done", True, attachable=True)
    assert "reanalyze_with_probes" not in available_actions("done", True, attachable=False)
    assert "reanalyze_with_probes" not in available_actions("queued", False, attachable=True)


def test_detail_shows_the_probe_section_and_the_run_buttons_for_matching_checks(client, web_db, ids, probe_runner):
    path, _ = web_db
    incident_id = ids["done_today"]
    _move_to_catalog_host(path, incident_id)
    conn = db.connect(path)
    try:
        with db.transaction(conn):
            store.insert(conn, incident_id, 3, "disk", "example-app02", "initial", NOW, 120, "ok",
                         "Filesystem <script>x</script>", None, command="df -h / /var/lib/docker /home")
            store.insert(conn, incident_id, 3, "memory", "example-app02", "initial", NOW, 11000, "timeout",
                         "", "10 秒で打ち切った")
    finally:
        conn.close()
    page = client.get(f"/partials/incidents/{incident_id}").text
    assert "確認した状態" in page and "2 件 · 成功 1" in page
    assert "Filesystem &lt;script&gt;x&lt;/script&gt;" in page and "<script>x</script>" not in page
    assert "時間切れ" in page and "10 秒で打ち切った" in page and "解析の前に" in page
    assert "$ df -h / /var/lib/docker /home" in page
    # 推奨の 2 件: free -m は memory に合う（vmctl ... vm exec ... -- free -m は言葉の先頭が違うので合わない）、docker stats は合わない
    assert page.count('name="name" value="') == 0 or "実行" in page
    # 結果を添える対象（運用者の未添付の結果）はないので、そのボタンは出ない
    assert "結果を添えて再解析" not in page


def test_operator_runs_a_probe_from_the_screen_and_can_reanalyze_with_it(client, web_db, ids, probe_runner):
    path, _ = web_db
    incident_id = ids["done_watch"]
    _move_to_catalog_host(path, incident_id, "example-app01")
    token = token_of(client)
    response = post(client, f"/incidents/{incident_id}/probe", token, {"name": "disk"})
    assert response.status_code == 200
    toast = _toast(response)
    assert toast["ok"] is True and "確認 disk を実行した: 成功" in toast["message"]
    assert probe_runner.calls == [("disk", "example-app01")]
    assert "result of disk &lt;script&gt;alert(1)&lt;/script&gt;" in response.text
    assert "まだ解析に添えていない" in response.text and "運用者が" in response.text
    assert "結果を添えて再解析" in response.text
    conn = db.connect(path)
    try:
        rows = store.for_incident(conn, incident_id)
        assert [(r["name"], r["trigger"], r["analysis_id"], r["status"]) for r in rows] == [("disk", "operator", None, "ok")]
        events = [r["type"] for r in conn.execute("SELECT type FROM events WHERE incident_id = ? ORDER BY id", (incident_id,))]
        assert events[-1] == "probe_run"
    finally:
        conn.close()
    page = client.get(f"/partials/incidents/{incident_id}").text
    assert "確認を実行した" in page and "disk: 成功" in page
    response = post(client, f"/incidents/{incident_id}/reanalyze_with_probes", token)
    assert _toast(response)["ok"] is True and "結果を添えて再解析する" in _toast(response)["message"]
    conn = db.connect(path)
    try:
        row = conn.execute("SELECT analysis_state, queue_reason FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        assert (row["analysis_state"], row["queue_reason"]) == ("queued", "manual")
    finally:
        conn.close()


def test_probe_failures_are_reported_and_stored_but_never_raise(client, web_db, ids, probe_runner):
    path, _ = web_db
    incident_id = ids["done_watch"]
    _move_to_catalog_host(path, incident_id, "example-app01")
    probe_runner.status = "timeout"
    token = token_of(client)
    response = post(client, f"/incidents/{incident_id}/probe", token, {"name": "uptime_load"})
    toast = _toast(response)
    assert toast["ok"] is False and "時間切れ" in toast["message"] and "打ち切った" in toast["message"]
    conn = db.connect(path)
    try:
        assert [r["status"] for r in store.for_incident(conn, incident_id)] == ["timeout"]
    finally:
        conn.close()


def test_unknown_probe_wrong_host_and_running_state_are_refused(client, web_db, ids, probe_runner):
    path, _ = web_db
    token = token_of(client)
    incident_id = ids["done_watch"]
    _move_to_catalog_host(path, incident_id, "example-app01")
    response = post(client, f"/incidents/{incident_id}/probe", token, {"name": "cat_etc_shadow"})
    assert _toast(response)["ok"] is False and "カタログにない" in _toast(response)["message"]
    response = post(client, f"/incidents/{incident_id}/probe", token, {"name": "ipsec_status"})
    assert _toast(response)["ok"] is False and "このホストには行えない" in _toast(response)["message"]
    response = post(client, f"/incidents/{incident_id}/probe", token, {"name": "uptime_load; id"})
    assert _toast(response)["ok"] is False
    # ホストが目録になければ VM の確認は行えない（API の確認は行える）
    _move_to_catalog_host(path, ids["done_today"], "example-monitor01")
    response = post(client, f"/incidents/{ids['done_today']}/probe", token, {"name": "uptime_load"})
    assert _toast(response)["ok"] is False and "このホストには行えない" in _toast(response)["message"]
    page = client.get(f"/partials/incidents/{ids['done_today']}").text
    assert 'name="name" value="' not in page  # 推奨の確認に VM のコマンドがあっても、目録にないホストでは「実行」が出ない
    response = post(client, f"/incidents/{ids['running']}/probe", token, {"name": "uptime_load"})
    assert _toast(response)["ok"] is False
    # 添える結果がなければ、結果を添えた再解析は行えない
    response = post(client, f"/incidents/{incident_id}/reanalyze_with_probes", token)
    assert _toast(response)["ok"] is False
    assert probe_runner.calls == []


def test_without_a_runner_the_screen_has_no_probe_controls(web_db, web_clock, probe, bundle_dir, ids):
    from fastapi.testclient import TestClient

    from tia.config import Config
    from tia.web.app import create_app

    app = create_app(web_db[0], Config(), bundle_dir=bundle_dir, llm_probe=probe, clock=web_clock)
    with TestClient(app, base_url=BASE_URL) as plain:
        page = plain.get(f"/partials/incidents/{ids['done_today']}").text
        assert "確認した状態" not in page and 'name="name"' not in page
        token = token_of(plain)
        response = post(plain, f"/incidents/{ids['done_today']}/probe", token, {"name": "uptime_load"})
        assert _toast(response)["ok"] is False


def test_same_probe_twice_within_a_minute_is_refused_without_touching_the_vm(client, web_db, ids, probe_runner):
    """「実行」の連打で対象の VM に ssh が飛び続けないように、同じ確認は 60 秒に 1 回。"""
    path, _ = web_db
    incident_id = ids["done_watch"]
    _move_to_catalog_host(path, incident_id, "example-app01")
    token = token_of(client)
    first = post(client, f"/incidents/{incident_id}/probe", token, {"name": "disk"})
    assert _toast(first)["ok"] is True
    second = post(client, f"/incidents/{incident_id}/probe", token, {"name": "disk"})
    assert second.status_code == 409 or _toast(second)["ok"] is False
    assert "実行したばかり" in _toast(second)["message"]
    assert probe_runner.calls == [("disk", "example-app01")]  # 2 回目は実行器に届かない
    other = post(client, f"/incidents/{incident_id}/probe", token, {"name": "memory"})
    assert _toast(other)["ok"] is True  # 別の確認は通る


def test_run_button_is_disabled_while_in_flight_and_only_the_latest_results_are_open(client, web_db, ids, probe_runner):
    path, _ = web_db
    incident_id = ids["done_today"]
    _move_to_catalog_host(path, incident_id)
    conn = db.connect(path)
    try:
        with db.transaction(conn):
            for i in range(14):
                store.insert(conn, incident_id, 3, "disk", "example-app02", "operator", NOW, 100, "ok",
                             f"output number {i}", None, command="df -h / /var/lib/docker /home")
    finally:
        conn.close()
    page = client.get(f"/partials/incidents/{incident_id}").text
    assert page.count('class="probe"') == 14
    # 最新の 10 件だけ開いて見せ、古い 4 件は折りたたむ
    assert page.count("<details class=\"probe-old\"") == 1 and "古い確認 4 件" in page
    assert "output number 13" in page.split("probe-old")[0]
    assert "output number 0" in page.split("probe-old")[1]
    # 「実行」のボタンは、要求が飛んでいる間は押せない（この件に合う推奨がなくても、型は固定する）
    template = (ROOT / "src" / "tia" / "web" / "templates" / "partials" / "incident.html").read_text(encoding="utf-8")
    form = template[template.index('hx-post="/incidents/{{ d.id }}/probe"'):]
    assert 'hx-disabled-elt="this"' in form[:form.index("</form>")]
    if 'name="name" value="' in page:
        assert 'hx-disabled-elt="this"' in page
