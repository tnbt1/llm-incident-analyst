import logging
from dataclasses import replace

import pytest

from builders import at
from fakes import FakeServer, FakeZabbix, Reply
from tia.collectors.base import SourceError
from tia.collectors.endpoints import ZabbixEndpoint
from tia.collectors.zabbix import ZabbixPoller

NOW = 1790661420  # 2026-09-29T05:57:00Z。共有部品の now と同じ時刻


@pytest.fixture
def zabbix():
    fake = FakeZabbix()
    with FakeServer(fake.handle) as server:
        fake.server = server
        fake.url = server.url + "/api_jsonrpc.php"
        yield fake


@pytest.fixture
def token_file(zabbix, tmp_path):
    path = tmp_path / "zabbix_api_token"
    path.write_text(zabbix.token + "\n", encoding="utf-8")
    return path


@pytest.fixture
def poller(zabbix, token_file):
    return ZabbixPoller(ZabbixEndpoint(zabbix.url, token_file))


def incidents(conn):
    return conn.execute("SELECT * FROM incidents ORDER BY id").fetchall()


def refs(conn):
    return [tuple(row) for row in conn.execute(
        "SELECT external_id, resolved_at, missing_rounds FROM alert_refs ORDER BY external_id")]


def events(conn):
    return [row["type"] for row in conn.execute("SELECT type FROM events ORDER BY id")]


def test_open_problems_become_incidents(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213, trigger_id=23456, severity=2, clock=NOW - 360)
    zabbix.add_problem(48220, trigger_id=23600, severity=1, clock=NOW - 50, name="Package updates available",
                       host="example-monitor01", keys=(), tags=())
    report = poller.poll(conn, now, cfg, rules)
    assert report.counts == {"fetched": 2, "created": 1, "skipped": 1}
    assert (report.complete, report.watermark) == (True, "48220")
    first, second = incidents(conn)
    assert (first["external_id"], first["host"], first["type"]) == ("48213", "example-router01", "cpu")
    assert (first["analysis_state"], first["problem_status"], first["source_severity"]) == (
        "held", "open", "Zabbix Warning")
    assert (second["host"], second["analysis_state"], second["skip_reason"]) == (
        "example-monitor01", "skipped", "below_threshold")


def test_requests_carry_the_token_and_ask_for_a_bounded_list(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213)
    poller.poll(conn, now, cfg, rules)
    sent = zabbix.server.requests[0]
    assert sent.headers["authorization"] == f"Bearer {zabbix.token}"
    assert sent.headers["content-type"] == "application/json-rpc"
    method, params = zabbix.calls[0]
    assert method == "problem.get"
    assert (params["recent"], params["suppressed"], params["limit"]) == (True, False, 200)
    assert params["severities"] == [1, 2, 3, 4, 5]
    assert (params["sortfield"], params["sortorder"]) == (["eventid"], "ASC")
    assert zabbix.methods() == ["problem.get", "trigger.get"]
    assert zabbix.calls[1][1]["triggerids"] == ["23456"]


def test_information_is_not_fetched_when_the_setting_says_so(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213, severity=2)
    zabbix.add_problem(48220, trigger_id=23600, severity=1)
    report = poller.poll(conn, now, replace(cfg, zabbix_fetch_min_severity=2), rules)
    assert report.counts == {"fetched": 1, "created": 1}
    assert zabbix.calls[0][1]["severities"] == [2, 3, 4, 5]


def test_second_poll_adds_nothing_and_asks_for_no_details(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213)
    zabbix.add_problem(48217, trigger_id=23501, name="Disk space is low", keys=("vfs.fs.size[/,pused]",))
    poller.poll(conn, now, cfg, rules)
    zabbix.calls.clear()
    report = poller.poll(conn, at(now, 30), cfg, rules)
    assert report.counts == {"fetched": 2, "known": 2}
    assert zabbix.methods() == ["problem.get"]
    assert [row["occurrence_count"] for row in incidents(conn)] == [1, 1]


def test_new_event_of_the_same_trigger_is_a_recurrence(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213, clock=NOW - 600)
    poller.poll(conn, now, cfg, rules)
    zabbix.recover(48213, 48214, NOW + 10)
    zabbix.add_problem(48230, clock=NOW + 40)
    report = poller.poll(conn, at(now, 60), cfg, rules)
    assert report.counts == {"fetched": 2, "known": 1, "resolved": 1, "recurred": 1}
    (incident,) = incidents(conn)
    assert (incident["occurrence_count"], incident["problem_status"]) == (2, "open")


def test_recovery_in_the_list_resolves_the_incident_at_its_time(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213)
    poller.poll(conn, now, cfg, rules)
    zabbix.recover(48213, 48214, NOW + 12)
    zabbix.calls.clear()
    report = poller.poll(conn, at(now, 30), cfg, rules)
    assert report.counts == {"fetched": 1, "known": 1, "resolved": 1}
    (incident,) = incidents(conn)
    assert (incident["problem_status"], incident["resolved_at"]) == ("resolved", "2026-09-29T05:57:12+00:00")
    assert zabbix.methods() == ["problem.get"]
    assert poller.poll(conn, at(now, 60), cfg, rules).counts == {"fetched": 1, "known": 1}


def test_problem_that_opened_and_recovered_between_polls_is_kept(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213, clock=NOW - 40)
    zabbix.recover(48213, 48214, NOW - 20)
    report = poller.poll(conn, now, cfg, rules)
    assert report.counts == {"fetched": 1, "created": 1}
    (incident,) = incidents(conn)
    assert (incident["problem_status"], incident["resolved_at"]) == ("resolved", "2026-09-29T05:56:40+00:00")


def test_problem_that_left_the_list_is_resolved_with_the_recovery_time(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213)
    zabbix.add_problem(48217, trigger_id=23501)
    poller.poll(conn, now, cfg, rules)
    zabbix.recover(48213, 48300, NOW + 100)
    zabbix.expire(48213)
    zabbix.calls.clear()
    report = poller.poll(conn, at(now, 600), cfg, rules)
    assert report.counts == {"fetched": 1, "known": 1, "resolved": 1}
    first, second = incidents(conn)
    assert (first["problem_status"], first["resolved_at"]) == ("resolved", "2026-09-29T05:58:40+00:00")
    assert second["problem_status"] == "open"
    assert zabbix.methods() == ["problem.get", "event.get", "event.get"]
    assert zabbix.calls[1][1]["eventids"] == ["48213"]
    assert zabbix.calls[2][1]["eventids"] == ["48300"]


def test_suppressed_problem_is_left_out_and_comes_in_when_the_maintenance_ends(conn, now, cfg, rules, zabbix,
                                                                                poller):
    zabbix.add_problem(48213, suppressed=True)
    assert poller.poll(conn, now, cfg, rules).counts == {}
    assert incidents(conn) == []
    zabbix.suppress(48213, False)
    assert poller.poll(conn, at(now, 30), cfg, rules).counts == {"fetched": 1, "created": 1}


def test_problem_suppressed_after_it_was_stored_stays_open(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213)
    poller.poll(conn, now, cfg, rules)
    zabbix.suppress(48213)
    zabbix.calls.clear()
    report = poller.poll(conn, at(now, 30), cfg, rules)
    assert report.counts == {"hidden": 1}
    assert incidents(conn)[0]["problem_status"] == "open"
    assert zabbix.methods() == ["problem.get", "event.get", "problem.get"]
    assert "suppressed" not in zabbix.calls[2][1]
    zabbix.suppress(48213, False)
    assert poller.poll(conn, at(now, 60), cfg, rules).counts == {"fetched": 1, "known": 1}


def test_problem_whose_severity_fell_below_the_fetch_threshold_stays_open(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213, severity=2)
    poller.poll(conn, now, cfg, rules)
    zabbix.problems["48213"]["severity"] = "0"
    assert poller.poll(conn, at(now, 30), cfg, rules).counts == {"hidden": 1}
    assert incidents(conn)[0]["problem_status"] == "open"


def test_problem_that_vanished_without_a_recovery_is_closed_after_three_listings(conn, now, cfg, rules, zabbix,
                                                                                 poller):
    zabbix.add_problem(48213)
    poller.poll(conn, now, cfg, rules)
    zabbix.expire(48213)
    assert poller.poll(conn, at(now, 30), cfg, rules).counts == {"missing": 1}
    assert poller.poll(conn, at(now, 60), cfg, rules).counts == {"missing": 1}
    assert incidents(conn)[0]["problem_status"] == "open"
    assert poller.poll(conn, at(now, 90), cfg, rules).counts == {"resolved": 1}
    (incident,) = incidents(conn)
    assert (incident["problem_status"], incident["resolved_at"]) == ("resolved", "2026-09-29T05:58:30+00:00")


def test_event_deleted_in_zabbix_is_closed_after_three_listings(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213)
    poller.poll(conn, now, cfg, rules)
    zabbix.purge(48213)
    assert [poller.poll(conn, at(now, 30 * n), cfg, rules).counts for n in (1, 2, 3)] == [
        {"missing": 1}, {"missing": 1}, {"resolved": 1}]
    assert poller.poll(conn, at(now, 120), cfg, rules).counts == {}
    assert zabbix.methods()[-1] == "problem.get"


def test_recovery_with_an_unreadable_time_uses_the_time_of_the_poll(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213)
    poller.poll(conn, now, cfg, rules)
    zabbix.recover(48213, 48214, "soon")
    poller.poll(conn, at(now, 30), cfg, rules)
    assert incidents(conn)[0]["resolved_at"] == "2026-09-29T05:57:30+00:00"


def test_listing_larger_than_one_page_is_read_in_pages(conn, now, cfg, rules, zabbix, poller):
    for number in range(5):
        zabbix.add_problem(48300 + number, trigger_id=23000 + number, clock=NOW - 3600 * (number + 1))
    small = replace(cfg, zabbix_page_size=2, zabbix_max_pages=5)
    report = poller.poll(conn, now, small, rules)
    assert report.counts == {"fetched": 5, "created": 5}
    assert report.complete is True
    pages = [params for method, params in zabbix.calls if method == "problem.get"]
    assert [p.get("eventid_from") for p in pages] == [None, "48302", "48304"]
    assert all(p["limit"] == 2 for p in pages)


def test_listing_beyond_the_limit_is_cut_and_resolves_nothing(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48100, trigger_id=22000, clock=NOW - 7200)
    poller.poll(conn, now, cfg, rules)
    zabbix.expire(48100)
    for number in range(6):
        zabbix.add_problem(48300 + number, trigger_id=23000 + number, clock=NOW - 3600 * (number + 2))
    small = replace(cfg, zabbix_page_size=2, zabbix_max_pages=2)
    zabbix.calls.clear()
    report = poller.poll(conn, at(now, 30), small, rules)
    assert report.counts == {"fetched": 4, "created": 4}
    assert report.complete is False
    assert incidents(conn)[0]["problem_status"] == "open"
    assert zabbix.methods() == ["problem.get", "problem.get", "trigger.get"]


def test_server_that_ignores_the_page_size_is_cut(conn, now, cfg, rules, zabbix, poller):
    for number in range(5):
        zabbix.add_problem(48300 + number, trigger_id=23000 + number, clock=NOW - 3600 * (number + 1))
    zabbix.ignore_limit = True
    report = poller.poll(conn, now, replace(cfg, zabbix_page_size=2, zabbix_max_pages=2), rules)
    assert report.counts == {"fetched": 4, "created": 4}
    assert report.complete is False


def test_malformed_rows_are_skipped_and_counted(conn, now, cfg, rules, zabbix, poller, caplog):
    zabbix.add_problem(48213)
    zabbix.add_problem(48250, trigger_id=23700, severity=2, clock="yesterday")
    zabbix.extra_rows = [None, "x", 5, {"eventid": "abc"}, {"name": "no id"}, {"eventid": True}]
    with caplog.at_level(logging.WARNING, logger="tia.collect"):
        report = poller.poll(conn, now, cfg, rules)
        again = poller.poll(conn, at(now, 30), cfg, rules)
    assert report.counts == {"fetched": 8, "rejected": 7, "created": 1}
    assert again.counts == {"fetched": 8, "rejected": 7, "known": 1}
    assert [row["external_id"] for row in incidents(conn)] == ["48213"]
    noted = [r.getMessage() for r in caplog.records]
    assert len(noted) == 1 and "48250" in noted[0]


def test_trigger_that_cannot_be_read_gives_an_unknown_host(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213, host=None)
    assert poller.poll(conn, now, cfg, rules).counts == {"fetched": 1, "created": 1}
    (incident,) = incidents(conn)
    assert (incident["host"], incident["type"]) == ("unknown", "cpu")


def test_wrong_token_is_a_credential_failure(conn, now, cfg, rules, zabbix, poller, token_file):
    token_file.write_text("zbx-another-token-9876543210\n", encoding="utf-8")
    zabbix.add_problem(48213)
    with pytest.raises(SourceError) as caught:
        poller.poll(conn, now, cfg, rules)
    assert caught.value.kind == "auth"
    assert "zbx-another-token" not in str(caught.value)
    assert incidents(conn) == []


def test_token_is_read_again_on_every_poll(conn, now, cfg, rules, zabbix, poller, token_file):
    zabbix.add_problem(48213)
    poller.poll(conn, now, cfg, rules)
    zabbix.token = "zbx-rotated-token-5555555555"
    token_file.write_text(zabbix.token + "\n", encoding="utf-8")
    assert poller.poll(conn, at(now, 30), cfg, rules).counts == {"fetched": 1, "known": 1}


def test_missing_token_file_sends_nothing(conn, now, cfg, rules, zabbix, poller, token_file):
    token_file.unlink()
    with pytest.raises(SourceError) as caught:
        poller.poll(conn, now, cfg, rules)
    assert caught.value.kind == "credential"
    assert zabbix.server.requests == []


@pytest.mark.parametrize(("data", "kind"), [
    ("Not authorized.", "auth"),
    ("Not authorised.", "auth"),
    ("Session terminated, re-login, please.", "auth"),
    ("API token expired.", "auth"),
    ('No permissions to call "problem.get".', "auth"),
    ('Invalid parameter "/severities/1": an integer is expected.', "rpc"),
    ("", "rpc"),
])
def test_refusal_by_zabbix_is_sorted_by_its_reason(conn, now, cfg, rules, zabbix, poller, data, kind):
    zabbix.replies.append(Reply(body={"jsonrpc": "2.0", "id": 1,
                                      "error": {"code": -32602, "message": "Invalid params.", "data": data}}))
    with pytest.raises(SourceError) as caught:
        poller.poll(conn, now, cfg, rules)
    assert caught.value.kind == kind
    assert "problem.get" in str(caught.value)
    assert "Invalid params." in str(caught.value)


def test_refusal_that_repeats_the_token_is_scrubbed(conn, now, cfg, rules, zabbix, poller):
    zabbix.replies.append(Reply(body={"jsonrpc": "2.0", "id": 1, "error": {
        "code": -32602, "message": "Invalid params.", "data": f"bad header Bearer {zabbix.token}"}}))
    with pytest.raises(SourceError) as caught:
        poller.poll(conn, now, cfg, rules)
    assert zabbix.token not in str(caught.value)
    assert "***" in str(caught.value)


@pytest.mark.parametrize("body", [
    [],
    "text",
    {"jsonrpc": "2.0", "id": 1},
    {"jsonrpc": "2.0", "id": 1, "result": {"eventid": "1"}},
    {"jsonrpc": "2.0", "id": 1, "result": "48213"},
    {"jsonrpc": "2.0", "id": 99, "result": []},
    {"jsonrpc": "2.0", "id": 1, "error": "broken"},
])
def test_answer_in_the_wrong_shape_is_a_failure(conn, now, cfg, rules, zabbix, poller, body):
    zabbix.replies.append(Reply(body=body))
    with pytest.raises(SourceError) as caught:
        poller.poll(conn, now, cfg, rules)
    assert caught.value.kind in ("invalid_response", "rpc")
    assert incidents(conn) == []


def test_failure_while_reading_details_stores_nothing_and_loses_nothing(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213)
    zabbix.add_problem(48217, trigger_id=23501)
    calls = iter([None, Reply(status=502, body="bad gateway")])
    original = zabbix.handle
    zabbix.server.handler = lambda request: next(calls, None) or original(request)
    with pytest.raises(SourceError) as caught:
        poller.poll(conn, now, cfg, rules)
    assert caught.value.kind == "server"
    assert incidents(conn) == []
    assert poller.poll(conn, at(now, 30), cfg, rules).counts == {"fetched": 2, "created": 2}


def test_failure_while_checking_missing_problems_keeps_them_open(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213)
    poller.poll(conn, now, cfg, rules)
    zabbix.expire(48213)
    calls = iter([None, Reply(status=500, body="error")])
    original = zabbix.handle
    zabbix.server.handler = lambda request: next(calls, None) or original(request)
    with pytest.raises(SourceError):
        poller.poll(conn, at(now, 30), cfg, rules)
    assert incidents(conn)[0]["problem_status"] == "open"
    assert refs(conn) == [("48213", None, 0)]
    assert poller.poll(conn, at(now, 60), cfg, rules).counts == {"missing": 1}


def test_stop_request_ends_the_poll_between_pages(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48100, trigger_id=22000)
    poller.poll(conn, now, cfg, rules)
    zabbix.expire(48100)
    for number in range(4):
        zabbix.add_problem(48300 + number, trigger_id=23000 + number, clock=NOW - 3600 * (number + 1))
    zabbix.calls.clear()
    answers = iter([False, True])
    report = poller.poll(conn, at(now, 30), replace(cfg, zabbix_page_size=2), rules,
                         should_stop=lambda: next(answers, True))
    assert report.complete is False
    assert report.counts == {"fetched": 2, "created": 2}
    assert zabbix.methods() == ["problem.get", "trigger.get"]
    assert incidents(conn)[0]["problem_status"] == "open"


def test_unreachable_zabbix_is_reported(conn, now, fast, rules, token_file):
    from fakes import unused_port

    poller = ZabbixPoller(ZabbixEndpoint(f"http://127.0.0.1:{unused_port()}/api_jsonrpc.php", token_file))
    with pytest.raises(SourceError) as caught:
        poller.poll(conn, now, fast, rules)
    assert caught.value.kind == "unreachable"


# 一覧が上限を超える場合。読み残しの続きを、次の収集で読む。

def add_many(zabbix, count, first=48300):
    for number in range(count):
        zabbix.add_problem(first + number, trigger_id=23000 + number, clock=NOW - 3600 * (number + 1))


def test_listing_cut_by_the_limit_continues_on_the_next_poll(conn, now, cfg, rules, zabbix, poller):
    add_many(zabbix, 6)
    small = replace(cfg, zabbix_page_size=2, zabbix_max_pages=2)
    first = poller.poll(conn, now, small, rules)
    assert (first.counts, first.complete) == ({"fetched": 4, "created": 4}, False)
    zabbix.calls.clear()
    second = poller.poll(conn, at(now, 30), small, rules)
    assert (second.counts, second.complete) == ({"fetched": 2, "created": 2}, True)
    assert [row["external_id"] for row in incidents(conn)] == [str(48300 + n) for n in range(6)]
    pages = [params for method, params in zabbix.calls if method == "problem.get"]
    assert [p.get("eventid_from") for p in pages] == ["48304", "48306"]


def test_round_that_was_read_to_the_end_starts_over_from_the_top(conn, now, cfg, rules, zabbix, poller):
    add_many(zabbix, 6)
    small = replace(cfg, zabbix_page_size=2, zabbix_max_pages=2)
    poller.poll(conn, now, small, rules)
    poller.poll(conn, at(now, 30), small, rules)
    zabbix.calls.clear()
    third = poller.poll(conn, at(now, 60), small, rules)
    assert zabbix.calls[0][1].get("eventid_from") is None
    assert (third.counts, third.complete) == ({"fetched": 4, "known": 4}, False)
    assert len(incidents(conn)) == 6


def test_continuation_survives_a_restart(tmp_path, now, cfg, rules, zabbix, poller, token_file):
    from contextlib import closing

    from tia import db

    add_many(zabbix, 6)
    small = replace(cfg, zabbix_page_size=2, zabbix_max_pages=2)
    path = tmp_path / "tia.sqlite"
    with closing(db.connect(path)) as first:
        poller.poll(first, now, small, rules)
    again = ZabbixPoller(ZabbixEndpoint(zabbix.url, token_file))
    with closing(db.connect(path)) as second:
        report = again.poll(second, at(now, 30), small, rules)
        assert (report.counts, report.complete) == ({"fetched": 2, "created": 2}, True)
        assert len(incidents(second)) == 6


def test_problem_that_left_a_long_list_is_resolved_when_the_round_completes(conn, now, cfg, rules, zabbix,
                                                                            poller):
    zabbix.add_problem(48100, trigger_id=22000, clock=NOW - 7200)
    poller.poll(conn, now, cfg, rules)
    zabbix.recover(48100, 48290, NOW + 5)
    zabbix.expire(48100)
    add_many(zabbix, 6)
    small = replace(cfg, zabbix_page_size=2, zabbix_max_pages=2)
    first = poller.poll(conn, at(now, 30), small, rules)
    assert (first.counts, first.complete) == ({"fetched": 4, "created": 4}, False)
    assert incidents(conn)[0]["problem_status"] == "open"
    second = poller.poll(conn, at(now, 60), small, rules)
    assert (second.counts, second.complete) == ({"fetched": 2, "created": 2, "resolved": 1}, True)
    stored = incidents(conn)[0]
    assert (stored["problem_status"], stored["resolved_at"]) == ("resolved", "2026-09-29T05:57:05+00:00")


def test_problem_seen_early_in_a_long_round_is_not_taken_for_missing(conn, now, cfg, rules, zabbix, poller):
    add_many(zabbix, 6)
    small = replace(cfg, zabbix_page_size=2, zabbix_max_pages=2)
    poller.poll(conn, now, small, rules)
    zabbix.calls.clear()
    second = poller.poll(conn, at(now, 30), small, rules)
    assert second.complete is True
    assert "event.get" not in zabbix.methods()
    assert all(row["problem_status"] == "open" for row in incidents(conn))


def test_unreadable_continuation_starts_over(conn, now, cfg, rules, zabbix, poller):
    from tia.collectors import state
    from tia.models import Source

    add_many(zabbix, 3)
    state.set_cursor(conn, Source.ZABBIX, "{broken")
    report = poller.poll(conn, now, cfg, rules)
    assert (report.counts, report.complete) == ({"fetched": 3, "created": 3}, True)
    assert zabbix.calls[0][1].get("eventid_from") is None


# 一覧から消えた問題。1 回の変な応答で、発生中のインシデントを閉じない。

def test_problem_missing_once_and_back_unresolved_stays_open(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213, severity=4, clock=NOW - 300)
    poller.poll(conn, now, cfg, rules)
    zabbix.withhold(48213)
    assert poller.poll(conn, at(now, 30), cfg, rules).counts == {"missing": 1}
    assert incidents(conn)[0]["problem_status"] == "open"
    zabbix.release(48213)
    for seconds in (60, 90):
        assert poller.poll(conn, at(now, seconds), cfg, rules).counts == {"fetched": 1, "known": 1}
        assert (incidents(conn)[0]["problem_status"], incidents(conn)[0]["resolved_at"]) == ("open", None)
    assert events(conn) == ["detected"]


def test_count_of_missing_listings_starts_over_when_the_problem_is_listed_again(conn, now, cfg, rules, zabbix,
                                                                                poller):
    zabbix.add_problem(48213)
    poller.poll(conn, now, cfg, rules)
    zabbix.withhold(48213)
    poller.poll(conn, at(now, 30), cfg, rules)
    poller.poll(conn, at(now, 60), cfg, rules)
    assert refs(conn) == [("48213", None, 2)]
    zabbix.release(48213)
    poller.poll(conn, at(now, 90), cfg, rules)
    assert refs(conn) == [("48213", None, 0)]
    zabbix.withhold(48213)
    assert [poller.poll(conn, at(now, 120 + 30 * n), cfg, rules).counts for n in range(3)] == [
        {"missing": 1}, {"missing": 1}, {"resolved": 1}]


def test_problem_closed_as_vanished_is_reopened_when_it_comes_back(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213, severity=4, clock=NOW - 300)
    poller.poll(conn, now, cfg, rules)
    zabbix.withhold(48213)
    for number in (1, 2, 3):
        poller.poll(conn, at(now, 30 * number), cfg, rules)
    (closed,) = incidents(conn)
    assert (closed["problem_status"], closed["resolved_at"]) == ("resolved", "2026-09-29T05:58:30+00:00")
    zabbix.release(48213)
    report = poller.poll(conn, at(now, 120), cfg, rules)
    assert report.counts == {"fetched": 1, "known": 1, "reopened": 1}
    (back,) = incidents(conn)
    assert (back["problem_status"], back["resolved_at"]) == ("open", None)
    assert refs(conn) == [("48213", None, 0)]
    assert events(conn) == ["detected", "resolved", "reopened"]
    assert poller.poll(conn, at(now, 150), cfg, rules).counts == {"fetched": 1, "known": 1}


def test_recovered_problem_in_the_list_is_not_reopened(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213)
    poller.poll(conn, now, cfg, rules)
    zabbix.recover(48213, 48214, NOW + 12)
    poller.poll(conn, at(now, 30), cfg, rules)
    assert poller.poll(conn, at(now, 60), cfg, rules).counts == {"fetched": 1, "known": 1}
    assert incidents(conn)[0]["problem_status"] == "resolved"
    assert events(conn) == ["detected", "resolved"]


def test_incomplete_listing_does_not_count_as_missing(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48100, trigger_id=22000, clock=NOW - 7200)
    poller.poll(conn, now, cfg, rules)
    zabbix.withhold(48100)
    add_many(zabbix, 6)
    small = replace(cfg, zabbix_page_size=2, zabbix_max_pages=2)
    cut = poller.poll(conn, at(now, 30), small, rules)
    assert (cut.complete, cut.counts) == (False, {"fetched": 4, "created": 4})
    assert refs(conn)[0] == ("48100", None, 0)
    done = poller.poll(conn, at(now, 60), small, rules)
    assert (done.complete, done.counts) == (True, {"fetched": 2, "created": 2, "missing": 1})
    assert refs(conn)[0] == ("48100", None, 1)


def test_suppressed_problem_does_not_count_as_missing(conn, now, cfg, rules, zabbix, poller):
    zabbix.add_problem(48213)
    poller.poll(conn, now, cfg, rules)
    zabbix.withhold(48213)
    poller.poll(conn, at(now, 30), cfg, rules)
    zabbix.release(48213)
    zabbix.suppress(48213)
    for number in (2, 3, 4, 5):
        assert poller.poll(conn, at(now, 30 * number), cfg, rules).counts == {"hidden": 1}
    assert refs(conn) == [("48213", None, 0)]
    assert incidents(conn)[0]["problem_status"] == "open"


def test_number_too_long_to_read_rejects_that_problem_only(conn, now, cfg, rules, zabbix, poller):
    import json

    zabbix.add_problem(48213)
    zabbix.add_problem(48217, trigger_id=23501, clock=1234567)
    zabbix.add_problem(48220, trigger_id=23600)
    original = zabbix.handle

    def handler(request):
        reply = original(request)
        text = json.dumps(reply.body)
        return Reply(body=text.replace('"1234567"', "9" * 5000)) if '"1234567"' in text else reply

    zabbix.server.handler = handler
    report = poller.poll(conn, now, cfg, rules)
    assert report.counts == {"fetched": 3, "created": 2, "rejected": 1}
    assert [row["external_id"] for row in incidents(conn)] == ["48213", "48220"]
