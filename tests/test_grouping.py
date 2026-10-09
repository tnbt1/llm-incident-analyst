import json

from builders import at, wazuh_hit, zabbix_problem
from tia import grouping, intake, queue
from tia.models import AnalysisState, ProblemStatus, Source
from tia.normalize import normalize_wazuh, normalize_zabbix

HOSTS = ["example-app01", "example-app03", "example-app02",
         "example-monitor01", "example-router01"]
NOW_CLOCK = 1790661420  # conftest の now（05:57:00Z）と同じ時刻
STARTED = 1790661060    # builders の既定の発生時刻（05:51:00Z）


def _ingest(conn, cfg, rules, now, host, n, keys=("system.cpu.util",), severity=2, clock=STARTED):
    raw = zabbix_problem(event_id=f"e{n}", trigger_id=f"t{n}", host=host, keys=keys, severity=severity,
                         clock=clock)
    return intake.apply(conn, normalize_zabbix(raw, cfg, rules), now, cfg).incident_id


def _row(conn, incident_id):
    return conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()


def test_four_incidents_are_not_grouped(conn, cfg, rules, now):
    for n, host in enumerate(HOSTS[:4]):
        _ingest(conn, cfg, rules, now, host, n)
    assert grouping.evaluate(conn, now, cfg) is None
    assert conn.execute("SELECT COUNT(*) FROM incidents WHERE source = 'group'").fetchone()[0] == 0


def test_five_incidents_in_five_minutes_become_one_group(conn, cfg, rules, now):
    ids = [_ingest(conn, cfg, rules, at(now, n * 30), host, n, severity=2 + n % 2) for n, host in enumerate(HOSTS)]
    group_id = grouping.evaluate(conn, at(now, 150), cfg)
    group = _row(conn, group_id)
    assert group["source"] == Source.GROUP
    assert group["title"] == "同時多発（5 件）"
    assert group["host"] == "複数"
    assert group["occurrence_count"] == 5
    assert group["severity"] == 3
    assert group["analysis_state"] == AnalysisState.HELD
    assert group["problem_status"] == ProblemStatus.OPEN
    for incident_id in ids:
        member = _row(conn, incident_id)
        assert member["analysis_state"] == AnalysisState.GROUPED
        assert member["group_id"] == group_id


def test_incidents_outside_the_window_are_not_counted(conn, cfg, rules, now):
    for n, host in enumerate(HOSTS):
        _ingest(conn, cfg, rules, at(now, n * 100), host, n, clock=NOW_CLOCK + n * 100)
    assert grouping.evaluate(conn, at(now, 400), cfg) is None


def test_root_host_down_groups_from_two_incidents(conn, cfg, rules, now):
    _ingest(conn, cfg, rules, now, "example-router01", 1, keys=("icmpping",), severity=4)
    _ingest(conn, cfg, rules, at(now, 20), "example-app01", 2, keys=("icmpping",), severity=4)
    group = _row(conn, grouping.evaluate(conn, at(now, 30), cfg))
    assert group["title"] == "example-router01 の停止に伴う連鎖（2 件）"
    assert group["host"] == "example-router01"


def test_root_host_alone_is_not_grouped(conn, cfg, rules, now):
    _ingest(conn, cfg, rules, now, "example-router01", 1, keys=("icmpping",), severity=4)
    assert grouping.evaluate(conn, at(now, 30), cfg) is None


def test_root_host_performance_problem_does_not_trigger_grouping(conn, cfg, rules, now):
    _ingest(conn, cfg, rules, now, "example-router01", 1)
    _ingest(conn, cfg, rules, at(now, 20), "example-app01", 2)
    assert grouping.evaluate(conn, at(now, 30), cfg) is None


def test_late_arrival_joins_the_waiting_group(conn, cfg, rules, now):
    for n, host in enumerate(HOSTS):
        _ingest(conn, cfg, rules, now, host, n)
    group_id = grouping.evaluate(conn, at(now, 10), cfg)
    late = _ingest(conn, cfg, rules, at(now, 40), "example-app01", 99, keys=("vfs.fs.size[/,pused]",))
    assert grouping.evaluate(conn, at(now, 45), cfg) == group_id
    assert _row(conn, late)["group_id"] == group_id
    assert _row(conn, group_id)["occurrence_count"] == 6
    assert _row(conn, group_id)["title"] == "同時多発（6 件）"


def test_group_that_started_analysis_takes_no_more_members(conn, cfg, rules, now):
    for n, host in enumerate(HOSTS):
        _ingest(conn, cfg, rules, now, host, n)
    group_id = grouping.evaluate(conn, at(now, 10), cfg)
    conn.execute("UPDATE incidents SET analysis_state = 'running' WHERE id = ?", (group_id,))
    late = _ingest(conn, cfg, rules, at(now, 40), "example-app01", 99, keys=("vfs.fs.size[/,pused]",))
    assert grouping.evaluate(conn, at(now, 45), cfg) is None
    assert _row(conn, late)["group_id"] is None


def test_skipped_incidents_are_not_members(conn, cfg, rules, now):
    for n, host in enumerate(HOSTS):
        _ingest(conn, cfg, rules, now, host, n, severity=1)
    assert grouping.evaluate(conn, at(now, 10), cfg) is None


def _group_of_five(conn, cfg, rules, now):
    ids = [_ingest(conn, cfg, rules, now, host, n) for n, host in enumerate(HOSTS)]
    return grouping.evaluate(conn, at(now, 10), cfg), ids


def _analysed(conn, group_id, now):
    queue.promote_held(conn, at(now, 70))
    queue.start(conn, group_id, at(now, 80))
    queue.complete(conn, group_id, at(now, 160), urgency="high", kind="network", summary="要約")


def test_old_problems_that_arrive_in_one_poll_are_not_grouped(conn, cfg, rules, now):
    for n in range(6):
        _ingest(conn, cfg, rules, now, HOSTS[n % 5], n, clock=NOW_CLOCK - (n + 1) * 3600)
    assert grouping.evaluate(conn, at(now, 10), cfg) is None
    assert conn.execute("SELECT COUNT(*) FROM incidents WHERE source = 'group'").fetchone()[0] == 0


def test_burst_an_hour_ago_is_grouped_when_it_arrives(conn, cfg, rules, now):
    for n, host in enumerate(HOSTS):
        _ingest(conn, cfg, rules, now, host, n, clock=NOW_CLOCK - 3600 + n * 30)
    group = _row(conn, grouping.evaluate(conn, at(now, 10), cfg))
    assert group["occurrence_count"] == 5
    assert group["started_at"] == "2026-09-29T04:57:00+00:00"
    assert group["last_occurrence_at"] == "2026-09-29T04:59:00+00:00"


def test_only_the_incidents_that_occurred_together_are_grouped(conn, cfg, rules, now):
    old = [_ingest(conn, cfg, rules, now, HOSTS[n], 50 + n, clock=NOW_CLOCK - 7200 - n * 1800) for n in range(2)]
    recent = [_ingest(conn, cfg, rules, now, host, n, clock=NOW_CLOCK - 60 + n * 10)
              for n, host in enumerate(HOSTS)]
    group_id = grouping.evaluate(conn, at(now, 10), cfg)
    assert _row(conn, group_id)["occurrence_count"] == 5
    assert all(_row(conn, i)["group_id"] == group_id for i in recent)
    assert all(_row(conn, i)["group_id"] is None for i in old)


def test_late_arrival_that_occurred_long_before_does_not_join(conn, cfg, rules, now):
    group_id, _ = _group_of_five(conn, cfg, rules, now)
    late = _ingest(conn, cfg, rules, at(now, 40), "example-app01", 99, clock=STARTED - 7200)
    assert grouping.evaluate(conn, at(now, 45), cfg) is None
    assert _row(conn, late)["group_id"] is None
    assert _row(conn, group_id)["occurrence_count"] == 5


def test_root_host_down_long_ago_does_not_group_new_incidents(conn, cfg, rules, now):
    _ingest(conn, cfg, rules, at(now, -10800), "example-router01", 1, keys=("icmpping",), severity=4,
            clock=NOW_CLOCK - 10800)
    _ingest(conn, cfg, rules, now, "example-app01", 2, clock=NOW_CLOCK - 20)
    _ingest(conn, cfg, rules, now, "example-app03", 3, clock=NOW_CLOCK - 10)
    assert grouping.evaluate(conn, at(now, 10), cfg) is None


def test_root_down_is_kept_with_the_group(conn, cfg, rules, now):
    root = _ingest(conn, cfg, rules, now, "example-router01", 1, keys=("icmpping",), severity=4)
    other = _ingest(conn, cfg, rules, at(now, 20), "example-app01", 2, keys=("icmpping",), severity=4)
    group_id = grouping.evaluate(conn, at(now, 30), cfg)
    assert json.loads(_row(conn, group_id)["raw_json"]) == {"members": [root, other], "root_down": True}
    intake.resolve(conn, Source.ZABBIX, "e1", at(now, 60), at(now, 70))
    grouping.evaluate(conn, at(now, 80), cfg)
    group = _row(conn, group_id)
    assert group["title"] == "example-router01 の停止に伴う連鎖（2 件）"
    assert group["host"] == "example-router01"
    assert group["problem_status"] == ProblemStatus.OPEN


def test_group_whose_members_all_recover_is_resolved_and_gets_no_followup(conn, cfg, rules, now):
    group_id, _ = _group_of_five(conn, cfg, rules, now)
    _analysed(conn, group_id, now)
    for n in range(5):
        intake.resolve(conn, Source.ZABBIX, f"e{n}", at(now, 300 + n * 10), at(now, 400))
    assert grouping.evaluate(conn, at(now, 410), cfg) is None
    group = _row(conn, group_id)
    assert group["problem_status"] == ProblemStatus.RESOLVED
    assert group["resolved_at"] == "2026-09-29T06:02:40+00:00"
    assert queue.schedule_followups(conn, at(now, 3 * 3600), cfg) == 0
    assert _row(conn, group_id)["analysis_state"] == AnalysisState.DONE


def test_group_stays_open_while_one_member_is_open(conn, cfg, rules, now):
    group_id, _ = _group_of_five(conn, cfg, rules, now)
    for n in range(4):
        intake.resolve(conn, Source.ZABBIX, f"e{n}", at(now, 300), at(now, 400))
    grouping.evaluate(conn, at(now, 410), cfg)
    group = _row(conn, group_id)
    assert group["problem_status"] == ProblemStatus.OPEN
    assert group["resolved_at"] is None


def test_group_of_wazuh_alerts_is_oneshot(conn, cfg, rules, now):
    for n in range(5):
        hit = wazuh_hit(alert_id=f"w-{n}", srcip=f"192.0.2.{n + 10}")
        intake.apply(conn, normalize_wazuh(hit, cfg, rules), now, cfg)
    group = _row(conn, grouping.evaluate(conn, at(now, 10), cfg))
    assert group["occurrence_count"] == 5
    assert group["problem_status"] == ProblemStatus.ONESHOT
    assert group["resolved_at"] is None


def test_member_whose_severity_rises_raises_the_group(conn, cfg, rules, now):
    group_id, _ = _group_of_five(conn, cfg, rules, now)
    assert _row(conn, group_id)["severity"] == 2
    again = zabbix_problem(event_id="e-again", trigger_id="t0", host=HOSTS[0], severity=4, clock=NOW_CLOCK)
    assert intake.apply(conn, normalize_zabbix(again, cfg, rules), at(now, 20), cfg).outcome == "recurred"
    grouping.evaluate(conn, at(now, 30), cfg)
    group = _row(conn, group_id)
    assert group["severity"] == 4
    assert group["last_occurrence_at"] == "2026-09-29T05:57:00+00:00"
    assert group["occurrence_count"] == 5


def test_analysed_group_keeps_its_title(conn, cfg, rules, now):
    group_id, _ = _group_of_five(conn, cfg, rules, now)
    _analysed(conn, group_id, now)
    conn.execute("UPDATE incidents SET title = '解析時の題名' WHERE id = ?", (group_id,))
    intake.resolve(conn, Source.ZABBIX, "e0", at(now, 300), at(now, 400))
    grouping.evaluate(conn, at(now, 410), cfg)
    assert _row(conn, group_id)["title"] == "解析時の題名"


def test_unchanged_group_is_not_rewritten(conn, cfg, rules, now):
    group_id, _ = _group_of_five(conn, cfg, rules, now)
    before = dict(_row(conn, group_id))
    grouping.evaluate(conn, at(now, 45), cfg)
    assert dict(_row(conn, group_id)) == before


def test_prioritized_incident_is_not_absorbed(conn, cfg, rules, now):
    ids = [_ingest(conn, cfg, rules, now, HOSTS[n % 5], n) for n in range(6)]
    queue.prioritize(conn, ids[0], at(now, 5))
    group_id = grouping.evaluate(conn, at(now, 10), cfg)
    first = _row(conn, ids[0])
    assert (first["analysis_state"], first["group_id"], first["priority"]) == (AnalysisState.QUEUED, None, 1)
    assert _row(conn, group_id)["occurrence_count"] == 5

