from datetime import UTC, datetime, timedelta, timezone

import pytest

from tia.models import AnalysisState, IncidentType, ProblemStatus, Source, from_iso, to_iso


def test_values_are_the_strings_stored_in_the_database():
    assert Source.ZABBIX == "zabbix"
    assert AnalysisState.RETRY_WAIT == "retry_wait"
    assert ProblemStatus.ONESHOT == "oneshot"
    assert IncidentType.CONTAINER == "container"
    assert len(AnalysisState) == 8
    assert len(IncidentType) == 13


def test_to_iso_converts_to_utc_seconds():
    jst = timezone(timedelta(hours=9))
    assert to_iso(datetime(2026, 9, 29, 14, 57, 0, 123456, tzinfo=jst)) == "2026-09-29T05:57:00+00:00"


def test_to_iso_refuses_a_time_without_a_zone():
    with pytest.raises(ValueError, match="タイムゾーン"):
        to_iso(datetime(2026, 9, 29, 5, 57))


def test_iso_strings_sort_in_time_order():
    early, late = datetime(2026, 9, 29, 5, 57, tzinfo=UTC), datetime(2026, 9, 29, 15, 0, tzinfo=UTC)
    assert to_iso(early) < to_iso(late)
    assert from_iso(to_iso(late)) == late
