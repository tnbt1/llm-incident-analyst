import pytest

from tia.collectors.base import PollReport, SourceError, read_secret, scrub
from tia.models import Source

TOKEN = "zbx-token-0123456789abcdef"


def test_secret_is_read_without_the_trailing_newline(tmp_path):
    path = tmp_path / "token"
    path.write_text(TOKEN + "\n", encoding="utf-8")
    assert read_secret(path, "Zabbix の API トークン", header_safe=True) == TOKEN


def test_password_may_contain_spaces_and_other_scripts(tmp_path):
    path = tmp_path / "password"
    path.write_text("合い言葉 with space 123\n", encoding="utf-8")
    assert read_secret(path, "パスワード") == "合い言葉 with space 123"


@pytest.mark.parametrize(("content", "header_safe"), [
    (b"", False),
    (b"\n\n", False),
    (b"short\n", False),
    (b"line-one-0123\nline-two-0123\n", False),
    (b"tab\tinside-0123456789\n", False),
    (b"\xff\xfe-not-utf8-0123456789", False),
    (b"x" * 5000, False),
    ("トークン-0123456789".encode(), True),
    (b"token with space 0123456789", True),
])
def test_unusable_secret_is_refused_without_showing_it(tmp_path, content, header_safe):
    path = tmp_path / "secret"
    path.write_bytes(content)
    with pytest.raises(SourceError) as caught:
        read_secret(path, "Zabbix の API トークン", header_safe=header_safe)
    assert caught.value.kind == "credential"
    assert "Zabbix の API トークン" in str(caught.value)
    shown = content.decode("utf-8", "replace").strip()
    assert not shown or shown not in str(caught.value)


def test_missing_secret_file_names_the_path_only(tmp_path):
    with pytest.raises(SourceError) as caught:
        read_secret(tmp_path / "absent", "パスワード")
    assert caught.value.kind == "credential"
    assert "absent" in str(caught.value)


def test_scrub_hides_secrets_and_cleans_the_text():
    text = f"Invalid header b'Bearer {TOKEN}'\x00\x1b[31m and again {TOKEN}"
    cleaned = scrub(text, (TOKEN,))
    assert TOKEN not in cleaned
    assert cleaned.count("***") == 2
    assert "\x00" not in cleaned and "\x1b" not in cleaned


def test_scrub_cuts_long_text():
    assert len(scrub("x" * 5000)) == 200


def test_scrub_accepts_any_object():
    assert scrub(ValueError("boom")) == "boom"
    assert scrub(None) == "None"


def test_source_error_carries_kind_and_wait():
    error = SourceError("throttled", "混雑", retry_after=120)
    assert (error.kind, str(error), error.retry_after) == ("throttled", "混雑", 120)
    assert SourceError("timeout", "遅い").retry_after is None


def test_report_defaults_to_a_complete_empty_poll():
    report = PollReport(Source.ZABBIX)
    assert (dict(report.counts), report.complete, report.watermark) == ({}, True, None)


def test_rejection_is_noted_once_per_item(caplog):
    import logging

    from tia.collectors.base import note_rejected

    log, seen = logging.getLogger("tia.collect.test"), set()
    with caplog.at_level(logging.WARNING, logger="tia.collect"):
        for _ in range(3):
            note_rejected(seen, log, "Zabbix の問題", "48250", ValueError("時刻が読めない\x00"))
        note_rejected(seen, log, "Zabbix の問題", "48251", ValueError("別の問題"))
    assert [r.getMessage() for r in caplog.records] == ["Zabbix の問題を読み飛ばした: 時刻が読めない",
                                                        "Zabbix の問題を読み飛ばした: 別の問題"]


def test_memory_of_rejections_is_bounded():
    import logging

    from tia.collectors.base import REJECTED_MEMORY, note_rejected

    log, seen = logging.getLogger("tia.collect.test"), set()
    for number in range(REJECTED_MEMORY + 5):
        note_rejected(seen, log, "Wazuh のアラート", f"w-{number}", "形が違う")
    assert len(seen) <= REJECTED_MEMORY


# 相手が、秘密を形を変えて返してくる場合。

HARD = 'pa"ss\\word 日本-0123456789'


def shapes(secret, user=None):
    import base64
    import json
    import urllib.parse

    found = {
        "plain": secret,
        "json": json.dumps(secret)[1:-1],
        "json, other scripts kept": json.dumps(secret, ensure_ascii=False)[1:-1],
        "url": urllib.parse.quote(secret),
        "url, every mark": urllib.parse.quote(secret, safe=""),
        "form": urllib.parse.quote_plus(secret),
        "base64": base64.b64encode(secret.encode()).decode(),
        "base64 for urls": base64.urlsafe_b64encode(secret.encode()).decode(),
        "first half": secret[:12],
        "json inside json": json.dumps(json.dumps(secret)[1:-1])[1:-1],
    }
    if user:
        found["header"] = base64.b64encode(f"{user}:{secret}".encode()).decode()
    return found


@pytest.mark.parametrize("shape", list(shapes(HARD)))
def test_scrub_hides_a_secret_in_the_shapes_a_peer_may_send_back(shape):
    shown = shapes(HARD)[shape]
    cleaned = scrub(f"bad credentials [{shown}] given", (HARD,))
    assert cleaned == "bad credentials [***] given"


def test_scrub_hides_a_secret_that_was_cut_at_the_end_of_the_text():
    assert scrub("the peer said: " + HARD[:6], (HARD,)) == "the peer said: ***"
    assert scrub("the peer said: pass", (HARD,)) == "the peer said: pass"


def test_scrub_hides_every_occurrence_and_leaves_the_rest():
    import json

    text = f"first {HARD}, second {json.dumps(HARD)}, third {HARD[:9]}."
    assert scrub(text, (HARD,)) == 'first ***, second "***", third ***.'


def test_scrub_hides_the_longest_shape_first():
    # 形を変えた秘密の中に、元の秘密の先頭が現れる。先頭だけを消して、残りを出さない。
    token = "abcdefgh%41rest-of-token"
    import urllib.parse

    cleaned = scrub("got " + urllib.parse.quote(token, safe="") + " end", (token,))
    assert cleaned == "got *** end"
