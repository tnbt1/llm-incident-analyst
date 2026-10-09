import time
from dataclasses import replace

import pytest
import trustme

from fakes import FakeServer, Reply, SlowHeaderServer, unused_port
from tia.collectors.base import SourceError
from tia.collectors.http import Http, tls_context

TOKEN = "zbx-token-0123456789abcdef"


def post(cfg, url, body=None, verify=True, **options):
    with Http(cfg, verify) as http:
        return http.post_json(url, body if body is not None else {"ping": 1}, **options)


def failure(cfg, url, **options) -> SourceError:
    with pytest.raises(SourceError) as caught:
        post(cfg, url, **options)
    # 元の例外をつなげない。元の例外の文には、送ったヘッダーが入ることがある。
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None or caught.value.__suppress_context__
    return caught.value


def test_json_goes_out_and_comes_back(fast):
    with FakeServer(lambda request: Reply(body={"echo": request.json(), "題": "日本語"})) as server:
        result = post(fast, server.url + "/api", {"名前": "値"}, content_type="application/json-rpc",
                      headers={"Authorization": f"Bearer {TOKEN}"})
        sent = server.requests[0]
    assert result == {"echo": {"名前": "値"}, "題": "日本語"}
    assert (sent.method, sent.path) == ("POST", "/api")
    assert sent.headers["content-type"] == "application/json-rpc"
    assert sent.headers["authorization"] == f"Bearer {TOKEN}"
    assert sent.headers["user-agent"] == "tia-collector"


def test_basic_credentials_are_sent(fast):
    with FakeServer(lambda request: Reply(body=[])) as server:
        post(fast, server.url, auth=("analyzer_ro", "合い言葉 0123"))
        header = server.requests[0].headers["authorization"]
    import base64
    assert base64.b64decode(header.removeprefix("Basic ")).decode() == "analyzer_ro:合い言葉 0123"


@pytest.mark.parametrize(("status", "kind"), [(401, "auth"), (403, "auth"), (429, "throttled"), (500, "server"),
                                              (502, "server"), (503, "server"), (400, "client"), (404, "client"),
                                              (302, "client"), (204, "client")])
def test_status_decides_the_kind_of_failure(fast, status, kind):
    reply = Reply(status=status, body={"error": "x"}, headers={"Location": "/elsewhere"} if status == 302 else {})
    with FakeServer(lambda request: reply) as server:
        error = failure(fast, server.url)
        assert len(server.requests) == 1
    assert error.kind == kind
    assert str(status) in str(error)


def test_redirect_is_not_followed(fast):
    with FakeServer(lambda request: Reply(status=307, headers={"Location": "/again"})) as server:
        assert failure(fast, server.url).kind == "client"
        assert [r.path for r in server.requests] == ["/"]


@pytest.mark.parametrize(("value", "seconds"), [("120", 120), ("0", 0), ("soon", None), ("-5", None),
                                                ("9999999", None)])
def test_requested_wait_is_read_when_it_is_a_number(fast, value, seconds):
    with FakeServer(lambda request: Reply(status=429, headers={"Retry-After": value})) as server:
        assert failure(fast, server.url).retry_after == seconds


def test_reason_of_a_refusal_is_kept_short_and_without_secrets(fast):
    body = {"error": {"reason": f"Fielddata access on the [_id] field is disallowed {TOKEN} " + "x" * 5000}}
    with FakeServer(lambda request: Reply(status=400, body=body)) as server:
        error = failure(fast, server.url, secrets=(TOKEN,))
    assert "Fielddata access" in str(error)
    assert TOKEN not in str(error)
    assert len(str(error)) < 260


def test_credential_failure_does_not_repeat_what_the_server_said(fast):
    with FakeServer(lambda request: Reply(status=401, body=f"bad token {TOKEN}")) as server:
        error = failure(fast, server.url, secrets=(TOKEN,))
    assert str(error) == "認証に失敗した（HTTP 401）"


def test_silent_server_is_a_timeout(fast):
    with FakeServer(lambda request: Reply(body={}, delay=1.6)) as server:
        error = failure(fast, server.url)
    assert error.kind == "timeout"


def test_slow_drip_is_cut_at_the_time_limit(fast):
    # 1 回ごとの待ちは制限より短い。全体では制限を超える。
    reply = Reply(body=b'{"a": "' + b"x" * 40 + b'"}', drip=(4, 0.15))
    with FakeServer(lambda request: reply) as server:
        error = failure(fast, server.url)
    assert error.kind == "timeout"


def test_closed_port_is_unreachable(fast):
    error = failure(fast, f"http://127.0.0.1:{unused_port()}/api")
    assert error.kind == "unreachable"


def test_body_that_is_not_json_is_invalid(fast):
    with FakeServer(lambda request: Reply(body=b"<html>502 Bad Gateway</html>")) as server:
        assert failure(fast, server.url).kind == "invalid_response"


@pytest.mark.parametrize("body", [b"", b"\xff\xfe", b'{"a": ', b"[" * 100000])
def test_broken_json_is_invalid(fast, body):
    with FakeServer(lambda request: Reply(body=body)) as server:
        assert failure(fast, server.url).kind == "invalid_response"


def test_oversized_response_is_refused(fast):
    small = replace(fast, collector_max_response_mb=1)
    with FakeServer(lambda request: Reply(body=b'"' + b"x" * (1024 * 1024) + b'"')) as server:
        error = failure(small, server.url)
    assert error.kind == "too_large"
    assert "1 MiB" in str(error)


def test_response_under_the_limit_is_accepted(fast):
    small = replace(fast, collector_max_response_mb=1)
    with FakeServer(lambda request: Reply(body=b'"' + b"x" * (1024 * 1024 - 2) + b'"')) as server:
        assert len(post(small, server.url)) == 1024 * 1024 - 2


def test_certificate_from_the_given_ca_is_trusted(fast, server_tls, ca_file):
    with FakeServer(lambda request: Reply(body={"ok": True}), tls=server_tls) as server:
        assert post(fast, server.url, verify=tls_context(ca_file)) == {"ok": True}


def test_certificate_from_another_ca_is_refused(fast, server_tls, tmp_path):
    other = tmp_path / "other-ca.pem"
    trustme.CA().cert_pem.write_to_path(other)
    with FakeServer(lambda request: Reply(body={"ok": True}), tls=server_tls) as server:
        error = failure(fast, server.url, verify=tls_context(other))
        assert server.requests == []
    assert error.kind == "tls"


def test_certificate_is_checked_against_the_os_when_no_ca_is_given(fast, server_tls):
    with FakeServer(lambda request: Reply(body={"ok": True}), tls=server_tls) as server:
        assert failure(fast, server.url, verify=tls_context(None)).kind == "tls"


def test_certificate_for_another_name_is_refused(fast, ca, ca_file):
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ca.issue_cert("wazuh.example").configure_cert(context)
    with FakeServer(lambda request: Reply(body={"ok": True}), tls=context) as server:
        assert failure(fast, server.url, verify=tls_context(ca_file)).kind == "tls"


def test_plain_http_server_behind_an_https_address_is_a_tls_failure(fast, ca_file):
    with FakeServer(lambda request: Reply(body={"ok": True})) as server:
        error = failure(fast, f"https://localhost:{server.port}", verify=tls_context(ca_file))
    assert error.kind == "tls"


@pytest.mark.parametrize("content", [None, b"not a certificate"])
def test_unusable_ca_file_is_a_tls_failure(tmp_path, content):
    path = tmp_path / "ca.pem"
    if content is not None:
        path.write_bytes(content)
    with pytest.raises(SourceError) as caught:
        tls_context(path)
    assert caught.value.kind == "tls"
    assert "ca.pem" in str(caught.value)


def test_proxy_settings_of_the_environment_are_ignored(fast, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{unused_port()}")
    monkeypatch.setenv("ALL_PROXY", f"http://127.0.0.1:{unused_port()}")
    with FakeServer(lambda request: Reply(body={"ok": True})) as server:
        assert post(fast, server.url) == {"ok": True}


def test_header_that_cannot_be_sent_does_not_leak_into_the_error(fast):
    with FakeServer(lambda request: Reply(body={})) as server:
        error = failure(fast, server.url, headers={"Authorization": f"Bearer {TOKEN}\nX-Injected: 1"},
                        secrets=(TOKEN,))
        assert server.requests == []
    assert TOKEN not in str(error)
    assert error.kind == "client"


# 1 回の要求の全体の制限時間。応答の種類にも、通信の段階にもよらない。fast の制限は 1 秒。
# 混んだ機械でも通るよう、判定には余裕を持たせる。直す前は 8 秒以上かかった。
SOON = 3.5


def timed_failure(cfg, url, **options):
    started = time.monotonic()
    error = failure(cfg, url, **options)
    return error, time.monotonic() - started


@pytest.mark.parametrize(("status", "kind"), [(500, "server"), (503, "server"), (401, "auth"),
                                              (429, "throttled"), (400, "client"), (404, "client")])
def test_refusal_sent_slowly_does_not_hold_the_collector(fast, status, kind):
    reply = Reply(status=status, body=b"e" * 80, drip=(2, 0.3))
    with FakeServer(lambda request: reply) as server:
        error, seconds = timed_failure(fast, server.url)
    assert error.kind == kind
    assert seconds < SOON


def test_refusal_sent_slowly_keeps_the_status_and_what_was_read(fast):
    reply = Reply(status=400, body=b"bad sort field " + b"x" * 200, drip=(15, 0.4))
    with FakeServer(lambda request: reply) as server:
        error, seconds = timed_failure(fast, server.url)
    assert str(error).startswith("予期しない応答（HTTP 400）: bad sort field")
    assert seconds < SOON


def test_headers_sent_slowly_are_cut_at_the_time_limit(fast):
    with SlowHeaderServer() as server:
        error, seconds = timed_failure(fast, server.url)
    assert error.kind == "timeout"
    assert seconds < SOON


def test_time_limit_covers_the_whole_request_not_each_read(fast):
    # 1 回ごとの待ちは 0.3 秒で、読み取りの制限より短い。全体では 6 秒かかる。
    reply = Reply(body=b'{"a": "' + b"x" * 40 + b'"}', drip=(2, 0.3))
    with FakeServer(lambda request: reply) as server:
        error, seconds = timed_failure(fast, server.url)
    assert error.kind == "timeout"
    assert seconds < SOON


def test_time_limit_starts_again_for_the_next_request(fast):
    with FakeServer(lambda request: Reply(body={"ok": True}, delay=0.4)) as server, Http(fast) as http:
        for _ in range(4):
            assert http.post_json(server.url, {"ping": 1}) == {"ok": True}


def test_number_with_too_many_digits_is_read_as_empty(fast):
    body = b'{"a": ' + b"9" * 5000 + b', "b": 12345678901234567890, "c": -' + b"1" * 31 + b', "d": [1.5, 7]}'
    with FakeServer(lambda request: Reply(body=body)) as server:
        assert post(fast, server.url) == {"a": None, "b": 12345678901234567890, "c": None, "d": [1.5, 7]}


def test_compressed_answer_is_measured_after_it_is_unpacked(fast):
    small = replace(fast, collector_max_response_mb=1)
    big = Reply(body=b'"' + b"x" * (2 * 1024 * 1024) + b'"', gzip=True)
    with FakeServer(lambda request: big) as server:
        assert failure(small, server.url).kind == "too_large"
    with FakeServer(lambda request: Reply(body={"ok": True}, gzip=True)) as server:
        assert post(small, server.url) == {"ok": True}


@pytest.mark.parametrize(("body", "shown"), [
    ({"error": {"root_cause": [{"type": "x", "reason": "inner"}], "type": "search_phase_execution_exception",
                "reason": "all shards failed"}, "status": 400},
     "予期しない応答（HTTP 400）: search_phase_execution_exception: all shards failed"),
    ({"error": {"reason": "no type here"}}, "予期しない応答（HTTP 400）: no type here"),
    ({"error": "plain words"}, "予期しない応答（HTTP 400）: plain words"),
    ({"message": "another shape"}, '予期しない応答（HTTP 400）: {"message": "another shape"}'),
    ("not json at all", "予期しない応答（HTTP 400）: not json at all"),
    ("", "予期しない応答（HTTP 400）"),
])
def test_refusal_shows_the_stated_reason_only(fast, body, shown):
    with FakeServer(lambda request: Reply(status=400, body=body)) as server:
        assert str(failure(fast, server.url)) == shown


def test_reason_of_a_refusal_is_read_only_up_to_a_limit():
    class Endless:
        status_code = 400
        served = 0

        def iter_bytes(self):
            while True:
                self.served += 1
                yield b"x" * 800

    answer = Endless()
    assert len(Http._reason(answer)) == 2000
    assert answer.served == 3


def _ca_without_key_usage(tmp_path):
    """Wazuh の証明書の道具が作る形の認証局。keyUsage 拡張がない。"""
    import datetime
    import ssl

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Wazuh")])
    ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .sign(ca_key, hashes.SHA256()))
    srv_key = ec.generate_private_key(ec.SECP256R1())
    srv_cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
                .issuer_name(ca_name).public_key(srv_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                            x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]),
                               critical=False)
                .sign(ca_key, hashes.SHA256()))
    ca_path = tmp_path / "wazuh-root-ca.pem"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path = tmp_path / "server.pem"
    cert_path.write_bytes(srv_cert.public_bytes(serialization.Encoding.PEM)
                          + srv_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path))
    return ca_path, context


def test_ca_without_key_usage_extension_is_accepted(fast, tmp_path):
    """Wazuh の自前の認証局には keyUsage がなく、Python 3.13 の厳格な検証が拒む。CA を明示したときは受け入れる。"""
    ca_path, server_tls = _ca_without_key_usage(tmp_path)
    with FakeServer(lambda request: Reply(body={"ok": True}), tls=server_tls) as server:
        assert post(fast, server.url, verify=tls_context(ca_path)) == {"ok": True}


def test_ca_without_key_usage_still_refuses_another_ca(fast, tmp_path):
    ca_path, server_tls = _ca_without_key_usage(tmp_path)
    other = tmp_path / "other-ca.pem"
    trustme.CA().cert_pem.write_to_path(other)
    with FakeServer(lambda request: Reply(body={"ok": True}), tls=server_tls) as server:
        error = failure(fast, server.url, verify=tls_context(other))
        assert server.requests == []
    assert error.kind == "tls"
