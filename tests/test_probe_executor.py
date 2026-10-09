"""VM 側の実行器 analyst-probe。名前 1 語だけを受け、表の固定のコマンドをシェルを通さずに動かす。"""
from __future__ import annotations

import importlib.util
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from deploy_standin import ROOT, HostStandin, docker_available
from tia.probes.catalog import Catalog

EXECUTOR = ROOT / "deploy" / "remote-host" / "analyst-probe"


def load_executor():
    spec = importlib.util.spec_from_loader("analyst_probe", importlib.machinery.SourceFileLoader("analyst_probe", str(EXECUTOR)))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def conf(tmp_path):
    path = tmp_path / "analyst-probe.conf"
    path.write_text("ROLES=docker\nGUARD_TABLE=example_app01_guard\nCOMPOSE=/opt/app01/docker-compose.yml\n",
                    encoding="utf-8")
    return path


def run(name: str, conf: Path, **env: str) -> subprocess.CompletedProcess:
    full = {"PATH": os.environ["PATH"], "SSH_ORIGINAL_COMMAND": name, "TIA_PROBE_CONF": str(conf), **env}
    return subprocess.run([sys.executable, str(EXECUTOR)], env=full, capture_output=True, text=True, timeout=60)


def test_executor_is_executable_and_has_a_python_shebang():
    assert os.access(EXECUTOR, os.X_OK)
    assert EXECUTOR.read_text(encoding="utf-8").startswith("#!/usr/bin/python3\n")


def test_named_probe_runs_and_returns_its_output(conf):
    result = run("uptime_load", conf)
    assert result.returncode == 0, result.stderr
    assert "load average" in result.stdout
    result = run("disk", conf)
    assert result.returncode == 0 and "Filesystem" in result.stdout
    result = run("accounts", conf)
    assert result.returncode == 0 and "root:" in result.stdout


@pytest.mark.parametrize("requested", ["uptime_load; id", "../run", "", "a" * 300, "disk x", "cat /etc/shadow",
                                       "UPTIME_LOAD", "uptime_load\nid", "unknown_probe"])
def test_anything_but_a_known_name_is_refused_without_running(conf, requested):
    result = run(requested, conf)
    assert result.returncode == 2
    assert result.stdout == ""


def test_probes_for_another_role_or_a_missing_value_are_refused(tmp_path):
    frr = tmp_path / "frr.conf"
    frr.write_text("ROLES=frr\nGUARD_TABLE=example_router_fw\n", encoding="utf-8")
    assert run("compose_ps", frr).returncode == 2
    assert run("docker_events_1h", frr).returncode == 2
    docker = tmp_path / "docker.conf"
    docker.write_text("ROLES=docker\nGUARD_TABLE=example_app02_guard\n", encoding="utf-8")  # COMPOSE がない
    assert run("compose_ps", docker).returncode == 2
    assert run("ipsec_status", docker).returncode == 2
    missing = tmp_path / "none.conf"  # conf 自体がない VM では、役割の要らない確認だけ動く
    assert run("uptime_load", missing).returncode == 0
    assert run("guard_counters", missing).returncode == 2


def _override(tmp_path, table):
    path = tmp_path / "table.json"
    path.write_text(json.dumps(table), encoding="utf-8")
    return str(path)


def test_slow_probe_is_killed_at_the_timeout(tmp_path, conf):
    override = _override(tmp_path, {"slow": {"stages": [["sleep", "30"]]}})
    result = run("slow", conf, TIA_PROBE_TABLE_OVERRIDE=override, TIA_PROBE_TIMEOUT="1")
    assert result.returncode == 3
    assert "打ち切った" in result.stderr


def test_big_output_is_cut_at_the_cap_with_a_marker(tmp_path, conf):
    override = _override(tmp_path, {"big": {"stages": [["head", "-c", "100000", "/dev/zero"]]}})
    result = run("big", conf, TIA_PROBE_TABLE_OVERRIDE=override, TIA_PROBE_CAP="1000")
    assert result.returncode == 0
    assert result.stdout.endswith("…（切り詰めた）\n") and len(result.stdout.encode()) < 1100


def test_pipeline_stages_are_connected_without_a_shell(tmp_path, conf):
    override = _override(tmp_path, {"pipe": {"stages": [["printf", "a\\nb\\nc\\n"], ["tail", "-n", "1"]]},
                                    "bad": {"stages": [["ls", "/nonexistent-x"]]}})
    result = run("pipe", conf, TIA_PROBE_TABLE_OVERRIDE=override)
    assert (result.returncode, result.stdout) == (0, "c\n")
    result = run("bad", conf, TIA_PROBE_TABLE_OVERRIDE=override)
    assert result.returncode == 4 and "nonexistent-x" in result.stdout  # 標準エラーは出力の後ろに添える


def test_missing_command_and_a_failing_first_stage_are_failures_without_a_traceback(tmp_path, conf):
    override = _override(tmp_path, {"gone": {"stages": [["no-such-command-x", "x"]]},
                                    "first_fails": {"stages": [["sh", "-c", "echo out; echo denied >&2; exit 1"], ["tail", "-n", "1"]]}})
    result = run("gone", conf, TIA_PROBE_TABLE_OVERRIDE=override)
    assert result.returncode == 4 and "コマンドを動かせない: no-such-command-x" in result.stdout
    assert "Traceback" not in result.stdout + result.stderr
    result = run("first_fails", conf, TIA_PROBE_TABLE_OVERRIDE=override)
    assert result.returncode == 4 and "out" in result.stdout and "denied" in result.stdout  # pipefail と同じ


def test_executor_table_matches_the_catalog_word_for_word():
    """VM 側の表と解析基盤のカタログは同じ名前・同じ言葉。片方だけ変えると気づく。"""
    module = load_executor()
    catalog = Catalog.load(ROOT / "config" / "probes.yaml")
    host_probes = {name: probe for name, probe in catalog.probes.items() if probe.where == "host"}
    assert set(module.TABLE) == set(host_probes)
    for name, probe in host_probes.items():
        host = "example-router01" if probe.hosts and "example-router01" in probe.hosts else "example-app01"
        entry = catalog.hosts[host]
        stages = []
        for argv in module.TABLE[name]["stages"]:
            words = []
            for word in argv:
                if word.startswith("{existing:"):
                    words.extend(word[len("{existing:"):-1].split(","))
                else:
                    words.append(word.replace("{compose}", entry.compose or "").replace("{guard_table}", entry.guard_table))
            stages.append(shlex.join(words))
        assert " | ".join(stages) == catalog.command_for(probe, host), name
        roles = set(module.TABLE[name].get("roles", []))
        expected = {r for r in ("frr", "docker") if probe.hosts is not None
                    and all(r in catalog.hosts[h].roles for h in probe.hosts)}
        assert roles == expected, name


def test_sudoers_names_every_privileged_command_of_the_table():
    module = load_executor()
    sudoers = (ROOT / "deploy" / "sudoers" / "analyst-probe").read_text(encoding="utf-8")
    sudoers = sudoers.replace("@GUARD_TABLE@", "example_app01_guard").replace("@COMPOSE@", "/x/docker-compose.yml")
    allowed = " ".join(line.strip().rstrip(",\\") for line in sudoers.splitlines() if not line.startswith("#"))
    for name, entry in module.TABLE.items():
        for argv in entry["stages"]:
            if argv[:2] != ["sudo", "-n"]:
                continue
            words = [w.replace("{guard_table}", "example_app01_guard").replace("{compose}", "/x/docker-compose.yml")
                     for w in argv[2:]]
            spelled = " ".join(w.replace(" ", "\\ ") for w in words[1:])
            assert f"/{words[0]} {spelled}" in allowed, name


standin_only = pytest.mark.skipif(not docker_available(), reason="docker か ssh がない")
docker_marker = pytest.mark.docker


@standin_only
@docker_marker
def test_executor_through_sshd_runs_only_the_named_probe():
    try:
        with HostStandin() as box:
            key = box.tmp / "probe_key"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True,
                           capture_output=True, timeout=60)
            box.install_probe_user(key.with_suffix(".pub").read_bytes())
            good = box.probe(key, "uptime_load")
            assert good.returncode == 0, good.stderr
            assert "load average" in good.stdout
            # sshd の ForceCommand が効き、頼んだコマンドは実行器の名前の照合で断られる
            bad = box.probe(key, "cat /etc/shadow")
            assert (bad.returncode, bad.stdout) == (2, "")
            none = box.probe(key)
            assert none.returncode == 2 and none.stdout == ""
            # 代役に docker はないので失敗で終わるが、sudo -n はパスワードを待たずに戻る
            compose = box.probe(key, "compose_ps")
            assert compose.returncode == 4
            # 逆転送は sshd が断る（-R はすぐに要求が届く。-L は接続が来るまで何も送らないので検証にならない）
            base = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                    "-o", f"UserKnownHostsFile={box.known_hosts}", "-o", "IdentitiesOnly=yes",
                    "-o", "ExitOnForwardFailure=yes", "-i", str(key), "-p", str(box.port)]
            forward = subprocess.run(base + ["-N", "-R", "127.0.0.1:0:127.0.0.1:22", "analyst-probe@127.0.0.1"],
                                     capture_output=True, text=True, timeout=120)
            assert forward.returncode == 255 and "forwarding failed" in forward.stderr, forward.stderr
            # 順方向の転送: 局所のポートを開いて実際につなぐと、sshd が administratively prohibited で断る
            import socket
            with socket.socket() as probe_sock:
                probe_sock.bind(("127.0.0.1", 0))
                local_port = probe_sock.getsockname()[1]
            local = subprocess.Popen(base + ["-N", "-L", f"127.0.0.1:{local_port}:127.0.0.1:22", "analyst-probe@127.0.0.1"],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                import time
                deadline = time.monotonic() + 20
                banner = b""
                while time.monotonic() < deadline and local.poll() is None:
                    try:
                        with socket.create_connection(("127.0.0.1", local_port), timeout=2) as conn:
                            conn.settimeout(3)
                            try:
                                banner = conn.recv(64)
                            except OSError:
                                banner = b""
                        break
                    except OSError:
                        time.sleep(0.5)
                assert not banner.startswith(b"SSH-"), banner  # 転送の先の sshd のバナーが届いたら転送が通っている
            finally:
                local.kill()
                _, err = local.communicate(timeout=30)
            assert local.returncode != 0 or "administratively prohibited" in err or "open failed" in err
            # 利用者 ops の鍵では analyst-probe に入れない
            wrong = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                                    "-o", f"UserKnownHostsFile={box.known_hosts}", "-o", "IdentitiesOnly=yes",
                                    "-i", str(box.key), "-p", str(box.port), "analyst-probe@127.0.0.1", "uptime_load"],
                                   capture_output=True, text=True, timeout=120)
            assert wrong.returncode == 255
    except (subprocess.CalledProcessError, RuntimeError) as exc:
        detail = getattr(exc, "stderr", None)
        pytest.skip(f"代役のコンテナを作れない: {detail[-300:] if detail else exc}")


def test_logins_reads_sshd_session_too_and_leaves_out_the_probe_users():
    """OpenSSH 9.8 以降（Ubuntu 26.04）は認証を sshd-session が記録する。確認の利用者自身のログインは除く。"""
    module = load_executor()
    stages = module.TABLE["logins"]["stages"]
    assert "_COMM=sshd" in stages[0] and "_COMM=sshd-session" in stages[0]
    assert any(argv[:2] == ["grep", "-Ev"] and "analyst-probe" in argv[2] and "monitor-tunnel" in argv[2] for argv in stages)
    catalog = Catalog.load(ROOT / "config" / "probes.yaml")
    command = catalog.command_for(catalog.probes["logins"], "example-app01")
    assert "_COMM=sshd-session" in command and "grep -Ev" in command


def test_vm_timeout_is_a_little_longer_than_the_analyzers_per_probe_timeout():
    """VM 側は解析基盤が待つ時間 + 少しで打ち切る。長く残すと sudo journalctl が解析の後も走り続ける。"""
    from tia.config import Config

    module = load_executor()
    assert module.TIMEOUT == Config().probes_timeout_sec + 5
    assert module.TIMEOUT <= 20
