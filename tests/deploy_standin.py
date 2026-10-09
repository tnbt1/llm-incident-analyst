"""監視対象の VM の代わりのコンテナ。確認専用の利用者 analyst-probe の経路（sshd の ForceCommand、鍵認証、sudo -n）を
実機に触らずに試すためのもの。

Ubuntu 24.04 に sshd、nftables、sudo、python3 を入れ、利用者 ops（鍵でだけ入れ、sudo -n が使える）と、見本のゲスト FW を置く。
docker と systemd はないので、compose_ps などの確認は「失敗」で終わる（それも確認の結果のうち）。
"""
from __future__ import annotations

import shutil
import socket
import subprocess
import tempfile
import textwrap
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "llm-incident-analyst-host-standin:1"
DOCKERFILE = textwrap.dedent("""\
    FROM ubuntu:24.04
    RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \\
        openssh-server nftables sudo python3 iproute2 ca-certificates >/dev/null && rm -rf /var/lib/apt/lists/* \\
     && mkdir -p /run/sshd && ssh-keygen -A >/dev/null \\
     && useradd -m -s /bin/bash ops && install -d -o ops -g ops -m 700 /home/ops/.ssh \\
     && printf 'ops ALL=(ALL) NOPASSWD:ALL\\n' > /etc/sudoers.d/ops && chmod 440 /etc/sudoers.d/ops \\
     && printf 'PasswordAuthentication no\\nKbdInteractiveAuthentication no\\n' > /etc/ssh/sshd_config.d/10-standin.conf
    CMD ["/usr/sbin/sshd", "-D", "-e"]
    """)
# 見本のゲスト FW。入力は既定で拒否し、管理経路からの SSH と公開ポートだけを通す形
GUARD = textwrap.dedent("""\
    destroy table inet example_app01_guard
    table inet example_app01_guard {
      chain input {
        type filter hook input priority -10; policy drop;
        iif "lo" accept
        ct state established,related accept
        ct state invalid drop
        ip protocol icmp accept comment "ICMP"
        iifname "eth0" ip saddr 192.0.2.5 tcp dport 22 counter accept comment "SSH from the management path"
        iifname "eth0" udp dport 26900-26902 counter accept comment "app01 UDP"
        iifname "eth0" ip saddr 192.0.2.7 tcp dport 10050 ct state new counter accept comment "Zabbix passive agent"
        counter drop
      }
    }
    """)


def docker_available() -> bool:
    return (shutil.which("docker") is not None and shutil.which("ssh") is not None
            and subprocess.run(["docker", "version"], capture_output=True).returncode == 0)


class HostStandin:
    """with で立て、抜けると消す。"""

    def __init__(self, vm: str = "example-app01", ip: str = "192.0.2.6") -> None:
        self.name = f"llm-incident-analyst-host-{uuid.uuid4().hex[:8]}"
        self.tmp = Path(tempfile.mkdtemp(prefix="tia-standin-"))
        self.key = self.tmp / "id_ed25519"
        self.known_hosts = self.tmp / "known_hosts"
        self.port = 0
        self.vm = vm
        self.ip = ip

    def _build_image(self) -> None:
        if subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode == 0:
            return
        subprocess.run(["docker", "build", "-q", "-t", IMAGE, "-"], input=DOCKERFILE.encode(), check=True,
                       capture_output=True, timeout=600)

    def run(self, command: str, *, check: bool = True, stdin: bytes | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(["docker", "exec", "-i", self.name, "bash", "-c", command], input=stdin, capture_output=True,
                              text=stdin is None, check=check, timeout=120)

    def _wait_for_sshd(self) -> None:
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1) as probe:
                    if probe.recv(4).startswith(b"SSH"):
                        return
            except OSError:
                pass
            time.sleep(0.2)
        raise RuntimeError("代役の sshd が立ち上がらない")

    def __enter__(self) -> HostStandin:
        self._build_image()
        subprocess.run(["docker", "run", "-d", "--name", self.name, "--hostname", self.vm, "--cap-add", "NET_ADMIN",
                        "-p", "127.0.0.1::22", IMAGE], check=True, capture_output=True, timeout=120)
        port_line = subprocess.run(["docker", "port", self.name, "22/tcp"], check=True, capture_output=True, text=True,
                                   timeout=60).stdout.strip().splitlines()[0]
        self.port = int(port_line.rsplit(":", 1)[1])
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)], check=True,
                       capture_output=True, timeout=60)
        self.run("install -o ops -g ops -m 600 /dev/stdin /home/ops/.ssh/authorized_keys",
                 stdin=self.key.with_suffix(".pub").read_bytes())
        self.run("cat > /etc/app-guard.nft", stdin=GUARD.encode())
        self.run(textwrap.dedent(f"""\
            set -e
            ip addr add {self.ip}/32 dev lo 2>/dev/null || true
            nft -f /etc/app-guard.nft
            # 代役には docker の橋から入るので、動いている表にだけ 22 を許す
            nft insert rule inet example_app01_guard input tcp dport 22 ct state new accept comment '"standin ssh"'
            touch /var/log/dpkg.log
            """))
        self._wait_for_sshd()
        scan = subprocess.run(["ssh-keyscan", "-T", "5", "-t", "ed25519", "-p", str(self.port), "127.0.0.1"],
                              capture_output=True, text=True, timeout=60).stdout
        if "ssh-ed25519" not in scan:
            raise RuntimeError("代役のホスト鍵が取れない")
        self.known_hosts.write_text(scan, encoding="utf-8")
        return self

    def __exit__(self, *_: object) -> None:
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def install_probe_user(self, pubkey: bytes, *, roles: str = "docker", guard_table: str = "example_app01_guard",
                           compose: str = "/opt/app01/docker-compose.yml") -> None:
        """確認専用の利用者 analyst-probe を docs/probes.md の手順と同じ形で置く: 実行器、sshd の drop-in、sudoers、conf。"""
        self.run("install -d -m 755 /usr/local/lib/analyst-probe && cat > /usr/local/lib/analyst-probe/run",
                 stdin=(ROOT / "deploy" / "remote-host" / "analyst-probe").read_bytes())
        self.run("cat > /etc/ssh/sshd_config.d/61-analyst-probe.conf",
                 stdin=(ROOT / "deploy" / "remote-host" / "analyst-probe-sshd.conf").read_bytes())
        sudoers = (ROOT / "deploy" / "sudoers" / "analyst-probe").read_text(encoding="utf-8")
        sudoers = sudoers.replace("@GUARD_TABLE@", guard_table).replace("@COMPOSE@", compose)
        self.run("cat > /etc/sudoers.d/analyst-probe", stdin=sudoers.encode())
        self.run(f"""set -e
            chmod 755 /usr/local/lib/analyst-probe/run
            chmod 440 /etc/sudoers.d/analyst-probe
            visudo -c -q -f /etc/sudoers.d/analyst-probe
            getent passwd analyst-probe >/dev/null || useradd --system --user-group --home-dir /var/lib/analyst-probe \\
                --create-home --shell /bin/sh analyst-probe
            install -d -o analyst-probe -g analyst-probe -m 700 /var/lib/analyst-probe/.ssh
            printf 'ROLES={roles}\\nGUARD_TABLE={guard_table}\\nCOMPOSE={compose}\\n' > /etc/analyst-probe.conf
            chmod 644 /etc/analyst-probe.conf
            sshd -t
            kill -HUP 1
            """)
        self.run("install -o analyst-probe -g analyst-probe -m 600 /dev/stdin /var/lib/analyst-probe/.ssh/authorized_keys",
                 stdin=b"restrict " + pubkey)

    def probe(self, key: Path, *command: str) -> subprocess.CompletedProcess:
        """解析基盤と同じ条件で、analyst-probe として代役に入る。"""
        return subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                               "-o", f"UserKnownHostsFile={self.known_hosts}", "-o", "IdentitiesOnly=yes",
                               "-i", str(key), "-p", str(self.port), "analyst-probe@127.0.0.1", *command],
                              capture_output=True, text=True, timeout=120)
