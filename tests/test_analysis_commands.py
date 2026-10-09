"""推奨コマンドの検査。変更や破壊を伴う操作の検出と、文書のコマンドとの照合。"""
import pytest

from tia.analysis.commands import destructive_reason

# 変更や破壊を伴う。レビュアーの一覧と、この環境の語彙。
DESTRUCTIVE = [
    "rm -rf /var/lib/docker", "rm -r -f /var/lib/docker", "rm --recursive --force /var", "rm -r /var/lib/docker",
    "rm /etc/fstab", "rm -fr /tmp/x", "sudo rm -rf /", "rm \\\n-rf /", "rm​ -rf /", "ｒｍ －ｒｆ /",
    "docker compose stop", "docker compose up -d", "docker compose kill", "docker compose down",
    "docker compose pull && docker compose up -d", "docker compose restart", "docker rm x", "docker rmi x",
    "docker kill x", "docker stop x", "docker system prune -f", "docker volume rm x",
    "kubectl delete pod -n kube-system coredns-xxx", "kubectl drain node1 --force", "kubectl scale deploy x --replicas=0",
    "kubectl apply -f x.yaml", "kubectl edit deploy x", "kubectl patch deploy x -p '{}'", "kubectl cordon node1",
    "vmctl vm stop web01", "vmctl vm delete web01", "vmctl vm restart web01", "virsh destroy web01", "virsh shutdown web01",
    "virsh undefine web01",
    "systemctl start nginx", "systemctl stop nginx", "systemctl restart docker", "systemctl --now disable nginx",
    "systemctl -H monitor01 stop nginx", "systemctl restart  nginx", "systemctl enable --now foo", "systemctl mask foo",
    "sed -i 's/a/b/' /etc/nginx/nginx.conf", "echo x > /var/lib/foo/config", "tee /etc/hosts <<< x",
    "echo x >> /etc/hosts", "echo x > /etc/hosts", "openssl rand > /root/.ssh/authorized_keys",
    "git push --force origin main", "git push -f origin main", "git reset --hard HEAD~3", "git clean -fd",
    "dd of=/dev/sda bs=1M", "dd if=/dev/zero of=/dev/sda", "mkfs.ext4 /dev/sdb", "mkfs /dev/sdb", "mkswap /dev/sdb",
    "wipefs -a /dev/sdb", "fdisk /dev/sda", "parted /dev/sda rm 1", "lvremove vg/lv", "vgremove vg", "zfs destroy p/d",
    "nft flush ruleset", "nft add rule inet f i drop", "iptables -F", "iptables -t nat -F", "iptables -X",
    "iptables -D INPUT 1", "iptables -I INPUT -j DROP", "iptables -A INPUT -j DROP", "ip link set eth0 down",
    "ip addr flush dev eth0", "ufw disable", "ufw allow 22",
    "bash <(curl -s http://x/install.sh)", "sh -c \"$(curl -fsSL http://x)\"", "curl -s http://x | zsh",
    "curl -s http://x/install.sh | sh", "wget -qO- http://x | sudo bash", "echo cm0gLXJmIC8= | base64 -d | sh",
    "python3 -c 'import shutil; shutil.rmtree(\"/var\")'", "perl -e 'unlink glob \"*\"'",
    "find / -name '*.log' -delete", "find /var -exec rm -rf {} +", "find / -name x | xargs rm",
    "kill -9 1", "kill -KILL 1234", "kill -SIGKILL 1234", "kill 1234", "pkill nginx", "killall nginx",
    "chmod -R 0777 /", "chmod a+rwx -R /", "chmod 777 /etc/hosts", "chown root /etc/hosts", "crontab -r",
    "apt autoremove -y", "apt-get install x", "apt remove x", "pacman -S x", "pacman -Rns x", "pip uninstall -y x",
    "swapoff -a", "umount /var", "mount -o remount,ro /", "setenforce 0", "sysctl -w net.ipv4.ip_forward=0",
    "usermod -L alice", "userdel alice", "groupdel ops", "chpasswd", "passwd alice", "truncate -s 0 /var/log/x",
    "truncate /var/log/x", "shutdown -h now", "reboot", "poweroff", "halt", "init 6",
    "docker exec x rm -rf /data", "vmctl vm exec web01 -- sudo systemctl restart docker", "ssh monitor01 sudo reboot",
    "sudo -u alice rm -rf x", "env FOO=1 rm -rf x", "nohup rm -rf x &", "uptime; rm -rf /", "uptime && reboot",
    "uptime || reboot", "echo $(rm -rf /)", "echo `rm -rf /`", "cat /etc/hosts | tee /etc/hosts.bak",
    "vtysh -c 'configure terminal'", "zabbix_server -R config_cache_reload", "caddy reload", "tailscale down",
    "mysql -e 'DROP TABLE x'", "docker compose exec zabbix-server rm -rf /var/lib/zabbix",
    "rsync -a --delete /a/ /b/", "mv /etc/hosts /etc/hosts.bak", "cp x /etc/hosts", "ln -sf x /etc/y",
    ": > /var/log/syslog", "cat /dev/null > /var/log/syslog",
]

# 読み取りだけ。レビュアーの誤検出の一覧と、文書にあるコマンド。
READ_ONLY = [
    "last reboot", "last -x reboot shutdown", "journalctl -k | grep -i shutdown", "grep -i reboot /var/log/syslog",
    "cat /etc/passwd", "getent passwd analyzer_ro", "grep analyzer_ro /etc/passwd", "ls -l /etc/passwd",
    "who -b", "uptime", "systemctl status docker", "systemctl show -p Restart docker", "systemctl list-units --failed",
    "systemctl is-active docker", "systemctl is-enabled docker", "journalctl -u sshd | grep -i halt",
    "docker ps --filter status=restarting", "docker inspect web --format '{{.HostConfig.RestartPolicy}}'",
    "docker events --since 1h --filter event=kill", "docker compose ps", "docker compose logs --tail 50 x",
    "docker logs --tail 100 x", "docker stats --no-stream", "docker exec x cat /etc/hostname",
    "grep -r 'systemctl restart' /var/log/", "stat -c %U:%G /etc/shadow", "dmesg | grep -i 'halt'",
    "ps aux | grep -v grep | grep killall", "man truncate", "which pkill", "ls /usr/bin/passwd",
    "tail -n 50 /var/log/apt/history.log | grep -i install", "grep passwd /var/log/auth.log",
    "test -f /run/reboot-required && cat /run/reboot-required", "df -h / /var/lib/docker", "free -h", "ss -ltnp",
    "ip -4 addr show", "ip route", "nft list ruleset", "iptables -L -n -v", "iptables -t nat -S", "ufw status",
    "kubectl get pods -A", "kubectl describe pod x", "kubectl logs x", "vmctl vm exec web01 -- df -h",
    "vmctl vm exec web01 -- systemctl status docker", "ssh monitor01 uptime", "sudo vtysh -c 'show bgp summary'",
    "vtysh -c 'show ip route'", "mysql -e 'SELECT 1'", "git status", "git log -5", "git diff", "pacman -Q docker",
    "apt list --installed | grep docker", "pip list", "cat /proc/meminfo", "echo $PATH", "echo ok > /dev/null",
    "ls -la /tmp", "find /var/log -name '*.log' -mtime +7", "tailscale status", "zabbix_get -s x -k agent.ping",
    "curl -s -m 5 http://127.0.0.1:8000/health", "curl -s http://x | jq .", "python3 -m json.tool x.json",
    "sort < /tmp/x", "wc -l < /var/log/syslog", "mount | grep /var", "crontab -l", "sysctl net.ipv4.ip_forward",
    "swapon --show", "journalctl --since '1 hour ago' -u ssh --no-pager", "echo 'rm -rf' | wc -c",
    "grep -c rm /var/log/syslog", "ls /var/lib/docker", "cat /run/reboot-required",
    "docker compose -f /opt/x/compose.yaml ps", "timeout 5 ping -c 3 192.0.2.7", "watch -n 5 df -h", "env | sort",
]


@pytest.mark.parametrize("command", DESTRUCTIVE)
def test_destructive_command_is_named(command):
    assert destructive_reason(command), command


@pytest.mark.parametrize("command", READ_ONLY)
def test_read_only_command_is_allowed(command):
    assert destructive_reason(command) is None, (command, destructive_reason(command))


def test_unparseable_command_is_refused():
    assert destructive_reason("echo 'unterminated")


# ---- 文書のコマンドとの照合（M-3） ----
from tia.analysis.commands import matches_template, templates_in  # noqa: E402

DOC = """# 手順

```bash
# 容量を見る
$ df -h / /var/lib/docker
sudo systemctl status docker
docker compose -f /opt/x/compose.yaml \\
  ps
vmctl vm get <VM>
cp -a /etc/nftables.conf "$netchange_dir/proposed.nft"
kubectl get pods -n ${NAMESPACE}
ls -la /tmp   # 一時ファイル
python3 - <<'PY'
print("a")
PY
vmctl vm exec x -- sudo -n python3 -c '
import json
print(json.dumps({"a": 1}))
'
```

```yaml
image: nginx:1.25
restart: always
```

```text
Active: active (running) since Mon
```

```console
$ systemctl restart ssh
```

```
uptime
```
"""


def test_templates_come_from_shell_blocks_only_and_are_joined():
    templates = templates_in([DOC])
    assert "df -h / /var/lib/docker" in templates
    assert "systemctl status docker" in templates
    assert "docker compose -f /opt/x/compose.yaml ps" in templates
    assert "ls -la /tmp" in templates
    assert "uptime" in templates and "systemctl restart ssh" in templates
    assert "image: nginx:1.25" not in templates and "restart: always" not in templates
    assert "Active: active (running) since Mon" not in templates
    assert not any(t == "'" or t.endswith("-c '") or t == "PY" for t in templates), templates
    assert any(t.startswith("python3 - <<'PY'") and "print(\"a\")" in t for t in templates)
    assert any(t.startswith("vmctl vm exec x -- sudo -n python3 -c '") and "json.dumps" in t for t in templates)


@pytest.mark.parametrize("command, verified", [
    ("docker compose -f /opt/x/compose.yaml ps", True),
    ("sudo docker compose -f /opt/x/compose.yaml ps", True),
    ("docker compose -f /opt/x/compose.yaml down", False),
    ("docker compose", False),
    ("systemctl restart ssh", True),
    ("systemctl restart sshd", False),
    ("vmctl vm get web01", True),
    ("vmctl vm get", False),
    ("cp -a /etc/nftables.conf /root/netchange/20261003/proposed.nft", True),
    ("kubectl get pods -n kube-system", True),
    ("kubectl get pods -n kube-system -o wide", False),
    ("image: nginx:1.25", False),
    ("df -h / /var/lib/docker", True),
    ("df -h /", False),
    ("ｄｆ　-h / /var/lib/docker", True),
])
def test_verification_is_word_wise_from_the_start(command, verified):
    assert matches_template(command, templates_in([DOC])) is verified


def test_placeholder_can_stand_for_several_words():
    templates = templates_in(["```bash\nvmctl vm exec <VM> -- <コマンド>\n```"])
    assert matches_template("vmctl vm exec web01 -- df -h /", templates)
    assert not matches_template("vmctl vm exec web01 --", templates)


def test_sudo_n_does_not_swallow_the_command():
    """`sudo -n` の -n は値を取らない。`sudo -n cat /etc/passwd` は読み取りで、/etc/passwd がコマンドに見えてはいけない。"""
    for cmd in ("sudo -n cat /etc/passwd",
                "vmctl vm exec example-app01 -- sudo -n cat /etc/passwd",
                "sudo -n grep alice /etc/passwd", "sudo -n -u root cat /etc/shadow", "doas -n last -F"):
        assert destructive_reason(cmd) is None, cmd
    # 値を取るオプションは従来どおり。nice -n 10 と timeout の秒数、sudo -u root は外して中身を見る
    assert destructive_reason("nice -n 10 rm -rf /var/lib/docker") is not None
    assert destructive_reason("sudo -u root passwd ops") is not None
    assert destructive_reason("sudo -n passwd ops") is not None
