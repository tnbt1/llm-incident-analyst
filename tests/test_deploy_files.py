"""配置物の形。Compose、Caddy、画像の作り方、設定の写し。実機にはつながない。"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
SECRETS = ("zabbix_api_token", "wazuh_indexer_password", "openwebui_api_key", "probe_ssh_key")


def test_compose_keeps_the_container_locked_down():
    compose = yaml.safe_load((DEPLOY / "compose.yaml").read_text(encoding="utf-8"))
    service = compose["services"]["analyzer"]
    assert compose["name"] == "llm-incident-analyst"
    assert service["user"] == "10001:10001" and service["read_only"] is True
    assert service["cap_drop"] == ["ALL"] and "no-new-privileges:true" in service["security_opt"]
    assert service["mem_limit"] == "512m" and service["stop_grace_period"] == "30s"
    assert service["restart"] == "unless-stopped" and service["tmpfs"] == ["/tmp"]
    assert service["ports"] == ["127.0.0.1:38090:8000"]  # 外には Caddy だけが公開する
    assert set(service["secrets"]) == set(SECRETS)
    env = service["environment"]
    # 接続先は .env で変えられるように ${変数:-既定} で書く
    assert env["TIA_LLM_URL"].startswith("${TIA_LLM_URL:-") and env["TIA_LLM_URL"].endswith("/openai}")  # Open WebUI の中継経路
    assert env["TIA_ZABBIX_URL"].startswith("${TIA_ZABBIX_URL:-") and env["TIA_ZABBIX_URL"].endswith("/api_jsonrpc.php}")
    assert env["TIA_WAZUH_URL"].startswith("${TIA_WAZUH_URL:-https://")
    assert env["TIA_WAZUH_USER"] == "${TIA_WAZUH_USER:-analyzer_ro}"
    assert env["TIA_WAZUH_CA_FILE"] == "${TIA_WAZUH_CA_FILE:-/config/ca/wazuh-root-ca.pem}"
    # 設定の上書きの .env。なくても起動する
    assert service["env_file"] == [{"path": ".env", "required": False}]
    assert compose["networks"]["monitoring"]["external"] is True
    assert compose["networks"]["zabbix_frontend"]["external"] is True
    assert service["logging"]["options"] == {"max-size": "10m", "max-file": "5"}
    assert "build" not in service and service["image"].startswith("llm-incident-analyst:")
    assert set(service["volumes"]) == {"./config:/config:ro", "./data:/data", "./backups:/backups"}
    for name in SECRETS:
        assert compose["secrets"][name] == {"file": f"./secrets/{name}"}


def test_compose_default_tag_is_the_project_version():
    """compose の既定の画像の版は pyproject の版と同じ。版を上げたとき、古い画像で動き続けない。"""
    import tomllib

    with (ROOT / "pyproject.toml").open("rb") as handle:
        version = tomllib.load(handle)["project"]["version"]
    text = (DEPLOY / "compose.yaml").read_text(encoding="utf-8")
    assert f"image: llm-incident-analyst:${{TIA_IMAGE_TAG:-{version}}}" in text


@pytest.mark.docker
@pytest.mark.skipif(shutil.which("docker") is None, reason="docker がない")
def test_compose_file_is_accepted_by_docker_compose(tmp_path):
    shutil.copytree(DEPLOY, tmp_path / "deploy")
    for name in SECRETS:
        (tmp_path / "deploy" / "secrets" / name).write_text("fake-token-for-local-test\n", encoding="utf-8")
    result = subprocess.run(["docker", "compose", "-f", str(tmp_path / "deploy" / "compose.yaml"), "config", "--quiet"],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr


def test_caddy_site_keeps_the_host_and_streams_events():
    text = (DEPLOY / "caddy" / "site.caddy").read_text(encoding="utf-8")
    assert "https://<MONITORING_VM_IP>:11443 {" in text and "bind <MONITORING_VM_IP>" in text and "tls internal" in text
    assert "reverse_proxy 127.0.0.1:38090" in text and "flush_interval -1" in text
    assert "basic_auth" in text and "<bcrypt" in text
    assert "header_up Host" not in text  # Host は書き換えない
    assert re.search(r"read_timeout\s+\d+m", text)
    assert text.startswith("# >>> llm-incident-analyst >>>") and text.rstrip().endswith("# <<< llm-incident-analyst <<<")


def test_dockerfile_is_pinned_and_runs_as_the_analyzer_user():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert text.count("FROM python:3.13-slim@sha256:") == 2
    assert "USER 10001:10001" in text and "HEALTHCHECK" in text
    assert 'ENTRYPOINT ["tia"]' in text and "--knowledge" in text and "--config-dir" in text
    assert "requirements.txt" in text and "--require-hashes" in text
    # OS の道具は、確認が使う openssh-client だけ。ビルドの道具を入れない
    installs = re.findall(r"apt-get install[^\n]*", text)
    assert len(installs) == 1 and installs[0].rstrip(" \\").endswith("openssh-client >/dev/null"), installs
    assert text.count("apt-get") == 2 and "rm -rf /var/lib/apt/lists/*" in text


def test_requirements_cover_the_runtime_dependencies_with_hashes():
    text = (DEPLOY / "requirements.txt").read_text(encoding="utf-8")
    for name in ("fastapi", "httpx", "jinja2", "python-multipart", "pyyaml", "tzdata", "uvicorn"):
        assert re.search(rf"^{name}==", text, re.M | re.I), name
    assert "pytest" not in text and "trustme" not in text and "--hash=sha256:" in text
    # 本体はビルドの道具なしで入れる。手元で作った wheel を --no-deps で
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "deploy/dist/tia-*.whl" in dockerfile and "--no-deps tia-*.whl" in dockerfile


def test_dockerignore_leaves_out_tests_secrets_and_data():
    text = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    for entry in ("tests", "secrets", "data", "*.sqlite", ".git", ".venv", "deploy/local"):
        assert entry in text.split(), entry


def test_production_settings_file_loads_and_points_at_the_container_paths():
    from tia.config import load_config

    cfg = load_config(DEPLOY / "config" / "analyzer.yaml")
    assert cfg.knowledge_bundle_dir == "/config/knowledge" and cfg.backup_dir == "/backups"
    assert cfg.knowledge_recipe == "/config/knowledge.yaml"
    assert cfg.web_cookie_secure is True and cfg.worker_enabled is True and cfg.web_host == "0.0.0.0"
    assert cfg.web_system_name == "Incident Analyst"


def test_copied_config_files_match_the_originals():
    for name in ("type-rules.yaml", "knowledge.yaml", "probes.yaml"):
        assert (DEPLOY / "config" / name).read_bytes() == (ROOT / "config" / name).read_bytes(), name
    assert (DEPLOY / "local" / "config" / "knowledge.yaml").read_bytes() == (ROOT / "config" / "knowledge.yaml").read_bytes()
    # 手元の通しの写しは、ip が代役の VM を指す以外は同じ
    original = (ROOT / "config" / "probes.yaml").read_text(encoding="utf-8").splitlines()
    local = [line for line in (DEPLOY / "local" / "config" / "probes.yaml").read_text(encoding="utf-8").splitlines()
             if not line.startswith("# 手元の通しの写し")]
    assert len(local) == len(original)
    for mine, theirs in zip(local, original, strict=True):
        if mine != theirs:
            assert mine.strip() == "ip: 172.28.41.6" and theirs.strip().startswith("ip: 192.0.2."), (mine, theirs)


def test_no_real_host_keys_are_shipped():
    """ホスト鍵は配置のときに ssh-keyscan で集める。リポジトリには入れない。"""
    assert not (ROOT / "config" / "probes_known_hosts").exists()
    assert not (DEPLOY / "config" / "probes_known_hosts").exists()
    assert not (DEPLOY / "known_hosts").exists()


def test_secrets_readme_names_the_files_and_the_mode():
    text = (DEPLOY / "secrets" / "README.md").read_text(encoding="utf-8")
    for name in SECRETS:
        assert name in text
    assert "0440" in text and "10001" in text


def test_local_stack_has_a_stand_in_vm_for_the_probes():
    compose = yaml.safe_load((DEPLOY / "local" / "compose.yaml").read_text(encoding="utf-8"))
    vm = compose["services"]["vm"]
    assert vm["networks"]["probes"] == {"ipv4_address": "172.28.41.6"}
    assert compose["networks"]["probes"]["ipam"]["config"] == [{"subnet": "172.28.41.0/24"}]
    analyzer = compose["services"]["analyzer"]
    assert "probes" in analyzer["networks"] and "probe_ssh_key" in analyzer["secrets"]
    assert "./secrets/probes_known_hosts:/config/probes_known_hosts:ro" in analyzer["volumes"]
    assert compose["secrets"]["probe_ssh_key"] == {"file": "./secrets/probe_ssh_key"}
    dockerfile = (DEPLOY / "local" / "Dockerfile.vm").read_text(encoding="utf-8")
    assert "deploy/remote-host/analyst-probe " in dockerfile and "analyst-probe-sshd.conf" in dockerfile
    assert "deploy/sudoers/analyst-probe" in dockerfile and "visudo -c" in dockerfile
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "/deploy/local/secrets/probe_ssh_key\n" in ignore and "/deploy/local/secrets/vm_host_key\n" in ignore
