"""接続先と、秘密を置いたファイルの場所。環境変数から読む。秘密の値そのものは持たない。"""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_ZABBIX_TOKEN_FILE = "/run/secrets/zabbix_api_token"
DEFAULT_WAZUH_PASSWORD_FILE = "/run/secrets/wazuh_indexer_password"
DEFAULT_WAZUH_USER = "analyzer_ro"
# LLM の API。Open WebUI の中継経路。末尾の /openai を外した場所が、認証のいらない /health の根。
DEFAULT_LLM_URL = "http://127.0.0.1:18080/openai"
DEFAULT_LLM_API_KEY_FILE = "/run/secrets/openwebui_api_key"


class EndpointError(ValueError):
    """接続先の設定が誤っている。"""


@dataclass(frozen=True)
class ZabbixEndpoint:
    url: str
    token_file: Path


@dataclass(frozen=True)
class WazuhEndpoint:
    url: str
    user: str
    password_file: Path
    ca_file: Path | None


@dataclass(frozen=True)
class Endpoints:
    zabbix: ZabbixEndpoint | None
    wazuh: WazuhEndpoint | None


@dataclass(frozen=True)
class LlmEndpoint:
    url: str
    api_key_file: Path
    model: str

    @property
    def chat_url(self) -> str:
        return f"{self.url}/chat/completions"

    @property
    def models_url(self) -> str:
        return f"{self.url}/models"

    @property
    def health_url(self) -> str:
        """Open WebUI の /health。認証がいらない。URL の末尾が /openai なら、その手前が根。"""
        root = self.url[:-len("/openai")] if self.url.endswith("/openai") else self.url
        return f"{root}/health"


def _url(env: Mapping[str, str], name: str, schemes: tuple[str, ...]) -> str | None:
    """URL を確かめて返す。誤りの表示に値は出さない。値に秘密が混ざっていても漏らさないため。"""
    value = env.get(name, "").strip()
    if not value:
        return None
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise EndpointError(f"{name} を URL として読めない") from None
    if parts.scheme not in schemes or not parts.hostname:
        raise EndpointError(f"{name} は {' か '.join(schemes)} で始まる URL で書く")
    if parts.username is not None or parts.password is not None:
        raise EndpointError(f"{name} に利用者名やパスワードを書かない。秘密はファイルで渡す")
    if parts.query or parts.fragment:
        raise EndpointError(f"{name} に ? と # を書かない")
    if port == 0:
        raise EndpointError(f"{name} のポートは 1 から 65535 で書く")
    return value.rstrip("/")


def _path(env: Mapping[str, str], name: str, default: str | None) -> Path | None:
    value = env.get(name, "").strip() or default
    return Path(value) if value else None


def load_endpoints(env: Mapping[str, str] | None = None) -> Endpoints:
    """URL のない系統は収集しない。Wazuh は利用者名とパスワードを送るので https に限る。"""
    env = os.environ if env is None else env
    zabbix_url = _url(env, "TIA_ZABBIX_URL", ("http", "https"))
    wazuh_url = _url(env, "TIA_WAZUH_URL", ("https",))
    zabbix = None
    if zabbix_url:
        zabbix = ZabbixEndpoint(zabbix_url, _path(env, "TIA_ZABBIX_TOKEN_FILE", DEFAULT_ZABBIX_TOKEN_FILE))
    wazuh = None
    if wazuh_url:
        user = env.get("TIA_WAZUH_USER", "").strip() or DEFAULT_WAZUH_USER
        if ":" in user or not user.isprintable():
            raise EndpointError("TIA_WAZUH_USER に : と制御文字を書かない")
        wazuh = WazuhEndpoint(wazuh_url, user, _path(env, "TIA_WAZUH_PASSWORD_FILE", DEFAULT_WAZUH_PASSWORD_FILE),
                              _path(env, "TIA_WAZUH_CA_FILE", None))
    return Endpoints(zabbix, wazuh)


def load_llm_endpoint(env: Mapping[str, str] | None = None, *, model: str = "example/model-27b") -> LlmEndpoint:
    """LLM の接続先。TIA_LLM_URL がなければ既定の宛先を使う。モデル名は TIA_LLM_MODEL で設定を上書きできる。"""
    env = os.environ if env is None else env
    url = _url(env, "TIA_LLM_URL", ("http", "https")) or DEFAULT_LLM_URL
    name = env.get("TIA_LLM_MODEL", "").strip() or model
    if not name.isprintable() or " " in name:
        raise EndpointError("TIA_LLM_MODEL に空白と制御文字を書かない")
    key_file = _path(env, "TIA_LLM_API_KEY_FILE", DEFAULT_LLM_API_KEY_FILE)
    assert key_file is not None
    return LlmEndpoint(url, key_file, name)
