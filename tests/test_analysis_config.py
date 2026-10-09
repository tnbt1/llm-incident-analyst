"""LLM、文脈、ワーカーの設定と、LLM の接続先。"""
from dataclasses import replace
from pathlib import Path

import pytest

from tia.collectors.endpoints import DEFAULT_LLM_URL, EndpointError, LlmEndpoint, load_llm_endpoint
from tia.config import Config, load_config


def test_llm_defaults_match_the_design(cfg):
    assert cfg.llm_model == "example/model-27b"
    assert cfg.llm_temperature == 0.2
    assert cfg.llm_retry_temperature == 0.0
    assert cfg.llm_max_tokens == 1200
    assert cfg.llm_timeout_sec == 240
    assert cfg.llm_connect_timeout_sec == 5
    assert cfg.llm_thinking is False
    assert cfg.llm_context_tokens == 131072
    assert cfg.context_input_budget_tokens == 15600
    assert (cfg.context_rules_budget_tokens, cfg.context_cases_budget_tokens, cfg.context_cases_max,
            cfg.context_stats_budget_tokens, cfg.context_dynamic_budget_tokens) == (500, 900, 3, 200, 5000)
    assert cfg.context_token_margin_percent == 10
    assert cfg.worker_idle_sec == 2


def test_timeout_longer_than_open_webui_allows_is_rejected():
    with pytest.raises(ValueError, match="llm.timeout_sec"):
        Config(llm_timeout_sec=300)


@pytest.mark.parametrize("name, value", [
    ("llm_temperature", 2.5), ("llm_temperature", "0.2"), ("llm_retry_temperature", -1),
    ("llm_temperature", True), ("llm_thinking", "no"), ("llm_model", ""), ("llm_model", "a b"),
    ("llm_model", "x" * 200), ("llm_max_tokens", 0), ("context_token_margin_percent", 51),
    ("context_dynamic_budget_tokens", 10),
])
def test_wrong_llm_value_names_the_key(name, value):
    with pytest.raises(ValueError, match=name.replace("_", ".", 1)):
        Config(**{name: value})


def test_input_and_output_must_fit_the_context_length():
    with pytest.raises(ValueError, match="llm.context_tokens"):
        Config(llm_context_tokens=8192, context_input_budget_tokens=8000, llm_max_tokens=1200)


def test_settings_file_holds_the_new_blocks():
    cfg = load_config(Path(__file__).resolve().parents[1] / "config" / "analyzer.yaml")
    assert cfg == Config()


def test_settings_file_accepts_the_llm_block(tmp_path):
    path = tmp_path / "a.yaml"
    path.write_text("llm:\n  model: other/model\n  thinking: true\n  timeout_sec: 120\ncontext:\n  history_max: 3\n",
                    encoding="utf-8")
    cfg = load_config(path)
    assert (cfg.llm_model, cfg.llm_thinking, cfg.llm_timeout_sec, cfg.context_history_max) == (
        "other/model", True, 120, 3)


def test_llm_endpoint_defaults_to_the_tunnel():
    endpoint = load_llm_endpoint({})
    assert endpoint == LlmEndpoint(DEFAULT_LLM_URL, Path("/run/secrets/openwebui_api_key"), "example/model-27b")
    assert endpoint.chat_url == "http://127.0.0.1:18080/openai/chat/completions"
    assert endpoint.models_url == "http://127.0.0.1:18080/openai/models"
    assert endpoint.health_url == "http://127.0.0.1:18080/health"


def test_llm_endpoint_reads_the_environment():
    endpoint = load_llm_endpoint({"TIA_LLM_URL": "http://127.0.0.1:18090/openai/", "TIA_LLM_API_KEY_FILE": "/k",
                                  "TIA_LLM_MODEL": "m/x"}, model="ignored")
    assert endpoint == LlmEndpoint("http://127.0.0.1:18090/openai", Path("/k"), "m/x")
    assert endpoint.health_url == "http://127.0.0.1:18090/health"


def test_llm_endpoint_without_openai_suffix_uses_the_url_as_root():
    endpoint = load_llm_endpoint({"TIA_LLM_URL": "http://127.0.0.1:8000/v1"})
    assert endpoint.health_url == "http://127.0.0.1:8000/v1/health"


@pytest.mark.parametrize("env", [
    {"TIA_LLM_URL": "ftp://x/openai"}, {"TIA_LLM_URL": "http://user:pw@x/openai"},
    {"TIA_LLM_URL": "http://x/openai?x=1"}, {"TIA_LLM_MODEL": "a b"},
])
def test_bad_llm_environment_is_refused_without_showing_the_value(env):
    with pytest.raises(EndpointError) as info:
        load_llm_endpoint(env)
    assert "pw" not in str(info.value)


def test_knowledge_settings_still_load_with_the_new_fields(cfg):
    assert replace(cfg, llm_timeout_sec=10).llm_timeout_sec == 10
