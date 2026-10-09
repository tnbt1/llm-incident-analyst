from pathlib import Path

import pytest

from tia.collectors.endpoints import EndpointError, load_endpoints


def test_nothing_is_collected_without_urls():
    endpoints = load_endpoints({})
    assert endpoints.zabbix is None
    assert endpoints.wazuh is None


def test_defaults_point_at_the_compose_secrets():
    endpoints = load_endpoints({"TIA_ZABBIX_URL": "http://zabbix-web-apache-mysql:8080/api_jsonrpc.php",
                                "TIA_WAZUH_URL": "https://wazuh.indexer:9200/"})
    assert endpoints.zabbix.url == "http://zabbix-web-apache-mysql:8080/api_jsonrpc.php"
    assert endpoints.zabbix.token_file == Path("/run/secrets/zabbix_api_token")
    assert endpoints.wazuh.url == "https://wazuh.indexer:9200"
    assert endpoints.wazuh.user == "analyzer_ro"
    assert endpoints.wazuh.password_file == Path("/run/secrets/wazuh_indexer_password")
    assert endpoints.wazuh.ca_file is None


def test_files_and_user_can_be_set():
    endpoints = load_endpoints({"TIA_ZABBIX_URL": "https://zabbix.example/api_jsonrpc.php",
                                "TIA_ZABBIX_TOKEN_FILE": "/tmp/t", "TIA_WAZUH_URL": "https://indexer:9200",
                                "TIA_WAZUH_USER": "reader", "TIA_WAZUH_PASSWORD_FILE": "/tmp/p",
                                "TIA_WAZUH_CA_FILE": "/config/root-ca.pem"})
    assert endpoints.zabbix.token_file == Path("/tmp/t")
    assert endpoints.wazuh.user == "reader"
    assert endpoints.wazuh.password_file == Path("/tmp/p")
    assert endpoints.wazuh.ca_file == Path("/config/root-ca.pem")


def test_only_one_source_can_be_set():
    endpoints = load_endpoints({"TIA_WAZUH_URL": "https://wazuh.indexer:9200"})
    assert endpoints.zabbix is None
    assert endpoints.wazuh is not None


@pytest.mark.parametrize(("name", "value"), [
    ("TIA_ZABBIX_URL", "zabbix-web:8080"),
    ("TIA_ZABBIX_URL", "ftp://zabbix/api_jsonrpc.php"),
    ("TIA_ZABBIX_URL", "http:///api_jsonrpc.php"),
    ("TIA_ZABBIX_URL", "http://zabbix/api_jsonrpc.php?auth=1"),
    ("TIA_ZABBIX_URL", "http://zabbix/api_jsonrpc.php#x"),
    ("TIA_ZABBIX_URL", "http://zabbix:99999/api_jsonrpc.php"),
    ("TIA_ZABBIX_URL", "http://zabbix:0/api_jsonrpc.php"),
    ("TIA_WAZUH_URL", "http://wazuh.indexer:9200"),
])
def test_wrong_url_is_rejected_with_the_name(name, value):
    with pytest.raises(EndpointError, match=name):
        load_endpoints({name: value})


def test_url_with_a_password_is_rejected_without_showing_it():
    with pytest.raises(EndpointError) as caught:
        load_endpoints({"TIA_WAZUH_URL": "https://reader:s3cret-value@wazuh.indexer:9200"})
    assert "TIA_WAZUH_URL" in str(caught.value)
    assert "s3cret-value" not in str(caught.value)


@pytest.mark.parametrize("user", ["a:b", "a\nb"])
def test_wrong_user_is_rejected(user):
    with pytest.raises(EndpointError, match="TIA_WAZUH_USER"):
        load_endpoints({"TIA_WAZUH_URL": "https://wazuh.indexer:9200", "TIA_WAZUH_USER": user})
