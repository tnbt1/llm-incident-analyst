"""秘密の検査。値はすべてテスト用に作ったもので、本物の秘密ではない。

検査は、束の生成と同じ順で行う（無害化の後の文を調べる）。
"""
import hashlib

import pytest

from tia.knowledge import safety
from tia.knowledge.safety import SecretFound, line_digest, neutralise, scan_secrets

VALUE = "Xk9mQ2vLp7w"
HEX64 = "3f9a1c0b7e2d4f6a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a"
BCRYPT = "$2a$14$Zkx1a9Qm3pLr8vN2bT5yUeWq7sD4fG6hJ8kL0zX2cV4bN6mQ8wE0y"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
BASE64_KEY = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="

# (名前, 文, 見つかる行)。文が複数の行のときは、値のある行を指す。
FOUND = [
    # 日本語の見出し語と区切り
    ("japanese password", f"パスワード: Xk9#mQ2vLp7w", 1),
    ("japanese token", f"トークン: {HEX64}", 1),
    ("japanese token in prose", f"Zabbix の API トークンは {HEX64} を使う", 1),
    ("password wa", f"password は {VALUE}", 1),
    ("fullwidth colon", f"password\uff1a {VALUE}", 1),
    ("fullwidth letters", f"\uff50\uff41\uff53\uff53\uff57\uff4f\uff52\uff44: {VALUE}", 1),
    ("nbsp after colon", f"password:\u00a0{VALUE}", 1),
    ("wide space after colon", f"password:\u3000{VALUE}", 1),
    ("arrow", f"password -> {VALUE}", 1),
    # 囲みと表
    ("backticks", f"password: `{VALUE}`", 1),
    ("bold", f"password: **{VALUE}**", 1),
    ("table cell", f"| password | {VALUE} |", 1),
    ("table cell in backticks", f"| password | `{VALUE}` |", 1),
    ("table column", f"| 利用者 | パスワード |\n|---|---|\n| wazuh-wui | Xk9#mQ2vLp7w |", 3),
    ("table column of tokens", f"| 用途 | トークン | 備考 |\n|---|---|---|\n| analyzer | {HEX64} | 読み取り専用 |", 3),
    # 値の字種
    ("value with dollar", "password: Pa$$w0rd1234", 1),
    ("value with angle", "password: Pa<w0rd1234>", 1),
    ("value with brace", "password: Pa{w0rd1234", 1),
    ("value in parentheses", f"password: ({VALUE})", 1),
    ("value after comma", f"password: ,{VALUE}", 1),
    ("value after semicolon", f"PASSWORD=;{VALUE}", 1),
    ("quoted value with a space", 'MYSQL_ROOT_PASSWORD: "Xk9 mQ2vLp7w"', 1),
    ("words as a value", "password: my secret pass", 1),
    ("short value", "password: abc12", 1),
    ("numeric value", "password: 12345678", 1),
    ("value like a date", "password: 2026-09-29", 1),
    ("value like an address", "password: 192.0.2.7", 1),
    ("value like a path", f"password: /{VALUE}", 1),
    ("value like a url", f"password: x://{VALUE}", 1),
    ("value with katakana", "password: パスワード123abc", 1),
    ("base64 value", "  password: WGs5bVEydkxwN3daeg==", 1),
    # 名前
    ("env list", f"      - MYSQL_ROOT_PASSWORD={VALUE}", 1),
    ("env map", f"      MYSQL_ROOT_PASSWORD: {VALUE}", 1),
    ("indexer password", "INDEXER_PASSWORD=Xk9#mQ2vLp7w", 1),
    ("export with spaces", f"export ZBX_PASS = '{VALUE}'", 1),
    ("PASS", f"PASS={VALUE}", 1),
    ("authd.pass", f"authd.pass: {VALUE}", 1),
    ("passphrase", f"passphrase: {VALUE}", 1),
    ("credentials", f"credentials: {VALUE}", 1),
    ("auth", f"auth: {VALUE}", 1),
    ("key", f"key: {VALUE}{VALUE}", 1),
    ("apikey", f"apikey: {VALUE}{VALUE}", 1),
    ("secret", f"secret = {VALUE}Zz", 1),
    ("aws secret", "aws_secret_access_key = wJalrXUtnFEMIbPxRfiCYzEXAMPLEKEYabcdEFGH", 1),
    ("json password", f'{{"username": "admin", "password": "{VALUE}"}}', 1),
    ("json pass", f'{{"user": "admin", "pass": "{VALUE}"}}', 1),
    ("json auth", f'{{"jsonrpc":"2.0","method":"host.get","auth":"{HEX64}","id":1}}', 1),
    ("zabbix token assignment", f"ZABBIX_API_TOKEN={HEX64}", 1),
    ("token and a hex value", "token 3f9a1c0b7e2d4f6a8b9c0d1e2f3a4b5c6d7e8f9a", 1),
    ("wireguard private key", f"PrivateKey = {BASE64_KEY}", 1),
    ("wireguard preshared key", f"PresharedKey = {BASE64_KEY}", 1),
    ("ipsec psk", f': PSK "{VALUE}Zz"', 1),
    ("ipsec secrets", f'10.0.0.1 10.0.0.2 : PSK "{VALUE}Zz"', 1),
    ("zabbix psk", "TLSPSK=1f2e3d4c5b6a79880f1e2d3c4b5a69781f2e3d4c5b6a79880f1e2d3c4b5a6978", 1),
    ("game password", f"ServerAdminPassword={VALUE}", 1),
    ("game arguments", f"?ServerPassword={VALUE}?ServerAdminPassword=Zz9mQ2vLp7w", 1),
    ("xml value", f'<property name="ServerPassword" value="{VALUE}"/>', 1),
    ("xml telnet value", f'<property name="TelnetPassword" value="{VALUE}"/>', 1),
    ("login line", f"login: admin / {VALUE}", 1),
    # コマンドの引数
    ("curl -u", f"curl -k -u admin:{VALUE} https://192.0.2.7:9200/_cat/indices", 1),
    ("curl --user", f"curl --user analyzer_ro:{VALUE} https://192.0.2.7:9200", 1),
    ("mysql -p", f"mysql -uroot -p{VALUE} zabbix", 1),
    ("mysql --password=", f"mysql -uroot --password={VALUE} zabbix", 1),
    ("--password and a space", f"zabbix_get --user admin --password {VALUE}", 1),
    ("sshpass", f"sshpass -p '{VALUE}' ssh user@192.0.2.7", 1),
    ("docker login", f"docker login -u alice -p {VALUE} registry.local", 1),
    ("netrc", f"machine 192.0.2.7 login admin password {VALUE}", 1),
    ("base64 -d", "echo WGs5bVEydkxwN3daeg== | base64 -d", 1),
    # ハッシュ
    ("bcrypt in a Caddyfile", f"basicauth {{ alice {BCRYPT} }}", 1),
    ("bcrypt on its own", f"    alice {BCRYPT}", 1),
    ("bcrypt in the environment", f"BASIC_AUTH_HASH={BCRYPT}", 1),
    ("bcrypt as base64", "alice JDJhJDE0JFpreDFhOVFtM3BMcjh2TjJiVDV5VWVXcTdzRDRmRzZoSjhrTDB6WDJjVjRiTjZtUTh3RTB5", 1),
    ("apr1", "alice:$apr1$abcdefgh$ABCDEFGHIJKLMNOPQRSTUV", 1),
    ("sha512 crypt", "root:$6$rounds=5000$saltsalt$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./abcdefghijklmnopqrstuv:19000:0:99999:7:::", 1),
    # 決まった形のトークン
    ("tailscale key", "tailscale up --authkey tskey-auth-kABC123CNTRL-abcdefghijklmnopqrstuvwxyz123456", 1),
    ("tailscale key assignment", "TS_AUTHKEY=tskey-auth-kABC123CNTRL-abcdefghijklmnopqrstuvwxyz123456", 1),
    ("tailscale client key", "tskey-client-kABC123CNTRL-abcdefghijklmnopqrstuvwxyz123456", 1),
    ("jwt", JWT, 1),
    ("jwt in a header", f"curl -H 'Authorization: Bearer {JWT}'", 1),
    ("bearer and a hex value", f'curl -H "Authorization: Bearer {HEX64}" https://x/api_jsonrpc.php', 1),
    ("basic", "Authorization: Basic YWRtaW46WGs5bVEydkxwN3c=", 1),
    ("wazuh agent key", f"001 agent01 192.0.2.6 {HEX64}", 1),
    ("k3s token", "K10abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789::server:abcdef0123456789abcdef0123456789", 1),
    ("k3s token assignment", "K3S_TOKEN=K10abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789::server:abcdef0123456789abcdef0123456789", 1),
    ("google api key", "AIzaSyA1234567890abcdefghijklmnopqrstuvw", 1),
    ("slack webhook", "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX", 1),
    ("discord webhook", "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd", 1),
    ("steam token", "+sv_setsteamaccount 0123456789ABCDEF0123456789ABCDEF", 1),
    # URL
    ("url password", f"https://admin:{VALUE}@192.0.2.7:9200/", 1),
    ("url password with a slash", "https://admin:Xk9/Q2vLp7w@192.0.2.7:9200/", 1),
    ("url password with a percent", "mysql://zabbix:Xk9%40Q2vLp7w@db/zabbix", 1),
    # 鍵
    ("openssh key", "-----BEGIN OPENSSH PRIVATE KEY-----", 1),
    ("rsa key", "-----BEGIN RSA PRIVATE KEY-----", 1),
    ("encrypted key", "-----BEGIN ENCRYPTED PRIVATE KEY-----", 1),
    ("pgp key", "-----BEGIN PGP PRIVATE KEY BLOCK-----", 1),
    ("key in lower case", "-----begin openssh private key-----", 1),
    ("key with four dashes", "----BEGIN OPENSSH PRIVATE KEY----", 1),
    ("ssh2 armour", "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----", 1),
    ("indented key", "    -----BEGIN OPENSSH PRIVATE KEY-----", 1),
    ("putty key", "PuTTY-User-Key-File-3: ssh-ed25519", 1),
    ("putty private lines", "Private-Lines: 1", 1),
    ("body of a key", "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACD", 1),
    ("key in a json value", '"private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC"', 1),
    # 次の行の値
    ("value on the next line", f"password:\n  {VALUE}", 2),
    ("block value", f"password: |\n  {VALUE}", 2),
    ("folded block value", f"MYSQL_PASSWORD: >-\n    {VALUE}", 2),
    ("continued command", f"zabbix_get --password \\\n  {VALUE}", 2),
    # 見えない文字で切った名前と値
    ("zero width space in the name", f"pass\u200bword: {VALUE}", 1),
    ("soft hyphen in the name", f"pass\u00adword: {VALUE}", 1),
    ("variation selector in the name", f"pass\ufe0fword: {VALUE}", 1),
    ("tag character in the name", f"pass\U000e0041word: {VALUE}", 1),
    ("soft hyphen in a token", "tskey-auth-kABC123CNTRL-abcdefgh\u00adijklmnopqrstuvwxyz123456", 1),
]

PASSED = [
    ("nsswitch", "passwd:         compat systemd"),
    ("nsswitch files", "passwd: files systemd"),
    ("getent", "getent passwd: llm-tunnel"),
    ("token type", "token_type: Bearer"),
    ("token expiry", "token_expiry: 2026-12-31"),
    ("token ttl", "token_ttl: 24h"),
    ("max tokens", "max_tokens: 1200"),
    ("count of tokens", "トークン: 44,513"),
    ("tokens", "tokens=44513"),
    ("secret name", "secretName: zabbix-tls"),
    ("secret key ref", "secretKeyRef: {name: db, key: password}"),
    ("password policy", "password_min_length: 12"),
    ("password hash algorithm", "password_hash: bcrypt"),
    ("token disabled", "token=disabled"),
    ("psk enabled", "psk: enabled"),
    ("secret enable", "secret: enable"),
    ("redacted", "password: REDACTED"),
    ("redacted in brackets", "password: [REDACTED]"),
    ("masked with stars", "password: ********"),
    ("masked with x", "password: xxxxxxxx"),
    ("masked in groups", "password: XXXX-XXXX-XXXX"),
    ("masked in japanese", "password: \uff08伏せ字\uff09"),
    ("changeme", "password: changeme"),
    ("changeme in the environment", "MYSQL_ROOT_PASSWORD: changeme"),
    ("your api key", "api_key: YOUR_API_KEY"),
    ("your password", "password: YOUR_PASSWORD"),
    ("placeholder in angle brackets", "password: <パスワード>"),
    ("placeholder in ascii brackets", "password: <password>"),
    ("variable", "MYSQL_PASSWORD=${MYSQL_PASSWORD}"),
    ("plain variable", "MYSQL_PASSWORD=$MYSQL_PASSWORD"),
    ("template", 'secret: "{{ vault_secret }}"'),
    ("zabbix macro", "{$ZBX_PASSWORD}=設定済み"),
    ("yaml tag", "password: !ENV ZBX_PASS"),
    ("path to a secret file", "ZABBIX_API_TOKEN_FILE=/run/secrets/zabbix_api_token"),
    ("relative path to a secret file", "ZABBIX_API_TOKEN_FILE=secrets/zabbix_api_token"),
    ("compose secret file", "    file: secrets/zabbix_api_token"),
    ("file name as a value", "password: credentials.json"),
    ("pointer in a table", "| secret | `/opt/monitoring-stack/credentials.json` |"),
    ("table header", "| password | 変更した日 |"),
    ("table column that points elsewhere",
     "| 利用者 | パスワード |\n|---|---|\n| wazuh-wui | `credentials.json` を参照 |\n| kuma | 別紙 |\n| zabbix | 未設定 |"),
    ("private key path", "private_key: ~/.ssh/id_ed25519"),
    ("private key file", "private_key_file: id_ed25519.key"),
    ("identity file", "IdentityFile ~/.ssh/id_ed25519"),
    ("sshd setting", "PasswordAuthentication no"),
    ("sshd grep", "sudo sshd -T | grep -Ei 'passwordauthentication|permitrootlogin'"),
    ("sshd effective setting", "passwordauthentication=no"),
    ("sshd prohibit", "PermitRootLogin: prohibit-password"),
    ("ssh option", "ssh -o PasswordAuthentication=no -o PubkeyAuthentication=yes user@host"),
    ("ssh preferred", "ssh -o PreferredAuthentications=publickey,password user@host"),
    ("docker password stdin", "docker login --password-stdin"),
    ("docker user and group", "docker run -u 1000:1000 -p 8080:80 image"),
    ("ssh port", "ssh -p 2222 user@192.0.2.7"),
    ("mkdir", "mkdir -p /opt/monitoring-stack/backups"),
    ("mysql prompt", "mysql -uroot -p zabbix"),
    ("curl with variables", "curl -u \"$USER:$PASS\" https://192.0.2.7:9200"),
    ("curl with placeholders", "curl -u <利用者>:<パスワード> https://192.0.2.7:9200"),
    ("pam", "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.44 user=root"),
    ("prose about a token", "token: 運用者が発行する"),
    ("prose about a password", "パスワード: 本人の端末にだけ表示する"),
    ("prose about a key", "秘密鍵は GPU サーバーから出さない"),
    ("bearer in prose", "Bearer トークンを使う"),
    ("basic in prose", "basic authentication is used for the dashboard"),
    ("basic and a long word", "Basic authentication_required"),
    ("bearer placeholder", "Authorization: Bearer <トークン>"),
    ("bearer variable", "Authorization: Bearer $TOKEN"),
    ("api key description", "api_key: string (required)"),
    ("code that prints", 'print("Password:", accounts[name]["password"])'),
    ("wazuh rule", "rule.id: 5710 sshd: Attempt to login using a non-existent user"),
    ("zabbix item key", "item key: vfs.fs.size[/,pused]"),
    ("pwd", "pwd: /home/alice"),
    ("PWD", "PWD=/opt/monitoring-stack"),
    ("relative pwd", "pwd=monitoring/compose"),
    ("ssh fingerprint", "ED25519 key fingerprint is SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8."),
    ("certificate fingerprint", "SHA256 Fingerprint=3F:9A:1C:0B:7E:2D:4F:6A:8B:9C:0D:1E:2F:3A:4B:5C:6D:7E:8F:9A:0B:1C:2D:3E:4F:5A:6B:7C:8D:9E:0F:1A"),
    ("host key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAookIt94wqjQlyuFnt6siusQPbu+5XNgOJJn1AhamfT"),
    ("commit hash", "参照コミット `e6ad3e7c0b7e2d4f6a8b9c0d1e2f3a4b5c6d7e8f`"),
    ("image digest", f"image: zabbix/zabbix-server-mysql@sha256:{HEX64}"),
    ("sha256 of a file", f"sha256 {HEX64}"),
    ("uuid", "volume ID: 3f9a1c0b-7e2d-4f6a-8b9c-0d1e2f3a4b5c"),
    ("cluster id", "cluster ID: 3f9a1c0b-7e2d-4f6a-8b9c-0d1e2f3a4b5c"),
    ("word that begins with sk-", "task sk-learn-based-anomaly-detection"),
    ("slug that begins with sk-", " sk-ipping-this-is-a-long-slug-here"),
    ("prose about jwt", "JWT は eyJ で始まる"),
    ("example key of aws", "AKIAIOSFODNN7EXAMPLE"),
    ("public key", "-----BEGIN PUBLIC KEY-----"),
    ("certificate", "-----BEGIN CERTIFICATE-----"),
    ("prose that quotes the armour", "`-----BEGIN OPENSSH PRIVATE KEY-----` で始まる行があれば中止する"),
    ("url without a password", "ssh://alice@192.0.2.7:22/"),
    ("scp", "scp user@host:/path/file ."),
    ("git url", "git clone https://github.com/<maintainer>/app-server.git"),
    ("port and a path", "rsync://backup:873/module@snapshot"),
    ("at sign in a query", "https://example.com:8443/path?x=a@b"),
    ("mail address after a url", "smtp://relay:587 から a@example.com へ"),
    ("proxy and a host", "http://proxy:3128 user@host"),
    ("prose cell that ends with a key word",
     "| 2026-09-20 | 拠点間 IKEv2接続、異なる2つのPSK | `docs/VPN-SETTING-EXAMPLE.md`、`SETTING.md` |"),
    ("relative path in upper case", "secret: docs/VPN-SETTING-EXAMPLE.md"),
    ("key that has no value", "password:\nusername: admin"),
    ("key followed by a heading", "password:\n\n## 次の節"),
    ("list of settings", "password:\n  min_length: 12"),
]


def _scan(text):
    cleaned, _ = neutralise(text)
    return scan_secrets("maintenance.md", cleaned)


@pytest.mark.parametrize(("name", "text", "line"), FOUND, ids=[case[0] for case in FOUND])
def test_secret_shape_is_found(name, text, line):
    findings = _scan(text)
    assert [(f.file, f.line) for f in findings] == [("maintenance.md", line)]


@pytest.mark.parametrize(("name", "text"), PASSED, ids=[case[0] for case in PASSED])
def test_harmless_shape_does_not_stop_the_build(name, text):
    assert _scan(text) == []


@pytest.mark.parametrize(("name", "text", "line"), FOUND, ids=[case[0] for case in FOUND])
def test_message_never_repeats_the_line(name, text, line):
    finding = _scan(text)[0]
    assert finding.hint in safety.HINTS.values()
    assert finding.kind in safety.KIND_LABELS
    message = str(SecretFound([finding])) + finding.hint
    cleaned = neutralise(text)[0].split("\n")[line - 1]
    for word in cleaned.replace('"', " ").replace("'", " ").replace("=", " ").replace(":", " ").split():
        if len(word) >= 5 and word.isascii():
            assert word not in message


def test_value_that_contains_a_key_word_is_not_repeated():
    text = "DB_PASS=token-Xk9mQ2vLp7wQQ=def12345"
    finding = _scan(text)[0]
    assert "Xk9mQ2vLp7wQQ" not in finding.hint and "token-" not in finding.hint
    assert "Xk9mQ2vLp7wQQ" not in str(SecretFound([finding]))


def test_block_of_a_key_is_one_finding():
    text = ("前の行\n-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACD\n"
            "password: Xk9mQ2vLp7w\n-----END OPENSSH PRIVATE KEY-----\n後の行")
    assert [(f.line, f.kind) for f in _scan(text)] == [(2, "private_key")]


def test_finding_carries_the_digest_of_its_line():
    text = "前の行\nMYSQL_PASSWORD=Xk9mQ2vLp7w\n"
    finding = _scan(text)[0]
    assert finding.digest == hashlib.sha256("MYSQL_PASSWORD=Xk9mQ2vLp7w".encode()).hexdigest()
    assert finding.digest == line_digest("MYSQL_PASSWORD=Xk9mQ2vLp7w")
    assert finding.digest not in str(SecretFound([finding]))


def test_cluster_id_is_not_a_secret():
    assert _scan("clusterid: 3f9a1c0b-7e2d-4f6a-8b9c-0d1e2f3a4b5c") == []
