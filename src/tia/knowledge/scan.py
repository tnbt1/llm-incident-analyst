"""秘密の形をした文字列の検査。束は LLM に渡り、画面にも出る。見つけた値そのものは、どこにも出さない。

調べるのは 1 行ずつ。表の見出しと、名前の次の行にある値だけは、前後の行も見る。
名前は 2 つに分ける。人が値を決める名前（password など）は、短い値や数字だけの値も秘密として数える。
機械が値を作る名前（token、secret など）は、長さと字種のある値だけを数える。
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass

KIND_LABELS = {"private_key": "秘密鍵", "token": "トークン", "bearer": "認証ヘッダー", "credential": "パスワードや鍵の値",
               "hash": "パスワードのハッシュ"}
# 見つけた規則の名前。文書の行からは 1 文字も取らない。値や名前を、表示や記録に繰り返さないため。
HINTS = {
    "key_block": "秘密鍵のブロック",
    "token": "トークンの形",
    "bearer": "認証ヘッダーの値",
    "assignment": "名前と値の組",
    "table": "表の列の値",
    "next_line": "名前の次の行の値",
    "argument": "コマンドの引数",
    "url": "URL の中のパスワード",
    "hash": "パスワードのハッシュ",
    "encoded": "符号化した値",
}
MAX_SCANNED_LINE = 100_000
MAX_KEY_BLOCK_LINES = 400
MAX_VALUE = 400

_ARMOUR = re.compile(r"-{4,5} ?BEGIN (?:[A-Z0-9]{1,20} ){0,4}PRIVATE KEY(?: BLOCK)? ?-{4,5}", re.IGNORECASE)
_ARMOUR_END = re.compile(r"-{4,5} ?END (?:[A-Z0-9]{1,20} ){0,4}PRIVATE KEY(?: BLOCK)? ?-{4,5}", re.IGNORECASE)
_ARMOUR_BODY = re.compile(r"""(?:\\[nr]|[\s"'])*[A-Za-z0-9+/]{20}""")
_BASE64_LINE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_PUTTY = re.compile(r"PuTTY-User-Key-File-[0-9]{1,2}:|Private-Lines:[ \t]{0,8}[0-9]{1,6}[ \t]*$")
_KEY_BODY = re.compile(r"(?<![A-Za-z0-9+/])b3BlbnNzaC1rZXktdjE[A-Za-z0-9+/]{20}")
_TOKENS = re.compile(
    r"(?<![A-Za-z0-9_-])(?:"
    r"tskey-[A-Za-z0-9]+-[A-Za-z0-9-]{8,}"
    r"|gh[pousr]_[A-Za-z0-9]{30,}"
    r"|github_pat_[A-Za-z0-9_]{30,}"
    r"|glpat-[A-Za-z0-9_-]{20,}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|sk-(?=[A-Za-z_-]{0,80}[0-9])[A-Za-z0-9_-]{20,}"
    r"|AIza[0-9A-Za-z_-]{30,40}"
    r"|K10[0-9a-f]{40,80}::[a-z]{1,20}:[0-9a-f]{16,80}"
    r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r")")
_WEBHOOKS = re.compile(
    r"hooks\.slack\.com/services/T[A-Za-z0-9]{6,16}/B[A-Za-z0-9]{6,16}/[A-Za-z0-9]{16,64}"
    r"|discord(?:app)?\.com/api/webhooks/[0-9]{10,24}/[A-Za-z0-9_-]{30,100}"
    r"|sv_setsteamaccount[ \t]{1,8}[0-9A-Fa-f]{32}(?![0-9A-Fa-f])")
_AGENT_KEY = re.compile(r"[ \t]{0,8}[0-9]{3,6}[ \t]{1,8}[^\s]{1,64}[ \t]{1,8}(?:any|[0-9A-Fa-f.:/]{3,45})[ \t]{1,8}"
                        r"[0-9a-f]{64}[ \t]*$")
_HASHES = re.compile(
    r"\$2[abxy]?\$[0-9]{2}\$[./A-Za-z0-9]{40,60}"
    r"|\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}"
    r"|\$[156]\$(?:rounds=[0-9]{1,9}\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{22,86}"
    r"|\$y\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{1,86}\$[./A-Za-z0-9]{43}"
    r"|\$argon2(?:id|i|d)\$[^\s$]{1,40}\$[^\s$]{1,60}\$[A-Za-z0-9+/]{8,64}\$[A-Za-z0-9+/]{16,128}"
    r"|(?<![A-Za-z0-9+/])JDJ[hi5]J[A-Za-z0-9+/]{60,120}")
_BEARER = re.compile(r"(?<![A-Za-z0-9])bearer[ \t]{1,8}([A-Za-z0-9._~+/=-]{16,})", re.IGNORECASE)
_BASIC = re.compile(r"(?<![A-Za-z0-9])basic[ \t]{1,8}([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9_+/=-])", re.IGNORECASE)
_URL_PASSWORD = re.compile(r"[A-Za-z][A-Za-z0-9+.-]{1,15}://[^\s/:@]{1,64}:([^\s:@]{3,128})@[A-Za-z0-9\[]")
_PORT_AND_PATH = re.compile(r"[0-9]{1,5}(?:/|$)")
_USER_OPTION = re.compile(r"""(?<![A-Za-z0-9-])(?:-u|--user)(?:[ \t]{1,8}|=)["']?([^\s:"']{1,64}):([^\s"']{3,128})""")
_MYSQL = re.compile(r"(?<![A-Za-z0-9_-])(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)(?![A-Za-z0-9_-])"
                    r"[^\n|;&]{0,200}?[ \t]-p([^\s]{3,128})")
_SSHPASS = re.compile(r"""(?<![A-Za-z0-9_-])sshpass[ \t]{1,8}-p[ \t]{0,8}["']?([^\s"']{3,128})""")
_DOCKER_LOGIN = re.compile(r"""(?<![A-Za-z0-9_-])docker[ \t]{1,8}login(?![A-Za-z0-9_-])[^\n|;&]{0,200}?"""
                           r"""[ \t]-p[ \t]{1,8}"""
                           r"""["']?([^\s"']{3,128})""")
_NETRC = re.compile(r"(?<![A-Za-z0-9_-])machine[ \t]{1,8}[^\s]{1,128}[ \t]{1,8}login[ \t]{1,8}[^\s]{1,128}[ \t]{1,8}"
                    r"password[ \t]{1,8}([^\s]{3,128})")
_DECODED = re.compile(r"""echo[ \t]{1,8}(?:-n[ \t]{1,8})?["']?([A-Za-z0-9+/]{12,512}={0,2})["']?"""
                      r"""[ \t]{0,8}\|[ \t]{0,8}"""
                      r"""base64[ \t]{1,8}(?:-d|-D|--decode)(?![A-Za-z0-9-])""")
_LOGIN_PAIR = re.compile(r"(?<![A-Za-z0-9_.-])(?:login|user|username|account)[ \t]{0,8}[:=][ \t]{0,8}[^\s/]{1,64}"
                         r"[ \t]{0,4}/[ \t]{0,4}([^\s]{6,128})", re.IGNORECASE)
_XML_VALUE = re.compile(r"""(?<![A-Za-z0-9_-])name[ \t]{0,4}=[ \t]{0,4}["']([^"'\n]{1,80})["'][^<>\n]{0,40}?"""
                        r"""(?<![A-Za-z0-9_-])value[ \t]{0,4}=[ \t]{0,4}["']([^"'\n]{1,200})["']""", re.IGNORECASE)

# 名前の中の言葉。長いものを先に並べる。短い言葉は、名前の部品の全体に当たるときだけ数える。
_LONG_WORDS = ("passphrase", "password", "passwd", "preshared_key", "preshared-key", "presharedkey", "private_key",
               "private-key", "privatekey", "access_key", "access-key", "accesskey", "auth_key", "auth-key", "authkey",
               "api_key", "api-key", "apikey", "credentials", "credential", "secret", "token")
_SHORT_WORDS = ("tlspsk", "pass", "auth", "psk", "pwd", "key")
_JAPANESE_WORDS = ("パスワード", "パスフレーズ", "合言葉", "暗証番号", "トークン", "秘密鍵", "シークレット")
_KEY_WORD = re.compile("|".join(re.escape(word) for word in (*_JAPANESE_WORDS, *_LONG_WORDS, *_SHORT_WORDS)),
                       re.IGNORECASE)
# 人が決める値を持つ名前。短い値や数字だけの値も、秘密として数える
_HUMAN_WORDS = frozenset({"password", "passphrase", "pass", "パスワード", "パスフレーズ", "合言葉", "暗証番号"})
_GENERIC_WORDS = frozenset({"key"})
GENERIC_MIN_LENGTH = 20
BARE_MIN_LENGTH = 20
STRONG_MIN_LENGTH = 8
WEAK_MIN_LENGTH = 4
IDENT_LIMIT = 40
_IDENT = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
# 名前の後ろに付いて、値が秘密そのものではないことを表す言葉。`token_expiry`、`password_file` など
_DESCRIBES = frozenset({
    "file", "files", "path", "dir", "name", "names", "ref", "refs", "type", "types", "expiry", "expires", "expire",
    "expiration", "ttl", "url", "uri", "hash", "hashed", "algo", "algorithm", "length", "len", "min", "max",
    "policy", "required", "enabled", "disabled", "authentication", "stdin", "prompt", "field", "column", "header",
    "id", "ids", "count", "limit", "size", "age", "days", "lifetime", "timeout", "format", "encoding", "mode",
    "source", "location", "endpoint", "command", "cmd", "version", "rotation", "rotate", "reset", "change", "changed",
    "update", "updated", "check", "strength", "complexity", "history", "retry", "retries", "attempts", "error",
    "errors", "failed", "failure", "s", "es",
})
_NOT_A_VALUE = frozenset({
    "true", "false", "yes", "no", "none", "null", "nil", "required", "optional", "enabled", "disabled", "enable",
    "disable", "on", "off", "string", "str", "int", "integer", "bool", "boolean", "text", "number", "redacted",
    "masked", "hidden", "removed", "changeme", "change_me", "change-me", "example", "sample", "dummy", "placeholder",
    "todo", "tbd", "unset", "empty", "default", "bcrypt", "sha256", "sha512", "md5", "argon2", "scrypt", "pbkdf2",
    "bearer", "basic", "digest", "password", "secret", "token", "prohibit-password",
})
_MASK = re.compile(r"[*xX•●#._-]+")
_WRAPPED = re.compile(r"<[^<>]{0,200}>|\$\{[^{}]{0,200}\}|\$[A-Za-z_][A-Za-z0-9_]{0,80}|\{\{[^{}]{0,200}\}\}"
                      r"|\{\$[^{}]{0,200}\}|%[A-Za-z_][A-Za-z0-9_]{0,80}%|\[[^\[\]]{0,200}\]")
_YAML_TAG = re.compile(r"![A-Za-z][A-Za-z0-9_/-]{0,40}(?:[ \t]|$)")
_YOURS = re.compile(r"(?:your|my|the|some|insert|enter|put)[_-][A-Za-z0-9_-]{1,80}", re.IGNORECASE)
_HIRAGANA = re.compile(r"[ぁ-ゖ]")
_FILE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,80}\.(?:json|ya?ml|txt|key|pem|crt|cer|conf|cfg|ini|env|md|sh|py|sql|csv|log"
                        r"|toml|xml|html|gz|tar|zip|bak|pub|service)")
_PLAIN_PATH = re.compile(r"[a-z0-9._~-]{1,80}(?:/[a-z0-9._~-]{0,80}){1,20}")
_SEGMENT = re.compile(r"[^/]+")
_PASSWORD_CHARACTERS = re.compile(r"[!#-&*+\--:=?-Z\\^_a-z|~]+")   # 引用符、かっこ、コンマ、セミコロンを除いた ASCII
_EDGE = "()[]{}<>,;\"'`*、。「」"
_JAPANESE_END = re.compile(r"[、。」]")
_BLOCK_MARK = frozenset({"|", ">", "|-", ">-", "|+", ">+", "\\"})
_ASSIGNMENT = re.compile(r"""[ \t-]{0,40}["']?[A-Za-z0-9_.぀-ヿ一-鿿-]{1,80}["']?[ \t]{0,8}[:=](?:[ \t]|$)""")
_RULE_ROW = re.compile(r"[ \t]{0,8}\|?[ \t:|-]{0,2000}-[ \t:|-]{0,2000}\|[ \t:|-]{0,2000}$")


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    kind: str
    hint: str
    digest: str = ""


class SecretFound(ValueError):
    """文書に、鍵やパスワードの形をした文字列がある。値は載せない。"""

    def __init__(self, findings: list[Finding]):
        self.findings = list(findings)
        places = "、".join(f"{f.file}:{f.line} {KIND_LABELS.get(f.kind, f.kind)}" for f in self.findings)
        super().__init__(f"文書に秘密の形をした文字列がある: {places}")


def line_digest(line: str) -> str:
    """許可の一覧で行を指すための値。検査した行（無害化の後）の SHA-256。"""
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def _classes(value: str) -> int:
    return (any("a" <= c <= "z" for c in value) + any("A" <= c <= "Z" for c in value)
            + any("0" <= c <= "9" for c in value))


def _is_placeholder(value: str) -> bool:
    """伏せ字、変数の参照、設定の言葉。値の全体がその形のときだけ当てはまる。"""
    if not value or _MASK.fullmatch(value) or _WRAPPED.fullmatch(value) or _YOURS.fullmatch(value):
        return True
    return value.lower() in _NOT_A_VALUE or _YAML_TAG.match(value) is not None


def _points_elsewhere(value: str) -> bool:
    """場所やファイルの名前か。でたらめな部分（大文字、小文字、数字が全部ある）を持つものは、場所とみなさない。"""
    looks = (value.startswith(("/", "./", "../", "~/")) or "://" in value
             or _FILE_NAME.fullmatch(value.rsplit("/", 1)[-1]) is not None or _PLAIN_PATH.fullmatch(value) is not None)
    if not looks:
        return False
    return not any(len(part) >= STRONG_MIN_LENGTH and _classes(part) == 3 for part in _SEGMENT.findall(value))


def _core(token: str) -> str:
    return token.strip(_EDGE)


def _is_strong(token: str, minimum: int = STRONG_MIN_LENGTH) -> bool:
    """機械が作った値に見えるか。長さがあり、大文字、小文字、数字のうち 2 種類以上を含む。"""
    core = _core(token)
    if len(core) < minimum or len(core) > MAX_VALUE or not core.isascii():
        return False
    return _classes(core) >= 2 and not _is_placeholder(core) and not _points_elsewhere(core)


def _is_weak(value: str, *, words: bool) -> bool:
    """人が決めた値に見えるか。短い値、数字だけの値、言葉を並べた値。文や、場所を指す値は数えない。"""
    if _HIRAGANA.search(value) or _is_placeholder(value) or _points_elsewhere(value):
        return False
    letters = sum(1 for c in value if c.isascii() and c.isalnum())
    if letters < WEAK_MIN_LENGTH:
        return False
    parts = value.split()
    if len(parts) > 1 and not words:
        return False
    return all(_PASSWORD_CHARACTERS.fullmatch(part) or not part.isascii() for part in parts) \
        and not any(_is_placeholder(part) for part in parts[:1])


def _judge(value: str, *, quoted: bool, human: bool, explicit: bool, minimum: int = STRONG_MIN_LENGTH) -> bool:
    """名前の後ろの値が、秘密に見えるか。"""
    value = value.strip()
    if not value or _is_placeholder(value) or _is_placeholder(_core(value)):
        return False
    parts = value.split()
    candidates = parts if quoted else parts[:1]
    if any(_is_strong(part, minimum) for part in candidates):
        return True
    if not (human and explicit):
        return False
    if quoted or len(parts) == 1:
        return _is_weak(value if quoted else parts[0], words=quoted)
    first = _JAPANESE_END.split(parts[0])[0]
    if _is_weak(first, words=False):
        return True
    return first.isascii() and all(part.isascii() for part in parts) and len(value) >= STRONG_MIN_LENGTH \
        and _is_weak(value, words=True)


@dataclass(frozen=True)
class _Key:
    start: int        # 名前の始まりの位置
    end: int          # 名前の終わりの位置
    human: bool
    generic: bool
    option: bool


def _boundary(text: str, left: int, right: int) -> bool:
    """`left` と `right` の間が、名前の部品の切れ目か。"""
    if left < 0 or right >= len(text):
        return True
    before, after = text[left], text[right]
    if before not in _IDENT or after not in _IDENT or before in "_.-" or after in "_.-":
        return True
    return (before.islower() or before.isdigit()) and after.isupper()


def _describes(tail: str) -> bool:
    """名前の残りが、値の説明（`_file`、`Name`、`s` など）か。"""
    tail = tail.lstrip("_.-")
    if not tail:
        return False
    parts = re.findall(r"[A-Z]?[a-z0-9]+|[A-Z0-9]+", tail)
    if not parts:
        return False
    lowered = tail.lower()
    return parts[-1].lower() in _DESCRIBES or any(lowered.startswith(word) for word in ("authentication", "stdin"))


def _keys(line: str) -> Iterator[_Key]:
    for match in _KEY_WORD.finditer(line):
        word = match.group(0)
        if not word.isascii():
            yield _Key(match.start(), match.end(), word in _HUMAN_WORDS, False, False)
            continue
        start, end = match.start(), match.end()
        lowered = word.lower().replace("_", "").replace("-", "")
        if word.lower() in _SHORT_WORDS and not (_boundary(line, start - 1, start)
                                                 and _boundary(line, end - 1, end)):
            continue   # `bypass` や `PreferredAuthentications` の一部
        first = start
        while first > 0 and start - first < IDENT_LIMIT and line[first - 1] in _IDENT:
            first -= 1
        last = end
        while last < len(line) and last - end < IDENT_LIMIT and line[last] in _IDENT:
            last += 1
        tail = line[end:last].rstrip(".-")
        if _describes(tail):
            continue
        yield _Key(first, end + len(tail), lowered in _HUMAN_WORDS, lowered in _GENERIC_WORDS,
                   line[first:start].startswith("-") or (first > 0 and line[first:first + 1] == "-"))


def _skip(line: str, position: int, characters: str, limit: int = IDENT_LIMIT) -> int:
    end = min(len(line), position + limit)
    while position < end and line[position] in characters:
        position += 1
    return position


def _value_after(line: str, position: int, *, cell: bool) -> tuple[str, bool]:
    """位置から後ろの値と、囲まれていたか。"""
    rest = line[position:position + MAX_VALUE]
    if rest.startswith("**"):
        rest = rest[2:]
        close = rest.find("**")
        return (rest[:close] if close >= 0 else rest.split(" ")[0]), False
    if rest[:1] in ("\"", "'", "`"):
        close = rest.find(rest[0], 1)
        if close > 0:
            return rest[1:close], True
        rest = rest[1:]
    if cell:
        rest = rest.split("|")[0]
        if rest.strip().startswith("`") and rest.strip().endswith("`") and len(rest.strip()) > 2:
            return rest.strip()[1:-1], True
    rest = _JAPANESE_END.split(rest.split(" #")[0])[0]   # 値の後ろに続く文は、値に入れない
    return rest.strip(), False


def _assigned(line: str) -> Iterator[tuple[str, bool, _Key, bool]]:
    """行の中の、名前と値の組。(値, 囲まれていたか, 名前, はっきりした区切りか) を返す。"""
    for key in _keys(line):
        position = _skip(line, key.end, "\"'`*")
        spaced = _skip(line, position, " \t")
        explicit = True
        if line.startswith(("->", "=>"), spaced):
            after = spaced + 2
        elif line[spaced:spaced + 1] in (":", "=", "→", "|"):
            after = spaced + 1
        elif line[spaced:spaced + 1] == "は":   # 「は」
            after, explicit = spaced + 1, False
        elif spaced > position and spaced < len(line):
            after, explicit = spaced, key.option
        elif key.option and spaced == len(line) and spaced > position:
            after = spaced
        else:
            continue
        cell = line[spaced:spaced + 1] == "|"
        if cell and line[line.rfind("|", 0, key.start) + 1:key.start].strip(" \t*`\"'"):
            continue   # 文の終わりが言葉に当たっただけのセル。名前だけのセルの次を、値として調べる
        value, quoted = _value_after(line, _skip(line, after, " \t"), cell=cell)
        bare = not explicit and line[spaced:spaced + 1] != "は" and not quoted
        yield value, quoted, key, explicit if not bare else False
        if bare:
            continue


def _credential(value: str, quoted: bool, key: _Key, explicit: bool, *, bare: bool = False) -> bool:
    minimum = GENERIC_MIN_LENGTH if key.generic else (BARE_MIN_LENGTH if bare else STRONG_MIN_LENGTH)
    return _judge(value, quoted=quoted, human=key.human and not key.generic, explicit=explicit, minimum=minimum)


def _cells(line: str) -> list[str]:
    text = line.strip()
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|"):
        text = text[:-1]
    return [cell.strip() for cell in text.split("|")]


def _header_key(cell: str) -> _Key | None:
    """表の見出しが、秘密を入れる列を表すか。見出しが言葉で終わるときだけ数える。"""
    text = cell.strip(" \t*`")
    found = None
    for key in _keys(text):
        if key.end == len(text):
            found = key
    return found


def _in_line(line: str) -> tuple[str, str] | None:
    """1 行の中で見つかる形。(種類, 規則) を返す。名前と値の組は、ここでは調べない。"""
    if _KEY_BODY.search(line) or _PUTTY.match(line.strip()):
        return "private_key", "key_block"
    token = _TOKENS.search(line)
    if token is not None and not (token.group(0).startswith("AKIA") and token.group(0).endswith("EXAMPLE")):
        return "token", "token"
    if _WEBHOOKS.search(line) or _AGENT_KEY.fullmatch(line):
        return "token", "token"
    if _HASHES.search(line):
        return "hash", "hash"
    for match in _BEARER.finditer(line):
        value = match.group(1)
        if any(c.isdigit() for c in value) and not _is_placeholder(value):
            return "bearer", "bearer"
    for match in _BASIC.finditer(line):
        if _classes(match.group(1)) >= 2:
            return "bearer", "bearer"
    for match in _USER_OPTION.finditer(line):
        user, password = match.group(1), match.group(2)
        if not (_is_placeholder(password) or _is_placeholder(user) or password.isdigit() or user.isdigit()
                or _HIRAGANA.search(password)):
            return "credential", "argument"
    for pattern in (_MYSQL, _SSHPASS, _DOCKER_LOGIN, _NETRC):
        match = pattern.search(line)
        if match is not None and not _is_placeholder(_core(match.group(1))) and _core(match.group(1)):
            return "credential", "argument"
    if _DECODED.search(line):
        return "credential", "encoded"
    for match in _URL_PASSWORD.finditer(line):
        password = match.group(1)
        if not (_is_placeholder(password) or _PORT_AND_PATH.match(password)):
            return "credential", "url"
    match = _LOGIN_PAIR.search(line)
    if match is not None and _is_strong(match.group(1)):
        return "credential", "assignment"
    for match in _XML_VALUE.finditer(line):
        key = next((k for k in _keys(match.group(1)) if k.end == len(match.group(1))), None)
        if key is not None and _credential(match.group(2), True, key, True):
            return "credential", "assignment"
    return None


def _armour(lines: list[str], index: int) -> bool:
    """秘密鍵の囲みの行か。囲みを説明しているだけの文は数えない。"""
    line = lines[index]
    match = _ARMOUR.search(line)
    if match is None:
        return False
    if line.strip(" \t>").strip() == match.group(0):
        return True
    if _ARMOUR_BODY.match(line, match.end()):
        return True
    following = lines[index + 1].strip() if index + 1 < len(lines) else ""
    return bool(following) and _BASE64_LINE.fullmatch(following) is not None and line.rstrip().endswith(match.group(0))


def _follows(lines: list[str], index: int) -> int | None:
    """値が次の行にあるとき、その行の位置。名前と値の組や見出しが続くときは None。"""
    for position in range(index + 1, min(index + 4, len(lines))):
        text = lines[position].strip()
        if not text:
            continue
        if text.startswith(("#", "|", "```", "~~~", "- ")) or _ASSIGNMENT.match(lines[position]):
            return None
        return position
    return None


def scan_secrets(file: str, text: str) -> list[Finding]:
    """秘密の形をした文字列のある行。1 行につき 1 件。値や行の文は、結果に入れない。

    全角で書いた名前や区切りも見つけるため、行を互換の形（NFKC）にそろえてから調べる。
    繰り返しの上限を決めてあり、長い行でも時間がかからない。
    """
    raw = text.split("\n")
    lines = [unicodedata.normalize("NFKC", line[:MAX_SCANNED_LINE]) for line in raw]
    findings: dict[int, Finding] = {}
    columns: dict[int, _Key] = {}
    skip_until = -1

    def add(index: int, kind: str, rule: str) -> None:
        findings.setdefault(index, Finding(file, index + 1, kind, HINTS[rule], line_digest(raw[index])))

    for index, line in enumerate(lines):
        if index <= skip_until or index in findings:
            continue
        if _armour(lines, index):
            add(index, "private_key", "key_block")
            for position in range(index + 1, min(index + MAX_KEY_BLOCK_LINES, len(lines))):
                if _ARMOUR_END.search(lines[position]):
                    skip_until = position
                    break
                if _ARMOUR.search(lines[position]):
                    break
            continue
        row = line.lstrip().startswith("|")
        if not row:
            columns = {}
        elif index + 1 < len(lines) and _RULE_ROW.fullmatch(lines[index + 1]) and "|" in lines[index + 1]:
            columns = {number: key for number, cell in enumerate(_cells(line))
                       if (key := _header_key(cell)) is not None}
        found = _in_line(line)
        if found is not None:
            add(index, *found)
            continue
        for value, quoted, key, explicit in _assigned(line):
            if (explicit or key.option) and (not value or value in _BLOCK_MARK):
                position = _follows(lines, index)
                if position is not None and _credential(lines[position].strip().strip("\"'`"), True, key, True):
                    add(position, "credential", "next_line")
                continue
            bare = not explicit and not quoted and "は" not in line[key.end:key.end + IDENT_LIMIT + 2]
            if _credential(value, quoted, key, explicit or (quoted and not key.option), bare=bare):
                add(index, "credential", "argument" if key.option else "assignment")
                break
        if index in findings or not (row and columns) or _RULE_ROW.fullmatch(line):
            continue
        cells = _cells(line)
        for number, key in columns.items():
            if number < len(cells) and _header_key(cells[number]) is None:
                cell = cells[number]
                quoted = len(cell) > 2 and cell.startswith("`") and cell.endswith("`")
                if _credential(cell.strip("`") if quoted else cell, quoted, key, True):
                    add(index, "credential", "table")
                    break
    return [findings[index] for index in sorted(findings)]
