"""推奨コマンドの検査と照合。

- `destructive_reason`: 変更や破壊を伴う操作を見つける。コマンドの位置にある語で判定し、引数や grep の中の語では判定しない。
  `sudo`、`env`、`;`、`&&`、`|`、`$(`、バッククォートの後もコマンドの位置とみなす。
  `docker exec`、`vmctl vm exec`、`ssh`、`xargs`、`find -exec`、`sh -c` の中身も調べる。
- `normalise_command`、`templates_in`、`matches_template`: 文書のコードブロックにあるコマンドのひな形と、推奨コマンドの照合。
  シェルのコードブロックだけを対象にし、`\\` の行継続をつなぎ、変数や `<…>` の穴は語の単位で合わせる。

判定はコマンドの位置の語で行い、照合は文書のシェルのブロックに対して語の単位で行う。
"""
from __future__ import annotations

import re
import shlex
import unicodedata
from collections.abc import Iterable

from tia.knowledge.safety import neutralise

SYSTEM_PATHS = ("/etc", "/var", "/opt", "/boot", "/usr", "/root", "/home", "/srv", "/run", "/dev/sd", "/dev/nvme",
                "/dev/vd", "/dev/md", "/dev/mapper")
HARMLESS_TARGETS = ("/dev/null", "/dev/stdout", "/dev/stderr", "/tmp/", "/proc/self/")
# コマンドの位置を変えない前置き。値を取るものは後ろの語を 1 つ飛ばす。
WRAPPERS = {"sudo", "doas", "env", "nohup", "time", "nice", "ionice", "stdbuf", "command", "builtin", "exec", "watch",
            "timeout", "chroot", "unbuffer", "strace", "setsid"}
# 値を取るオプション。包みのコマンドごとに違う。sudo の -n（パスワードを聞かない）は値を取らないが、nice の -n は取る
WRAPPER_VALUE_OPTIONS = {"-u", "-g", "-c", "-i", "-o", "-e", "-s", "-C", "-D", "-h", "-p", "-r", "-U", "-T",
                         "--user", "--group", "--output", "--interval", "--signal", "--kill-after", "--foreground"}
WRAPPER_VALUE_OPTIONS_BY_COMMAND = {"nice": {"-n", "--adjustment"}, "ionice": {"-n", "-c"}, "stdbuf": {"-i", "-o", "-e"},
                                    "watch": {"-n", "--interval"}}
SEPARATORS = {";", "&&", "||", "|", "|&", "(", "&", "{", "}"}
SHELL_FENCES = ("", "bash", "sh", "shell", "console", "zsh", "text", "plain")

ReasonTable = tuple[tuple[str, re.Pattern[str]], ...]


def _rules(table: Iterable[tuple[str, str]]) -> ReasonTable:
    return tuple((reason, re.compile(pattern)) for reason, pattern in table)


# コマンドの位置にある語（前置きを除いた先頭）だけで決まるもの
FIRST_WORDS: dict[str, str] = {
    **{name: "ファイルの削除" for name in ("rm", "rmdir", "shred", "unlink", "wipe")},
    **{name: "再起動と停止" for name in ("shutdown", "reboot", "poweroff", "halt", "telinit")},
    **{name: "ディスクの書き換え" for name in ("mkswap", "wipefs", "fdisk", "sfdisk", "parted", "gdisk", "cfdisk", "lvremove",
                                     "vgremove", "pvremove", "lvreduce", "mdadm", "fstrim", "blkdiscard")},
    **{name: "プロセスの停止" for name in ("kill", "pkill", "killall", "fuser")},
    **{name: "権限と所有者の変更" for name in ("chmod", "chown", "chgrp", "setfacl", "chattr")},
    **{name: "利用者とパスワードの変更" for name in ("userdel", "groupdel", "useradd", "usermod", "groupadd", "groupmod",
                                        "passwd", "chpasswd", "visudo", "gpasswd")},
    **{name: "ファイルの書き換え" for name in ("truncate", "mv", "cp", "ln", "install", "tee", "dd", "patch", "mkfs")},
    **{name: "マウントとスワップの変更" for name in ("umount", "swapoff")},
    **{name: "カーネルの設定変更" for name in ("setenforce", "rmmod", "insmod", "modprobe")},
    **{name: "ネットワークの変更" for name in ("ifdown", "ifup", "wg-quick", "wg")},
    **{name: "インラインのコード" for name in ("eval", "source")},
}
SHELLS = ("sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3", "python2", "perl", "ruby", "node")
_FETCH_SUBSTITUTION = re.compile(r"[$<]\s*\(\s*(curl|wget|fetch)\b")
# 先頭の語と、それに続く語や引数で決まるもの。パターンは、前置きを除いた 1 つのコマンド（空白 1 つで区切った形）に当てる。
ARGUMENT_RULES = _rules((
    ("サービスの操作", r"^systemctl(\s+-\S+(\s+\S+)?)*\s+(start|stop|restart|reload|try-restart|reload-or-restart|enable|"
                   r"disable|mask|unmask|kill|isolate|daemon-reload|daemon-reexec|edit|set-property|revert|"
                   r"reset-failed|poweroff|reboot|halt|suspend|hibernate)\b"),
    ("サービスの操作", r"^systemctl\b.*\s--now\b"),
    ("コンテナの操作", r"^docker(\s+-\S+)*\s+(rm|rmi|kill|stop|start|restart|pause|unpause|run|create|pull|push|prune|"
                   r"update|rename|commit|load|import|build|tag|login|logout)\b"),
    ("コンテナの操作", r"^docker(\s+-\S+)*\s+(system|volume|network|image|container|builder|buildx)\s+(prune|rm|remove|"
                   r"create|connect|disconnect|load|import|build|push|pull)\b"),
    ("コンテナの操作", r"^docker(\s+-\S+)*\s+compose(\s+-\S+(\s+\S+)?)*\s+(down|rm|restart|stop|kill|up|pull|start|run|"
                   r"create|build|push|pause|unpause|recreate)\b"),
    ("Kubernetes の変更", r"^kubectl(\s+-\S+(\s+\S+)?)*\s+(delete|drain|scale|apply|edit|patch|cordon|uncordon|taint|"
                      r"create|replace|label|annotate|set|cp|run|expose|autoscale|rollout)\b"),
    ("仮想マシンの操作", r"^vmctl(\s+-\S+(\s+\S+)?)*\s+vm\s+(stop|start|restart|delete|create|apply|rm)\b"),
    ("仮想マシンの操作", r"^virsh\s+(destroy|shutdown|reboot|reset|undefine|start|suspend|resume|delete|detach-\S+|"
                     r"attach-\S+|snapshot-delete|vol-delete|vol-wipe|pool-delete|setmem|setvcpus|migrate)\b"),
    ("ファイルの書き換え", r"^sed(\s+-\S+)*\s+(-i|--in-place)\b"),
    ("ファイルの書き換え", r"^perl(\s+-\S+)*\s+-\S*i"),
    ("ファイルの書き換え", r"^rsync\b.*\s--delete"),
    ("ディスクの書き換え", r"^(zfs|zpool)\s+(destroy|remove|detach|offline|clear|scrub)\b"),
    ("ディスクの書き換え", r"^btrfs\s+(subvolume\s+delete|balance|device\s+(delete|remove))\b"),
    ("ディスクの書き換え", r"^mount\s"),
    ("履歴の書き換え", r"^git(\s+-\S+(\s+\S+)?)*\s+(push\b.*\s(--force|-f|--force-with-lease|--delete)\b|reset\s+--hard|"
                   r"clean\b|checkout\s+--\s|restore\b|rebase\b|branch\s+-D|stash\s+drop|filter-branch\b|"
                   r"filter-repo\b|gc\s+--prune)"),
    ("ファイアウォールの変更", r"^(iptables|ip6tables|iptables-restore|ip6tables-restore)\b.*(\s-(F|X|D|I|A|P|R|N|Z|t\s+\S+\s+-(F|X|D|I|A|P|R|N|Z))\b|"
                        r"\s--(flush|delete|insert|append|policy|delete-chain|new-chain|replace|zero)\b)"),
    ("ファイアウォールの変更", r"^iptables-restore\b"),
    ("ファイアウォールの変更", r"^nft(\s+-\S+)*\s+(flush|add|delete|insert|replace|destroy|create|rename|reset|-f)\b"),
    ("ファイアウォールの変更", r"^ufw\s+(enable|disable|allow|deny|reject|limit|delete|reset|route|default|insert|prepend)\b"),
    ("ファイアウォールの変更", r"^firewall-cmd\b.*--(add|remove|reload|set|new|delete|change|permanent)"),
    ("ネットワークの変更", r"^ip(\s+-\S+)*\s+(link|addr|address|a|route|r|rule|neigh|tunnel|netns)\s+(set|add|del|delete|"
                     r"flush|replace|change|append|prepend|exec)\b"),
    ("ネットワークの変更", r"^nmcli\b.*\s(down|up|delete|modify|add|reload|connect|disconnect|off|on)\b"),
    ("ネットワークの変更", r"^networkctl\s+(down|up|reload|reconfigure|renew|forcerenew)\b"),
    ("ネットワークの変更", r"^tailscale\s+(down|up|logout|set|cert|serve|funnel|switch)\b"),
    ("ネットワークの変更", r"^(ipsec|strongswan|swanctl)\b.*\s(restart|stop|start|down|up|reload|--terminate|--initiate|"
                     r"--load-all|--flush)\b"),
    ("ルーターの設定変更", r"^vtysh\b.*\b(configure|conf t|write|reload|clear)\b"),
    ("監視サーバーの操作", r"^zabbix_server(\s+-\S+(\s+\S+)?)*\s+(-R|--runtime-control)\b"),
    ("ウェブサーバーの操作", r"^caddy\s+(reload|stop|start|run|adapt|trust|untrust|upgrade|add-package|remove-package)\b"),
    ("ウェブサーバーの操作", r"^caddy\s+fmt\b.*--overwrite"),
    ("パッケージの変更", r"^(apt|apt-get|aptitude)(\s+-\S+)*\s+(install|remove|purge|autoremove|upgrade|dist-upgrade|"
                    r"full-upgrade|dpkg-reconfigure)\b"),
    ("パッケージの変更", r"^(dnf|yum|zypper)(\s+-\S+)*\s+(install|remove|erase|upgrade|update|autoremove|reinstall|"
                    r"downgrade)\b"),
    ("パッケージの変更", r"^pacman(\s+-\S+)*\s+-(S|R|U|Rns|Rs|Syu|Syyu)\b"),
    ("パッケージの変更", r"^(pip|pip3|npm|pnpm|yarn|gem|cargo|snap|flatpak|brew|uv)(\s+-\S+)*\s+(install|uninstall|remove|"
                    r"add|rm|upgrade|update|refresh|revert)\b"),
    ("定期実行の変更", r"^crontab(\s+-u\s+\S+)?\s+(-r|-e|-i|[^-\s]\S*)"),
    ("マウントとスワップの変更", r"^swapon(?!\s+(--show|-s)\b)"),
    ("再起動と停止", r"^init\s+[06]\b"),
    ("カーネルの設定変更", r"^sysctl(\s+-\S+)*\s+(-w|--write|\S+=\S*)"),
    ("データの書き換え", r"^(mysql|mariadb|psql|sqlite3)\b.*\b(DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE|CREATE|GRANT|REVOKE|"
                    r"REPLACE|VACUUM)\b"),
    ("インラインのコード", r"^(python|python3|python2|perl|ruby|node|php|lua|awk|gawk)(\s+-\S+)*\s+-\S*[ce]\s"),
    ("検索しながらの削除", r"^find\b.*\s(-delete|-fprint\S*|-fls)\b"),
    ("インターネットからの実行", r"^(curl|wget|fetch)\b.*\|\s*(sudo\s+)?(sh|bash|zsh|dash|ksh|python3?|perl)\b"),
    ("インターネットからの実行", r"\bbase64\s+(-d|--decode)\b.*\|\s*(sudo\s+)?(sh|bash|zsh|dash|python3?)\b"),
))
# 中身のコマンドをさらに調べるもの
INNER_COMMAND = {"xargs", "ssh", "doas"}
_TOKEN_OK = re.compile(r"^[\w./:@%+=,\-]+$")


class _Unparseable(ValueError):
    """シェルとして読めない。"""


def prepare(command: str) -> str:
    """検査の前に形をそろえる。見えない文字を除き、互換の形にし、行継続をつなぎ、空白を 1 つにする。"""
    text = neutralise(str(command))[0]
    text = unicodedata.normalize("NFKC", text)
    text = text.replace("\\\n", " ").replace("\\\r\n", " ")
    text = text.replace("`", " ( ")
    # `$(`、`<(`、`>(` を語に分け、引用の中でも見つけられるようにする
    text = re.sub(r"([$<>])\(", r" \1 ( ", text)
    return " ".join(text.split())


def _tokens(text: str) -> list[str]:
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError as exc:
        raise _Unparseable(str(exc)) from None


def _segments(tokens: list[str]) -> list[tuple[list[str], bool]]:
    """区切りで分けた、コマンドの位置から始まる語の並びと、その段がパイプの後かどうか。`$(` と `(` の後も新しい段になる。"""
    segments: list[tuple[list[str], bool]] = [([], False)]
    for token in tokens:
        if token in SEPARATORS or token == ")" or token == "$":
            segments.append(([], token in ("|", "|&")))
            continue
        segments[-1][0].append(token)
    return [(segment, piped) for segment, piped in segments if segment]


def _strip_wrappers(words: list[str]) -> list[str]:
    """`sudo -u x`、`env A=1`、`nohup`、`timeout 5` などの前置きを外す。"""
    index = 0
    while index < len(words):
        word = words[index]
        if word in WRAPPERS:
            index += 1
            if word == "timeout" and index < len(words) and not words[index].startswith("-"):
                index += 1
            takes_value = WRAPPER_VALUE_OPTIONS | WRAPPER_VALUE_OPTIONS_BY_COMMAND.get(word, set())
            while index < len(words) and words[index].startswith("-"):
                option = words[index]
                index += 1
                if option in takes_value and index < len(words):
                    index += 1
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", word):
            index += 1
            continue
        break
    return words[index:]


def _redirect_target(words: list[str]) -> str | None:
    """`>` や `>>` の先が守るべき場所なら、その場所を返す。"""
    for position, word in enumerate(words):
        if word in (">", ">>", "&>", ">|") and position + 1 < len(words):
            target = words[position + 1]
            if target.startswith(SYSTEM_PATHS) and not target.startswith(HARMLESS_TARGETS):
                return target
    return None


def _inner_of(words: list[str]) -> list[str] | None:
    """包みのコマンドの中身。docker exec、vmctl vm exec、kubectl exec、ssh、xargs、sh -c、find -exec。"""
    head = words[0]
    if head in ("sh", "bash", "zsh", "dash", "ksh") and "-c" in words:
        position = words.index("-c")
        return _tokens(" ".join(words[position + 1:])) if position + 1 < len(words) else None
    if head == "xargs":
        rest = [w for w in words[1:] if not w.startswith("-")]
        return rest or None
    if head == "ssh":
        index = 1
        while index < len(words) and words[index].startswith("-"):
            index += 2 if words[index] in ("-p", "-i", "-o", "-l", "-F", "-J", "-L", "-R", "-D", "-W", "-b", "-c", "-e", "-m") else 1
        return words[index + 1:] or None
    if head == "docker" and len(words) > 2 and (words[1] == "exec" or (words[1] == "compose" and "exec" in words[2:4])):
        start = words.index("exec") + 1
        index = start
        while index < len(words) and words[index].startswith("-"):
            index += 2 if words[index] in ("-u", "--user", "-w", "--workdir", "-e", "--env", "--env-file", "--index") else 1
        return words[index + 1:] or None
    if head == "kubectl" and "exec" in words[1:3] and "--" in words:
        return words[words.index("--") + 1:] or None
    if head == "vmctl" and "exec" in words and "--" in words:
        return words[words.index("--") + 1:] or None
    if head == "find":
        for flag in ("-exec", "-execdir", "-ok", "-okdir"):
            if flag in words:
                inner = words[words.index(flag) + 1:]
                for terminator in (";", "+"):
                    if terminator in inner:
                        inner = inner[: inner.index(terminator)]
                return inner or None
    return None


def _reason_for_words(words: list[str], depth: int = 0, *, piped: bool = False) -> str | None:
    words = _strip_wrappers(words)
    if not words:
        return None
    target = _redirect_target(words)
    if target is not None:
        return f"{target} への書き込み"
    head = words[0].rsplit("/", 1)[-1]
    if head in FIRST_WORDS:
        return FIRST_WORDS[head]
    if head in SHELLS:
        if "<" in words or any(_FETCH_SUBSTITUTION.search(word) for word in words[1:]):
            return "取ってきた内容の実行"
        if piped and not [word for word in words[1:] if not word.startswith("-")]:
            return "パイプからシェルの実行"
    if head.startswith("mkfs"):
        return FIRST_WORDS["mkfs"]
    line = " ".join([head, *words[1:]])
    for reason, pattern in ARGUMENT_RULES:
        if pattern.search(line):
            return reason
    if depth < 4:
        inner = _inner_of([head, *words[1:]])
        if inner:
            for segment, inner_piped in _segments(inner):
                reason = _reason_for_words(segment, depth + 1, piped=inner_piped)
                if reason:
                    return reason
    return None


def destructive_reason(command: str) -> str | None:
    """変更や破壊を伴う操作なら、その種類を返す。読み取りだけなら None。読めないコマンドは「読めない」。"""
    text = prepare(command)
    if not text:
        return None
    try:
        tokens = _tokens(text)
    except _Unparseable:
        return "シェルとして読めない"
    for segment, piped in _segments(tokens):
        reason = _reason_for_words(segment, piped=piped)
        if reason:
            return reason
    return None


# ---- 文書のコマンドとの照合 ----

_FENCE = re.compile(r"^\s*(`{3,}|~{3,})\s*([A-Za-z0-9_+-]*)")
_PROMPT = re.compile(r"^\s*(?:\$|#|>)\s+")
_HEREDOC = re.compile(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")
PLACEHOLDER_WORDS = ("…", "...")


def normalise_command(command: str) -> str:
    """照合のための形。見えない文字を除き、互換の形にし、先頭のプロンプト記号と `sudo` を外し、空白を 1 つにそろえる。"""
    text = prepare(command)
    text = _PROMPT.sub("", text)
    words = text.split()
    while words and words[0] in ("sudo", "doas"):
        words = words[1:]
        while words and words[0].startswith("-"):
            option = words.pop(0)
            if option in ("-u", "-g") and words:
                words.pop(0)
    return " ".join(words)


def _strip_comment(line: str) -> str:
    """行末の注釈を外す。`#` の前に空白があり、引用の外にあるときだけ。"""
    position = line.find(" #")
    while position != -1:
        head = line[:position]
        if head.count("'") % 2 == 0 and head.count('"') % 2 == 0:
            return head.rstrip()
        position = line.find(" #", position + 1)
    return line


def _balanced(text: str) -> bool:
    """引用が閉じていれば真。"""
    try:
        shlex.split(text, posix=True)
    except ValueError:
        return False
    return True


def _shell_lines(texts: Iterable[str]) -> Iterable[str]:
    """シェルのコードブロックの行だけを返す。言語の指定がないか、bash、sh、shell、console、zsh のブロック。"""
    for text in texts:
        fence: str | None = None
        for line in text.split("\n"):
            match = _FENCE.match(line)
            if match is not None:
                if fence is None:
                    fence = match.group(1)
                    language = match.group(2).lower()
                    include = language in SHELL_FENCES[:5]
                    if not include:
                        fence = "skip:" + fence
                    continue
                if line.strip().startswith(fence.removeprefix("skip:")):
                    fence = None
                    continue
            if fence is not None and not fence.startswith("skip:"):
                yield line
            elif fence is None:
                yield "\x00"  # ブロックの外。つなぎかけのコマンドを閉じる印


def _join_commands(lines: Iterable[str]) -> Iterable[str]:
    """`\\` の行継続、閉じていない引用、ヒアドキュメントを 1 つのコマンドにつなぐ。"""
    buffer: list[str] = []
    terminator: str | None = None
    for line in lines:
        if line == "\x00":
            if buffer:
                yield "\n".join(buffer)
            buffer, terminator = [], None
            continue
        if terminator is not None:
            buffer.append(line)
            if line.strip() == terminator:
                yield "\n".join(buffer)
                buffer, terminator = [], None
            continue
        stripped = line.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        buffer.append(line)
        joined = "\n".join(buffer)
        if stripped.endswith("\\"):
            continue
        heredoc = _HEREDOC.search(joined)
        if heredoc is not None and not any(part.strip() == heredoc.group(1) for part in buffer[1:]):
            terminator = heredoc.group(1)
            continue
        if not _balanced(joined):
            continue
        yield joined
        buffer = []
    if buffer:
        yield "\n".join(buffer)


def templates_in(texts: Iterable[str]) -> frozenset[str]:
    """文書のシェルのコードブロックにあるコマンドのひな形。注釈と空行は除き、継続行はつなぐ。"""
    found: set[str] = set()
    for command in _join_commands(_shell_lines(texts)):
        # 行継続はつなぎ、複数行の引用やヒアドキュメントは改行を残して 1 つのひな形にする
        command = command.replace("\\\n", " ")
        lines = command.split("\n")
        if len(lines) == 1:
            command = _strip_comment(command)
        shape = normalise_command(command) if len(lines) == 1 else _multiline_shape(command)
        if shape:
            found.add(shape)
    return frozenset(found)


def _multiline_shape(command: str) -> str:
    first, _, rest = command.partition("\n")
    head = normalise_command(first)
    return f"{head}\n{rest}" if head else ""


def commands_in(texts: Iterable[str]) -> frozenset[str]:
    """後方互換の名前。templates_in と同じ。"""
    return templates_in(texts)


_ANGLE = re.compile(r"<[^<>]+>")


def _words_match(template: list[str], command: list[str]) -> bool:
    """語の単位で、先頭から全部が合えば真。

    穴の合い方: `…` は 0 語以上、`<…>` は 1 語以上（コマンドや引数の並びを表す）、シェルの変数を含む語は 1 語。
    """
    if not template:
        return not command
    head, rest = template[0], template[1:]
    if head in PLACEHOLDER_WORDS:
        return any(_words_match(rest, command[k:]) for k in range(len(command) + 1))
    if _ANGLE.search(head):
        return any(_words_match(rest, command[k:]) for k in range(1, len(command) + 1))
    if "$" in head:
        return bool(command) and _words_match(rest, command[1:])
    return bool(command) and command[0] == head and _words_match(rest, command[1:])


def matches_template(command: str, templates: Iterable[str]) -> bool:
    """推奨コマンドが、文書のひな形のどれかに語の単位で合えば真。部分一致は認めない。"""
    shape = normalise_command(command)
    if not shape:
        return False
    words = shape.split(" ")
    for template in templates:
        if "\n" in template:
            if template.split("\n", 1)[0] == shape or template == shape:
                return True
            continue
        if _words_match(template.split(" "), words):
            return True
    return False
