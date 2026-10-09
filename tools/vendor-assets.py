#!/usr/bin/env python3
"""画面が使う外部の資産を、リポジトリに取り込む。HTMX と書体 3 つ。

画面は閲覧のたびに外部へ通信しない。取り込んだものは `src/tia/web/static/` に置き、
出どころ、版、SHA-256、ライセンスを `SOURCES.md` に書く。もう一度実行すると、ハッシュが合うものは飛ばす。

    uv run tools/vendor-assets.py            # 取り込む
    uv run tools/vendor-assets.py --verify   # 取り込み済みのものが SOURCES.md と合うか確かめる
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "src" / "tia" / "web" / "static"
FONTS = STATIC / "fonts"
SOURCES = STATIC / "SOURCES.md"
MANIFEST = STATIC / "vendor.json"

HTMX_VERSION = "2.0.11"
HTMX_URL = f"https://cdn.jsdelivr.net/npm/htmx.org@{HTMX_VERSION}/dist/htmx.min.js"
HTMX_LICENSE_URL = f"https://cdn.jsdelivr.net/npm/htmx.org@{HTMX_VERSION}/LICENSE"
# Google Fonts の CSS。woff2 を返す UA で取り、unicode-range ごとの部分ファイルを集める
FONT_CSS = ("https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,400..800"
            "&family=IBM+Plex+Mono:wght@400;500;600&family=Zen+Kaku+Gothic+New:wght@400;500;700&display=swap")
OFL = {
    "Bricolage Grotesque": "https://raw.githubusercontent.com/google/fonts/main/ofl/bricolagegrotesque/OFL.txt",
    "IBM Plex Mono": "https://raw.githubusercontent.com/google/fonts/main/ofl/ibmplexmono/OFL.txt",
    "Zen Kaku Gothic New": "https://raw.githubusercontent.com/google/fonts/main/ofl/zenkakugothicnew/OFL.txt",
}
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
# 部分ファイルの名前は、直前のコメント（latin など）か、URL の末尾の番号（日本語の分割）
FACE = re.compile(r"(?:/\* (?P<subset>[\w\[\]-]+) \*/\s*)?@font-face \{(?P<body>.*?)\}", re.S)
SLICE = re.compile(r"\.(\d+)\.woff2$")
PROP = re.compile(r"\s*(?P<name>[\w-]+):\s*(?P<value>[^;]+);")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url: str, *, headers: dict[str, str] | None = None) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def load_manifest() -> dict:
    if MANIFEST.exists():
        return json.loads(MANIFEST.read_text(encoding="utf-8"))
    return {"htmx": {}, "fonts": {}, "licenses": {}}


def have(path: Path, digest: str | None) -> bool:
    return bool(digest) and path.exists() and sha256(path.read_bytes()) == digest


def vendor_htmx(manifest: dict) -> None:
    target = STATIC / "htmx.min.js"
    entry = manifest.get("htmx") or {}
    if entry.get("version") == HTMX_VERSION and have(target, entry.get("sha256")):
        print(f"htmx {HTMX_VERSION}: 取り込み済み")
        return
    data = fetch(HTMX_URL)
    target.write_bytes(data)
    license_text = fetch(HTMX_LICENSE_URL).decode("utf-8")
    (STATIC / "LICENSE-htmx.txt").write_text(license_text, encoding="utf-8")
    manifest["htmx"] = {"version": HTMX_VERSION, "url": HTMX_URL, "sha256": sha256(data), "bytes": len(data),
                        "license": "Zero-Clause BSD", "license_file": "LICENSE-htmx.txt"}
    print(f"htmx {HTMX_VERSION}: {len(data):,} バイト")


def vendor_fonts(manifest: dict) -> None:
    css = fetch(FONT_CSS).decode("utf-8")
    FONTS.mkdir(parents=True, exist_ok=True)
    fonts = manifest.setdefault("fonts", {})
    rules: list[str] = []
    counter: dict[str, int] = {}
    for match in FACE.finditer(css):
        props = {m.group("name"): m.group("value").strip() for m in PROP.finditer(match.group("body"))}
        family = props["font-family"].strip("'\"")
        weight = props["font-weight"].replace(" ", "-")
        style = props.get("font-style", "normal")
        url_match = re.search(r"url\((https://[^)]+)\)", props["src"])
        if not url_match:
            continue
        url = url_match.group(1)
        subset = match.group("subset")
        if not subset:
            sliced = SLICE.search(url)
            subset = f"slice{sliced.group(1)}" if sliced else "all"
        slug = family.lower().replace(" ", "-")
        counter[slug] = counter.get(slug, 0) + 1
        name = f"{slug}-{weight}-{style}-{subset}.woff2".replace("[", "").replace("]", "")
        path = FONTS / name
        entry = fonts.get(name) or {}
        if entry.get("url") != url or not have(path, entry.get("sha256")):
            data = fetch(url)
            path.write_bytes(data)
            fonts[name] = {"family": family, "weight": props["font-weight"], "style": style, "subset": subset,
                           "url": url, "sha256": sha256(data), "bytes": len(data), "license": "SIL OFL 1.1"}
        rule = (f"@font-face {{ font-family: '{family}'; font-style: {style}; font-weight: {props['font-weight']}; "
                f"font-display: swap; src: url('fonts/{name}') format('woff2');")
        if "unicode-range" in props:
            rule += f" unicode-range: {props['unicode-range']};"
        if "font-stretch" in props:
            rule += f" font-stretch: {props['font-stretch']};"
        rules.append(rule + " }")
    (STATIC / "fonts.css").write_text("/* 書体はリポジトリに同梱する。元は Google Fonts。tools/vendor-assets.py が作る。 */\n"
                                      + "\n".join(rules) + "\n", encoding="utf-8")
    for family, url in OFL.items():
        slug = family.lower().replace(" ", "-")
        text = fetch(url).decode("utf-8")
        (STATIC / f"LICENSE-{slug}.txt").write_text(text, encoding="utf-8")
        manifest.setdefault("licenses", {})[family] = {"url": url, "file": f"LICENSE-{slug}.txt", "sha256": sha256(text.encode())}
    total = sum(e["bytes"] for e in fonts.values())
    print(f"書体: {len(fonts)} ファイル、{total:,} バイト（" + "、".join(f"{k} {v}" for k, v in sorted(counter.items())) + "）")


def write_sources(manifest: dict) -> None:
    lines = ["# 画面の静的資産の出どころ", "", "`tools/vendor-assets.py` が取り込み、この表を書く。手で直さない。", "",
             "| ファイル | 出どころ | 版 | SHA-256 | ライセンス |", "|---|---|---|---|---|"]
    h = manifest["htmx"]
    lines.append(f"| `htmx.min.js` | {h['url']} | {h['version']} | `{h['sha256']}` | {h['license']}（`{h['license_file']}`） |")
    for name, e in sorted(manifest["fonts"].items()):
        lines.append(f"| `fonts/{name}` | {e['url']} | {e['family']} {e['weight']} {e['subset']} | `{e['sha256']}` | {e['license']} |")
    lines += ["", "## ライセンスの文", ""]
    for family, e in sorted(manifest["licenses"].items()):
        lines.append(f"- {family}: `{e['file']}`（{e['url']}）")
    lines.append("- HTMX: `LICENSE-htmx.txt`")
    SOURCES.write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify(manifest: dict) -> int:
    bad = 0
    checks = [(STATIC / "htmx.min.js", manifest.get("htmx", {}).get("sha256"))]
    checks += [(FONTS / name, e["sha256"]) for name, e in manifest.get("fonts", {}).items()]
    for path, digest in checks:
        if not have(path, digest):
            print(f"合わない: {path.relative_to(ROOT)}")
            bad += 1
    print(f"確認 {len(checks)} ファイル、合わない {bad}")
    return 1 if bad else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    manifest = load_manifest()
    if args.verify:
        return verify(manifest)
    STATIC.mkdir(parents=True, exist_ok=True)
    vendor_htmx(manifest)
    vendor_fonts(manifest)
    MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    write_sources(manifest)
    print(f"{SOURCES.relative_to(ROOT)} を書いた")
    return 0


if __name__ == "__main__":
    sys.exit(main())
