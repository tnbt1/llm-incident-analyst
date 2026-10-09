"""同梱した静的資産。出どころの表と中身が合うこと、外部へ出ないこと。"""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "src" / "tia" / "web" / "static"
MANIFEST = json.loads((STATIC / "vendor.json").read_text(encoding="utf-8"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_htmx_is_vendored_and_matches_the_record():
    entry = MANIFEST["htmx"]
    assert entry["version"].startswith("2.") and _sha(STATIC / "htmx.min.js") == entry["sha256"]
    assert (STATIC / entry["license_file"]).exists()
    assert "htmx" in (STATIC / "htmx.min.js").read_text(encoding="utf-8")[:4000]


def test_every_font_file_matches_the_record_and_vice_versa():
    files = {p.name for p in (STATIC / "fonts").glob("*.woff2")}
    assert files == set(MANIFEST["fonts"]), "表にないファイル、ファイルのない表はない"
    for name, entry in MANIFEST["fonts"].items():
        assert _sha(STATIC / "fonts" / name) == entry["sha256"], name
        assert entry["license"] == "SIL OFL 1.1"
    families = {e["family"] for e in MANIFEST["fonts"].values()}
    assert families == {"Bricolage Grotesque", "IBM Plex Mono", "Zen Kaku Gothic New"}
    weights = {e["weight"] for e in MANIFEST["fonts"].values() if e["family"] == "Zen Kaku Gothic New"}
    assert weights == {"400", "500", "700"}, "使う太さだけを同梱する"


def test_fonts_css_points_only_at_vendored_files():
    css = (STATIC / "fonts.css").read_text(encoding="utf-8")
    urls = re.findall(r"url\('([^']+)'\)", css)
    assert urls and all(u.startswith("fonts/") for u in urls)
    assert {u[len("fonts/"):] for u in urls} == set(MANIFEST["fonts"])
    assert "http" not in css


def test_licence_texts_are_present_for_each_family():
    for family, entry in MANIFEST["licenses"].items():
        text = (STATIC / entry["file"]).read_text(encoding="utf-8")
        assert "SIL OPEN FONT LICENSE" in text.upper(), family


def test_sources_document_lists_every_vendored_file():
    text = (STATIC / "SOURCES.md").read_text(encoding="utf-8")
    assert "`htmx.min.js`" in text and MANIFEST["htmx"]["sha256"] in text
    for name, entry in MANIFEST["fonts"].items():
        assert f"`fonts/{name}`" in text and entry["sha256"] in text


def test_total_size_stays_reasonable():
    total = sum(p.stat().st_size for p in STATIC.rglob("*") if p.is_file())
    assert total < 8 * 1024 * 1024


def test_app_css_keeps_the_design_tokens_and_no_external_reference():
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    for token in ("--brand:#5B45A8", "--now:#D6402F", "--today:#F2B705", "--watch:#2F6FD0", "--ignore:#8A919C",
                  ':root[data-theme="dark"]', "prefers-reduced-motion", ":focus-visible", "Bricolage Grotesque",
                  "Zen Kaku Gothic New", "IBM Plex Mono"):
        assert token in css, token
    assert "fonts.googleapis" not in css and "proto-bar" not in css


def test_vendor_script_verifies_without_network():
    import subprocess
    import sys

    result = subprocess.run([sys.executable, str(ROOT / "tools" / "vendor-assets.py"), "--verify"],
                            capture_output=True, text=True, cwd=ROOT, timeout=120)
    assert result.returncode == 0 and "合わない 0" in result.stdout
