import json
from datetime import date

import pytest
from knowledge_helpers import TODAY, build_fixture, reseal, rewrite

from tia.knowledge import bundle as bundle_module
from tia.knowledge.bundle import BundleError, freshness, full_document, load_bundle


@pytest.fixture
def built(tmp_path):
    return build_fixture(tmp_path)


def test_bundle_is_loaded_from_the_place_that_holds_current(built, tmp_path):
    bundle = load_bundle(tmp_path / "bundles")
    assert bundle.version == built.version
    assert bundle.built_on == TODAY
    assert bundle.path == built.path
    assert len(bundle.sections) == 22
    assert bundle.tokens == built.tokens
    assert bundle.card_tokens == built.card_tokens
    assert bundle.card.startswith("# 環境カード\n")
    assert bundle.estimator == "tia-chars-v1"
    assert set(bundle.index) == {"aliases", "hosts", "types", "terms"}
    assert sorted(bundle.source_hashes) == ["README.md", "architecture.md", "maintenance.md", "registers.md"]


def test_bundle_is_loaded_from_its_own_directory(built):
    assert load_bundle(built.path).version == built.version


def test_sections_keep_their_order_and_attributes(built):
    bundle = load_bundle(built.path)
    assert [s.file for s in bundle.sections][:4] == ["README.md", "README.md", "README.md", "architecture.md"]
    section = next(s for s in bundle.sections if s.heading == "FRRの状態")
    assert section.hosts == {"vm-router01": 2}
    assert section.types == {"net": 1}
    assert section.preferred is True and section.in_card is False
    assert section.tokens > 0
    assert bundle.section(section.id) is section
    with pytest.raises(KeyError):
        bundle.section("none")


def test_old_version_can_still_be_loaded(built, tmp_path):
    newer = build_fixture(tmp_path, date(2026, 9, 30))
    assert load_bundle(tmp_path / "bundles").version == newer.version
    assert load_bundle(built.path).version == built.version


@pytest.mark.parametrize("content", ["", "\n", "../outside\n", "20260929-zzzzzzzzzzzz\n", "20260929-8eec4848b37c/..\n",
                                     "/etc\n", "20260929-8eec4848b37c\nextra\n"])
def test_pointer_that_is_not_a_version_is_refused(built, tmp_path, content):
    (tmp_path / "bundles" / "current").write_text(content, encoding="utf-8")
    with pytest.raises(BundleError, match="current"):
        load_bundle(tmp_path / "bundles")


def test_pointer_to_a_version_that_is_not_there_is_refused(built, tmp_path):
    (tmp_path / "bundles" / "current").write_text("20260101-0123456789ab\n", encoding="utf-8")
    with pytest.raises(BundleError, match="束がない"):
        load_bundle(tmp_path / "bundles")


def test_place_without_a_bundle_is_refused(tmp_path):
    (tmp_path / "empty").mkdir()
    for path in (tmp_path / "empty", tmp_path / "none"):
        with pytest.raises(BundleError, match="束がない"):
            load_bundle(path)


@pytest.mark.parametrize("name", ["card.md", "index.json", "sections.json"])
def test_bundle_with_a_missing_file_is_refused(built, name):
    (built.path / name).unlink()
    with pytest.raises(BundleError, match=name.replace(".", r"\.")):
        load_bundle(built.path)


def test_bundle_without_a_manifest_is_not_a_bundle(built, tmp_path):
    (built.path / "manifest.json").unlink()
    for path in (built.path, tmp_path / "bundles"):
        with pytest.raises(BundleError, match="束がない"):
            load_bundle(path)


@pytest.mark.parametrize("name", ["card.md", "index.json", "sections.json"])
def test_changed_content_is_refused(built, name):
    path = built.path / name
    changed = path.read_bytes().replace(b"vm-router01", b"vm-router09", 1)
    assert changed != path.read_bytes()
    path.write_bytes(changed)
    with pytest.raises(BundleError, match="ハッシュが合わない"):
        load_bundle(built.path)


def test_appended_byte_is_refused(built):
    with (built.path / "card.md").open("ab") as handle:
        handle.write(b"\n")
    with pytest.raises(BundleError, match="ハッシュが合わない"):
        load_bundle(built.path)


@pytest.mark.parametrize(("change", "message"), [
    (lambda m: m.update(format=1), "形式"),
    (lambda m: m.update(format=3), "形式"),
    (lambda m: m.pop("format"), "形式"),
    (lambda m: m.update(version="20260929-000000000000"), "版"),
    (lambda m: m.update(version="../x"), "版"),
    (lambda m: m.update(built_on="2026-09-28"), "生成日"),
    (lambda m: m.update(built_on="きのう"), "生成日"),
    (lambda m: m.update(content_hash=3), "ハッシュ"),
    (lambda m: m["counts"].update(sections=21), "節の数"),
    (lambda m: m["counts"].update(tokens=1), "トークン"),
    (lambda m: m["counts"].update(card_tokens="多い"), "counts"),
    (lambda m: m.update(counts=[]), "counts"),
    (lambda m: m.update(source={"files": {"../x.md": "0" * 64}}), "source"),
    (lambda m: m.update(source={"files": {"a.md": "短い"}}), "source"),
    (lambda m: m.update(source=[]), "source"),
    (lambda m: m.update(notices="なし"), "notices"),
    (lambda m: m.update(estimator=None), "estimator"),
])
def test_manifest_with_a_wrong_value_is_refused(built, change, message):
    rewrite(built.path / "manifest.json", change)
    with pytest.raises(BundleError, match=message):
        load_bundle(built.path)


@pytest.mark.parametrize("content", ["", "{", "[]", "null", '"text"'])
def test_manifest_that_is_not_a_mapping_is_refused(built, content):
    (built.path / "manifest.json").write_text(content, encoding="utf-8")
    with pytest.raises(BundleError, match=r"manifest\.json"):
        load_bundle(built.path)


@pytest.mark.parametrize(("change", "message"), [
    (lambda s: s[0].update(id=s[1]["id"]), "重なっている"),
    (lambda s: s[0].update(id="../x"), "id"),
    (lambda s: s[0].pop("text"), "text"),
    (lambda s: s[0].update(extra=1), "extra"),
    (lambda s: s[0].update(text=3), "text"),
    (lambda s: s[0].update(text=s[0]["text"] + "書き足し"), "sha256"),
    (lambda s: s[0].update(tokens=-1), "tokens"),
    (lambda s: s[0].update(tokens=True), "tokens"),
    (lambda s: s[0].update(level=9), "level"),
    (lambda s: s[0].update(hosts={"vm": 3}), "hosts"),
    (lambda s: s[0].update(hosts={"vm": 2.0}), "hosts"),
    (lambda s: s[0].update(hosts={"vm": True}), "hosts"),
    (lambda s: s[0].update(tokens=10.0), "tokens"),
    (lambda s: s[0].update(hosts=["vm"]), "hosts"),
    (lambda s: s[0].update(types={"net": "強"}), "types"),
    (lambda s: s[0].update(in_card="yes"), "in_card"),
    (lambda s: s[0].update(confirmed_on="きのう"), "confirmed_on"),
    (lambda s: s[0].update(file="../x.md"), "file"),
    (lambda s: s.append("節ではない"), "節"),
])
def test_sections_with_a_wrong_value_are_refused(built, change, message):
    rewrite(built.path / "sections.json", change)
    reseal(built.path)
    with pytest.raises(BundleError, match=message):
        load_bundle(built.path)


@pytest.mark.parametrize(("change", "message"), [
    (lambda i: i["hosts"].update({"vm-x": {"none-0000000000": 2}}), "索引.*ない節"),
    (lambda i: i["terms"].update({"zzz": {"weight": 3, "heading": ["none-0000000000"], "body": []}}), "索引.*ない節"),
    (lambda i: i["terms"].update({"zzz": {"weight": 9, "heading": [], "body": []}}), "索引"),
    (lambda i: i["terms"].update({"zzz": {"weight": 2.0, "heading": [], "body": []}}), "索引"),
    (lambda i: i["terms"].update({"zzz": {"weight": True, "heading": [], "body": []}}), "索引"),
    (lambda i: i["hosts"].update({"vm-x": {"a": 1.0}}), "索引"),
    (lambda i: i["terms"].update({"zzz": "x"}), "索引"),
    (lambda i: i.pop("types"), "索引"),
    (lambda i: i.pop("aliases"), "索引"),
    (lambda i: i["aliases"].update({"x": "vm-router01"}), "aliases"),
    (lambda i: i["aliases"].update({"x": []}), "aliases"),
    (lambda i: i["aliases"].update({"x": [3]}), "aliases"),
    (lambda i: i.update(hosts=[]), "索引"),
])
def test_index_with_a_wrong_value_is_refused(built, change, message):
    rewrite(built.path / "index.json", change)
    reseal(built.path)
    with pytest.raises(BundleError, match=message):
        load_bundle(built.path)


def test_sections_that_are_not_a_list_are_refused(built):
    (built.path / "sections.json").write_text("{}\n", encoding="utf-8")
    reseal(built.path)
    with pytest.raises(BundleError, match=r"sections\.json"):
        load_bundle(built.path)


def test_card_that_is_not_utf8_is_refused(built):
    (built.path / "card.md").write_bytes(b"\xff\xfe")
    reseal(built.path)
    with pytest.raises(BundleError, match=r"card\.md"):
        load_bundle(built.path)


def test_file_that_is_too_large_is_refused(built, monkeypatch):
    monkeypatch.setattr(bundle_module, "MAX_BUNDLE_FILE_BYTES", 100)
    with pytest.raises(BundleError, match="大きすぎる"):
        load_bundle(built.path)


def test_full_document_is_every_section_in_order(built):
    bundle = load_bundle(built.path)
    text, tokens = full_document(bundle)
    assert tokens == bundle.tokens
    assert text.startswith("# テスト用の運用マニュアル\n")
    assert text.endswith("ゲームVM の待受と、FRR の転送を確認する。\n")
    positions = [text.index(section.text) for section in bundle.sections]
    assert positions == sorted(positions)
    assert "## 構成の要点" in text, "環境カードに入れた節も、全文には含める"
    assert full_document(bundle) == (text, tokens)


@pytest.mark.parametrize(("today", "age", "stale"), [
    (date(2026, 9, 29), 0, False),
    (date(2026, 10, 29), 30, False),
    (date(2026, 10, 30), 31, True),
    (date(2026, 9, 1), 0, False),
])
def test_age_of_the_bundle(built, today, age, stale):
    result = freshness(load_bundle(built.path), today)
    assert (result.age_days, result.stale) == (age, stale)
    assert result.source_changed is None
    assert result.changed_files == ()


def test_stale_limit_can_be_changed(built):
    assert freshness(load_bundle(built.path), date(2026, 10, 6), stale_after_days=7).stale is False
    assert freshness(load_bundle(built.path), date(2026, 10, 7), stale_after_days=7).stale is True


def test_unchanged_source_is_reported_as_unchanged(built, tmp_path):
    result = freshness(load_bundle(built.path), TODAY, source_dir=tmp_path / "source")
    assert result.source_changed is False
    assert result.changed_files == ()


def test_changed_and_missing_documents_are_named(built, tmp_path):
    source = tmp_path / "source"
    (source / "README.md").write_text("# 書き換えた\n", encoding="utf-8")
    (source / "registers.md").unlink()
    result = freshness(load_bundle(built.path), TODAY, source_dir=source)
    assert result.source_changed is True
    assert result.changed_files == ("README.md", "registers.md")


def test_source_that_is_not_there_is_unknown(built, tmp_path):
    result = freshness(load_bundle(built.path), TODAY, source_dir=tmp_path / "none")
    assert result.source_changed is None


def test_document_that_points_outside_the_source_counts_as_changed(built, tmp_path):
    source = tmp_path / "source"
    original = (source / "README.md").read_bytes()
    outside = tmp_path / "outside.md"
    outside.write_bytes(original)
    (source / "README.md").unlink()
    (source / "README.md").symlink_to(outside)
    result = freshness(load_bundle(built.path), TODAY, source_dir=source)
    assert result.changed_files == ("README.md",)


def test_loading_does_not_write(built, tmp_path):
    before = {p: p.read_bytes() for p in (tmp_path / "bundles").rglob("*") if p.is_file()}
    bundle = load_bundle(tmp_path / "bundles")
    full_document(bundle)
    freshness(bundle, TODAY, source_dir=tmp_path / "source")
    assert {p: p.read_bytes() for p in (tmp_path / "bundles").rglob("*") if p.is_file()} == before


def test_manifest_is_kept_for_the_record(built):
    bundle = load_bundle(built.path)
    assert bundle.notices == ()
    assert json.loads((built.path / "manifest.json").read_text(encoding="utf-8"))["version"] == bundle.version
