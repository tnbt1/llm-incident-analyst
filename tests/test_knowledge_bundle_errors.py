"""束を読めないときの扱い。読めない原因が何でも、BundleError で知らせる。"""
import os
import shutil

import pytest
from knowledge_helpers import build_fixture

from tia.cli import main
from tia.knowledge.bundle import BundleError, load_bundle
from tia.knowledge.select import select_sections

pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="root は権限に関係なく読めてしまう")


@pytest.fixture
def built(tmp_path):
    result = build_fixture(tmp_path)
    yield result
    # 後始末ができるよう、外側から順に権限を戻す
    os.chmod(tmp_path / "bundles", 0o755)
    os.chmod(result.path, 0o755)
    for path in result.path.iterdir():
        os.chmod(path, 0o755 if path.is_dir() else 0o644)


@pytest.mark.parametrize("target", ["place", "version"])
def test_directory_that_may_not_be_read_is_a_bundle_error(built, tmp_path, target):
    place = tmp_path / "bundles"
    locked = place if target == "place" else built.path
    os.chmod(locked, 0)
    with pytest.raises(BundleError) as error:
        load_bundle(place)
    assert str(locked if target == "place" else built.path) in str(error.value) or str(place) in str(error.value)


@pytest.mark.parametrize("name", ["manifest.json", "sections.json", "index.json", "card.md"])
def test_file_that_may_not_be_read_is_a_bundle_error(built, name):
    os.chmod(built.path / name, 0)
    with pytest.raises(BundleError, match=name.replace(".", r"\.")):
        load_bundle(built.path)


@pytest.mark.parametrize("name", ["manifest.json", "sections.json", "card.md"])
def test_directory_in_the_place_of_a_file_is_a_bundle_error(built, name):
    (built.path / name).unlink()
    (built.path / name).mkdir()
    with pytest.raises(BundleError):
        load_bundle(built.path)


def test_pointer_that_is_a_directory_is_a_bundle_error(built, tmp_path):
    pointer = tmp_path / "bundles" / "current"
    pointer.unlink()
    pointer.mkdir()
    with pytest.raises(BundleError, match="束がない|current"):
        load_bundle(tmp_path / "bundles")


def test_pointer_that_may_not_be_read_is_a_bundle_error(built, tmp_path):
    os.chmod(tmp_path / "bundles" / "current", 0)
    with pytest.raises(BundleError, match="current"):
        load_bundle(tmp_path / "bundles")
    os.chmod(tmp_path / "bundles" / "current", 0o644)


@pytest.mark.parametrize("command", [["show"], ["select", "--host", "vm-monitor01", "--type", "disk"]])
def test_commands_stop_without_a_traceback(built, tmp_path, capsys, command):
    os.chmod(tmp_path / "bundles", 0)
    assert main(["knowledge", *command, "--bundle", str(tmp_path / "bundles")]) == 2
    out = capsys.readouterr()
    assert out.err.startswith("中止: ") and "Traceback" not in out.err and out.out == ""


def test_readable_bundle_is_still_loaded(built, tmp_path):
    copy = tmp_path / "copy"
    shutil.copytree(tmp_path / "bundles", copy)
    bundle = load_bundle(copy)
    assert select_sections(bundle, hosts=["vm-monitor01"], incident_type="disk", title="")
