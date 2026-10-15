"""Тесты lab/project.py. Только стандартная библиотека и pytest.

Файлы-«pcap» здесь просто байты: project.py не разбирает формат, он хранит и проверяет файлы.
"""
import hashlib
import json
import os
import shutil
import stat
from pathlib import Path

import pytest

from lab.models import LabError
from lab.project import add_source, create_project, open_project, verify_sources

PCAP_BYTES = b"\xd4\xc3\xb2\xa1" + bytes(range(256)) * 40


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_pcap(directory: Path, name: str, data: bytes = PCAP_BYTES) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(data)
    return path


def make_project_with_source(tmp_path: Path):
    root = tmp_path / "proj"
    create_project(root, "demo")
    src = make_pcap(tmp_path / "in", "capture.pcap")
    result = add_source(root, src)
    return root, src, result


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


# 1. создание проекта
def test_create_project_makes_manifest_and_sources_dir(tmp_path):
    root = tmp_path / "proj"
    project = create_project(root, "demo")

    assert (root / "project.json").is_file()
    assert (root / "sources").is_dir()
    assert (root / "cache").is_dir()
    assert project.name == "demo"
    assert project.sources == {}
    assert json.loads((root / "project.json").read_text(encoding="utf-8"))["name"] == "demo"
    assert not list(root.glob(".project.*"))  # временных файлов атомарной записи не осталось


# 2. add_source копирует, хэш верный, исходник не тронут
def test_add_source_copies_file_and_leaves_original_untouched(tmp_path):
    root = tmp_path / "proj"
    create_project(root, "demo")
    src = make_pcap(tmp_path / "in", "capture.pcap")
    before_bytes = src.read_bytes()
    before_stat = src.stat()

    result = add_source(root, src)

    expected = hashlib.sha256(before_bytes).hexdigest()
    assert result.source_id == expected
    assert result.already_added is False
    copy = root / result.path
    assert copy.is_file() and copy != src
    assert copy.read_bytes() == before_bytes
    assert sha256_of(copy) == expected
    # исходник: те же байты, то же время изменения, те же права
    assert src.read_bytes() == before_bytes
    assert src.stat().st_mtime_ns == before_stat.st_mtime_ns
    assert src.stat().st_mode == before_stat.st_mode
    assert expected in open_project(root).sources


# 3. тот же файл под другим именем не создаёт дубль
def test_same_content_under_other_name_is_not_duplicated(tmp_path):
    root = tmp_path / "proj"
    create_project(root, "demo")
    first = add_source(root, make_pcap(tmp_path / "in1", "one.pcap"))
    second = add_source(root, make_pcap(tmp_path / "in2", "totally_other_name.pcapng"))

    assert first.already_added is False
    assert second.already_added is True
    assert second.source_id == first.source_id
    assert second.path == first.path
    assert len(open_project(root).sources) == 1
    assert [p.name for p in (root / "sources").iterdir()] == [Path(first.path).name]


# 4. копия проекта в другом каталоге открывается
def test_copied_project_opens_with_same_hashes(tmp_path):
    root, _, result = make_project_with_source(tmp_path)
    moved = tmp_path / "elsewhere" / "proj_copy"
    shutil.copytree(root, moved)

    original = open_project(root)
    copied = open_project(moved)

    assert copied.path != original.path
    assert set(copied.sources) == set(original.sources) == {result.source_id}
    assert sha256_of(moved / copied.sources[result.source_id]["path"]) == result.source_id


# 5. изменённый файл в sources/ -> SOURCE_CHANGED
def test_open_project_detects_modified_source(tmp_path):
    root, _, result = make_project_with_source(tmp_path)
    copy = root / result.path
    copy.chmod(0o644)  # специально снимаем защиту, имитируем порчу
    with copy.open("ab") as f:
        f.write(b"tampered")

    with pytest.raises(LabError) as excinfo:
        open_project(root)
    assert excinfo.value.code == "SOURCE_CHANGED"


# 6. в project.json нет абсолютных путей
def test_manifest_has_only_relative_posix_paths(tmp_path):
    root, _, result = make_project_with_source(tmp_path)
    text = (root / "project.json").read_text(encoding="utf-8")
    data = json.loads(text)

    strings = []

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                strings.append(key)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, str):
            strings.append(node)

    walk(data)
    for s in strings:
        assert not s.startswith("/"), s
        assert "\\" not in s, s
        assert "/home/" not in s and "/mnt/" not in s and "C:" not in s, s
    assert str(tmp_path) not in text
    assert data["sources"][result.source_id]["path"] == "sources/%s.pcap" % result.source_id


# 7. копию в sources/ нельзя перезаписать
def test_source_copy_is_read_only(tmp_path):
    root, _, result = make_project_with_source(tmp_path)
    copy = root / result.path

    assert not copy.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    if is_root():
        pytest.skip("root игнорирует биты прав, проверку записи пропускаем")
    with pytest.raises(PermissionError):
        copy.open("ab")


# --- дополнительные проверки ожидаемых ошибок и progress ---

def test_open_project_reports_missing_source(tmp_path):
    root, _, result = make_project_with_source(tmp_path)
    copy = root / result.path
    copy.chmod(0o644)
    copy.unlink()

    with pytest.raises(LabError) as excinfo:
        open_project(root)
    assert excinfo.value.code == "SOURCE_MISSING"


def test_add_source_rejects_missing_input_file(tmp_path):
    root = tmp_path / "proj"
    create_project(root, "demo")
    with pytest.raises(LabError) as excinfo:
        add_source(root, tmp_path / "nope.pcap")
    assert excinfo.value.code == "SOURCE_MISSING"


def test_open_project_rejects_broken_or_absent_manifest(tmp_path):
    with pytest.raises(LabError) as excinfo:
        open_project(tmp_path / "does_not_exist")
    assert excinfo.value.code == "BAD_PROJECT"

    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "project.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(LabError) as excinfo:
        open_project(broken)
    assert excinfo.value.code == "BAD_PROJECT"


def test_open_project_rejects_absolute_path_in_manifest(tmp_path):
    root, _, result = make_project_with_source(tmp_path)
    manifest = root / "project.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["sources"][result.source_id]["path"] = "/home/someone/capture.pcap"
    manifest.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(LabError) as excinfo:
        open_project(root)
    assert excinfo.value.code == "BAD_PROJECT"


def test_verify_sources_reports_progress(tmp_path):
    root, _, result = make_project_with_source(tmp_path)
    project = open_project(root)
    calls = []

    verify_sources(project, progress=lambda *args: calls.append(args))

    assert calls, "progress должен вызываться"
    assert calls[-1] == (result.source_id, len(PCAP_BYTES), len(PCAP_BYTES))
