"""Фасад: проект на диске, импорт без дублей, потоки и якоря через api."""
import tempfile
from functools import lru_cache
from pathlib import Path

from lab import api
from tools.stand import make_stand as ms


@lru_cache(maxsize=1)
def stand_dir():
    p = Path(tempfile.mkdtemp())
    ms.main(p)
    return p


def new_project(tmp_path):
    return api.create_project(tmp_path / "proj", "t")


def test_import_twice_is_not_duplicated(tmp_path):
    pr = new_project(tmp_path)
    first = api.import_capture(pr, stand_dir() / "rec01.pcapng")
    second = api.import_capture(pr, stand_dir() / "rec01.pcapng")
    assert not first["already_imported"] and second["already_imported"]
    assert len(pr.sources) == 1
    assert len(list((tmp_path / "proj" / "sources").iterdir())) == 1


def test_stream_and_anchor_through_facade(tmp_path):
    pr = new_project(tmp_path)
    sid = api.import_capture(pr, stand_dir() / "rec01.pcapng")["source_id"]
    s = api.list_sessions(pr, sid)[0]
    a = api.anchor(pr, s.session_id, "B>A", 0, 8)
    assert a["length"] == 8 and a["packets"] and len(a["bytes_sha256"]) == 64


def test_reopened_project_keeps_sources(tmp_path):
    pr = new_project(tmp_path)
    sid = api.import_capture(pr, stand_dir() / "rec01.pcapng")["source_id"]
    again = api.open_project(tmp_path / "proj")
    assert sid in again.sources
