"""Фасад: импорт не создаёт дублей, потоки и якоря доступны через api."""
import tempfile
from pathlib import Path

import pytest

from lab import api
from tools.stand import make_stand as ms


@pytest.fixture(scope="module")
def d():
    p = Path(tempfile.mkdtemp())
    ms.main(p)
    return p


def test_import_twice_is_not_duplicated(d):
    pr = api.open_project("x")
    first = api.import_capture(pr, d / "rec01.pcapng")
    second = api.import_capture(pr, d / "rec01.pcapng")
    assert not first["already_imported"] and second["already_imported"]
    assert len(pr.sources) == 1


def test_stream_and_anchor_through_facade(d):
    pr = api.open_project("x")
    sid = api.import_capture(pr, d / "rec01.pcapng")["source_id"]
    s = api.list_sessions(pr, sid)[0]
    a = api.anchor(pr, s.session_id, "B>A", 0, 8)
    assert a["length"] == 8 and a["packets"] and len(a["bytes_sha256"]) == 64
