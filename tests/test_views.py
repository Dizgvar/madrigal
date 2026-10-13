"""Представления для интерфейса: JSON-совместимость, дыры без нулей, явное усечение окна."""
import json
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


def load(tmp_path, name):
    pr = api.create_project(tmp_path / "proj", "t")
    sid = api.import_capture(pr, stand_dir() / name)["source_id"]
    return pr, sid


def test_sessions_view_is_json_and_has_role_label(tmp_path):
    pr, sid = load(tmp_path, "def_nostart.pcap")
    rows = api.describe_sessions(pr, sid)
    json.dumps(rows)                                  # не должно падать
    unknown = [r for r in rows if not r["roles_known"]]
    assert unknown and all(r["role_label"] == "роли неизвестны" for r in unknown)
    assert not any("клиент" in json.dumps(r, ensure_ascii=False).lower() for r in rows)


def test_stream_view_matches_raw_bytes(tmp_path):
    pr, sid = load(tmp_path, "rec01.pcapng")
    s = api.list_sessions(pr, sid)[0]
    raw = b"".join(sp.data for sp in api.get_stream(pr, s.session_id, "B>A").spans() if sp.data)
    d = api.describe_stream(pr, s.session_id, "B>A", 0, 10**9)
    json.dumps(d)
    assert bytes.fromhex("".join(sp["hex"] for sp in d["spans"] if sp["hex"])) == raw
    assert d["window"]["truncated"] is False


def test_gap_has_no_hex_not_zeros(tmp_path):
    pr, sid = load(tmp_path, "def_loss.pcap")
    s = api.list_sessions(pr, sid)[0]
    d = api.describe_stream(pr, s.session_id, "B>A", 0, 10**9)
    gaps = [sp for sp in d["spans"] if sp["kind"] == "gap"]
    assert gaps and all(g["hex"] is None for g in gaps)


def test_conflict_is_visible_with_both_variants(tmp_path):
    pr, sid = load(tmp_path, "def_conflict.pcap")
    found = []
    for s in api.list_sessions(pr, sid):
        for dirn in ("A>B", "B>A"):
            found += api.describe_stream(pr, s.session_id, dirn, 0, 10**9)["conflicts"]
    assert found and found[0]["kept"]["hex"] != found[0]["other"]["hex"]


def test_window_is_clipped_and_marked_truncated(tmp_path):
    pr, sid = load(tmp_path, "rec01.pcapng")
    s = api.list_sessions(pr, sid)[0]
    d = api.describe_stream(pr, s.session_id, "B>A", 4, 10)
    assert d["window"]["truncated"] is True and d["window"]["offset"] == 4
    total = sum(sp["end"] - sp["start"] for sp in d["spans"])
    assert total == 10 and d["spans"][0]["start"] == 4 and d["spans"][0]["clipped"] is True
