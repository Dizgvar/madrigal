"""Сквозные тесты: стенд -> файл -> импорт -> сборка. Эталон берётся из самого генератора (не из имён файлов)."""
import tempfile
from pathlib import Path

import pytest

from lab.capture import CaptureError, load_segments
from lab.streams import build_all, import_source
from tools.stand import make_stand as ms


@pytest.fixture(scope="module")
def d():
    p = Path(tempfile.mkdtemp())
    ms.main(p)
    return p


def target(sessions):
    return max(sessions, key=lambda s: s.n_packets)        # самое «тяжёлое» соединение


def streams(path, **kw):
    sid, ss, diag = import_source(path)
    t = target(ss)
    r = build_all(ss, **kw)
    return t, r[(t.session_id, "A>B")], r[(t.session_id, "B>A")], diag, ss


def expected(actions, seed):
    return ms.session(actions, seed)[2]


@pytest.mark.parametrize("name,actions,seed", [("rec01.pcapng", ms.ACTIONS_1, 1), ("rec02.pcap", ms.ACTIONS_2, 2)])
def test_clean_files_reassemble_exactly(d, name, actions, seed):
    t, c2s, s2c, diag, ss = streams(d / name)
    exp = expected(actions, seed)
    assert t.roles_known and c2s.start_known
    assert b"".join(s.data for s in c2s.spans()) == exp["c2s"]
    assert b"".join(s.data for s in s2c.spans()) == exp["s2c"]
    assert diag["skipped:arp"] == 1 and len(ss) == 2          # ARP пропущен и посчитан; фон - отдельная сессия


def test_pcapng_nanoseconds_and_dpkt_crosscheck(d, tmp_path):
    pk, _, _ = ms.session(ms.ACTIONS_2, 2)
    ms.write_pcapng(tmp_path / "n.pcapng", pk, nano=True)
    ms.write_pcapng(tmp_path / "u.pcapng", pk)
    a, b = load_segments(tmp_path / "n.pcapng"), load_segments(tmp_path / "u.pcapng")
    assert [x.ts_us for x in a] == [x.ts_us for x in b]
    dpkt = pytest.importorskip("dpkt")
    with open(d / "rec01.pcapng", "rb") as f:
        ref = [(ts, len(buf)) for ts, buf in dpkt.pcapng.Reader(f)]
    mine = list(__import__("lab.capture", fromlist=["x"]).read_frames(d / "rec01.pcapng", __import__("collections").Counter()))
    assert len(ref) == len(mine) and all(abs(r[0] - m.ts_us / 1e6) < 1e-5 and r[1] == len(m.data) for r, m in zip(ref, mine))


def test_reorder_gives_same_bytes(d):
    _, c2s, s2c, *_ = streams(d / "def_reorder.pcap")
    assert b"".join(s.data for s in s2c.spans()) == expected(ms.ACTIONS_1, 1)["s2c"]


def test_dup_no_duplicate_bytes(d):
    _, c2s, s2c, *_ = streams(d / "def_dup.pcap")
    assert b"".join(s.data for s in s2c.spans()) == expected(ms.ACTIONS_1, 1)["s2c"] and len(s2c.dups) == 1


def test_loss_gap_of_exact_size(d):
    _, c2s, s2c, *_ = streams(d / "def_loss.pcap")
    gaps = [s for s in s2c.spans() if s.kind == "gap"]
    assert len(gaps) == 1 and gaps[0].end - gaps[0].start == ms.MSS and gaps[0].data is None


def test_snaplen_cut(d):
    _, c2s, s2c, *_ = streams(d / "def_snaplen.pcap")
    g = [s for s in s2c.spans() if s.kind == "gap"]
    assert len(g) == 1 and g[0].note == "truncated_capture"


def test_conflict_detected_with_packets(d):
    _, c2s, s2c, *_ = streams(d / "def_conflict.pcap")
    assert len(s2c.conflicts) == 1 and [s.kind for s in s2c.spans()].count("conflict") == 1


def test_no_start(d):
    t, c2s, s2c, *_ = streams(d / "def_nostart.pcap")
    assert not t.roles_known and not c2s.start_known


def test_badcsum_and_offload(d):
    segs = load_segments(d / "def_badcsum.pcap")
    assert sum(s.checksum == "bad" for s in segs) == 1
    segs = load_segments(d / "def_offload.pcap")
    assert sum(s.checksum == "bad" for s in segs) > 10          # все пакеты клиента «плохие» - это offloading


def test_garbage_file(tmp_path):
    (tmp_path / "x.pcap").write_bytes(b"hello world")
    with pytest.raises(CaptureError):
        load_segments(tmp_path / "x.pcap")


def test_truncated_file_does_not_crash(d, tmp_path):
    raw = (d / "rec02.pcap").read_bytes()
    (tmp_path / "cut.pcap").write_bytes(raw[:-7])
    from collections import Counter
    diag = Counter()
    load_segments(tmp_path / "cut.pcap", diag)
    assert diag["file_truncated"] == 1
