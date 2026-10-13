"""Регрессии, найденные при ревью: каждый тест падал на старом коде."""
import struct
import time

import pytest

from lab import api
from lab.capture import ACK, SYN, CaptureError, Segment, load_segments
from lab.streams import build_stream, split_sessions
from tools.stand import make_stand as ms

C, S = ("10.0.0.5", 51000), ("10.0.0.9", 5020)


def seg(pkt, seq, payload=b"", flags=ACK, declared=None, checksum="ok"):
    return Segment(pkt, pkt * 1000, C, S, seq, 0, flags, payload,
                   len(payload) if declared is None else declared, 66, checksum)


def stream_of(segs, **kw):
    return build_stream(split_sessions(segs, "f" * 64)[0], "A>B", **kw)


def test_truncated_last_packet_without_fin_leaves_tail_gap():
    st = stream_of([seg(1, 99, flags=SYN), seg(2, 100, b"AAAA"), seg(3, 104, b"BB", declared=6)])
    last = st.spans()[-1]
    assert last.kind == "gap" and (last.start, last.end) == (6, 10) and last.data is None
    assert any("конец потока не виден" in w for w in st.warnings)    # конец по-прежнему НЕ объявлен известным


def test_bad_checksum_is_reported_to_user():
    segs = [seg(1, 99, flags=SYN), seg(2, 100, b"AAAA", checksum="bad")]
    assert any("checksum" in w for w in stream_of(segs, checksum_policy="report").warnings)
    assert any("ИСКЛЮЧЕНО" in w for w in stream_of(segs, checksum_policy="strict").warnings)


def test_long_stream_is_not_quadratic():
    segs = [seg(1, 99, flags=SYN)] + [seg(i + 2, 100 + i * 10, b"x" * 10) for i in range(20000)]
    t = time.time()
    st = stream_of(segs)
    assert st.known_bytes == 200000
    assert time.time() - t < 2.0          # было ~7.7 c


def _blk(t, body):
    pad = (-len(body)) % 4
    tot = 12 + len(body) + pad
    return struct.pack("<II", t, tot) + body + b"\0" * pad + struct.pack("<I", tot)


def test_broken_pcapng_gives_capture_error_not_struct_error(tmp_path):
    shb = _blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = _blk(1, struct.pack("<HHI", 1, 0, 65535))
    (tmp_path / "bad.pcapng").write_bytes(shb + idb + _blk(6, b"\0" * 8))
    with pytest.raises(CaptureError):
        load_segments(tmp_path / "bad.pcapng")


def test_reopened_project_can_show_streams(tmp_path):
    pr = api.create_project(tmp_path / "p", "t")
    stand = tmp_path / "stand"
    ms.main(stand)
    sid = api.import_capture(pr, stand / "rec01.pcapng")["source_id"]
    first = api.list_sessions(pr, sid)[0]
    expected = api.get_stream(pr, first.session_id, "B>A").known_bytes
    again = api.open_project(tmp_path / "p")
    assert len(api.list_sessions(again, sid)) == 2
    assert api.get_stream(again, first.session_id, "B>A").known_bytes == expected
