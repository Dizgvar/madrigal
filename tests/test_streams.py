"""Тесты сборки потока: по одному на каждую ситуацию из раздела 7.3 кейса."""
from lab.capture import ACK, FIN, SYN, Segment
from lab.streams import build_all, build_stream, split_sessions

C, S = ("10.0.0.5", 51000), ("10.0.0.9", 5020)


def seg(pkt, seq, payload=b"", flags=ACK, src=C, dst=S, declared=None, checksum="ok"):
    return Segment(pkt, pkt * 1000, src, dst, seq, 0, flags, payload,
                   len(payload) if declared is None else declared, 66, checksum)


def stream_of(segs, direction="A>B", **kw):
    ss = split_sessions(segs, "f" * 64)
    assert len(ss) == 1
    return build_stream(ss[0], direction, **kw)


def known(st):
    return b"".join(s.data for s in st.spans() if s.kind == "known")


HS = [seg(1, 99, flags=SYN), seg(2, 500, flags=SYN | ACK, src=S, dst=C)]   # рукопожатие: данные с seq 100


def test_in_order():
    st = stream_of(HS + [seg(3, 100, b"AAAA"), seg(4, 104, b"BBBB")])
    assert known(st) == b"AAAABBBB" and st.start_known and st.session.roles_known


def test_reorder():
    st = stream_of(HS + [seg(3, 104, b"BBBB"), seg(4, 100, b"AAAA")])
    assert known(st) == b"AAAABBBB"
    assert [s.kind for s in st.spans()] == ["known"]


def test_identical_retransmission_not_duplicated():
    st = stream_of(HS + [seg(3, 100, b"AAAA"), seg(4, 100, b"AAAA"), seg(5, 104, b"BB")])
    assert known(st) == b"AAAABB"
    assert [d.pkt_no for d in st.dups] == [4]                              # пакет-повтор сохранён
    assert {r["role"] for r in st.trace(0, 4)} == {"data", "duplicate"}


def test_loss_is_gap_not_zeros():
    st = stream_of(HS + [seg(3, 100, b"AAAA"), seg(4, 108, b"CCCC")])
    sp = st.spans()
    assert [s.kind for s in sp] == ["known", "gap", "known"]
    assert sp[1].data is None and (sp[1].start, sp[1].end) == (4, 8) and sp[1].note == "not_captured"
    assert b"\x00" not in known(st)


def test_snaplen_truncation_marked():
    st = stream_of(HS + [seg(3, 100, b"AA", declared=4), seg(4, 104, b"CC")])
    sp = st.spans()
    assert sp[1].kind == "gap" and sp[1].note == "truncated_capture" and (sp[1].start, sp[1].end) == (2, 4)


def test_conflict_visible_policy_first_and_unknown():
    segs = HS + [seg(3, 100, b"AAAA"), seg(4, 100, b"AXAA")]
    st = stream_of(segs)
    c = [s for s in st.spans() if s.kind == "conflict"]
    assert len(st.conflicts) == 1 and len(c) == 1 and (c[0].start, c[0].end) == (0, 4) and c[0].data == b"AAAA"
    assert any(r["role"] == "conflict_variant" and r["pkt_no"] == 4 for r in st.trace(0, 4))
    st2 = stream_of(segs, overlap_policy="unknown")
    assert [s for s in st2.spans() if s.kind == "conflict"][0].data is None


def test_no_handshake_roles_unknown():
    st = stream_of([seg(3, 100, b"AAAA"), seg(4, 104, b"BB")])
    assert not st.start_known and not st.session.roles_known and known(st) == b"AAAABB"
    assert any("начало" in w for w in st.warnings)


def test_checksum_policies():
    segs = HS + [seg(3, 100, b"AAAA"), seg(4, 104, b"BBBB", checksum="bad"), seg(5, 108, b"CC")]
    assert known(stream_of(segs, checksum_policy="report")) == b"AAAABBBBCC"
    st = stream_of(segs, checksum_policy="strict")
    assert [s.kind for s in st.spans()] == ["known", "gap", "known"]
    assert st.spans()[1].note == "excluded_by_checksum_policy"


def test_port_reuse_makes_new_session():
    a = [seg(1, 99, flags=SYN), seg(2, 100, b"AA"), seg(3, 102, flags=FIN | ACK)]
    b = [seg(4, 7000, flags=SYN), seg(5, 7001, b"ZZ")]
    ss = split_sessions(a + b, "f" * 64)
    assert len(ss) == 2 and ss[0].session_id != ss[1].session_id

def test_new_syn_after_rst_makes_new_session():
    """RST обрывает сессию — следующий SYN открывает новую."""
    a = [seg(1, 99, flags=SYN), seg(2, 100, b"AA"), seg(3, 102, flags=RST)]
    b = [seg(4, 7000, flags=SYN), seg(5, 7001, b"ZZ")]
    ss = split_sessions(a + b, "f" * 64)
    assert len(ss) == 2


def test_new_syn_different_isn_makes_new_session():
    """Тот же SYN-флаг, но другой ISN — новая сессия (переустановка соединения)."""
    a = [seg(1, 99, flags=SYN), seg(2, 100, b"AA")]
    b = [seg(3, 5000, flags=SYN), seg(4, 5001, b"ZZ")]
    ss = split_sessions(a + b, "f" * 64)
    assert len(ss) == 2


def test_syn_retransmission_same_session():
    ss = split_sessions([seg(1, 99, flags=SYN), seg(2, 99, flags=SYN), seg(3, 100, b"A")], "f" * 64)
    assert len(ss) == 1


def test_seq_wraparound():
    st = stream_of([seg(1, 0xFFFFFFFC, b"AAAA"), seg(2, 0, b"BBBB")])
    assert known(st) == b"AAAABBBB"

def test_seq_wraparound_with_syn():
    """SYN около 2**32, данные переходят через ноль."""
    st = stream_of([
        seg(1, 0xFFFFFFFE, flags=SYN),           # ISN = 2**32-2
        seg(2, 0xFFFFFFFF, b"AAAA"),              # данные с 2**32-1
        seg(3, 0, b"BBBB"),                       # seq перескочил через ноль
        seg(4, 4, b"CCCC"),
    ])
    assert known(st) == b"AAAABBBBCCCC"
    assert st.start_known


def test_tail_gap_when_fin_seen():
    st = stream_of(HS + [seg(3, 100, b"AA"), seg(4, 104, flags=FIN | ACK)])
    assert st.spans()[-1].kind == "gap" and (st.spans()[-1].start, st.spans()[-1].end) == (2, 4)


def test_error_in_one_session_does_not_block_others(monkeypatch):
    import lab.streams as m
    ss = split_sessions(HS + [seg(3, 100, b"A")] + [seg(10, 5, flags=SYN, src=("1.1.1.1", 1), dst=("2.2.2.2", 2))], "f" * 64)
    orig = m.build_stream
    monkeypatch.setattr(m, "build_stream", lambda s, d, *a: (_ for _ in ()).throw(ValueError("boom")) if s.number == 1 else orig(s, d, *a))
    res = build_all(ss)
    assert res[(ss[0].session_id, "A>B")].error and res[(ss[1].session_id, "A>B")].error is None
