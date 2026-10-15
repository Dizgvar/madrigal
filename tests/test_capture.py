"""Тесты capture: неподдерживаемое диагностируется, не падает."""
import struct

import pytest

from lab.capture import CaptureError, parse_frame, Frame  


def _eth(ethertype: int) -> bytes:
    return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + struct.pack(">H", ethertype)


def _ipv4(proto: int, payload: bytes = b"") -> bytes:
    total = 20 + len(payload)
    ip = struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0x4000, 64, proto, 0) \
         + b"\x7f\x00\x00\x01" + b"\x7f\x00\x00\x01"
    return ip + payload


def _frame(pkt_no: int, data: bytes, linktype: int = 1) -> Frame:
    return Frame(pkt_no=pkt_no, ts_us=0, data=data, orig_len=len(data),
                 linktype=linktype, iface=0)


def test_ipv6_is_skipped_not_crash():
    fr = _frame(1, _eth(0x86DD) + b"\x00" * 40)
    seg, why = parse_frame(fr)
    assert seg is None and why == "ipv6"


def test_arp_is_skipped():
    fr = _frame(1, _eth(0x0806) + b"\x00" * 28)
    seg, why = parse_frame(fr)
    assert seg is None and why == "arp"


def test_udp_is_skipped():
    fr = _frame(1, _eth(0x0800) + _ipv4(proto=17))
    seg, why = parse_frame(fr)
    assert seg is None and why == "not_tcp"


def test_ip_fragment_is_skipped():
    # MF=1
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20, 0, 0x2000, 64, 6, 0) \
         + b"\x7f\x00\x00\x01" + b"\x7f\x00\x00\x01"
    fr = _frame(1, _eth(0x0800) + ip)
    seg, why = parse_frame(fr)
    assert seg is None and why == "ip_fragment"


def test_unsupported_linktype_is_skipped():
    """linktype != 1 не роняет программу — попадает в skipped."""
    fr = _frame(1, b"\x00" * 60, linktype=101)
    seg, why = parse_frame(fr)
    assert seg is None and why == "linktype_101"


def test_truncated_ethernet_is_skipped():
    fr = _frame(1, b"\x02\x00\x00\x00\x00\x01")
    seg, why = parse_frame(fr)
    assert seg is None and why == "truncated_ethernet"


def test_ip_total_length_zero_is_skipped():
    """Типичный TSO/GSO на хосте — не падать, а диагностировать."""
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 0, 0, 0x4000, 64, 6, 0) \
         + b"\x7f\x00\x00\x01" + b"\x7f\x00\x00\x01"
    tcp = struct.pack(">HHIIBBHHH", 1, 2, 0, 0, 5 << 4, 0x18, 0, 0, 0)
    fr = _frame(1, _eth(0x0800) + ip + tcp)
    seg, why = parse_frame(fr)
    assert seg is None and why == "ip_total_length_zero"

def test_load_segments_counts_skipped(tmp_path):
    """Смешанный файл: 1 TCP + 1 IPv6 + 1 UDP → diag["skipped:ipv6"] == 1 и т.д."""
    from collections import Counter
    from lab.capture import load_segments
    diag = Counter()
    segs = load_segments(tmp_path / "mixed.pcap", diag)
    assert len(segs) == 1
    assert diag["skipped:ipv6"] == 1
    assert diag["skipped:not_tcp"] == 1




    
