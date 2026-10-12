"""M1. Чтение PCAP/PCAPNG и разбор Ethernet/IPv4/TCP. Исходный файл только читается."""
import hashlib
import struct
from collections import Counter
from dataclasses import dataclass

SYN, FIN, RST, ACK = 0x02, 0x01, 0x04, 0x10
LIMITS = {"max_file_bytes": 512 << 20, "max_frames": 1_000_000, "max_frame_len": 1 << 20}


class CaptureError(Exception):
    """Файл нельзя прочитать. Первое слово сообщения - код ошибки."""


@dataclass(frozen=True)
class Frame:
    pkt_no: int      # с 1, как в Wireshark
    ts_us: int       # время в точке захвата, микросекунды от 1970
    data: bytes      # захваченные байты кадра
    orig_len: int    # длина кадра на проводе
    linktype: int
    iface: int


@dataclass(frozen=True)
class Segment:
    pkt_no: int
    ts_us: int
    src: tuple         # (ip, port)
    dst: tuple
    seq: int           # сырой TCP seq 0..2**32-1
    ack: int
    flags: int
    payload: bytes     # реально захваченные байты данных
    declared_len: int  # сколько данных заявлено заголовками IP/TCP
    payload_off: int   # смещение данных от начала кадра
    checksum: str      # "ok" | "bad" | "unverified"


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------- контейнеры ----------
_PCAP_MAGIC = {  # магия -> (порядок байтов, наносекунды?)
    b"\xd4\xc3\xb2\xa1": ("<", False), b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True), b"\xa1\xb2\x3c\x4d": (">", True),
}


def read_frames(path, diag):
    """Генератор Frame. Всё необычное считает в diag (Counter)."""
    import os
    if os.path.getsize(path) > LIMITS["max_file_bytes"]:
        raise CaptureError("LIMIT_EXCEEDED: файл больше %d байт" % LIMITS["max_file_bytes"])
    with open(path, "rb") as f:
        magic = f.read(4)
        f.seek(0)
        if magic == b"\x0a\x0d\x0d\x0a":
            yield from _read_pcapng(f, diag)
        elif magic in _PCAP_MAGIC:
            yield from _read_pcap(f, diag)
        else:
            raise CaptureError("NOT_A_CAPTURE: первые байты %s - не pcap и не pcapng" % magic.hex())


def _read_pcap(f, diag):
    endian, nano = _PCAP_MAGIC[f.read(4)]
    hdr = f.read(20)
    if len(hdr) < 20:
        raise CaptureError("TRUNCATED_FILE: оборван заголовок pcap")
    _vmaj, _vmin, _tz, _sig, _snaplen, link = struct.unpack(endian + "HHiIII", hdr)
    n = 0
    while True:
        rh = f.read(16)
        if not rh:
            return
        if len(rh) < 16:
            diag["file_truncated"] += 1
            return
        sec, frac, incl, orig = struct.unpack(endian + "IIII", rh)
        if incl > LIMITS["max_frame_len"]:
            raise CaptureError("BAD_RECORD: кадр %d заявляет длину %d" % (n + 1, incl))
        data = f.read(incl)
        if len(data) < incl:
            diag["file_truncated"] += 1
            return
        n += 1
        yield Frame(n, sec * 1_000_000 + (frac // 1000 if nano else frac), data, orig, link, 0)


def _units(tsres):
    return 2 ** (tsres & 0x7F) if tsres & 0x80 else 10 ** tsres


def _read_pcapng(f, diag):
    endian, ifaces, n = "<", [], 0     # ifaces: [(linktype, единиц в секунде)]
    while True:
        head = f.read(8)
        if not head:
            return
        if len(head) < 8:
            diag["file_truncated"] += 1
            return
        if head[:4] == b"\x0a\x0d\x0d\x0a":            # Section Header Block
            bom = f.read(4)
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise CaptureError("BAD_PCAPNG: неизвестный порядок байтов в SHB")
            total = struct.unpack(endian + "I", head[4:8])[0]
            f.read(max(total - 12, 0))
            ifaces = []                                # новая секция - новые интерфейсы
            continue
        btype, total = struct.unpack(endian + "II", head)
        if total < 12 or total % 4:
            raise CaptureError("BAD_PCAPNG: блок с длиной %d" % total)
        body = f.read(total - 8)
        if len(body) < total - 8:
            diag["file_truncated"] += 1
            return
        body = body[:-4]                               # хвостовая копия длины
        if btype == 1:                                 # Interface Description Block
            link, _res, _snap = struct.unpack(endian + "HHI", body[:8])
            tsres, off = 6, 8
            while off + 4 <= len(body):
                code, ln = struct.unpack(endian + "HH", body[off:off + 4])
                if code == 0:
                    break
                if code == 9 and ln == 1:
                    tsres = body[off + 4]
                off += 4 + ln + (-ln) % 4
            ifaces.append((link, _units(tsres)))
        elif btype == 6:                               # Enhanced Packet Block
            iface, th, tl, cap, orig = struct.unpack(endian + "IIIII", body[:20])
            if iface >= len(ifaces):
                diag["pcapng_bad_interface"] += 1
                continue
            if cap > LIMITS["max_frame_len"]:
                raise CaptureError("BAD_RECORD: кадр заявляет длину %d" % cap)
            link, units = ifaces[iface]
            n += 1
            yield Frame(n, ((th << 32) | tl) * 1_000_000 // units, body[20:20 + cap], orig, link, iface)
        elif btype in (2, 3):
            diag["pcapng_unsupported_packet_block_%d" % btype] += 1   # нумерация может разойтись с Wireshark
        # остальные блоки (статистика, имена, комментарии) безопасно пропускаем


# ---------- разбор кадра ----------
def _csum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def parse_frame(fr):
    """Frame -> (Segment, None) или (None, причина_пропуска)."""
    d = fr.data
    if fr.linktype != 1:
        return None, "linktype_%d" % fr.linktype
    if len(d) < 14:
        return None, "truncated_ethernet"
    et, off = int.from_bytes(d[12:14], "big"), 14
    while et in (0x8100, 0x88A8):                      # VLAN-теги
        if len(d) < off + 4:
            return None, "truncated_vlan"
        et, off = int.from_bytes(d[off + 2:off + 4], "big"), off + 4
    if et != 0x0800:
        return None, {0x86DD: "ipv6", 0x0806: "arp"}.get(et, "ethertype_0x%04x" % et)
    ip = d[off:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None, "bad_ipv4"
    ihl, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], "big")
    if ihl < 20 or len(ip) < ihl:
        return None, "bad_ipv4"
    if int.from_bytes(ip[6:8], "big") & 0x3FFF:
        return None, "ip_fragment"
    if ip[9] != 6:
        return None, "not_tcp"
    if total == 0:
        return None, "ip_total_length_zero"            # типично для TSO/GSO при захвате на хосте
    if total < ihl + 20:
        return None, "bad_ipv4"
    tcp = ip[ihl:total]                                # хвост кадра после total - выравнивание Ethernet
    if len(tcp) < 20:
        return None, "truncated_tcp"
    doff = (tcp[12] >> 4) * 4
    if doff < 20 or doff > total - ihl:
        return None, "bad_tcp_header"
    if len(tcp) < doff:
        return None, "truncated_tcp"
    declared = total - ihl - doff
    full = len(ip) >= total                            # весь TCP-сегмент есть в записи
    if full:
        pseudo = ip[12:20] + b"\x00\x06" + (total - ihl).to_bytes(2, "big")
        status = "ok" if _csum(pseudo + tcp) == 0xFFFF else "bad"
    else:
        status = "unverified"
    seg = Segment(
        pkt_no=fr.pkt_no, ts_us=fr.ts_us,
        src=(".".join(map(str, ip[12:16])), int.from_bytes(tcp[0:2], "big")),
        dst=(".".join(map(str, ip[16:20])), int.from_bytes(tcp[2:4], "big")),
        seq=int.from_bytes(tcp[4:8], "big"), ack=int.from_bytes(tcp[8:12], "big"),
        flags=tcp[13], payload=bytes(tcp[doff:]), declared_len=declared,
        payload_off=off + ihl + doff, checksum=status)
    return seg, None


def load_segments(path, diag=None, progress=None):
    """Файл -> список Segment. diag: Counter с причинами пропусков.
    progress(n) вызывается раз в 5000 кадров; чтобы отменить - бросьте из него исключение."""
    diag = diag if diag is not None else Counter()
    out = []
    for fr in read_frames(path, diag):
        if fr.pkt_no > LIMITS["max_frames"]:
            raise CaptureError("LIMIT_EXCEEDED: больше %d кадров" % LIMITS["max_frames"])
        diag["frames"] += 1
        seg, why = parse_frame(fr)
        if seg is None:
            diag["skipped:" + why] += 1
        else:
            out.append(seg)
        if progress and fr.pkt_no % 5000 == 0:
            progress(fr.pkt_no)
    return out
