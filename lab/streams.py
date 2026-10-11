"""M2. Сессии и сборка направленных потоков. Правило: неизвестное - это дыра (gap), а не нули."""
import bisect
import hashlib
from collections import Counter, namedtuple

from .capture import ACK, FIN, RST, SYN, file_sha256, load_segments

MAX_STREAM_BYTES = 256 << 20
Piece = namedtuple("Piece", "start end data pkt_no payload_off")   # принятые байты потока [start,end)
Conflict = namedtuple("Conflict", "start end kept_pkt kept_data new_pkt new_data new_off")
Span = namedtuple("Span", "start end kind data note")              # kind: known | gap | conflict


class Session:
    def __init__(self, source_id, number, a, b, roles_known):
        self.source_id, self.number = source_id, number
        self.session_id = "%s:%d" % (source_id[:12], number)
        self.a, self.b, self.roles_known = a, b, roles_known     # A - инициатор, если роли известны
        self.segments = {"A>B": [], "B>A": []}
        self.isn = {}               # направление -> сырой seq пакета SYN
        self.fin_dirs, self.rst, self.has_data = set(), False, False

    def direction_of(self, seg):
        return "A>B" if seg.src == self.a else "B>A"

    @property
    def closed(self):
        return self.rst or len(self.fin_dirs) == 2

    def add(self, seg):
        d = self.direction_of(seg)
        self.segments[d].append(seg)
        if seg.flags & SYN:
            self.isn.setdefault(d, seg.seq)
        if seg.flags & FIN:
            self.fin_dirs.add(d)
        if seg.flags & RST:
            self.rst = True
        if seg.declared_len:
            self.has_data = True

    @property
    def n_packets(self):
        return sum(len(v) for v in self.segments.values())


def _starts_new(s, seg):
    if not (seg.flags & SYN) or (seg.flags & ACK):           # открывает только «чистый» SYN
        return False
    if s.closed or not s.roles_known:
        return True
    isn = s.isn.get(s.direction_of(seg))
    return (isn != seg.seq) if isn is not None else s.has_data   # тот же ISN - повтор SYN


def split_sessions(segments, source_id):
    """Разные соединения не смешиваются: ключ - пара адресов, но новый SYN после закрытия
    (или с другим ISN) - это НОВАЯ сессия."""
    sessions, current = [], {}
    for seg in segments:
        key = frozenset((seg.src, seg.dst))
        s = current.get(key)
        if s is not None and _starts_new(s, seg):
            s = None
        if s is None:
            if (seg.flags & SYN) and not (seg.flags & ACK):
                a, b, known = seg.src, seg.dst, True
            elif seg.flags & SYN:                            # SYN-ACK отправил ответчик
                a, b, known = seg.dst, seg.src, True
            else:
                a, b = sorted([seg.src, seg.dst])
                known = False                                # начала нет - роли НЕ известны
            s = Session(source_id, len(sessions) + 1, a, b, known)
            sessions.append(s)
            current[key] = s
        s.add(seg)
    return sessions


def _unwrap(seqs):
    """32-битные seq -> «длинные» числа (переход через 2**32 не ломает порядок)."""
    out, last = [], None
    for q in seqs:
        if last is None:
            u = q
        else:
            d = (q - last) & 0xFFFFFFFF
            u = last + (d - (1 << 32) if d >= 0x80000000 else d)
        out.append(u)
        last = u
    return out


def _merge(ranges):
    out = []
    for a, b in sorted(ranges):
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out


class DirectedStream:
    def __init__(self, session, direction, overlap_policy, checksum_policy):
        self.session, self.direction = session, direction
        self.overlap_policy, self.checksum_policy = overlap_policy, checksum_policy
        self.pieces, self.dups, self.conflicts = [], [], []
        self.truncated, self.excluded = [], []   # (start, declared_end, pkt_no)
        self.start_known, self.end_pos = False, None
        self.base_raw = 0
        self.warnings, self.error = [], None
        self._hash = None

    @property
    def known_bytes(self):
        return sum(p.end - p.start for p in self.pieces)

    # --- добавление байтов ---
    def _add(self, s, e, data, pkt, poff):
        if not self.pieces or s >= self.pieces[-1].end:       # быстрый путь: данные по порядку
            self.pieces.append(Piece(s, e, data, pkt, poff))
            return
        key = lambda p: p.start
        j = max(bisect.bisect_right(self.pieces, s, key=key) - 1, 0)
        cur, free = s, []
        while cur < e:
            while j < len(self.pieces) and self.pieces[j].end <= cur:
                j += 1
            if j >= len(self.pieces) or self.pieces[j].start >= e:
                free.append((cur, e))
                break
            p = self.pieces[j]
            if p.start > cur:
                free.append((cur, p.start))
                cur = p.start
            o_end = min(e, p.end)
            old = p.data[cur - p.start:o_end - p.start]
            new = data[cur - s:o_end - s]
            if old == new:
                self.dups.append(Piece(cur, o_end, new, pkt, poff + cur - s))
            else:
                self.conflicts.append(Conflict(cur, o_end, p.pkt_no, old, pkt, new, poff + cur - s))
            cur = o_end
            j += 1
        for a, b in free:
            bisect.insort(self.pieces, Piece(a, b, data[a - s:b - s], pkt, poff + a - s), key=key)

    # --- представление ---
    def _gap_reason(self, a, b):
        if any(t[0] < b and t[1] > a for t in self.excluded):
            return "excluded_by_checksum_policy"
        if any(t[0] < b and t[1] > a for t in self.truncated):
            return "truncated_capture"
        return "not_captured"

    def spans(self):
        """Поток целиком: known / conflict / gap. У gap data=None (никаких нулей)."""
        out, pos = [], 0
        cr = _merge([(c.start, c.end) for c in self.conflicts])

        def put(a, b, kind, data, note=""):
            if b <= a:
                return
            if out and out[-1][2] == kind == "known" and out[-1][1] == a:
                out[-1][1] = b
                out[-1][3].append(data)
            else:
                out.append([a, b, kind, [data] if data is not None else None, note])

        for p in self.pieces:
            if p.start > pos:
                put(pos, p.start, "gap", None, self._gap_reason(pos, p.start))
            cur = p.start
            for cs, ce in cr:
                if ce <= cur or cs >= p.end:
                    continue
                a, b = max(cs, p.start), min(ce, p.end)
                if a > cur:
                    put(cur, a, "known", p.data[cur - p.start:a - p.start])
                hide = self.overlap_policy == "unknown"
                put(a, b, "conflict", None if hide else p.data[a - p.start:b - p.start],
                    "overlap_with_different_data")
                cur = b
            if cur < p.end:
                put(cur, p.end, "known", p.data[cur - p.start:])
            pos = p.end
        if self.end_pos is not None and self.end_pos > pos:
            put(pos, self.end_pos, "gap", None, self._gap_reason(pos, self.end_pos))
        return [Span(a, b, k, (b"".join(c) if c is not None else None), n) for a, b, k, c, n in out]

    def trace(self, a, b):
        """Диапазон потока [a,b) -> пакеты и байты источника (обратный переход)."""
        res = []
        for role, items in (("data", self.pieces), ("duplicate", self.dups)):
            for p in items:
                if p.start < b and p.end > a:
                    lo, hi = max(a, p.start), min(b, p.end)
                    res.append({"role": role, "pkt_no": p.pkt_no, "payload_off": p.payload_off + lo - p.start,
                                "len": hi - lo, "stream_start": lo, "stream_end": hi})
        for c in self.conflicts:
            if c.start < b and c.end > a:
                lo, hi = max(a, c.start), min(b, c.end)
                res.append({"role": "conflict_variant", "pkt_no": c.new_pkt, "payload_off": c.new_off + lo - c.start,
                            "len": hi - lo, "stream_start": lo, "stream_end": hi})
        return sorted(res, key=lambda r: (r["stream_start"], r["pkt_no"]))

    def assembly_hash(self):
        """Отпечаток результата сборки: меняется, если изменились байты, политики или происхождение."""
        if self._hash is None:
            h = hashlib.sha256(("%s|%s|%s|%s" % (self.session.session_id, self.direction,
                                                 self.overlap_policy, self.checksum_policy)).encode())
            for p in self.pieces:
                h.update(b"%d,%d,%d;" % (p.start, p.end, p.pkt_no))
                h.update(p.data)
            self._hash = h.hexdigest()
        return self._hash

    def anchor(self, a, b):
        """Якорь происхождения: что именно в источнике соответствует [a,b)."""
        vis = []
        for s in self.spans():
            if s.data is not None and s.start < b and s.end > a:
                vis.append(s.data[max(a, s.start) - s.start:min(b, s.end) - s.start])
        vis = b"".join(vis)
        return {"source_id": self.session.source_id, "session_id": self.session.session_id,
                "direction": self.direction, "seq_start": (self.base_raw + a) & 0xFFFFFFFF,
                "length": b - a, "stream_off": a, "packets": self.trace(a, b),
                "bytes_sha256": hashlib.sha256(vis).hexdigest(), "assembly_hash": self.assembly_hash()}


def build_stream(session, direction, overlap_policy="first", checksum_policy="report"):
    """overlap_policy: first (побеждают первые пришедшие байты) | unknown (конфликт = неизвестно).
    checksum_policy: report (оставить, но показать) | strict (исключить 'bad') | ignore."""
    st = DirectedStream(session, direction, overlap_policy, checksum_policy)
    segs = session.segments[direction]
    uw = _unwrap([s.seq for s in segs])
    syn_u = next((u for s, u in zip(segs, uw) if s.flags & SYN), None)
    items = []
    for s, u in zip(segs, uw):
        ud = u + (1 if s.flags & SYN else 0)                  # SYN занимает один номер
        if checksum_policy == "strict" and s.checksum == "bad":
            st.excluded.append((ud, ud + s.declared_len, s.pkt_no))
            continue
        items.append((s, ud))
    cand = [ud for s, ud in items if s.declared_len > 0]
    if syn_u is not None:
        base, st.start_known = syn_u + 1, True
    elif cand:
        base = min(cand)
        st.warnings.append("начало соединения не видно: позиция 0 = первый наблюдаемый байт, а не начало потока")
    else:
        return st
    st.base_raw = base & 0xFFFFFFFF
    st.excluded = [(a - base, b - base, p) for a, b, p in st.excluded]
    for s, ud in items:
        start = ud - base
        if s.flags & FIN:
            st.end_pos = max(st.end_pos or 0, start + s.declared_len)
        if s.declared_len == 0:
            continue
        if start < 0:
            st.warnings.append("пакет %d: данные раньше начала потока, пропущен" % s.pkt_no)
            continue
        if len(s.payload) < s.declared_len:
            st.truncated.append((start, start + s.declared_len, s.pkt_no))
        if s.payload:
            st._add(start, start + len(s.payload), s.payload, s.pkt_no, s.payload_off)
        if st.known_bytes > MAX_STREAM_BYTES:
            raise MemoryError("LIMIT_EXCEEDED: поток больше %d байт" % MAX_STREAM_BYTES)
    if st.conflicts:
        st.warnings.append("%d перекрытий с РАЗНЫМИ данными (политика: %s)" % (len(st.conflicts), overlap_policy))
    if st.truncated:
        st.warnings.append("%d пакетов обрезаны при захвате (snaplen)" % len(st.truncated))
    if st.end_pos is None and not session.rst:
        st.warnings.append("конец потока не виден (нет FIN/RST)")
    return st


def build_all(sessions, overlap_policy="first", checksum_policy="report"):
    """Все потоки. Ошибка одной сессии записывается в .error и НЕ останавливает остальные."""
    res = {}
    for s in sessions:
        for d in ("A>B", "B>A"):
            try:
                res[(s.session_id, d)] = build_stream(s, d, overlap_policy, checksum_policy)
            except Exception as e:                            # noqa: BLE001 - сознательно: изоляция сессий
                st = DirectedStream(s, d, overlap_policy, checksum_policy)
                st.error = "%s: %s" % (type(e).__name__, e)
                res[(s.session_id, d)] = st
    return res


def import_source(path, progress=None):
    """Файл -> (source_id, сессии, диагностика)."""
    diag = Counter()
    sid = file_sha256(path)
    return sid, split_sessions(load_segments(path, diag, progress), sid), diag
