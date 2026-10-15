"""Представления для интерфейса: объекты потока и сессии -> обычные словари, пригодные для JSON.

Здесь нет логики сборки, только упаковка готовых результатов. Правило то же: дыра (gap)
имеет hex=None, а не строку из нулей. Усечение показа всегда помечено явно.
"""
import logging

from .models import DirectedStream, Session

log = logging.getLogger(__name__)

DEFAULT_WINDOW = 64 * 1024     # сколько байт потока показывать за один запрос


def _hex(data):
    return None if data is None else data.hex()


def stream_to_dict(stream: DirectedStream, offset: int = 0, limit: int = DEFAULT_WINDOW) -> dict:
    """Поток -> словарь для интерфейса. Показывает окно [offset, offset+limit).

    Куски, частично попавшие в окно, обрезаются и помечаются clipped=True.
    Если окно не охватывает весь поток, window.truncated=True (молча не обрезаем).

    Пример:
        >>> d = stream_to_dict(stream, 0, 32)
        >>> d["spans"][0]["kind"], d["window"]["truncated"]
        ('known', True)
    """
    if offset < 0 or limit <= 0:
        raise ValueError("offset must be >= 0 and limit > 0")
    spans = stream.spans()
    total = spans[-1].end if spans else 0
    lo, hi = offset, offset + limit
    out = []
    for s in spans:
        if s.end <= lo or s.start >= hi:
            continue
        a, b = max(s.start, lo), min(s.end, hi)
        data = None if s.data is None else s.data[a - s.start:b - s.start]
        out.append({"start": a, "end": b, "kind": s.kind, "note": s.note,
                    "hex": _hex(data), "clipped": (a, b) != (s.start, s.end)})
    conflicts = [{"start": c.start, "end": c.end,
                  "kept": {"pkt_no": c.kept_pkt, "hex": c.kept_data.hex()},
                  "other": {"pkt_no": c.new_pkt, "hex": c.new_data.hex()}}
                 for c in stream.conflicts if c.start < hi and c.end > lo]
    sess = stream.session
    return {
        "session_id": sess.session_id,
        "direction": stream.direction,
        "roles_known": sess.roles_known,
        "start_known": stream.start_known,
        "known_bytes": stream.known_bytes,
        "total_len": total,
        "overlap_policy": stream.overlap_policy,
        "checksum_policy": stream.checksum_policy,
        "warnings": list(stream.warnings),
        "error": stream.error,
        "window": {"offset": offset, "end": min(hi, total), "total": total,
                   "truncated": total > hi or offset > 0},
        "spans": out,
        "conflicts": conflicts,
    }


def session_to_dict(session: Session, streams: dict) -> dict:
    """Сессия и её два направления -> строка таблицы «Сессии».

    streams: {"A>B": DirectedStream, "B>A": DirectedStream}.
    Если роли неизвестны, role_label = "роли неизвестны" (слов «клиент/сервер» нет).
    """
    dirs = {}
    for d, st in streams.items():
        spans = st.spans()
        dirs[d] = {"known_bytes": st.known_bytes,
                   "gaps": sum(1 for s in spans if s.kind == "gap"),
                   "conflicts": len(st.conflicts),
                   "warnings": list(st.warnings),
                   "error": st.error}
    return {
        "session_id": session.session_id,
        "a": "%s:%d" % session.a,
        "b": "%s:%d" % session.b,
        "roles_known": session.roles_known,
        "role_label": "A = инициатор" if session.roles_known else "роли неизвестны",
        "n_packets": session.n_packets,
        "directions": dirs,
    }
