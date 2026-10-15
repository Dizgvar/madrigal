"""M7. Фасад: ЕДИНСТВЕННОЕ место, откуда веб-интерфейс и командная строка вызывают приложение.

Статус функций:
  РАБОТАЕТ  - настоящая реализация;
  ЗАГЛУШКА  - возвращает фиктивные данные правильного формата, чтобы остальные
              могли работать, пока модуль не готов. Заглушки помечены "stub": True.
"""
from pathlib import Path

from . import project as _project
from . import store as _store
from .models import Anchor, LabError
from .streams import build_all, build_stream, import_source
from .views import DEFAULT_WINDOW, session_to_dict, stream_to_dict


def create_project(path, name):
    """РАБОТАЕТ. Создаёт папку проекта (project.json, sources/, cache/)."""
    return _project.create_project(path, name)


def open_project(path, progress=None):
    """РАБОТАЕТ. Открывает проект и сверяет SHA-256 всех источников."""
    return _project.open_project(path, progress=progress)


def import_capture(project, path, progress=None):
    """РАБОТАЕТ. Копирует файл в sources/ проекта и разбирает копию.

    Повторный импорт того же содержимого (даже под другим именем) не создаёт дубль.
    Сессии пока держатся в памяти (SQLite-кэш будет позже).
    """
    added = _project.add_source(project.path, path)
    sid, sessions, diag = import_source(Path(project.path) / added.path, progress)
    if sid != added.source_id:
        raise LabError("SOURCE_CHANGED", "hash mismatch right after copy", source_id=added.source_id)
    entry = project.sources.setdefault(sid, {"path": added.path, "sessions": [], "diag": {}})
    entry["sessions"], entry["diag"] = sessions, dict(diag)
    return {"source_id": sid, "already_imported": added.already_added,
            "diag": dict(diag), "sessions": len(sessions)}


def list_sessions(project, source_id):
    """РАБОТАЕТ. Список Session источника.

    После open_project сессий в памяти нет (кэш - это то, что пересобирается), поэтому при первом
    обращении источник разбирается заново из sources/. Исходный файл только читается.
    """
    entry = project.sources[source_id]
    if not entry["sessions"]:
        sid, sessions, diag = import_source(Path(project.path) / entry["path"])
        if sid != source_id:
            raise LabError("SOURCE_CHANGED", "source content differs from its hash", source_id=source_id)
        entry["sessions"], entry["diag"] = sessions, dict(diag)
    return entry["sessions"]


def _policies(project) -> dict:
    r = _store.get_settings(project.path)["reassembly"]
    return {"overlap_policy": r["overlap_policy"], "checksum_policy": r["checksum_policy"]}


def get_stream(project, session_id, direction, overlap_policy=None, checksum_policy=None):
    """РАБОТАЕТ. DirectedStream нужной сессии и направления.

    Политики сборки по умолчанию берутся из настроек проекта (project.json), а не зашиты в код.
    """
    pol = _policies(project)
    overlap_policy = overlap_policy or pol["overlap_policy"]
    checksum_policy = checksum_policy or pol["checksum_policy"]
    prefix = session_id.split(":")[0]               # session_id = <12 символов source_id>:<номер>
    for sid in project.sources:
        if sid.startswith(prefix):
            for s in list_sessions(project, sid):
                if s.session_id == session_id:
                    return build_stream(s, direction, overlap_policy, checksum_policy)
    raise KeyError(session_id)


def describe_sessions(project, source_id) -> list:
    """РАБОТАЕТ. Сессии источника в виде словарей (для таблицы «Сессии», JSON-совместимо)."""
    sessions = list_sessions(project, source_id)
    built = build_all(sessions, **_policies(project))
    return [session_to_dict(s, {d: built[(s.session_id, d)] for d in ("A>B", "B>A")}) for s in sessions]


def describe_stream(project, session_id, direction, offset=0, limit=DEFAULT_WINDOW) -> dict:
    """РАБОТАЕТ. Поток для hex-просмотрщика: куски known/gap/conflict, hex, предупреждения.

    Показывает окно [offset, offset+limit); если поток больше, window.truncated=True.
    Дыра имеет hex=None. Слишком большой поток даёт error вместо исключения.
    """
    try:
        stream = get_stream(project, session_id, direction)
    except MemoryError as e:           # лимит размера: одна сессия не должна ломать остальные
        return {"session_id": session_id, "direction": direction, "error": str(e),
                "spans": [], "conflicts": [], "warnings": []}
    return stream_to_dict(stream, offset, limit)


def trace(project, session_id, direction, start, end) -> list:
    """РАБОТАЕТ. Диапазон потока [start, end) -> пакеты источника."""
    return get_stream(project, session_id, direction).trace(start, end)


def anchor(project, session_id, direction, start, end) -> Anchor:
    """РАБОТАЕТ. Якорь происхождения диапазона."""
    return get_stream(project, session_id, direction).anchor(start, end)


def find_by_action(project, action_id, window_s=2.0):
    """РАБОТАЕТ. Строка журнала (action_id = её idx) -> пакеты с данными в окне времени.

    Окно: capture_ts_us +- window_s, где capture_ts_us = время журнала минус clock_offset_s из настроек.
    Возвращает список словарей {session_id, direction, pkt_no, ts_us, payload_len, stream_start,
    stream_end}, по времени. stream_start/stream_end = None, если байты пакета не вошли в поток
    (например, это повторная передача). Пустой список значит «в окне пакетов с данными нет»;
    нет журнала или строки - это ошибка (LabError), а не пустой ответ.
    """
    actions = _store.read_actions(project.path)
    try:
        row = actions[int(action_id)]
    except (ValueError, IndexError, TypeError):
        raise LabError("BAD_ACTION", "no such action row", action_id=action_id, rows=len(actions)) from None
    if row["capture_ts_us"] is None:
        raise LabError("BAD_ACTION", "action time cannot be parsed: %s" % row["note"], action_id=action_id)
    lo = row["capture_ts_us"] - round(window_s * 1_000_000)
    hi = row["capture_ts_us"] + round(window_s * 1_000_000)
    out = []
    for sid in project.sources:
        for s in list_sessions(project, sid):
            for d in ("A>B", "B>A"):
                hits = [g for g in s.segments[d] if g.declared_len > 0 and lo <= g.ts_us <= hi]
                if not hits:
                    continue
                st = get_stream(project, s.session_id, d)
                where = {p.pkt_no: (p.start, p.end) for p in st.pieces}
                for g in hits:
                    a, b = where.get(g.pkt_no, (None, None))
                    out.append({"session_id": s.session_id, "direction": d, "pkt_no": g.pkt_no, "ts_us": g.ts_us,
                                "payload_len": g.declared_len, "stream_start": a, "stream_end": b})
    return sorted(out, key=lambda r: (r["ts_us"], r["pkt_no"]))


def compare(project, ranges):
    """НЕ РЕАЛИЗОВАНО (роль 3). Честно падает, а не возвращает пустой результат."""
    raise LabError("NOT_IMPLEMENTED", "compare() is not implemented yet")


# ---------------------------------------------------------------- настройки, журнал, наблюдения
def get_settings(project) -> dict:
    """РАБОТАЕТ. Настройки проекта (политики сборки, смещение часов журнала)."""
    return _store.get_settings(project.path)


def set_settings(project, patch) -> dict:
    """РАБОТАЕТ. Частичная смена настроек, например {"reassembly": {"overlap_policy": "unknown"}}."""
    return _store.set_settings(project.path, patch)


def load_actions(project, csv_path, columns=None, delimiter=","):
    """РАБОТАЕТ. Копирует журнал действий в проект; columns задаёт, какая колонка что значит."""
    return _store.load_actions(project.path, csv_path, columns, delimiter)


def list_actions(project):
    """РАБОТАЕТ. Строки журнала с временем журнала и временем в записи."""
    return _store.read_actions(project.path)


def add_observation(project, kind, text, anchors=None, author=""):
    """РАБОТАЕТ. Наблюдение / правило / гипотеза / контрпример. Без якоря - только гипотеза."""
    return _store.add_observation(project.path, kind, text, anchors, None, author)


def set_observation_status(project, obs_id, status, note="", anchors=None):
    """РАБОТАЕТ. Статус open / supported / refuted (refuted требует якорь контрпримера)."""
    return _store.set_observation_status(project.path, obs_id, status, note, anchors)


def list_observations(project):
    """РАБОТАЕТ. Все записи с актуальным статусом и историей."""
    return _store.list_observations(project.path)


def verify_anchor(project, anchor) -> dict:
    """РАБОТАЕТ. Проверка якоря заново по источнику: {"status": ok|stale|broken|missing, "reasons": [...]}.

    ok      байты те же и сборка та же;
    stale   байты те же, но изменились настройки сборки или происхождение (assembly_hash);
    broken  байты в этом месте другие (или диапазон вышел за поток);
    missing сессия или источник не найдены.
    """
    try:
        st = get_stream(project, anchor["session_id"], anchor["direction"])
    except KeyError:
        return {"status": "missing", "reasons": ["сессия %s не найдена в проекте" % anchor["session_id"]]}
    start = (anchor["seq_start"] - st.base_raw) & 0xFFFFFFFF      # привязка по TCP seq, а не по номеру куска
    if start > 1 << 30 or not st.pieces:
        return {"status": "broken", "reasons": ["seq_start не попадает в поток"]}
    now = st.anchor(start, start + anchor["length"])
    reasons = []
    if now["bytes_sha256"] != anchor["bytes_sha256"]:
        return {"status": "broken", "reasons": ["байты по якорю изменились"]}
    if now["stream_off"] != anchor.get("stream_off", now["stream_off"]):
        reasons.append("позиция в потоке изменилась: %s -> %s" % (anchor["stream_off"], now["stream_off"]))
    if now["assembly_hash"] != anchor["assembly_hash"]:
        reasons.append("сборка потока изменилась (настройки или происхождение байтов)")
    return {"status": "stale" if reasons else "ok", "reasons": reasons}


def apply_interpretation(project, stream, interp):
    """ЗАГЛУШКА (роль 4). Поток + интерпретация -> список ParsedMessage."""
    return [{"stub": True, "start": 0, "end": 8, "status": "COMPLETE",
             "fields": [{"name": "magic", "start": 0, "end": 2, "status": "RULE"},
                        {"name": "value", "start": 6, "end": 7, "status": "HYPOTHESIS"},
                        {"name": "?", "start": 7, "end": 8, "status": "UNKNOWN"}]}]


def validate(project, corpus, interp, settings):
    """ЗАГЛУШКА (роль 4). Проверка корпуса -> ValidationRun."""
    return {"stub": True, "run_id": "run-0001", "sessions": 2, "messages": {"COMPLETE": 10},
            "violations": 0, "bytes": {"RULE": 0.7, "HYPOTHESIS": 0.1, "UNKNOWN": 0.2}}


def is_current(project, run):
    """ЗАГЛУШКА (роль 4). (актуально?, список причин устаревания)."""
    return True, []


def make_report(project, run_id) -> str:
    """ЗАГЛУШКА (капитан, позже). Отчёт в Markdown."""
    return "# Отчёт (заглушка)\n"
