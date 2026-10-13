"""M7. Фасад: ЕДИНСТВЕННОЕ место, откуда веб-интерфейс и командная строка вызывают приложение.

Статус функций:
  РАБОТАЕТ  - настоящая реализация;
  ЗАГЛУШКА  - возвращает фиктивные данные правильного формата, чтобы остальные
              могли работать, пока модуль не готов. Заглушки помечены "stub": True.
"""
from pathlib import Path

from . import project as _project
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


def get_stream(project, session_id, direction, overlap_policy="first", checksum_policy="report"):
    """РАБОТАЕТ. DirectedStream нужной сессии и направления."""
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
    built = build_all(sessions)
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
    """ЗАГЛУШКА (роль 3). Действие из журнала -> кандидаты (сессии и пакеты в окне времени)."""
    return [{"stub": True, "session_id": "stub:1", "direction": "A>B", "pkt_no": 5, "dt_s": 0.31}]


def compare(project, ranges):
    """ЗАГЛУШКА (роль 3). Побайтовое сравнение диапазонов."""
    return {"stub": True, "rows": [{"pos": 0, "a": 0xAB, "b": 0xAB, "same": True},
                                   {"pos": 6, "a": 0x15, "b": 0x1E, "same": False}]}


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
