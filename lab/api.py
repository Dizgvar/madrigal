"""M7. Фасад: ЕДИНСТВЕННОЕ место, откуда веб-интерфейс и командная строка вызывают приложение.

Статус функций:
  РАБОТАЕТ  - настоящая реализация;
  ЗАГЛУШКА  - возвращает фиктивные данные правильного формата, чтобы остальные
              могли работать, пока модуль не готов. Заглушки помечены "stub": True.
"""
from .models import Anchor, Project
from .streams import build_stream, import_source


def open_project(path):
    """ЗАГЛУШКА. Потом: читает project.json, сверяет SHA-256 источников."""
    return Project(path=str(path))


def import_capture(project, path, progress=None):
    """РАБОТАЕТ (пока в памяти). Файл -> source_id. Повторный импорт того же файла не создаёт дубль."""
    sid, sessions, diag = import_source(path, progress)
    already = sid in project.sources
    project.sources.setdefault(sid, {"path": str(path), "sessions": sessions, "diag": dict(diag)})
    return {"source_id": sid, "already_imported": already, "diag": dict(diag), "sessions": len(sessions)}


def list_sessions(project, source_id):
    """РАБОТАЕТ. Список Session источника."""
    return project.sources[source_id]["sessions"]


def get_stream(project, session_id, direction, overlap_policy="first", checksum_policy="report"):
    """РАБОТАЕТ. DirectedStream нужной сессии и направления."""
    for src in project.sources.values():
        for s in src["sessions"]:
            if s.session_id == session_id:
                return build_stream(s, direction, overlap_policy, checksum_policy)
    raise KeyError(session_id)


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
    """ЗАГЛUШКА (роль 4). Поток + интерпретация -> список ParsedMessage."""
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