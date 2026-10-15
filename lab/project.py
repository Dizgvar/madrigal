"""Проект = папка на диске: project.json, sources/ (копии PCAP только для чтения), cache/ (не в Git).

Только стандартная библиотека. Project и LabError берём из lab/models.py (договор команды).

Коды ожидаемых ошибок (LabError.code):
  BAD_PROJECT     нет папки или project.json, битый JSON, неверная структура, плохой путь;
  SOURCE_MISSING  исходный файл не найден или не читается;
  SOURCE_CHANGED  содержимое файла в sources/ не совпадает с его source_id (SHA-256).
"""
import hashlib
import json
import logging
import os
import platform
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from . import __version__
from .models import LabError, Project

log = logging.getLogger(__name__)

FORMAT_VERSION = 1
MANIFEST_NAME = "project.json"
SOURCES_DIR = "sources"
CACHE_DIR = "cache"

_CHUNK = 1024 * 1024
_SOURCE_ID_RE = re.compile(r"[0-9a-f]{64}")
_SUFFIX_RE = re.compile(r"\.[a-z0-9]{1,8}")
_DRIVE_RE = re.compile(r"[A-Za-z]:")

# Настройки проекта по умолчанию. Хранятся в project.json, чтобы быть видимыми и переносимыми.
DEFAULT_SETTINGS = {
    "reassembly": {"overlap_policy": "first", "checksum_policy": "report"},
    "time": {"clock_offset_s": 0.0},
}

PathLike = str | os.PathLike[str]
# progress(source_id, байт_обработано, байт_всего)
ProgressCallback = Callable[[str, int, int], None]


@dataclass(frozen=True)
class AddResult:
    """Итог add_source: path относительный, с прямыми слэшами (как в project.json)."""

    source_id: str
    path: str
    already_added: bool


# ---------------------------------------------------------------- внутренние помощники

def _bad_project(message: str, **details: Any) -> LabError:
    return LabError("BAD_PROJECT", message, **details)


def _check_rel_path(rel: Any, where: str) -> PurePosixPath:
    """Путь источника должен быть ровно sources/<имя>: относительный, без «..», без обратных слэшей."""
    if not isinstance(rel, str) or not rel:
        raise _bad_project("path must be a non-empty string", where=where)
    if "\\" in rel or rel.startswith("/") or _DRIVE_RE.match(rel):
        raise _bad_project("path must be relative with forward slashes", where=where, path=rel)
    parts = PurePosixPath(rel).parts
    if len(parts) != 2 or parts[0] != SOURCES_DIR or ".." in parts:
        raise _bad_project("path must look like sources/<file>", where=where, path=rel)
    return PurePosixPath(rel)


def _abs_path(root: Path, rel: PurePosixPath) -> Path:
    return root.joinpath(*rel.parts)


def _write_manifest(root: Path, data: dict) -> None:
    """Атомарная запись: временный файл в той же папке, fsync, затем os.replace."""
    fd, tmp_name = tempfile.mkstemp(dir=root, prefix=".project.", suffix=".tmp")
    replaced = False
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, root / MANIFEST_NAME)
        replaced = True
    finally:
        if not replaced:
            Path(tmp_name).unlink(missing_ok=True)


def _load_manifest(root: Path) -> dict:
    """Читает и проверяет project.json. Неизвестные поля сохраняются, чтобы запись их не теряла."""
    manifest = root / MANIFEST_NAME
    if not root.is_dir() or not manifest.is_file():
        raise _bad_project("project.json not found", path=str(root))
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise _bad_project("project.json cannot be read: %s" % exc, path=str(manifest)) from exc

    if not isinstance(data, dict) or data.get("format_version") != FORMAT_VERSION:
        raise _bad_project("unsupported or missing format_version", expected=FORMAT_VERSION)
    if not isinstance(data.get("name"), str) or not data["name"]:
        raise _bad_project("name must be a non-empty string")
    sources = data.get("sources")
    if not isinstance(sources, dict):
        raise _bad_project("sources must be an object")
    for source_id, entry in sources.items():
        if not _SOURCE_ID_RE.fullmatch(source_id):
            raise _bad_project("source_id must be 64 lowercase hex characters", source_id=source_id)
        if not isinstance(entry, dict):
            raise _bad_project("source entry must be an object", source_id=source_id)
        _check_rel_path(entry.get("path"), source_id)
        if not isinstance(entry.get("sessions", []), list) or not isinstance(entry.get("diag", {}), dict):
            raise _bad_project("sessions must be a list and diag an object", source_id=source_id)
    return data


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _suffix(src: Path) -> str:
    """Расширение копии: как у исходника (строчными), если оно безопасное, иначе пустое."""
    suffix = src.suffix.lower()
    return suffix if _SUFFIX_RE.fullmatch(suffix) else ""


# ---------------------------------------------------------------- публичный API

def create_project(path: PathLike, name: str) -> Project:
    """Создаёт папку проекта с project.json, sources/ и cache/.

    Бросает LabError(BAD_PROJECT), если в папке уже есть project.json или имя пустое.

    Пример:
        >>> project = create_project("work/demo_project", "demo")
        >>> project.name, project.sources
        ('demo', {})
    """
    if not isinstance(name, str) or not name.strip():
        raise _bad_project("name must be a non-empty string")
    root = Path(path)
    if (root / MANIFEST_NAME).exists():
        raise _bad_project("project already exists", path=str(root))
    (root / SOURCES_DIR).mkdir(parents=True, exist_ok=True)
    (root / CACHE_DIR).mkdir(exist_ok=True)
    _write_manifest(root, {
        "format_version": FORMAT_VERSION, "name": name, "sources": {},
        "tool": {"name": "madrigal-lab", "version": __version__, "python": platform.python_version()},
        "settings": json.loads(json.dumps(DEFAULT_SETTINGS)),
    })
    log.info("project created: %s", root)
    return Project(path=str(root.resolve()), name=name, sources={})


def add_source(project_dir: PathLike, pcap_path: PathLike) -> AddResult:
    """Копирует PCAP/PCAPNG в sources/ и регистрирует его в project.json.

    Файл копируется один раз; SHA-256 считается по тем же байтам, что записываются в копию.
    Копия называется sources/<source_id><расширение> и получает права только чтение.
    Если такое содержимое уже есть (даже под другим именем), дубль не создаётся
    и возвращается already_added=True. Исходный файл только читается.

    Бросает LabError: BAD_PROJECT (проект повреждён), SOURCE_MISSING (нет файла),
    SOURCE_CHANGED (на месте будущей копии лежит файл с другим содержимым).

    Пример:
        >>> result = add_source("work/demo_project", "captures/session1.pcap")
        >>> result.already_added, result.path.startswith("sources/")
        (False, True)
        >>> add_source("work/demo_project", "captures/copy_of_session1.pcap").already_added
        True
    """
    root = Path(project_dir)
    data = _load_manifest(root)
    src = Path(pcap_path)
    if not src.is_file():
        raise LabError("SOURCE_MISSING", "source file not found", path=str(src))
    try:
        fin = src.open("rb")
    except OSError as exc:
        raise LabError("SOURCE_MISSING", "source file cannot be read: %s" % exc, path=str(src)) from exc

    sources_dir = root / SOURCES_DIR
    sources_dir.mkdir(exist_ok=True)
    with fin:
        fd, tmp_name = tempfile.mkstemp(dir=sources_dir, prefix=".incoming.", suffix=".tmp")
        tmp = Path(tmp_name)
        try:
            digest = hashlib.sha256()
            with os.fdopen(fd, "wb") as fout:
                while chunk := fin.read(_CHUNK):
                    digest.update(chunk)
                    fout.write(chunk)
                fout.flush()
                os.fsync(fout.fileno())
            source_id = digest.hexdigest()

            known = data["sources"].get(source_id)
            if known is not None:
                log.info("source already in project: %s", source_id)
                return AddResult(source_id, known["path"], True)

            rel = PurePosixPath("%s/%s%s" % (SOURCES_DIR, source_id, _suffix(src)))
            final = _abs_path(root, rel)
            if final.exists():
                # остаток прерванного добавления: годится, только если байты те же
                if _sha256_file(final) != source_id:
                    raise LabError("SOURCE_CHANGED", "file in sources/ does not match its hash",
                                   source_id=source_id, path=rel.as_posix())
            else:
                os.replace(tmp, final)
            os.chmod(final, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

            data["sources"][source_id] = {"path": rel.as_posix(), "sessions": [], "diag": {}}
            _write_manifest(root, data)
            log.info("source added: %s -> %s", source_id, rel.as_posix())
            return AddResult(source_id, rel.as_posix(), False)
        finally:
            tmp.unlink(missing_ok=True)


def open_project(path: PathLike, *, progress: ProgressCallback | None = None) -> Project:
    """Открывает проект, проверяет project.json и хэши всех источников.

    Project.path это абсолютный путь папки на момент открытия (в project.json он не хранится),
    поэтому скопированную в другое место папку можно открыть без правок.

    Бросает LabError: BAD_PROJECT, SOURCE_MISSING, SOURCE_CHANGED.

    Пример:
        >>> project = open_project("work/demo_project")
        >>> sorted(project.sources)[0][:8]
        '3f1a9c0e'
    """
    root = Path(path).resolve()
    data = _load_manifest(root)
    sources = {
        source_id: {
            "path": entry["path"],
            "sessions": list(entry.get("sessions", [])),
            "diag": dict(entry.get("diag", {})),
        }
        for source_id, entry in data["sources"].items()
    }
    project = Project(path=str(root), name=data["name"], sources=sources)
    verify_sources(project, progress)
    log.info("project opened: %s (%d sources)", root, len(sources))
    return project


def verify_sources(project: Project, progress: ProgressCallback | None = None) -> None:
    """Проверяет, что каждый файл в sources/ существует и его SHA-256 равен source_id.

    progress(source_id, байт_обработано, байт_всего) вызывается в начале и после каждого блока.
    Источники проверяются по возрастанию source_id; первая проблема прерывает проверку.

    Бросает LabError: SOURCE_MISSING (нет файла или он не читается),
    SOURCE_CHANGED (хэш не совпал), BAD_PROJECT (некорректный путь).

    Пример:
        >>> verify_sources(project, progress=lambda sid, done, total: print(sid[:8], done, total))
        3f1a9c0e 0 2048
        3f1a9c0e 2048 2048
    """
    root = Path(project.path)
    for source_id in sorted(project.sources):
        rel = _check_rel_path(project.sources[source_id].get("path"), source_id)
        file = _abs_path(root, rel)
        digest = hashlib.sha256()
        try:
            total = file.stat().st_size
            done = 0
            if progress:
                progress(source_id, done, total)
            with file.open("rb") as f:
                while chunk := f.read(_CHUNK):
                    digest.update(chunk)
                    done += len(chunk)
                    if progress:
                        progress(source_id, done, total)
        except OSError as exc:
            raise LabError("SOURCE_MISSING", "source file is missing or unreadable: %s" % exc,
                           source_id=source_id, path=rel.as_posix()) from exc
        actual = digest.hexdigest()
        if actual != source_id:
            raise LabError("SOURCE_CHANGED", "source file content differs from its hash",
                           source_id=source_id, path=rel.as_posix(), actual=actual)
