"""Хранилище проекта: настройки, журнал действий, наблюдения. Только стандартная библиотека.

Всё лежит В ПАПКЕ ПРОЕКТА и переносится вместе с ней (пути относительные):
  project.json                       настройки, сведения об инструменте, описание файла журнала;
  actions/actions.csv                копия журнала действий (SHA-256 в project.json);
  observations/observations.jsonl    наблюдения и гипотезы, ТОЛЬКО добавление строк.

Коды ожидаемых ошибок (LabError.code):
  BAD_SETTINGS, ACTIONS_MISSING, ACTIONS_CHANGED, BAD_ACTIONS, BAD_OBSERVATION, SOURCE_MISSING.
"""
import copy
import csv
import io
import json
import math
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .hashing import hash_obj, sha256_hex
from .models import LabError
from .project import DEFAULT_SETTINGS, _load_manifest, _write_manifest

OVERLAP_POLICIES = ("first", "unknown")
CHECKSUM_POLICIES = ("report", "strict", "ignore")
ACTION_COLUMNS = {"time": "time_utc", "action": "action", "param": "param", "value": "value", "result": "result"}
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


# ------------------------------------------------------------------ настройки
def _merged(saved) -> dict:
    s = copy.deepcopy(DEFAULT_SETTINGS)
    if saved is None:
        return s
    if not isinstance(saved, dict):
        raise LabError("BAD_SETTINGS", "settings must be an object")
    for section, vals in saved.items():
        if section not in s or not isinstance(vals, dict):
            raise LabError("BAD_SETTINGS", "unknown settings section", section=section)
        for key, val in vals.items():
            if key not in s[section]:       # опечатка в имени не должна пройти молча
                raise LabError("BAD_SETTINGS", "unknown setting", section=section, key=key)
            s[section][key] = val
    r, off = s["reassembly"], s["time"]["clock_offset_s"]
    if r["overlap_policy"] not in OVERLAP_POLICIES:
        raise LabError("BAD_SETTINGS", "overlap_policy must be one of %s" % (OVERLAP_POLICIES,), value=r["overlap_policy"])
    if r["checksum_policy"] not in CHECKSUM_POLICIES:
        raise LabError("BAD_SETTINGS", "checksum_policy must be one of %s" % (CHECKSUM_POLICIES,), value=r["checksum_policy"])
    if isinstance(off, bool) or not isinstance(off, (int, float)) or not math.isfinite(off):
        raise LabError("BAD_SETTINGS", "clock_offset_s must be a finite number", value=off)
    return s


def get_settings(root) -> dict:
    """Настройки проекта (с проверкой). Пример: get_settings(p)["reassembly"]["overlap_policy"] -> 'first'."""
    return _merged(_load_manifest(Path(root)).get("settings"))


def set_settings(root, patch: dict) -> dict:
    """Меняет настройки частично: set_settings(p, {"reassembly": {"overlap_policy": "unknown"}}).

    Смысл clock_offset_s: (время в журнале) минус (время в записи). Журнал спешит на 0.3 с -> 0.3.
    """
    root = Path(root)
    data = _load_manifest(root)
    cur = _merged(data.get("settings"))
    if not isinstance(patch, dict):
        raise LabError("BAD_SETTINGS", "patch must be an object")
    for section, vals in patch.items():
        if section not in cur or not isinstance(vals, dict):
            raise LabError("BAD_SETTINGS", "unknown settings section", section=section)
        cur[section].update(vals)
    data["settings"] = _merged(cur)          # повторная проверка целиком
    _write_manifest(root, data)
    return data["settings"]


def settings_hash(root) -> str:
    """Отпечаток настроек СБОРКИ (политики и защитные пределы). Смещение часов в него не входит."""
    from .capture import LIMITS
    from .streams import MAX_STREAM_BYTES
    s = get_settings(root)
    return hash_obj({"reassembly": s["reassembly"], "limits": dict(LIMITS), "max_stream_bytes": MAX_STREAM_BYTES})


# ------------------------------------------------------------------ журнал действий
def _parse_time(text):
    """ISO 8601 -> (микросекунды от 1970 UTC, заметка). Время без пояса считаем UTC и говорим об этом."""
    s = (text or "").strip()
    if not s:
        return None, "empty time"
    try:
        dt = datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith("Z") else s)
    except ValueError:
        return None, "unparsable time: %r" % s
    note = ""
    if dt.tzinfo is None:
        dt, note = dt.replace(tzinfo=timezone.utc), "no timezone, assumed UTC"
    d = dt - _EPOCH
    return (d.days * 86400 + d.seconds) * 1_000_000 + d.microseconds, note


def load_actions(root, csv_path, columns=None, delimiter=",") -> dict:
    """Копирует журнал действий в проект и запоминает, какая колонка что значит.

    columns: {"time": "имя_колонки", "action": "...", "param": ..., "value": ..., "result": ...};
    time и action обязательны; необязательную колонку можно отключить значением None.
    Пример: load_actions(p, "log.csv", {"time": "ts"}, delimiter=";").
    """
    root = Path(root)
    data = _load_manifest(root)
    cols = dict(ACTION_COLUMNS)
    cols.update(columns or {})
    try:
        raw = Path(csv_path).read_bytes()
    except OSError as e:
        raise LabError("SOURCE_MISSING", "actions file cannot be read: %s" % e, path=str(csv_path)) from e
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise LabError("BAD_ACTIONS", "actions file must be UTF-8") from e
    reader = csv.DictReader(io.StringIO(text, newline=""), delimiter=delimiter)
    header = reader.fieldnames or []
    for key in ("time", "action"):
        if cols.get(key) not in header:
            raise LabError("BAD_ACTIONS", "required column %r not found" % key, wanted=cols.get(key), header=header)
    for key, name in list(cols.items()):
        if name is not None and name not in header:
            cols[key] = None                  # необязательной колонки нет - так и запишем
    rows = sum(1 for _ in reader)
    dest = root / "actions" / "actions.csv"
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".incoming.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, dest)
    finally:
        Path(tmp).unlink(missing_ok=True)
    data["actions_file"] = {"path": "actions/actions.csv", "sha256": sha256_hex(raw),
                            "columns": cols, "delimiter": delimiter, "rows": rows}
    _write_manifest(root, data)
    return data["actions_file"]


def read_actions(root) -> list:
    """Строки журнала: idx, поля, время журнала (ts_us) и время в записи (capture_ts_us).

    capture_ts_us = ts_us - clock_offset_s. Строка с непонятным временем НЕ выбрасывается:
    у неё ts_us=None и заполнено поле note.
    """
    root = Path(root)
    af = _load_manifest(root).get("actions_file")
    if not af:
        raise LabError("ACTIONS_MISSING", "no actions file loaded")
    try:
        raw = (root / af["path"]).read_bytes()
    except OSError as e:
        raise LabError("ACTIONS_MISSING", "actions file missing: %s" % e) from e
    if sha256_hex(raw) != af["sha256"]:
        raise LabError("ACTIONS_CHANGED", "actions file differs from its recorded hash")
    offset = round(get_settings(root)["time"]["clock_offset_s"] * 1_000_000)
    cols, out = af["columns"], []
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig"), newline=""), delimiter=af.get("delimiter", ","))
    for idx, r in enumerate(reader):
        ts, note = _parse_time(r.get(cols["time"]))
        out.append({"idx": idx, "time": r.get(cols["time"]), "ts_us": ts,
                    "capture_ts_us": None if ts is None else ts - offset, "note": note,
                    "action": r.get(cols["action"]),
                    "param": r.get(cols["param"]) if cols.get("param") else None,
                    "value": r.get(cols["value"]) if cols.get("value") else None,
                    "result": r.get(cols["result"]) if cols.get("result") else None,
                    "raw": dict(r)})
    return out


# ------------------------------------------------------------------ наблюдения
KINDS = ("observation", "rule", "hypothesis", "counterexample")
STATUSES = ("open", "supported", "refuted")


def _obs_path(root) -> Path:
    return Path(root) / "observations" / "observations.jsonl"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_records(root) -> list:
    p = _obs_path(root)
    if not p.exists():
        return []
    recs = []
    with p.open(encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if line.strip():
                try:
                    recs.append(json.loads(line))
                except ValueError as e:      # битую строку не пропускаем молча
                    raise LabError("BAD_OBSERVATION", "line %d is not valid JSON" % n, path=str(p)) from e
    return recs


def _append(root, rec) -> None:
    p = _obs_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


def add_observation(root, kind, text, anchors=None, rules_hash=None, author="") -> dict:
    """Добавляет запись (файл только растёт). Без якоря допустима лишь гипотеза: такая запись
    помечается grounded=False, и интерфейс обязан показывать её как «без оснований»."""
    if kind not in KINDS:
        raise LabError("BAD_OBSERVATION", "kind must be one of %s" % (KINDS,), kind=kind)
    if not isinstance(text, str) or not text.strip():
        raise LabError("BAD_OBSERVATION", "text must be non-empty")
    anchors = list(anchors or [])
    if kind != "hypothesis" and not anchors:
        raise LabError("BAD_OBSERVATION", "only a hypothesis may have no anchors", kind=kind)
    n = sum(1 for r in _read_records(root) if r.get("kind") in KINDS) + 1
    rec = {"id": "obs-%04d" % n, "kind": kind, "text": text.strip(), "status": "open", "anchors": anchors,
           "rules_hash": rules_hash, "created_utc": _now(), "author": author}
    _append(root, rec)
    return rec


def set_observation_status(root, obs_id, status, note="", anchors=None) -> dict:
    """Меняет статус добавлением события (старая запись не переписывается).
    Опровержение (refuted) требует якорь контрпримера."""
    if status not in STATUSES:
        raise LabError("BAD_OBSERVATION", "status must be one of %s" % (STATUSES,), status=status)
    if not any(r.get("id") == obs_id for r in _read_records(root)):
        raise LabError("BAD_OBSERVATION", "no such observation", id=obs_id)
    if status == "refuted" and not anchors:
        raise LabError("BAD_OBSERVATION", "refuting needs an anchor of a counterexample")
    ev = {"kind": "status_change", "target": obs_id, "status": status, "note": note,
          "anchors": list(anchors or []), "created_utc": _now()}
    _append(root, ev)
    return ev


def list_observations(root) -> list:
    """Записи с учётом последних изменений статуса; у каждой grounded и history."""
    recs = _read_records(root)
    main = {r["id"]: dict(r, history=[], grounded=bool(r.get("anchors"))) for r in recs if r.get("kind") in KINDS}
    for r in recs:
        if r.get("kind") == "status_change":
            if r.get("target") not in main:
                raise LabError("BAD_OBSERVATION", "status change for unknown id", id=r.get("target"))
            main[r["target"]]["status"] = r["status"]
            main[r["target"]]["history"].append(r)
    return list(main.values())
