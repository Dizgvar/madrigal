"""Настройки, журнал действий, наблюдения, проверка якорей, find_by_action, CLI."""
import json
import shutil
import tempfile
from functools import lru_cache
from pathlib import Path

import pytest

from lab import api, cli, store
from lab.models import LabError
from tools.stand import make_stand as ms


@lru_cache(maxsize=1)
def stand_dir():
    p = Path(tempfile.mkdtemp())
    ms.main(p)
    return p


@pytest.fixture
def pr(tmp_path):
    p = api.create_project(tmp_path / "proj", "t")
    api.import_capture(p, stand_dir() / "rec01.pcapng")
    return p


def target_session(pr):
    sid = next(iter(pr.sources))
    return max(api.list_sessions(pr, sid), key=lambda s: s.n_packets)


# ---------- настройки ----------
def test_settings_default_saved_and_validated(pr):
    s = api.get_settings(pr)
    assert s["reassembly"] == {"overlap_policy": "first", "checksum_policy": "report"}
    assert json.loads((Path(pr.path) / "project.json").read_text())["tool"]["name"] == "madrigal-lab"
    api.set_settings(pr, {"reassembly": {"overlap_policy": "unknown"}})
    assert api.get_settings(pr)["reassembly"]["overlap_policy"] == "unknown"
    assert api.get_settings(pr)["reassembly"]["checksum_policy"] == "report"      # остальное не тронуто


@pytest.mark.parametrize("patch", [
    {"reassembly": {"overlap_policy": "last"}}, {"reassembly": {"overlap_polcy": "first"}},
    {"time": {"clock_offset_s": "0.3"}}, {"time": {"clock_offset_s": float("nan")}}, {"nope": {}},
])
def test_bad_settings_rejected_and_not_saved(pr, patch):
    before = api.get_settings(pr)
    with pytest.raises(LabError) as e:
        api.set_settings(pr, patch)
    assert e.value.code == "BAD_SETTINGS" and api.get_settings(pr) == before


def test_policy_from_settings_changes_stream_and_hash(pr, tmp_path):
    s = target_session(pr)
    h1 = api.get_stream(pr, s.session_id, "B>A").assembly_hash()
    api.set_settings(pr, {"reassembly": {"checksum_policy": "strict"}})
    st = api.get_stream(pr, s.session_id, "B>A")
    assert st.checksum_policy == "strict" and st.assembly_hash() != h1
    assert store.settings_hash(pr.path) != ""


# ---------- журнал действий ----------
def test_actions_load_read_and_clock_offset(pr):
    api.load_actions(pr, stand_dir() / "rec01_actions.csv")
    rows = api.list_actions(pr)
    assert len(rows) == 10 and rows[1]["action"] == "write" and rows[1]["value"] == "21"
    assert rows[0]["capture_ts_us"] == rows[0]["ts_us"]                   # смещение 0
    api.set_settings(pr, {"time": {"clock_offset_s": 0.3}})
    r0 = api.list_actions(pr)[0]
    assert r0["capture_ts_us"] == r0["ts_us"] - 300_000
    assert abs(r0["capture_ts_us"] - (ms.T0 + 1_000_000)) <= 1000         # журнал идёт с точностью до мс


def test_actions_custom_columns_and_semicolon(tmp_path, pr):
    f = tmp_path / "x.csv"
    f.write_text("ts;что;знач\n2025-10-09T00:00:00;set;5\nмусор;set;6\n", encoding="utf-8")
    r = api.load_actions(pr, f, {"time": "ts", "action": "что", "value": "знач"}, ";")
    assert r["rows"] == 2 and r["columns"]["param"] is None
    rows = api.list_actions(pr)
    assert rows[0]["note"] == "no timezone, assumed UTC" and rows[0]["value"] == "5"
    assert rows[1]["ts_us"] is None and "unparsable" in rows[1]["note"]    # плохая строка не пропадает


def test_actions_errors(tmp_path, pr):
    with pytest.raises(LabError) as e:
        api.list_actions(pr)
    assert e.value.code == "ACTIONS_MISSING"
    f = tmp_path / "y.csv"
    f.write_text("a,b\n1,2\n")
    with pytest.raises(LabError) as e:
        api.load_actions(pr, f)
    assert e.value.code == "BAD_ACTIONS"
    api.load_actions(pr, stand_dir() / "rec01_actions.csv")
    (Path(pr.path) / "actions" / "actions.csv").write_text("подмена\n")
    with pytest.raises(LabError) as e:
        api.list_actions(pr)
    assert e.value.code == "ACTIONS_CHANGED"


def test_find_by_action_uses_offset_and_reports_stream_range(pr):
    api.load_actions(pr, stand_dir() / "rec01_actions.csv")
    assert api.find_by_action(pr, 1, window_s=0.05) == []                  # без поправки часов окно мимо
    api.set_settings(pr, {"time": {"clock_offset_s": 0.3}})
    hits = api.find_by_action(pr, 1, window_s=0.05)                        # строка 1 = «write 21»
    assert {h["direction"] for h in hits} == {"A>B", "B>A"} and all(h["stream_start"] is not None for h in hits)
    assert all(abs(h["ts_us"] - (ms.T0 + 2_000_000)) < 60_000 for h in hits)
    with pytest.raises(LabError) as e:
        api.find_by_action(pr, 99)
    assert e.value.code == "BAD_ACTION"


def test_compare_is_honestly_not_implemented(pr):
    with pytest.raises(LabError) as e:
        api.compare(pr, [])
    assert e.value.code == "NOT_IMPLEMENTED"


# ---------- наблюдения ----------
def test_observations_rules(pr):
    s = target_session(pr)
    a = api.anchor(pr, s.session_id, "B>A", 0, 8)
    h = api.add_observation(pr, "hypothesis", "первые байты - магия")
    assert h["id"] == "obs-0001"
    with pytest.raises(LabError):
        api.add_observation(pr, "observation", "без якоря нельзя")
    o = api.add_observation(pr, "observation", "первые 8 байт ответа", [a])
    with pytest.raises(LabError):
        api.set_observation_status(pr, h["id"], "refuted")                  # опровержение без контрпримера
    api.set_observation_status(pr, h["id"], "refuted", "не сошлось", [a])
    got = {x["id"]: x for x in api.list_observations(pr)}
    assert got[h["id"]]["status"] == "refuted" and not got[h["id"]]["grounded"] and got[o["id"]]["grounded"]
    assert len(got[h["id"]]["history"]) == 1
    lines = (Path(pr.path) / "observations" / "observations.jsonl").read_text().splitlines()
    assert len(lines) == 3 and json.loads(lines[0])["status"] == "open"     # старая запись не переписана


def test_broken_observation_line_is_error_not_skipped(pr):
    api.add_observation(pr, "hypothesis", "x")
    with open(Path(pr.path) / "observations" / "observations.jsonl", "a") as f:
        f.write("{не json\n")
    with pytest.raises(LabError) as e:
        api.list_observations(pr)
    assert e.value.code == "BAD_OBSERVATION"


# ---------- якоря ----------
def test_verify_anchor_ok_stale_broken_missing(pr):
    s = target_session(pr)
    a = api.anchor(pr, s.session_id, "B>A", 10, 30)
    assert api.verify_anchor(pr, a) == {"status": "ok", "reasons": []}
    api.set_settings(pr, {"reassembly": {"checksum_policy": "strict"}})
    v = api.verify_anchor(pr, a)
    assert v["status"] == "stale" and v["reasons"]                         # байты те же, сборка другая
    assert api.verify_anchor(pr, dict(a, bytes_sha256="0" * 64))["status"] == "broken"
    assert api.verify_anchor(pr, dict(a, session_id="deadbeef0000:1"))["status"] == "missing"


def test_anchor_survives_project_copy(pr, tmp_path):
    s = target_session(pr)
    a = api.anchor(pr, s.session_id, "B>A", 10, 30)
    api.add_observation(pr, "observation", "перенос", [a])
    shutil.copytree(pr.path, tmp_path / "moved")
    p2 = api.open_project(tmp_path / "moved")
    assert api.verify_anchor(p2, a)["status"] == "ok"
    assert api.list_observations(p2)[0]["anchors"][0]["bytes_sha256"] == a["bytes_sha256"]
    assert str(tmp_path) not in (tmp_path / "moved" / "project.json").read_text()      # абсолютных путей нет


# ---------- фон стенда ----------
def test_noise_session_has_no_fake_gaps(pr):
    sid = next(iter(pr.sources))
    for d in api.describe_sessions(pr, sid):
        for dd in d["directions"].values():
            assert dd["gaps"] == 0


# ---------- CLI ----------
def test_cli_full_flow(tmp_path, capsys):
    proj = str(tmp_path / "p")
    run = lambda *a: cli.main(list(a))
    assert run("project", "new", proj, "demo") == 0
    assert run("project", "add", proj, str(stand_dir() / "rec01.pcapng")) == 0
    assert run("actions", "load", proj, str(stand_dir() / "rec01_actions.csv")) == 0
    assert run("project", "set", proj, "time.clock_offset_s=0.3") == 0
    assert run("actions", "find", proj, "1", "--window", "0.05") == 0
    out = capsys.readouterr().out
    assert "пакетов с данными в окне:" in out and "пакетов с данными в окне: 0" not in out
    assert run("obs", "add", proj, "hypothesis", "догадка") == 0
    assert run("obs", "list", proj) == 0 and "БЕЗ ОСНОВАНИЙ" in capsys.readouterr().out
    assert run("project", "verify", proj) == 0
    assert run("project", "set", proj, "reassembly.overlap_policy=bad") == 2          # ожидаемая ошибка -> код 2
    assert run("sessions", "/etc/hostname") == 2
