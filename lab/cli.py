"""Командная строка. Те же функции, что вызывает веб-интерфейс (lab/api.py).

  python -m lab.cli sessions <файл>                    соединения в записи (без проекта)
  python -m lab.cli project new <папка> <имя>          создать проект
  python -m lab.cli project add <папка> <файл>         скопировать запись в проект и разобрать
  python -m lab.cli project info <папка>               состав проекта и настройки
  python -m lab.cli project verify <папка>             проверить хэши источников и журнала
  python -m lab.cli project set <папка> раздел.ключ=значение ...
  python -m lab.cli actions load <папка> <csv> [--col ключ=колонка] [--delimiter ;]
  python -m lab.cli actions list <папка>
  python -m lab.cli actions find <папка> <номер_строки> [--window 2.0]
  python -m lab.cli obs add <папка> <вид> "<текст>" [--anchor СЕССИЯ,НАПРАВЛЕНИЕ,начало,конец]
  python -m lab.cli obs status <папка> <id> <статус> [--note ...] [--anchor ...]
  python -m lab.cli obs list <папка>
Код возврата: 0 успех, 2 ожидаемая ошибка (сообщение с кодом в stderr).
"""
import argparse
import json
import sys

from . import api
from .capture import CaptureError
from .models import LabError
from .streams import build_all, import_source


def cmd_sessions(args):
    sid, sessions, diag = import_source(args.file)
    print("источник: sha256:%s" % sid[:16])
    print("диагностика:", dict(sorted(diag.items())))
    streams = build_all(sessions)
    print("%-16s %-24s %-24s %-10s %7s" % ("сессия", "A", "B", "роли", "пакетов"))
    for s in sessions:
        roles = "известны" if s.roles_known else "НЕИЗВЕСТНЫ"
        print("%-16s %-24s %-24s %-10s %7d" % (s.session_id, "%s:%d" % s.a, "%s:%d" % s.b, roles, s.n_packets))
        for d in ("A>B", "B>A"):
            st = streams[(s.session_id, d)]
            gaps = sum(1 for sp in st.spans() if sp.kind == "gap")
            print("    %s: известных байт %d, дыр %d, конфликтов %d%s" % (
                d, st.known_bytes, gaps, len(st.conflicts), ("  ОШИБКА: " + st.error) if st.error else ""))
            for w in st.warnings:
                print("      !", w)


def _anchor_from(project, spec):
    sess, direction, a, b = spec.rsplit(",", 3)
    return api.anchor(project, sess, direction, int(a), int(b))


def cmd_project(args):
    if args.sub == "new":
        api.create_project(args.dir, args.name)
        print("проект создан:", args.dir)
        return
    project = api.open_project(args.dir)          # открытие уже проверяет хэши источников
    if args.sub == "add":
        r = api.import_capture(project, args.file)
        print("источник sha256:%s%s, сессий: %d" % (r["source_id"][:16], " (уже был)" if r["already_imported"] else "", r["sessions"]))
        print("диагностика:", dict(sorted(r["diag"].items())))
    elif args.sub == "info":
        print("проект:", project.name)
        for sid, e in sorted(project.sources.items()):
            print("  источник sha256:%s  %s" % (sid[:16], e["path"]))
        print("настройки:", json.dumps(api.get_settings(project), ensure_ascii=False))
        try:
            print("журнал действий: %d строк" % len(api.list_actions(project)))
        except LabError as e:
            print("журнал действий:", e.code)
        print("наблюдений:", len(api.list_observations(project)))
    elif args.sub == "verify":
        try:
            api.list_actions(project)
        except LabError as e:
            if e.code != "ACTIONS_MISSING":
                raise
        print("OK: %d источников, хэши совпали" % len(project.sources))
    elif args.sub == "set":
        patch = {}
        for item in args.items:
            key, _, val = item.partition("=")
            section, _, name = key.partition(".")
            try:
                val = json.loads(val)
            except ValueError:
                pass
            patch.setdefault(section, {})[name] = val
        print(json.dumps(api.set_settings(project, patch), ensure_ascii=False))


def cmd_actions(args):
    project = api.open_project(args.dir)
    if args.sub == "load":
        cols = dict(c.split("=", 1) for c in args.col)
        r = api.load_actions(project, args.file, cols, args.delimiter)
        print("журнал загружен: %d строк, колонки %s" % (r["rows"], r["columns"]))
    elif args.sub == "list":
        for a in api.list_actions(project):
            print("%3d  %s  %-8s %-6s %-8s %s" % (a["idx"], a["time"], a["action"], a["param"] or "", a["value"] or "",
                                                  a["note"] and "[" + a["note"] + "]" or ""))
    elif args.sub == "find":
        hits = api.find_by_action(project, args.idx, args.window)
        print("пакетов с данными в окне: %d" % len(hits))
        for h in hits:
            print("  пакет %-5d %s %-4s байт %-6d поток [%s, %s)" % (h["pkt_no"], h["session_id"], h["direction"],
                                                                   h["payload_len"], h["stream_start"], h["stream_end"]))


def cmd_obs(args):
    project = api.open_project(args.dir)
    anchors = [_anchor_from(project, s) for s in getattr(args, "anchor", [])]
    if args.sub == "add":
        r = api.add_observation(project, args.kind, args.text, anchors, author=args.author)
        print(r["id"], "добавлено" + ("" if anchors else " (БЕЗ ОСНОВАНИЙ)"))
    elif args.sub == "status":
        api.set_observation_status(project, args.id, args.status, args.note, anchors)
        print(args.id, "->", args.status)
    elif args.sub == "list":
        for o in api.list_observations(project):
            marks = ["%s" % api.verify_anchor(project, a)["status"] for a in o["anchors"]]
            print("%s [%s] %s: %s  якоря: %s%s" % (o["id"], o["status"], o["kind"], o["text"],
                                                  ",".join(marks) or "нет", "" if o["grounded"] else "  (БЕЗ ОСНОВАНИЙ)"))


def build_parser():
    p = argparse.ArgumentParser(prog="lab")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sessions"); s.add_argument("file"); s.set_defaults(func=cmd_sessions)

    pr = sub.add_parser("project"); pr.set_defaults(func=cmd_project)
    ps = pr.add_subparsers(dest="sub", required=True)
    x = ps.add_parser("new"); x.add_argument("dir"); x.add_argument("name")
    x = ps.add_parser("add"); x.add_argument("dir"); x.add_argument("file")
    ps.add_parser("info").add_argument("dir")
    ps.add_parser("verify").add_argument("dir")
    x = ps.add_parser("set"); x.add_argument("dir"); x.add_argument("items", nargs="+")

    ac = sub.add_parser("actions"); ac.set_defaults(func=cmd_actions)
    as_ = ac.add_subparsers(dest="sub", required=True)
    x = as_.add_parser("load"); x.add_argument("dir"); x.add_argument("file")
    x.add_argument("--col", action="append", default=[]); x.add_argument("--delimiter", default=",")
    as_.add_parser("list").add_argument("dir")
    x = as_.add_parser("find"); x.add_argument("dir"); x.add_argument("idx", type=int)
    x.add_argument("--window", type=float, default=2.0)

    ob = sub.add_parser("obs"); ob.set_defaults(func=cmd_obs)
    os_ = ob.add_subparsers(dest="sub", required=True)
    x = os_.add_parser("add"); x.add_argument("dir"); x.add_argument("kind"); x.add_argument("text")
    x.add_argument("--anchor", action="append", default=[]); x.add_argument("--author", default="")
    x = os_.add_parser("status"); x.add_argument("dir"); x.add_argument("id"); x.add_argument("status")
    x.add_argument("--note", default=""); x.add_argument("--anchor", action="append", default=[])
    os_.add_parser("list").add_argument("dir")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except (LabError, CaptureError) as e:
        print("ОШИБКА:", e, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
