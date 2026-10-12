"""Командная строка. Сейчас одна команда: sessions <файл>."""
import argparse
import sys

from .capture import CaptureError
from .streams import build_all, import_source


def cmd_sessions(args):
    try:
        sid, sessions, diag = import_source(args.file)
    except CaptureError as e:
        print("ОШИБКА:", e, file=sys.stderr)
        return 2
    print("источник: sha256:%s" % sid[:16])
    print("диагностика:", dict(sorted(diag.items())))
    streams = build_all(sessions)
    print("%-16s %-24s %-24s %-7s %7s" % ("сессия", "A", "B", "роли", "пакетов"))
    for s in sessions:
        roles = "известны" if s.roles_known else "НЕИЗВЕСТНЫ"
        print("%-16s %-24s %-24s %-10s %5d" % (s.session_id, "%s:%d" % s.a, "%s:%d" % s.b, roles, s.n_packets))
        for d in ("A>B", "B>A"):
            st = streams[(s.session_id, d)]
            gaps = sum(1 for sp in st.spans() if sp.kind == "gap")
            print("    %s: известных байт %d, дыр %d, конфликтов %d%s" % (
                d, st.known_bytes, gaps, len(st.conflicts), ("  ОШИБКА: " + st.error) if st.error else ""))
            for w in st.warnings:
                print("      !", w)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="lab")
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("sessions", help="показать соединения в записи")
    sp.add_argument("file")
    sp.set_defaults(func=cmd_sessions)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
