#!/usr/bin/env bash
# Запуск без интернета, если рядом лежит папка wheelhouse/ (см. scripts/make_wheelhouse.sh).
#   ./run.sh install   создать .venv и поставить зависимости
#   ./run.sh test      прогнать тесты
#   ./run.sh stand     создать синтетические записи в data/stand
#   ./run.sh web       запустить интерфейс на http://127.0.0.1:5000
#   ./run.sh cli ...   командная строка: ./run.sh cli sessions data/stand/rec01.pcapng
set -euo pipefail
cd "$(dirname "$0")"
PY="${PYTHON:-python3}"

install() {
  [ -d .venv ] || "$PY" -m venv .venv
  . .venv/bin/activate
  if [ -d wheelhouse ]; then
    pip install --no-index --find-links wheelhouse -r requirements.txt
  else
    echo "wheelhouse/ нет - ставлю из интернета" >&2
    pip install -r requirements.txt
  fi
}

[ -d .venv ] || install
. .venv/bin/activate
cmd="${1:-}"; shift || true
case "$cmd" in
  install) install ;;
  test)    python -m pytest -q "$@" ;;
  stand)   python tools/stand/make_stand.py data/stand ;;
  web)     python -m lab.web.app ;;
  cli)     python -m lab.cli "$@" ;;
  *)       sed -n '2,8p' "$0"; exit 1 ;;
esac
