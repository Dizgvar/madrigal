#!/usr/bin/env bash
# Собирает wheelhouse/ для установки БЕЗ интернета на Linux x86-64 сразу под несколько версий Python.
# Колёса разных версий в одной папке не мешают друг другу: pip берёт подходящие.
# Запускать там, где есть интернет. Результат кладут рядом с кодом в пакет сдачи (в Git не попадает).
set -euo pipefail
cd "$(dirname "$0")/.."
VERSIONS="${VERSIONS:-3.12 3.13 3.14}"
mkdir -p wheelhouse
for v in $VERSIONS; do
  echo "== Python $v"
  pip download -r requirements.txt -d wheelhouse --only-binary=:all: \
    --python-version "$v" --platform manylinux2014_x86_64 --implementation cp -q
done
ls wheelhouse | wc -l
echo "Проверка (с выключенным интернетом): python3 -m venv /tmp/clean && /tmp/clean/bin/pip install --no-index --find-links wheelhouse -r requirements.txt"
