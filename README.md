# МАДРИГАЛ: Лаборатория протоколов

Инструмент для исследования неизвестного бинарного обмена по TCP из файлов PCAP/PCAPNG.
Работает офлайн (интерфейс на localhost). Проверено на Python 3.12 и 3.14, Linux x86-64.

## Запуск (Ubuntu / WSL2)
    ./run.sh install                 # .venv + зависимости (из wheelhouse/, если папка есть)
    ./run.sh test                    # тесты
    ./run.sh stand                   # синтетические записи в data/stand
    ./run.sh cli sessions data/stand/rec01.pcapng
    ./run.sh web                     # http://127.0.0.1:5000

Без `run.sh`: `python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt && pytest -q`.

## Без интернета
    scripts/make_wheelhouse.sh       # там, где интернет: колёса под Python 3.12/3.13/3.14 (Linux x86-64)
    ./run.sh install                 # на целевой машине: ставит из wheelhouse/ с --no-index

## Работа с проектом из терминала
    ./run.sh cli project new work/demo demo
    ./run.sh cli project add work/demo data/stand/rec01.pcapng
    ./run.sh cli actions load work/demo data/stand/rec01_actions.csv
    ./run.sh cli project set work/demo time.clock_offset_s=0.3
    ./run.sh cli actions find work/demo 1 --window 0.05
    ./run.sh cli obs add work/demo hypothesis "текст гипотезы"
    ./run.sh cli obs list work/demo
    ./run.sh cli project verify work/demo

Файлы в `data/stand` создаются скриптом и являются СИНТЕТИЧЕСКИМИ, не данными кейса.
Форматы и договорённости: `docs/FORMATS.md`.
