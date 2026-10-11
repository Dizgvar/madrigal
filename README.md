# МАДРИГАЛ: Лаборатория протоколов

Инструмент для исследования неизвестного бинарного обмена по TCP из файлов PCAP/PCAPNG.

## Запуск (Ubuntu / WSL2)
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    pytest -q
    python tools/stand/make_stand.py data/stand     # синтетические тестовые записи
    python -m lab.cli sessions data/stand/rec01.pcapng

Файлы в data/stand создаются скриптом и являются СИНТЕТИЧЕСКИМИ, не данными кейса.
