# Форматы и договорённости

Структуры данных: `lab/models.py` (импортировать только оттуда). Номера пакетов с 1, смещения с 0,
диапазоны `[start, end)`. Время в микросекундах (`ts_us`, целое). Неизвестное это `Span(kind="gap",
data=None)`, никогда не нули. Ожидаемые ошибки: `LabError` / `CaptureError` с кодом, без `except: pass`.
Хэши: SHA-256, строчный hex. Новые зависимости только через капитана.

## Папка проекта
```
my-project/
├── project.json                      паспорт, настройки, источники, описание журнала
├── sources/<sha256>.pcap[ng]         КОПИИ записей, только чтение; имя = SHA-256 содержимого
├── actions/actions.csv               копия журнала действий (SHA-256 в project.json)
├── observations/observations.jsonl   наблюдения и гипотезы, только добавление строк
└── cache/                            пересобираемое, в Git не кладём
```
Все пути внутри проекта относительные, с прямыми слэшами. Папку можно копировать куда угодно.

## project.json
```json
{
  "format_version": 1,
  "name": "demo",
  "tool": {"name": "madrigal-lab", "version": "0.1.0", "python": "3.12.3"},
  "settings": {
    "reassembly": {"overlap_policy": "first", "checksum_policy": "report"},
    "time": {"clock_offset_s": 0.0}
  },
  "sources": {"<sha256>": {"path": "sources/<sha256>.pcapng", "sessions": [], "diag": {}}},
  "actions_file": {"path": "actions/actions.csv", "sha256": "...", "rows": 10, "delimiter": ",",
                   "columns": {"time": "time_utc", "action": "action", "param": "param",
                               "value": "value", "result": "result"}}
}
```
`tool.python` это версия, на которой проект СОЗДАН (справочно). Неизвестные поля при записи сохраняются.

### Настройки (`lab/store.py`, неизвестные ключи отвергаются)
| Ключ | Значения | Смысл |
|---|---|---|
| `reassembly.overlap_policy` | `first` / `unknown` | `first`: в конфликте побеждают первые пришедшие байты, участок помечен как конфликт. `unknown`: конфликтные байты считаются неизвестными |
| `reassembly.checksum_policy` | `report` / `strict` / `ignore` | `report`: пакеты с плохой суммой остаются, пользователь предупреждён. `strict`: такие пакеты исключаются, на их месте дыра. `ignore`: пакеты остаются, предупреждения нет |
| `time.clock_offset_s` | число | (время в журнале) МИНУС (время в записи). Журнал спешит на 0.3 с, значит 0.3. Время в записи = время журнала минус смещение |

Политики попадают в `assembly_hash` потока и в `store.settings_hash()`: смена политики делает
старые якоря `stale`, а старые проверки устаревшими.

## Журнал действий
CSV (UTF-8, разделитель задаётся). Какая колонка что значит, записывается при загрузке
(`load_actions(..., columns={"time": "...", "action": "..."}`). Обязательны `time` и `action`.
Время ISO 8601; без пояса считается UTC (в строке будет заметка). Строка с непонятным временем не
пропадает: `ts_us = None`, причина в `note`.

## Якорь (`Anchor`)
`source_id, session_id, direction, seq_start (сырой TCP seq), length, stream_off (справочно),
packets, bytes_sha256, assembly_hash`. Привязан к TCP seq, а не к «сообщению №7».
`api.verify_anchor` возвращает:
| Статус | Смысл |
|---|---|
| `ok` | байты те же и сборка та же |
| `stale` | байты те же, но изменились настройки сборки или позиция в потоке |
| `broken` | байты по якорю другие |
| `missing` | сессия не найдена в проекте |

## Наблюдения (`observations.jsonl`, одна запись на строку, файл только растёт)
```json
{"id": "obs-0001", "kind": "observation|rule|hypothesis|counterexample", "text": "...",
 "status": "open", "anchors": [ {якорь} ], "rules_hash": null, "created_utc": "...", "author": ""}
{"kind": "status_change", "target": "obs-0001", "status": "open|supported|refuted",
 "note": "...", "anchors": [ {якорь контрпримера} ], "created_utc": "..."}
```
Правила: без якоря допустима только `hypothesis` (в списке она помечается `grounded=False`, интерфейс
показывает «БЕЗ ОСНОВАНИЙ»); статус `refuted` требует якорь контрпримера; старые строки не переписываются;
битая строка это ошибка `BAD_OBSERVATION`, а не пропуск.

## Коды ошибок
`BAD_PROJECT, SOURCE_MISSING, SOURCE_CHANGED` (project.py); `BAD_SETTINGS, ACTIONS_MISSING, ACTIONS_CHANGED,
BAD_ACTIONS, BAD_OBSERVATION` (store.py); `BAD_ACTION, NOT_IMPLEMENTED` (api.py); `CaptureError`: `NOT_A_CAPTURE,
TRUNCATED_FILE, BAD_RECORD, BAD_PCAPNG, LIMIT_EXCEEDED`.
