"""ДОГОВОР КОМАНДЫ. Менять только с согласия капитана и с сообщением в общий чат.

Это не новые классы, а точка входа к тем структурам, что уже живут в capture.py и streams.py.
Все импортируют их ОТСЮДА, тогда при переезде кода ничего не сломается.

Правила (кратко, полный список в docs/FORMATS.md):
  * номера пакетов с 1, смещения с 0, диапазоны полуоткрытые [start, end);
  * время в микросекундах (ts_us, целое);
  * неизвестные данные это Span(kind="gap", data=None), НИКОГДА не нули;
  * ожидаемые ошибки это LabError или CaptureError с кодом, без «except: pass»;
  * хэши и якоря: SHA-256, строчный hex.
"""
from dataclasses import dataclass, field
from typing import TypedDict

from .capture import ACK, FIN, RST, SYN, CaptureError, Frame, Segment      # noqa: F401
from .streams import Conflict, DirectedStream, Piece, Session, Span        # noqa: F401


class LabError(Exception):
    """Ожидаемая ошибка приложения с кодом (например, STREAM_TOO_LARGE, BAD_PROJECT)."""

    def __init__(self, code, message, **details):
        super().__init__("%s: %s" % (code, message))
        self.code, self.message, self.details = code, message, details


class PacketRef(TypedDict):
    role: str            # data | duplicate | conflict_variant
    pkt_no: int
    payload_off: int     # смещение данных от начала кадра
    len: int
    stream_start: int
    stream_end: int


class Anchor(TypedDict):
    """Происхождение любого результата. Привязан к TCP seq, а не к «сообщению №7»."""
    source_id: str
    session_id: str
    direction: str       # "A>B" | "B>A"
    seq_start: int
    length: int
    stream_off: int      # справочно
    packets: list        # список PacketRef
    bytes_sha256: str
    assembly_hash: str


@dataclass
class Project:
    path: str
    name: str = "demo"
    sources: dict = field(default_factory=dict)    # source_id -> {"path", "sessions", "diag"}
