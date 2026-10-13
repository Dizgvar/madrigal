"""Канонический JSON и SHA-256. Через это считаются rules_hash, settings_hash, corpus_hash.

Канонический вид: ключи отсортированы, без пробелов, UTF-8. Один и тот же смысл всегда даёт
один и тот же хэш, независимо от порядка ключей и форматирования.
"""
import hashlib
import json


def canonical_json(obj) -> bytes:
    """Объект -> канонические байты JSON.

    Бросает ValueError для NaN/Infinity и TypeError для типов, которых нет в JSON.

    Пример:
        >>> canonical_json({"b": 1, "a": [1, 2]})
        b'{"a":[1,2],"b":1}'
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """SHA-256 в виде строчного hex (64 символа).

    Пример:
        >>> sha256_hex(b"abc")[:8]
        'ba7816bf'
    """
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj) -> str:
    """SHA-256 от канонического JSON объекта.

    Пример:
        >>> hash_obj({"a": 1, "b": 2}) == hash_obj({"b": 2, "a": 1})
        True
    """
    return sha256_hex(canonical_json(obj))
