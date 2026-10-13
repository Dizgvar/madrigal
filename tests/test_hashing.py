"""Канонический JSON и хэши: стабильность и отсутствие неожиданностей."""
import pytest

from lab.hashing import canonical_json, hash_obj, sha256_hex


def test_sha256_known_vector():
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_key_order_and_formatting_do_not_change_hash():
    a = {"framing": {"mode": "fixed", "size": 8}, "fields": [{"name": "x", "offset": 0}]}
    b = {"fields": [{"offset": 0, "name": "x"}], "framing": {"size": 8, "mode": "fixed"}}
    assert hash_obj(a) == hash_obj(b)


def test_value_change_changes_hash():
    assert hash_obj({"offset": 4}) != hash_obj({"offset": 5})


def test_list_order_matters():
    assert hash_obj({"allowed": [1, 2]}) != hash_obj({"allowed": [2, 1]})


def test_canonical_bytes_are_compact_utf8():
    assert canonical_json({"b": "я", "a": 1}) == '{"a":1,"b":"я"}'.encode("utf-8")


def test_nan_is_rejected():
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})
