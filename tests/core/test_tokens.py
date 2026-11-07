import html
import json
import string

import pytest
from hypothesis import given
from hypothesis import strategies as st

from control.core.tokens import TAG_LENGTH, TOKEN_LENGTH, derive_token, new_tag

KEY = b"lab-key-for-tests-only"
BASE32_LOWER = set(string.ascii_lowercase + "234567")


def test_derive_token_is_deterministic() -> None:
    a = derive_token(KEY, "run_01ABC", "pl_01XYZ")
    b = derive_token(KEY, "run_01ABC", "pl_01XYZ")
    assert a == b


def test_derive_token_shape() -> None:
    token = derive_token(KEY, "run_01ABC", "pl_01XYZ")
    assert len(token) == TOKEN_LENGTH == 12
    assert set(token) <= BASE32_LOWER
    # Must be usable as a DNS label: <token>.cb.lab.test
    assert token == token.lower()
    assert token[0].isalnum()


def test_derive_token_known_vector() -> None:
    # Pins the encoding (length-prefixed fields, lowercase base32, 12 chars) so a
    # change to the scheme cannot slip in unnoticed: old callbacks would stop mapping.
    # Vector: base32(HMAC-SHA256(b"k", u64be(5)+b"run_1" + u64be(4)+b"pl_1"))[:12].lower()
    assert derive_token(b"k", "run_1", "pl_1") == "53z4dmvadxjw"


def test_derive_token_differs_by_run_id() -> None:
    assert derive_token(KEY, "run_A", "pl_1") != derive_token(KEY, "run_B", "pl_1")


def test_derive_token_differs_by_placement_id() -> None:
    assert derive_token(KEY, "run_A", "pl_1") != derive_token(KEY, "run_A", "pl_2")


def test_derive_token_separator_is_unambiguous() -> None:
    assert derive_token(KEY, "ab", "c") != derive_token(KEY, "a", "bc")
    assert derive_token(KEY, "", "abc") != derive_token(KEY, "abc", "")


def test_derive_token_differs_by_key() -> None:
    assert derive_token(b"key-one", "run_A", "pl_1") != derive_token(b"key-two", "run_A", "pl_1")


def test_derive_token_rejects_empty_key() -> None:
    with pytest.raises(ValueError):
        derive_token(b"", "run_A", "pl_1")


@given(run_id=st.text(max_size=40), placement_id=st.text(max_size=40))
def test_derive_token_shape_property(run_id: str, placement_id: str) -> None:
    token = derive_token(KEY, run_id, placement_id)
    assert len(token) == 12
    assert set(token) <= BASE32_LOWER


def test_new_tag_shape() -> None:
    tag = new_tag()
    assert len(tag) == TAG_LENGTH == 16
    assert tag.isascii()
    assert tag.isalnum()


def test_new_tag_survives_html_escape_and_json_dumps() -> None:
    for _ in range(200):
        tag = new_tag()
        assert html.escape(tag) == tag
        assert html.escape(tag, quote=True) == tag
        assert json.dumps(tag) == f'"{tag}"'
        assert json.dumps(tag, ensure_ascii=True) == f'"{tag}"'


def test_new_tag_is_random() -> None:
    tags = {new_tag() for _ in range(1000)}
    assert len(tags) == 1000
