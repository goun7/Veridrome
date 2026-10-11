"""
Dal-kesen testler: Tamga çapa-katmanı — _enc_string (RFC 8785 JCS) + _ed25519_pubkey.

Kapsam:
  - _enc_string: JCS dize-serileştirme dalları (_ESCAPE tablosu, < 0x20 uXXXX kaçışı,
    0x7f HAM, UTF-8 HAM, çift-tırnak sarmalama, json.loads gidiş-dönüş)
  - _ed25519_pubkey: seed → node_id (ham açık-anahtar hex) — determinizm, boyut-red,
    zero-seed bilinen-sabit, delege-tutarlılığı
  - saf in-memory; network/HTTP/DB/subprocess YOK.

ORTAM-ANATOMI (production kaynak: src/veridrome/certificate/tamga_anchor.py):
  _ESCAPE = {'"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f',
             '\n': '\\n', '\r': '\\r', '\t': '\\t'}   # 7 giriş — '/' YOK
  _enc_string(s):
      out = ['"']
      for ch in s:
          ch in _ESCAPE          -> out.append(_ESCAPE[ch])
          elif ord(ch) < 0x20    -> out.append(f"\\u{ord(ch):04x}")   # küçük-hex
          else                   -> out.append(ch)   # HAM UTF-8 (non-ASCII kaçışlanMAZ)
      out.append('"')
  _ed25519_pubkey(seed):
      from veridrome.certificate.didkey import derive_public_key
      return derive_public_key(seed).hex()    # ValueError seed != 32 bayt
"""

from __future__ import annotations

import json
import sys

sys.path.insert(0, ".")
sys.path.insert(0, "src")

from veridrome.certificate.didkey import derive_public_key  # noqa: E402
from veridrome.certificate.tamga_anchor import (  # noqa: E402
    _ESCAPE,
    _ed25519_pubkey,
    _enc_string,
)


# ---------------------------------------------------------------------------
# _enc_string — kaçış tablosu dalları
# ---------------------------------------------------------------------------

class TestEncStringEscapeTable:
    """Her _ESCAPE girişi birebir üretmeli."""

    def test_table_exact_contents(self):
        """ORTAM-ANATOMI: tablo tam 7 giriş — '/' ve "'" kaçışlanMAZ."""
        assert _ESCAPE == {
            '"': '\\"',
            "\\": "\\\\",
            "\b": "\\b",
            "\f": "\\f",
            "\n": "\\n",
            "\r": "\\r",
            "\t": "\\t",
        }

    def test_double_quote(self):
        assert _enc_string('"') == '"\\""'

    def test_backslash(self):
        assert _enc_string("\\") == '"\\\\"'

    def test_backspace(self):
        assert _enc_string("\b") == '"\\b"'

    def test_form_feed(self):
        assert _enc_string("\f") == '"\\f"'

    def test_newline(self):
        assert _enc_string("\n") == '"\\n"'

    def test_carriage_return(self):
        assert _enc_string("\r") == '"\\r"'

    def test_tab(self):
        assert _enc_string("\t") == '"\\t"'

    def test_all_escapes_combined(self):
        s = '"\\' + "\b\f\n\r\t"
        out = _enc_string(s)
        assert out == '"\\"\\\\\\b\\f\\n\\r\\t"'
        assert json.loads(out) == s

    def test_escape_precedence_over_low_control(self):
        """ORTAM-OGRENDI: _ESCAPE önce sorgulanır — '\n' (0x0a) '\u000a' DEGIL '\n'."""
        assert _enc_string("\n") == '"\\n"'


class TestEncStringQuoting:
    """Çift-tırnak sarmalama davranışları."""

    def test_empty_string(self):
        assert _enc_string("") == '""'

    def test_simple_ascii(self):
        assert _enc_string("abc") == '"abc"'

    def test_returns_string_type(self):
        assert isinstance(_enc_string("x"), str)

    def test_always_wrapped_in_quotes(self):
        for s in ["", "a", "abc", "\n", "x\"y"]:
            out = _enc_string(s)
            assert out[0] == '"'
            assert out[-1] == '"'
            assert len(out) >= 2

    def test_forward_slash_not_escaped(self):
        """ORTAM-OGRENDI: '/' kaçışlanMAZ (JSON'da izinli, RFC 8785 minimal-kaçış)."""
        assert _enc_string("/") == '"/"'
        assert json.loads(_enc_string("/")) == "/"

    def test_single_quote_not_escaped(self):
        """ORTAM-OGRENDI: "'" kaçışlanMAZ (sadece '"' kaçışlanır)."""
        assert _enc_string("'") == '"\'"'
        assert json.loads(_enc_string("'")) == "'"

    def test_backtick_not_escaped(self):
        assert _enc_string("`") == '"`"'

    def test_no_quotes_inside_content(self):
        """İçerikteki tırnak kaçışlı — çıktı tek bir JSON dizesi."""
        assert json.loads(_enc_string('a"b"c')) == 'a"b"c'


class TestEncStringControlChars:
    """Kontrol-karakterleri < 0x20 → uXXXX kaçış dalları (boundary'ler dahil)."""

    def test_null_byte(self):
        assert _enc_string("\x00") == '"\\u0000"'

    def test_start_of_control_range(self):
        assert _enc_string("\x01") == '"\\u0001"'

    def test_tab_boundary_is_escape_not_unicode(self):
        """0x09 tablo girişi → '\\t' (\\u0009 üretmeZ)."""
        assert _enc_string("\x09") == '"\\t"'

    def test_unit_separator_0x1f(self):
        assert _enc_string("\x1f") == '"\\u001f"'

    def test_space_0x20_is_raw_boundary(self):
        """ORTAM-OGRENDI (boundary): 0x20 HAM — '< 0x20' kesin sınır, 0x20 kaçışlanMAZ."""
        assert _enc_string(" ") == '" "'

    def test_del_0x7f_is_raw(self):
        """ORTAM-OGRENDI (quirk): U+007F (DEL) HAM bırakılır — sadece < 0x20 kaçışlanır."""
        assert _enc_string("\x7f") == '"\x7f"'

    def test_all_control_chars_roundtrip(self):
        for cp in range(0x20):
            ch = chr(cp)
            out = _enc_string(ch)
            assert json.loads(out) == ch, f"roundtrip failed for U+{cp:04X}"

    def test_all_control_chars_have_four_hex_digits(self):
        import re
        for cp in range(0x20):
            if chr(cp) in _ESCAPE:
                continue
            m = re.fullmatch(r'"\\u([0-9a-f]{4})"', _enc_string(chr(cp)))
            assert m, f"U+{cp:04X} 4-basamak küçük-hex kaçış bekledi"
            assert int(m.group(1), 16) == cp

    def test_control_then_ascii_mix(self):
        assert _enc_string("a\x01b") == '"a\\u0001b"'

    def test_adjacent_control_chars(self):
        assert _enc_string("\x00\x1f\x00") == '"\\u0000\\u001f\\u0000"'


class TestEncStringNonAscii:
    """RFC 8785 §3.2.4 minimal-kaçış: non-ASCII HAM UTF-8."""

    def test_latin_accented(self):
        assert _enc_string("café") == '"café"'
        assert json.loads(_enc_string("café")) == "café"

    def test_two_byte_unicode(self):
        s = "héllo"
        out = _enc_string(s)
        assert out == '"' + s + '"'
        assert json.loads(out) == s

    def test_cjk(self):
        s = "日本語"
        assert _enc_string(s) == '"' + s + '"'
        assert json.loads(_enc_string(s)) == s

    def test_astral_plane_emoji(self):
        """ORTAM-OGRENDI: astral-düzey karakter (😀 U+1F600) surrogate-pair olarak
        DEĞIL ham UTF-8 olarak yazılır — json.loads ile gidiş-dönüş sağlanır."""
        s = "emoji😀"
        out = _enc_string(s)
        assert json.loads(out) == s
        assert "\\u" not in out

    def test_no_surrogate_escapes_anywhere(self):
        for s in ["\u20ac", "😀", "𝄞", "a\u20acb"]:
            assert "\\u" not in _enc_string(s)

    def test_non_ascii_not_escaped_like_python_json_ascii(self):
        """ORTAM-OGRENDI: json.dumps(ensure_ascii=True)'den FARKLI — € HAM."""
        assert _enc_string("\u20ac") == '"\u20ac"'
        assert _enc_string("\u20ac") != json.dumps("\u20ac", ensure_ascii=True)

    def test_mixed_ascii_control_nonascii(self):
        s = 'a"b\tcafé😀'
        out = _enc_string(s)
        assert out == '"a\\"b\\tcafé😀"'
        assert json.loads(out) == s

    def test_long_unicode_payload(self):
        s = "çağla" * 20
        out = _enc_string(s)
        assert json.loads(out) == s
        assert out.startswith('"') and out.endswith('"')


class TestEncStringRoundtrip:
    """Gidiş-dönüş özellikleri — çıktı daima geçerli JSON'dur."""

    def test_roundtrip_randomish_ascii(self):
        for s in ["hello world", "key.sub::value", "123", "  lead", "trail  ", "\t\t\t"]:
            assert json.loads(_enc_string(s)) == s

    def test_roundtrip_every_escape_entry(self):
        s = "".join(_ESCAPE.keys())
        assert json.loads(_enc_string(s)) == s

    def test_output_length_grows_with_escapes(self):
        """ORTAM-OGRENDI: her kaçış 1 karakteri 2'ye çevirir (uzunluk +1 kaçış başına)."""
        assert len(_enc_string("a")) == 3  # " a " → 3
        assert len(_enc_string("\n")) == 4  # " \ n " → 4
        assert len(_enc_string("a\n")) == 5  # " a \ n " → 5
        assert len(_enc_string("a\nb")) == 6  # " a \ n b " → 6
        assert len(_enc_string("a\n\tb")) == 8  # +1 daha (\t)

    def test_concatenation_property(self):
        """_enc_string(a)+_enc_string(b) iki ayrı JSON dizesidir (birleştirme yok)."""
        a, b = _enc_string("x"), _enc_string("y")
        assert a == '"x"' and b == '"y"'
        assert json.loads(a) + json.loads(b) == "xy"

    def test_deterministic(self):
        s = 'a"b\\c\td'
        assert _enc_string(s) == _enc_string(s) == _enc_string(s)

    def test_no_double_escaping(self):
        """ORTAM-OGRENDI: kaçış tekrar kaçışlanMAZ — '\\n' literal → '\\\\n'."""
        assert _enc_string("\\n") == '"\\\\n"'
        assert json.loads(_enc_string("\\n")) == "\\n"

    def test_is_valid_json_document_member(self):
        """Çıktı bir JSON nesne-üyesi değerinde kullanılabilir."""
        doc = '{"k":' + _enc_string('a"b\té') + "}"
        assert json.loads(doc) == {"k": 'a"b\té'}


# ---------------------------------------------------------------------------
# _ed25519_pubkey — seed → node_id dalları
# ---------------------------------------------------------------------------

class TestEd25519PubkeyShape:
    """Çıktı biçimi — 64 küçük-hex karakter (ham açık-anahtar)."""

    def test_returns_64_lowercase_hex(self):
        h = _ed25519_pubkey(b"\x42" * 32)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_known_42_seed_value(self):
        """ORTAM-ANATOMI: sabit-seed deterministik çıktı (bayt-bayt tekrarlanabilir)."""
        assert _ed25519_pubkey(b"\x42" * 32) == (
            "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
        )

    def test_zero_seed_is_known_ed25519_base_result(self):
        """ORTAM-OGRENDI: tüm-sıfır seed → bilinen Ed25519 '3b6a27bc...' sabiti."""
        assert _ed25519_pubkey(b"\x00" * 32) == (
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
        )

    def test_one_seed_value(self):
        assert _ed25519_pubkey(b"\x01" + b"\x00" * 31) == (
            "cecc1507dc1ddd7295951c290888f095adb9044d1b73d696e6df065d683bd4fc"
        )

    def test_ff_seed_differs_from_zero_seed(self):
        assert _ed25519_pubkey(b"\xff" * 32) != _ed25519_pubkey(b"\x00" * 32)

    def test_returns_str_type(self):
        assert isinstance(_ed25519_pubkey(b"\x00" * 32), str)


class TestEd25519PubkeyDeterminism:
    """Determinizm ve ayrılık özellikleri."""

    def test_same_seed_same_output(self):
        seed = bytes(range(32))
        assert _ed25519_pubkey(seed) == _ed25519_pubkey(seed) == _ed25519_pubkey(seed)

    def test_single_bit_flip_changes_output(self):
        """ORTAM-OGRENDI: seed'in tek biti çıktıyı tamamen değiştirir (çığ-etkisi)."""
        base = _ed25519_pubkey(b"\x00" * 32)
        for i in range(32):
            flipped = bytearray(b"\x00" * 32)
            flipped[i] = 0x01
            assert _ed25519_pubkey(bytes(flipped)) != base

    def test_distinct_seeds_give_distinct_pubkeys(self):
        pubs = {_ed25519_pubkey(bytes([i]) + b"\x00" * 31) for i in range(256)}
        assert len(pubs) == 256

    def test_pubkey_not_equal_to_seed_hex(self):
        seed = b"\x42" * 32
        assert _ed25519_pubkey(seed) != seed.hex()


class TestEd25519PubkeyDelegation:
    """derive_public_key delege-tutarlılığı (ORTAM-ANATOMI: .hex() delegasyonu)."""

    def test_matches_derive_public_key_hex(self):
        seed = bytes(range(32))
        assert _ed25519_pubkey(seed) == derive_public_key(seed).hex()

    def test_matches_for_random_seeds(self):
        import os
        for _ in range(8):
            seed = os.urandom(32)
            assert _ed25519_pubkey(seed) == derive_public_key(seed).hex()

    def test_delegates_to_didkey_module(self):
        """ORTAM-OGRENDI: didkey.derive_public_key'i çağırır — kendi kripto'su YOK."""
        seed = b"\x07" * 32
        expected = derive_public_key(seed).hex()
        assert _ed25519_pubkey(seed) == expected

    def test_result_is_hex_of_32_raw_bytes(self):
        seed = b"\x00" * 32
        raw = bytes.fromhex(_ed25519_pubkey(seed))
        assert len(raw) == 32
        assert raw == derive_public_key(seed)


class TestEd25519PubkeySeedLength:
    """Seed-boyut doğrulaması — sadece tam-32-bayt kabul edilir."""

    def test_empty_seed_rejected(self):
        import pytest
        with pytest.raises(ValueError, match="32 bytes"):
            _ed25519_pubkey(b"")

    def test_short_seed_rejected(self):
        import pytest
        with pytest.raises(ValueError):
            _ed25519_pubkey(b"\x42" * 31)

    def test_long_seed_rejected(self):
        import pytest
        with pytest.raises(ValueError):
            _ed25519_pubkey(b"\x42" * 33)

    def test_64_byte_seed_rejected(self):
        """ORTAM-OGRENDI: 64-bayt seed de RED (32 dışında hiçbir uzunluk kabul edilmez)."""
        import pytest
        with pytest.raises(ValueError):
            _ed25519_pubkey(b"\x42" * 64)

    def test_error_message_mentions_32_bytes(self):
        import pytest
        with pytest.raises(ValueError) as exc_info:
            _ed25519_pubkey(b"\x42" * 16)
        assert "32 bytes" in str(exc_info.value)
