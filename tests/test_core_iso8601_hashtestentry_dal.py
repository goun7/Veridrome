"""
Dal-kesen testler: Veridrome sertifika çekirdeği — _parse_iso8601 + _hash_test_entry.

Kapsam:
  - _parse_iso8601: ISO-8601 ayrıştırma dalleri (Z-soneki, ofset, naive→UTC enjeksiyonu,
    basic-format, hafta-tarihi, 24:00 gün-sonu, kesir-truncation, çöp/red)
  - _hash_test_entry: test-sonucu girdisi kanonik-hash dalleri (duration_ms zorlu-coercion,
    NaN/Infinity dahil, -0.0 ayrımı, ekstra-anahtar yok-sayma)
  - saf in-memory; network/HTTP/DB/subprocess YOK — sadece saf-fonksiyon girdileri.

ORTAM-ANATOMI (production kaynak: src/veridrome/certificate/core.py):
  _parse_iso8601(value):
      dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
      dt.tzinfo is None -> dt = dt.replace(tzinfo=utc)     # naive → UTC ENJEKTE
      exception -> None                                   # fail-closed (değil: fail-None)
  _hash_test_entry(entry):
      canon = {"name": str(entry.get("name", "")),
               "outcome": str(entry.get("outcome", ""))}
      "duration_ms" in entry and not None ->
          try: canon["duration_ms"] = float(entry["duration_ms"])
          except (TypeError, ValueError): pass             # sessizce düşür
      sha256(_canonical_bytes(canon))                      # sıralı-anahtar JSON
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import sys

sys.path.insert(0, ".")
sys.path.insert(0, "src")

from veridrome.certificate.core import (  # noqa: E402
    _canonical_bytes,
    _hash_test_entry,
    _parse_iso8601,
)

UTC = datetime.timezone.utc


# ---------------------------------------------------------------------------
# _parse_iso8601 — ayrıştırma dalları
# ---------------------------------------------------------------------------

class TestParseIso8601Valid:
    """Geçerli ISO-8601 girdi dalları — her biri timezone-aware dönmeli."""

    def test_z_suffix_utc(self):
        assert _parse_iso8601("2026-10-08T12:00:00Z") == datetime.datetime(
            2026, 10, 8, 12, 0, tzinfo=UTC
        )

    def test_z_suffix_returns_utc_tzinfo(self):
        assert _parse_iso8601("2026-10-08T12:00:00Z").tzinfo is UTC

    def test_explicit_plus_zero_offset_is_utc(self):
        r = _parse_iso8601("2026-10-08T12:00:00+00:00")
        assert r == datetime.datetime(2026, 10, 8, 12, 0, tzinfo=UTC)
        assert r.utcoffset() == datetime.timedelta(0)

    def test_positive_offset_preserved(self):
        r = _parse_iso8601("2026-10-08T12:00:00+03:00")
        assert r == datetime.datetime(
            2026, 10, 8, 12, 0, tzinfo=datetime.timezone(datetime.timedelta(hours=3))
        )
        assert r.utcoffset() == datetime.timedelta(hours=3)

    def test_negative_offset_preserved(self):
        r = _parse_iso8601("2026-10-08T12:00:00-05:00")
        assert r.utcoffset() == datetime.timedelta(hours=-5)
        assert r.tzinfo is not UTC  # ofset UTC'ye indirgenMEZ

    def test_offset_not_normalized_to_utc(self):
        """ORTAM-OGRENDI: +03:00 korunur, UTC'ye dönüştürülmez (saat DEĞİŞMEZ)."""
        r = _parse_iso8601("2026-10-08T12:00:00+03:00")
        assert r.hour == 12
        assert r == datetime.datetime(2026, 10, 8, 12, 0, tzinfo=datetime.timezone(datetime.timedelta(hours=3)))

    def test_naive_datetime_gets_utc_injected(self):
        """ORTAM-OGRENDI: tzinfo yoksa UTC varsayılır (naive → aware)."""
        r = _parse_iso8601("2026-10-08T12:00:00")
        assert r.tzinfo is UTC
        assert r == datetime.datetime(2026, 10, 8, 12, 0, tzinfo=UTC)

    def test_date_only_defaults_midnight(self):
        r = _parse_iso8601("2026-10-08")
        assert r == datetime.datetime(2026, 10, 8, 0, 0, tzinfo=UTC)
        assert r.tzinfo is UTC

    def test_minute_precision(self):
        assert _parse_iso8601("2026-10-08T12:00") == datetime.datetime(2026, 10, 8, 12, 0, tzinfo=UTC)

    def test_fractional_seconds_milliseconds(self):
        r = _parse_iso8601("2026-10-08T12:00:00.500Z")
        assert r.microsecond == 500_000

    def test_fractional_seconds_max_microseconds(self):
        r = _parse_iso8601("2026-12-31T23:59:59.999999Z")
        assert r == datetime.datetime(2026, 12, 31, 23, 59, 59, 999_999, tzinfo=UTC)

    def test_space_separator_accepted(self):
        assert _parse_iso8601("2026-10-08 12:00:00") == datetime.datetime(
            2026, 10, 8, 12, 0, tzinfo=UTC
        )

    def test_z_replacement_is_global(self):
        """ORTAM-OGRENDI: .replace('Z','+00:00') globaldir — 'ZZ' → '+00:00+00:00' → RED."""
        assert _parse_iso8601("2026-10-08T12:00:00ZZ") is None

    def test_basic_format_date(self):
        """ORTAM-OGRENDI: basic-format (ayraçsız) '20261008' Py3.14'de ayrışır."""
        assert _parse_iso8601("20261008") == datetime.datetime(2026, 10, 8, 0, 0, tzinfo=UTC)

    def test_basic_format_datetime_with_offset(self):
        r = _parse_iso8601("20261008T120000+0300")
        assert r == datetime.datetime(
            2026, 10, 8, 12, 0, tzinfo=datetime.timezone(datetime.timedelta(hours=3))
        )

    def test_week_date(self):
        """ORTAM-OGRENDI: ISO hafta-tarihi '2026-W41-1' → 2026-10-05 (Pazartesi)."""
        assert _parse_iso8601("2026-W41-1") == datetime.datetime(2026, 10, 5, 0, 0, tzinfo=UTC)

    def test_end_of_day_2400_rolls_to_next_day(self):
        """ORTAM-OGRENDI (quirk): 'T24:00:00' ISO-8601 gün-sonu → SONRAKİ gün 00:00."""
        r = _parse_iso8601("2026-10-08T24:00:00")
        assert r == datetime.datetime(2026, 10, 9, 0, 0, tzinfo=UTC)

    def test_datetime_object_input_roundtrips_via_str(self):
        """ORTAM-OGRENDI (quirk): datetime girdisi str()'ye çevrilip yeniden ayrışır."""
        r = _parse_iso8601(datetime.datetime(2026, 10, 8, 12))
        assert r == datetime.datetime(2026, 10, 8, 12, 0, tzinfo=UTC)

    def test_aware_datetime_object_input_roundtrips(self):
        r = _parse_iso8601(datetime.datetime(2026, 10, 8, 12, tzinfo=UTC))
        assert r == datetime.datetime(2026, 10, 8, 12, 0, tzinfo=UTC)

    def test_nanosecond_fraction_truncated_to_microsecond(self):
        """ORTAM-OGRENDI (quirk): 9 basamak kesir → 6 basamağa truncation (123456789→123456)."""
        r = _parse_iso8601("2026-10-08T12:00:00.123456789Z")
        assert r.microsecond == 123_456


class TestParseIso8601Invalid:
    """Geçersiz girdi dalları — hepsi None dönmeli (fail-None)."""

    def test_garbage(self):
        assert _parse_iso8601("garbage") is None

    def test_empty_string(self):
        assert _parse_iso8601("") is None

    def test_none_input(self):
        """ORTAM-OGRENDI: None → str(None)='None' → fromisoformat başarısız → None."""
        assert _parse_iso8601(None) is None

    def test_integer_input(self):
        assert _parse_iso8601(12345) is None

    def test_bytes_input(self):
        """ORTAM-OGRENDI (quirk): str(b'2026-10-08') = "b'2026-10-08'" → RED."""
        assert _parse_iso8601(b"2026-10-08") is None

    def test_invalid_month(self):
        assert _parse_iso8601("2026-13-01T00:00:00Z") is None

    def test_invalid_day(self):
        assert _parse_iso8601("2026-02-30T00:00:00") is None

    def test_invalid_all_fields(self):
        assert _parse_iso8601("2026-13-45T99:99:99Z") is None

    def test_zero_date(self):
        assert _parse_iso8601("0000-00-00T00:00:00Z") is None

    def test_leading_whitespace(self):
        """ORTAM-OGRENDI: strip YOK — boşluklu girdi RED edilir."""
        assert _parse_iso8601(" 2026-10-08T12:00:00Z") is None

    def test_trailing_whitespace(self):
        assert _parse_iso8601("2026-10-08T12:00:00Z ") is None

    def test_trailing_garbage_after_valid(self):
        assert _parse_iso8601("2026-10-08T12:00:00Zgarbage") is None

    def test_leading_garbage_before_valid(self):
        assert _parse_iso8601("garbage2026-10-08T12:00:00Z") is None

    def test_time_only(self):
        """ORTAM-OGRENDI: saat-tarihsiz '12:00:00' → RED (tarih ZORUNLU)."""
        assert _parse_iso8601("12:00:00") is None

    def test_time_only_with_t_prefix(self):
        assert _parse_iso8601("T123456") is None

    def test_ordinal_date_not_supported(self):
        assert _parse_iso8601("2026-282") is None

    def test_random_object(self):
        assert _parse_iso8601(object()) is None


class TestParseIso8601Properties:
    """Ayrık özellik denetimleri — hiçbir girdi exception fırlatmamalı."""

    def test_never_raises_on_any_string(self):
        for s in ["", "x", "\x00", "2026", "Z", "T", ".", "+", "-", "2026-10-08T12:00:00+" ]:
            assert _parse_iso8601(s) is _parse_iso8601(s)  # idempotent-çağrı, exception yok

    def test_result_always_aware_or_none(self):
        for s in ["2026-10-08", "2026-10-08T12:00:00Z", "garbage"]:
            r = _parse_iso8601(s)
            assert r is None or r.tzinfo is not None

    def test_roundtrip_z_equals_plus_offset(self):
        assert _parse_iso8601("2026-10-08T12:00:00Z") == _parse_iso8601("2026-10-08T12:00:00+00:00")


# ---------------------------------------------------------------------------
# _hash_test_entry — hash davranış dalları
# ---------------------------------------------------------------------------

def _manual_hash(name: str, outcome: str, duration_ms=None) -> str:
    canon = {"name": name, "outcome": outcome}
    if duration_ms is not None:
        canon["duration_ms"] = duration_ms
    return hashlib.sha256(_canonical_bytes(canon)).hexdigest()


class TestHashTestEntryStructure:
    """Kanonik yapı ve determinizm."""

    def test_full_entry_matches_manual_computation(self):
        entry = {"name": "test_a", "outcome": "passed", "duration_ms": 12.5}
        assert _hash_test_entry(entry) == _manual_hash("test_a", "passed", 12.5)

    def test_returns_64_char_hex_sha256(self):
        h = _hash_test_entry({"name": "a", "outcome": "b"})
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_deterministic_repeated_calls(self):
        entry = {"name": "test_a", "outcome": "passed", "duration_ms": 1.0}
        assert _hash_test_entry(entry) == _hash_test_entry(entry) == _hash_test_entry(entry)

    def test_different_names_collide_free(self):
        a = _hash_test_entry({"name": "test_a", "outcome": "passed"})
        b = _hash_test_entry({"name": "test_b", "outcome": "passed"})
        assert a != b

    def test_different_outcomes_collide_free(self):
        a = _hash_test_entry({"name": "test_a", "outcome": "passed"})
        b = _hash_test_entry({"name": "test_a", "outcome": "failed"})
        assert a != b

    def test_name_and_outcome_order_independent_in_canon(self):
        """name/outcome sırası hash'i değiştirmez (sorted-keys kanonik)."""
        assert _hash_test_entry({"outcome": "passed", "name": "test_a"}) == _hash_test_entry(
            {"name": "test_a", "outcome": "passed"}
        )

    def test_no_duration_key(self):
        assert _hash_test_entry({"name": "x", "outcome": "ok"}) == _manual_hash("x", "ok")

    def test_empty_entry(self):
        """ORTAM-OGRENDI: boş girdi → name='' outcome='' (get-defaultlar)."""
        assert _hash_test_entry({}) == _manual_hash("", "")

    def test_unicode_name(self):
        h = _hash_test_entry({"name": "çağrı_test", "outcome": "passed"})
        assert h == _manual_hash("çağrı_test", "passed")
        assert len(h) == 64

    def test_extra_keys_ignored(self):
        """ORTAM-OGRENDI: name/outcome/duration_ms dışındaki anahtarlar hash'LENMEZ."""
        base = {"name": "a", "outcome": "ok"}
        assert _hash_test_entry(base) == _hash_test_entry({**base, "extra": "ignored"})
        assert _hash_test_entry(base) == _hash_test_entry({**base, "meta": {"x": 1}})
        assert _hash_test_entry(base) == _hash_test_entry({**base, "node_id": "n1", "seq": 7})


class TestHashTestEntryDurationCoercion:
    """duration_ms zorlu-coercion dalları — ORTAM-OGRENDI: float() çağrısı HERŞEYİ kabul etmeye çalışır."""

    def test_float_duration_included(self):
        assert _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": 12.5}) == _manual_hash(
            "x", "ok", 12.5
        )

    def test_int_duration_coerced_to_float(self):
        h = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": 7})
        assert h == _manual_hash("x", "ok", 7.0)

    def test_none_duration_dropped(self):
        assert _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": None}) == _manual_hash(
            "x", "ok"
        )

    def test_string_numeric_coerced(self):
        """ORTAM-OGRENDI (quirk): '3.5' → 3.0+0.5 → DAHİL edilir (string→float)."""
        h = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": "3.5"})
        assert h == _manual_hash("x", "ok", 3.5)

    def test_string_int_coerced(self):
        h = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": "1000"})
        assert h == _manual_hash("x", "ok", 1000.0)

    def test_bytes_numeric_coerced(self):
        """ORTAM-OGRENDI (quirk): b'5' → float kabul eder → 5.0 DAHİL."""
        h = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": b"5"})
        assert h == _manual_hash("x", "ok", 5.0)

    def test_bool_true_coerced_to_one(self):
        """ORTAM-OGRENDI (quirk): bool float'ın alt-sınıfı — True → 1.0 DAHİL."""
        h = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": True})
        assert h == _manual_hash("x", "ok", 1.0)

    def test_bool_false_coerced_to_zero(self):
        h = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": False})
        assert h == _manual_hash("x", "ok", 0.0)

    def test_underscore_numeric_string_coerced(self):
        """ORTAM-OGRENDI (quirk): Python float() altçizgi kabul eder — '1_000' → 1000.0."""
        h = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": "1_000"})
        assert h == _manual_hash("x", "ok", 1000.0)

    def test_scientific_notation_string_coerced(self):
        h = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": "1e3"})
        assert h == _manual_hash("x", "ok", 1000.0)

    def test_whitespace_padded_string_coerced(self):
        """ORTAM-OGRENDI (quirk): float(' 5 ') boşlukları soyar → 5.0 DAHİL."""
        h = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": " 5 "})
        assert h == _manual_hash("x", "ok", 5.0)

    def test_nan_float_included(self):
        """ORTAM-OGRENDI (quirk): NaN DAHİL edilir — ValueError DEĞİL (json 'NaN' üretir)."""
        h = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": float("nan")})
        assert h != _manual_hash("x", "ok")
        assert len(h) == 64

    def test_infinity_included(self):
        h = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": float("inf")})
        assert h != _manual_hash("x", "ok")

    def test_negative_infinity_included(self):
        h = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": float("-inf")})
        assert h != _manual_hash("x", "ok")

    def test_string_nan_same_as_float_nan(self):
        """ORTAM-OGRENDI (quirk): 'nan' ile float('nan') AYNI hash (ikisi de NaN)."""
        a = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": "nan"})
        b = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": float("nan")})
        assert a == b

    def test_nan_hash_deterministic(self):
        entry = {"name": "x", "outcome": "ok", "duration_ms": float("nan")}
        assert _hash_test_entry(entry) == _hash_test_entry(entry)

    def test_negative_zero_distinct_from_positive_zero(self):
        """ORTAM-OGRENDI (quirk): -0.0 ≠ 0.0 hash'i (json '-0.0' üretir)."""
        p = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": 0.0})
        n = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": -0.0})
        assert p != n

    def test_false_zero_same_as_positive_zero(self):
        p = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": 0.0})
        f = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": False})
        z = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": 0})
        assert p == f == z

    def test_float_coercion_collapse_group(self):
        """ORTAM-OGRENDI: 1.0 == True == '1' == '1.0' == b'1' == 1 hepsi AYNI hash."""
        hashes = {
            _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": v})
            for v in [1.0, True, "1", "1.0", b"1", 1]
        }
        assert len(hashes) == 1

    def test_thousand_collapse_group(self):
        hashes = {
            _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": v})
            for v in ["1e3", "1_000", 1000.0, "1000", 1000]
        }
        assert len(hashes) == 1

    def test_big_int_loses_precision_as_float(self):
        """ORTAM-OGRENDI (quirk): 10**20 float'a dönüşümde duyarlılık kaybeder."""
        h = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": 10**20})
        assert h == _manual_hash("x", "ok", float(10**20))

    def test_repeating_decimal_stable(self):
        h1 = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": 1 / 3})
        h2 = _hash_test_entry({"name": "x", "outcome": "ok", "duration_ms": 0.3333333333333333})
        assert h1 == h2


class TestHashTestEntryDurationDropped:
    """Başarısız coercion dalları — (TypeError, ValueError) sessizce düşürülür."""

    def test_non_numeric_string_dropped(self):
        base = {"name": "x", "outcome": "ok"}
        assert _hash_test_entry({**base, "duration_ms": "abc"}) == _hash_test_entry(base)

    def test_empty_string_dropped(self):
        base = {"name": "x", "outcome": "ok"}
        assert _hash_test_entry({**base, "duration_ms": ""}) == _hash_test_entry(base)

    def test_whitespace_only_string_dropped(self):
        base = {"name": "x", "outcome": "ok"}
        assert _hash_test_entry({**base, "duration_ms": "  "}) == _hash_test_entry(base)

    def test_hex_string_dropped(self):
        base = {"name": "x", "outcome": "ok"}
        assert _hash_test_entry({**base, "duration_ms": "0x10"}) == _hash_test_entry(base)

    def test_list_dropped(self):
        base = {"name": "x", "outcome": "ok"}
        assert _hash_test_entry({**base, "duration_ms": [1, 2]}) == _hash_test_entry(base)

    def test_dict_dropped(self):
        """ORTAM-OGRENDI: dict duration TypeError → düşürülür (None ile AYNI hash)."""
        base = {"name": "x", "outcome": "ok"}
        assert _hash_test_entry({**base, "duration_ms": {"a": 1}}) == _hash_test_entry(base)

    def test_complex_dropped(self):
        base = {"name": "x", "outcome": "ok"}
        assert _hash_test_entry({**base, "duration_ms": complex(1, 2)}) == _hash_test_entry(base)

    def test_tuple_dropped(self):
        base = {"name": "x", "outcome": "ok"}
        assert _hash_test_entry({**base, "duration_ms": (1, 2)}) == _hash_test_entry(base)

    def test_set_dropped(self):
        base = {"name": "x", "outcome": "ok"}
        assert _hash_test_entry({**base, "duration_ms": {1}}) == _hash_test_entry(base)

    def test_object_dropped(self):
        base = {"name": "x", "outcome": "ok"}
        assert _hash_test_entry({**base, "duration_ms": object()}) == _hash_test_entry(base)

    def test_all_failures_collapse_to_no_duration_hash(self):
        """ORTAM-OGRENDI: her başarısız-coercion None-duration ile AYNI hash üretir."""
        base = {"name": "x", "outcome": "ok"}
        ref = _hash_test_entry(base)
        for bad in ["abc", "", "  ", "0x10", [1], {"a": 1}, (1,), complex(1), object(), None]:
            assert _hash_test_entry({**base, "duration_ms": bad}) == ref


class TestHashTestEntryFieldCoercion:
    """name/outcome str() coercion davranışları."""

    def test_missing_name_defaults_empty(self):
        assert _hash_test_entry({"outcome": "ok"}) == _manual_hash("", "ok")

    def test_missing_outcome_defaults_empty(self):
        assert _hash_test_entry({"name": "x"}) == _manual_hash("x", "")

    def test_none_name_becomes_string_none(self):
        """ORTAM-OGRENDI (quirk): name=None → 'None' (eksik-anhtar '' DEĞİL)."""
        assert _hash_test_entry({"name": None, "outcome": "ok"}) == _manual_hash("None", "ok")

    def test_none_outcome_becomes_string_none(self):
        assert _hash_test_entry({"name": "x", "outcome": None}) == _manual_hash("x", "None")

    def test_int_name_coerced(self):
        assert _hash_test_entry({"name": 42, "outcome": "ok"}) == _manual_hash("42", "ok")

    def test_tuple_name_coerced(self):
        assert _hash_test_entry({"name": (1, 2), "outcome": "ok"}) == _manual_hash("(1, 2)", "ok")

    def test_float_name_coerced(self):
        assert _hash_test_entry({"name": 1.5, "outcome": "ok"}) == _manual_hash("1.5", "ok")

    def test_bool_outcome_coerced(self):
        assert _hash_test_entry({"name": "x", "outcome": True}) == _manual_hash("x", "True")

    def test_none_name_differs_from_missing_name(self):
        """ORTAM-OGRENDI: name=None ile name-yok FARKLI hash'ler."""
        assert _hash_test_entry({"name": None, "outcome": "ok"}) != _hash_test_entry({"outcome": "ok"})

    def test_canonical_bytes_sorted_and_compact(self):
        """ORTAM-OGRENDI: kanonik encoding sıralı-anahtar + sıkışık (ensure_ascii=False)."""
        canon = _canonical_bytes({"b": 1, "a": "x", "c": None})
        assert canon == b'{"a":"x","b":1,"c":null}'
        assert json.loads(canon.decode()) == {"a": "x", "b": 1, "c": None}

    def test_hash_is_content_addressable(self):
        """Aynı içerik her zaman aynı hash — bağımsız yeniden-hesaplama."""
        entry = {"name": "test_a", "outcome": "passed", "duration_ms": 12.5}
        from veridrome.certificate.core import _hash_test_entry as h2  # bağımsız import
        assert _hash_test_entry(entry) == h2(entry)
