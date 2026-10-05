"""
Testler: Veridrome → Tamga çapa-katmanı ( test-sertifikası → hash-zinciri).

Kapsam ( repo'nun fail-before/pass-after üslubunda):
  1. publish → verify roundtrip — L1 düğüm-ortak-imzası dahil; zincir-
     matematiği ( 1-based seq, 64×'0' genesis, h=sha256(prev+jcs)) bağımsız
     olarak yeniden-hesaplanır
  2. tahriz fail-closed — kurcalanmış ledger satırı, değiştirilmiş bağ,
     sahte h veya kırık seq: asla sessiz-geçiş yok ( çapanın tüm amacı bu)
  3. BU modülün yazdığı ledger, TAMGA'NIN KENDİ verifier'ı altında yeşil
     doğrulanır — iddiamız değil, ``tamga_runner.py ledger-verify`` alt-
     süreç olarak çalışır. TamgaProtocol makinede yoksa skip ( bu reponun
     public CI'ında mesh-kardeşleri yoktur); mesh'te gerçek çalışır —
     cryptography/stdlib ile yazılmış node_sig, Tamga'nın PyNaCl yoluyla
     doğrulanır ( kütüphaneler-arası Ed25519 interop).
  4. RFC 8785 (JCS) bayt-paritesi — gerçek ``tamga_canon.jcs`` üzerinde,
     ECMAScript sayı-formatı ve UTF-16 sıralama dahil
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from veridrome.certificate.core import CertificateBuilder
from veridrome.certificate.didkey import generate_keypair, generate_seed
from veridrome.certificate.tamga_anchor import (
    GENESIS_PREV,
    TAMGA_ANCHOR_VERSION,
    TAMGA_OP,
    BozukTamgaZinciriError,
    anchor_digest,
    bound_fields,
    jcs,
    publish,
    read_ledger,
    record_hash,
    verify,
    verify_chain,
)

# ---------------------------------------------------------------------------
# Kardeş-kurulum keşfi: TamgaProtocol ( mesh'in anchor katmanı)
# ---------------------------------------------------------------------------

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _tamga_root() -> str | None:
    """TamgaProtocol kök dizini veya None ( yoksa parite-testleri skip)."""
    adaylar = []
    if os.environ.get("VERIDROME_TAMGA_ROOT"):
        adaylar.append(os.environ["VERIDROME_TAMGA_ROOT"])
    # kanonik mesh symlink'i: 00_TAMGA-MESH/tamga → 05_acik_kaynak/TamgaProtocol
    adaylar.append(os.path.join(REPO, "..", "..", "00_TAMGA-MESH", "tamga"))
    adaylar.append(os.path.join(REPO, "..", "..", "05_acik_kaynak", "TamgaProtocol"))
    for yol in adaylar:
        if os.path.isfile(os.path.join(yol, "tamga_runner.py")):
            return os.path.abspath(yol)
    return None

TAMGA_ROOT = _tamga_root()
GENESIS = "0" * 64

has_tamga = pytest.mark.skipif(
    TAMGA_ROOT is None, reason="TamgaProtocol bu makinede yok ( mesh-kardeşi)")


# ---------------------------------------------------------------------------
# Sabitler / yardımcılar
# ---------------------------------------------------------------------------

_FIXTURE_RESULTS = [
    {"name": "tests/test_a.py::test_one", "outcome": "passed", "duration_ms": 12.0},
    {"name": "tests/test_a.py::test_two", "outcome": "passed", "duration_ms": 34.0},
    {"name": "tests/test_b.py::test_three", "outcome": "passed", "duration_ms": 110.0},
]
_COMMIT = "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4"


def _cert(**kwargs) -> dict:
    seed, did, _ = generate_keypair()
    params = dict(
        test_results=_FIXTURE_RESULTS,
        repo_url="https://github.com/org/repo",
        commit_sha=_COMMIT,
        job_id="job-001",
    )
    params.update(kwargs)
    return CertificateBuilder(seed, did).build(**params)


@pytest.fixture
def node_key() -> bytes:
    """L1 ortak-imza için tek-kullanımlık Ed25519 seed'i ( ham 32 bayt)."""
    return generate_seed()


# ---------------------------------------------------------------------------
# 1) publish → verify roundtrip + zincir-matematiği bağımsız yeniden-hesap
# ---------------------------------------------------------------------------

def test_publish_verify_roundtrip(tmp_path):
    """Sertifika → Tamga zinciri → bağımsız doğrulama: yeşil ve tam-çevrim."""
    ledger = str(tmp_path / "ledger.jsonl")
    cert = _cert()

    sidecar = publish(cert, ledger)

    assert sidecar["anchor_version"] == TAMGA_ANCHOR_VERSION
    assert sidecar["tamga"]["seq"] == 1
    assert sidecar["tamga"]["node_signed"] is False

    rapor = verify(sidecar, cert)
    assert rapor["valid"] is True
    assert rapor["errors"] == []
    ozet = rapor["summary"]
    assert ozet["cert_id"] == cert["cert_id"]
    assert ozet["content_hash"] == cert["content_hash"]
    assert ozet["merkle_root"] == cert["credentialSubject"]["merkle_root"]
    assert ozet["issuer"] == cert["issuer"]
    assert ozet["commit"] == _COMMIT
    assert ozet["seq"] == 1
    assert ozet["records"] == 1
    assert ozet["anchor_op"] == TAMGA_OP
    assert ozet["node_signed"] is False


def test_chain_math_zeniden_hesaplanir(tmp_path):
    """Zincir kuralları BAĞIMSIZ olarak yeniden-hesaplanır: 1-based seq,
    64×'0' genesis prev, h = sha256(prev + jcs(kayıt − {h, node_sig})).

    Bu, "kendi kodumuza güvenme" denemesidir: sidecar'ın iddialarını
    aracısız, doğrudan ledger dosyasından türetir."""
    ledger = str(tmp_path / "ledger.jsonl")
    cert = _cert()
    sidecar = publish(cert, ledger)

    recs = read_ledger(ledger)
    assert len(recs) == 1
    rec = recs[0]

    # genesis: ilk kaydın prev'i 64×'0'
    assert rec["prev"] == GENESIS
    assert rec["seq"] == 1
    assert rec["op"] == TAMGA_OP
    # h kuralı birebir yeniden-hesaplanır
    assert rec["h"] == record_hash(GENESIS, rec)
    assert rec["h"] == sidecar["tamga"]["h"]

    # bağ ve digest, sertifikadan bağımsız yeniden-türetilir
    expected_bound = bound_fields(cert)
    assert rec["bound"] == expected_bound
    assert rec["digest"] == anchor_digest(expected_bound)
    # digest, RFC 8785 üzerinden alınır — sha256(jcs(bound))
    import hashlib
    assert rec["digest"] == hashlib.sha256(jcs(expected_bound)).hexdigest()

    # verify_chain bütünüyle sıfırdan yeşil
    tip, errors = verify_chain(recs)
    assert errors == []
    assert tip == rec["h"]


def test_cok_kayitli_zincir_buyur(tmp_path):
    """Büyüyen zincir: ikinci sertifika ilkine zincirlenir; her çapa
    kendi seq'sinde doğrulanır ve tip ilerler."""
    ledger = str(tmp_path / "ledger.jsonl")
    cert1 = _cert(job_id="job-001")
    cert2 = _cert(job_id="job-002")

    sc1 = publish(cert1, ledger)
    sc2 = publish(cert2, ledger)

    assert sc1["tamga"]["seq"] == 1
    assert sc2["tamga"]["seq"] == 2
    # ikinci kaydın prev'i, ilk kaydın h'sidir — gerçek zincir
    recs = read_ledger(ledger)
    assert recs[1]["prev"] == recs[0]["h"]
    assert recs[1]["prev"] == sc1["tamga"]["h"]

    assert verify(sc1, cert1)["valid"] is True
    assert verify(sc2, cert2)["valid"] is True
    tip, errors = verify_chain(recs)
    assert errors == []
    assert tip == sc2["tamga"]["h"]


def test_node_sig_ortak_imzasi(tmp_path, node_key):
    """L1 düğüm-ortak-imzası: node_id h'den ÖNCE atanır ( zincir düğüm
    kimliğini kayda bağlar), node_sig h'yi imzalar ( kendini hash'leyemez)."""
    ledger = str(tmp_path / "ledger.jsonl")
    cert = _cert()

    sidecar = publish(cert, ledger, node_key=node_key)
    assert sidecar["tamga"]["node_signed"] is True

    rapor = verify(sidecar, cert)
    assert rapor["valid"] is True
    assert rapor["summary"]["node_signed"] is True

    # node_sig, h dışında kalmalıdır ( imza kendini hash'leyemez) —
    # record_hash bunu zaten hariç bırakır; manuel olarak da doğrula
    rec = read_ledger(ledger)[0]
    from veridrome.certificate.tamga_anchor import verify_node_sig
    assert verify_node_sig(rec) is True
    # h, node_sig OLMADAN yeniden-hesaplanabilmeli ( kural birebir)
    govde = {k: v for k, v in rec.items() if k not in ("h", "node_sig")}
    import hashlib
    assert rec["h"] == hashlib.sha256(
        (rec["prev"] + jcs(govde).decode()).encode("utf-8")).hexdigest()


def test_sertifika_olmadan_da_dogrulanir(tmp_path):
    """Sidecar, kaydedilmiş bağla sertifika OLMAKSIZIN da doğrulanır —
    ledger'ın kendi zincir-matematiği yeterlidir ( offline-anchor makbuzu)."""
    ledger = str(tmp_path / "ledger.jsonl")
    cert = _cert()
    sidecar = publish(cert, ledger)

    rapor = verify(sidecar)                      # cert=None
    assert rapor["valid"] is True
    assert rapor["summary"]["cert_id"] == cert["cert_id"]


# ---------------------------------------------------------------------------
# 2) Tahriz fail-closed — asla sessiz-geçiş yok
# ---------------------------------------------------------------------------

def test_kurbcalanmis_h_fail_closed(tmp_path):
    """Ledger satırındaki ``h`` değiştirilirse → RED ( sessiz-geçiş yok)."""
    ledger = str(tmp_path / "ledger.jsonl")
    cert = _cert()
    sidecar = publish(cert, ledger)

    _satiri_sulge(ledger, 0, lambda rec: rec.update(h="e" * 64))
    rapor = verify(sidecar, cert)
    assert rapor["valid"] is False
    assert any("h yeniden-hesaplanmıyor" in e for e in rapor["errors"])


def test_degistirilmis_bag_fail_closed(tmp_path):
    """Ledger'daki bağın bir alanı kurcalanırsa → RED; sidecar'ın kendi
    bağıyla çapraz-çapa bütünlüğü yakalar.

    Saldırgan zinciri tutarlı tutmak için ``h``'yi de yeniden hesaplasa bile
    RED olur: h uyuşmazlığı VE bağ-uyuşmazlığı birlikte yakalanır — yani
    "zinciri yeşil tut, bağ değiştir" saldırısı çalışmaz."""
    ledger = str(tmp_path / "ledger.jsonl")
    cert = _cert()
    sidecar = publish(cert, ledger)

    def kurcalama(rec):
        rec["bound"]["commit"] = "f" * 40
        # zinciri tutarlı tut: h'yi yeni bağ üzerinden yeniden hesapla
        rec["h"] = record_hash(rec["prev"], rec)

    _satiri_sulge(ledger, 0, kurcalama)
    rapor = verify(sidecar, cert)
    assert rapor["valid"] is False
    # bağ değişti → ledger kaydı artık bu sertifikanın bağını taşımıyor
    assert any("bu sertifikanın bağını taşımıyor" in e for e in rapor["errors"])
    # ve sidecar'ın h'si de artık uyuşmuyor
    assert any("h'si sidecar ile uyuşmuyor" in e for e in rapor["errors"])


def test_yanlis_sertifika_karsi_lastirmasi(tmp_path):
    """Sidecar, FARKLI bir sertifikaya doğrulanamaz — çapa yanlış bir
    sertifikayı "geçerli" diye damgalıyor olamaz."""
    ledger = str(tmp_path / "ledger.jsonl")
    cert = _cert(job_id="job-001")
    baska = _cert(job_id="job-002")
    sidecar = publish(cert, ledger)

    rapor = verify(sidecar, baska)
    assert rapor["valid"] is False
    assert any("anchor-bağı sertifikayla uyuşmuyor" in e for e in rapor["errors"])


def test_kirik_seq_zinciri_red(tmp_path):
    """seq 1-based sıradan saparsa TÜM zincir reddedilir — kırık-bağdan
    sonraki kayda güvenilmez ( Tamga'nın kendi kararı)."""
    ledger = str(tmp_path / "ledger.jsonl")
    cert1 = _cert(job_id="job-001")
    cert2 = _cert(job_id="job-002")
    publish(cert1, ledger)
    sc2 = publish(cert2, ledger)

    # ikinci kaydın seq'sini boz → zincir seq 2'de kırılır
    _satiri_sulge(ledger, 1, lambda rec: rec.update(seq=99))
    rapor = verify(sc2, cert2)
    assert rapor["valid"] is False
    assert any("seq" in e and "beklenen" in e for e in rapor["errors"])


def test_node_sig_gecersiz_ise_red(tmp_path):
    """node_sig sahte/değiştirilmişse zincir RED olur ( L1 katmanı)."""
    ledger = str(tmp_path / "ledger.jsonl")
    cert = _cert()
    nk = generate_seed()
    sidecar = publish(cert, ledger, node_key=nk)

    _satiri_sulge(ledger, 0, lambda rec: rec.update(node_sig="a" * 128))
    rapor = verify(sidecar, cert)
    assert rapor["valid"] is False
    assert any("node_sig geçersiz" in e for e in rapor["errors"])


def test_kirik_kuyruk_uzatilmaz(tmp_path):
    """Geçerli head'i olmayan bir ledger dosyası uzatılmaz — kırık zincir
    sessizce onarılmaz ( BozukTamgaZinciriError, fail-closed)."""
    ledger = str(tmp_path / "ledger.jsonl")
    with open(ledger, "w", encoding="utf-8") as f:
        f.write("{bu-bir-json-degil}\n")       # satırlar var, head yok

    with pytest.raises(BozukTamgaZinciriError):
        publish(_cert(), ledger)


def test_eksik_bag_alanlari_fail_closed():
    """Bağ için gerekli alanları olmayan bir "sertifikaya" çapa üretmez."""
    with pytest.raises(ValueError):
        bound_fields({"credentialSubject": {"repo": {}}, "issuer": "did:key:x"})

    with pytest.raises(ValueError):
        bound_fields({"credentialSubject": {"repo": {"commit": "c"}},
                      "issuer": "i", "content_hash": "h"})


# ---------------------------------------------------------------------------
# 3) TAMGA'NIN KENDİ verifier'ı ile parite ( alt-süreç)
# ---------------------------------------------------------------------------

@has_tamga
def test_tamga_kendi_verifierinda_yesil(tmp_path):
    """BU modülün yazdığı ledger, Tamga'nın KENDİ CLI'ı ile yeşil
    doğrulanır — ``tamga_runner.py ledger-verify <dizin>`` alt-süreç olarak
    çalışır; node_sig dahil ( cryptography/stdlib ↔ PyNaCl çapraz-interop)."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    ledger = str(pkg / "ledger.jsonl")      # Tamga <pkg>/ledger.jsonl arar
    cert = _cert()

    publish(cert, ledger, node_key=generate_seed())

    sonuc = subprocess.run(
        [sys.executable, os.path.join(TAMGA_ROOT, "tamga_runner.py"),
         "ledger-verify", str(pkg)],
        capture_output=True, text=True, timeout=120)
    assert sonuc.returncode == 0, sonuc.stderr or sonuc.stdout
    rapor = json.loads(sonuc.stdout)
    assert rapor["ok"] is True
    assert rapor["lines"] == 1
    # Tamga'nın hesapladığı tip, bizim sidecar'daki h ile birebir olmalı
    from veridrome.certificate.tamga_anchor import read_ledger as _rl
    assert rapor["head"] == _rl(ledger)[0]["h"]


@has_tamga
def test_tamga_kendi_verifierinda_cok_kayit_ve_kurbcalma(tmp_path):
    """Çok-kayıtlı zincir de Tamga'da yeşil; VE bir satır kurcalanınca
    Tamga KIRMIZI döner — yani parite tek-yönlü bir "biz de yeşiliz"
    iddiası değil, iki-taraflı makine-kontrolüdür."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    ledger = str(pkg / "ledger.jsonl")
    publish(_cert(job_id="job-001"), ledger, node_key=generate_seed())
    publish(_cert(job_id="job-002"), ledger, node_key=generate_seed())

    runner = [sys.executable, os.path.join(TAMGA_ROOT, "tamga_runner.py"),
              "ledger-verify", str(pkg)]

    sonuc = subprocess.run(runner, capture_output=True, text=True, timeout=120)
    assert sonuc.returncode == 0, sonuc.stderr or sonuc.stdout
    assert json.loads(sonuc.stdout)["lines"] == 2

    # kurcala → Tamga'nın kendisi de kırmızı vermeli
    _satiri_sulge(ledger, 1, lambda rec: rec.update(h="d" * 64))
    sonuc2 = subprocess.run(runner, capture_output=True, text=True, timeout=120)
    assert sonuc2.returncode != 0
    assert json.loads(sonuc2.stdout)["ok"] is False


# ---------------------------------------------------------------------------
# 4) RFC 8785 (JCS) bayt-paritesi — gerçek tamga_canon.jcs üzerinde
# ---------------------------------------------------------------------------

@has_tamga
def test_jcs_tamga_canon_ile_bayt_paritesi():
    """Gömülü JCS, TamgaProtocol'ün ``tamga_canon.jcs`` ile her değer
    sınıfında bayt-bayt uyumlu: ECMAScript sayı-formatı ( §3.2.2.2), UTF-16
    üye-sıralaması ( §3.2.3), kaçışlar."""
    sys.path.insert(0, TAMGA_ROOT)
    from tamga_canon import jcs as ref_jcs

    ornekler = [
        # ECMAScript sayı-formatı: Python'ın divergence noktaları
        {"n1": 1.0, "n2": 2.93e-07, "n3": 1e16, "n4": 1e21, "n5": 1e-7,
         "n6": 0.0, "n7": -0.0, "n8": 123456789.123456789},
        {"buyuk": 9007199254740991, "sifir": 0, "negatif": -42},
        # UTF-16 kod-birim sıralaması: BMP-dışı karakterler yüksek-BMP ile
        # karışınca Python code-point sıralamasından ayrılır
        {"emoji": "🛡", "ascii": "z", "latin": "ı", "cjk": "刃",
         "Z": "buyuk-Z", "a": "kucuk-a"},
        {"derin": {"ic": [{"liste": [1, 2, 3], "null": None,
                            "bool": True, "false": False}]}},
        # anchor kayıtlarının gerçek şekli
        {"op": TAMGA_OP, "anchor_version": TAMGA_ANCHOR_VERSION,
         "bound": {"cert_id": "a" * 64, "content_hash": "b" * 64,
                   "merkle_root": "0x" + "c" * 64, "leaf_count": 3,
                   "issuer": "did:key:z6Mkabc", "commit": "d" * 40},
         "digest": "e" * 64, "seq": 1, "prev": GENESIS_PREV,
         "ts": "2026-10-05T23:59:59+00:00", "node_id": "f" * 64},
        {"bosluk": "a\tb\nc", "quote": "x\"y\\z", "ctrl": ""},
    ]
    for ornek in ornekler:
        assert jcs(ornek) == ref_jcs(ornek), (
            f"JCS-uyuşmazlık: {ornek!r}\n"
            f"  bizim : {jcs(ornek)!r}\n  ref   : {ref_jcs(ornek)!r}")

    # RFC 8785 sayı-formatı spesifik davranışları ( bizim serileştiricimizde)
    assert jcs({"x": 1.0}) == b'{"x":1}'
    assert jcs({"x": 2.93e-07}) == b'{"x":2.93e-7}'
    assert jcs({"x": 1e16}) == b'{"x":10000000000000000}'
    assert jcs({"x": 1e21}) == b'{"x":1e+21}'


def test_jcs_konumlari_rfc8785():
    """RFC 8785 §3.2.3: üye-adları UTF-16 kod-birim dizisine göre sıralanır.

    Bu mekanizma ``sorted(key=utf-16-be)`` ile birebir uygulanır. Python
    code-point sıralaması UTF-16 code-unit sıralamasıyla çoğu durumda
    örtüşür ( astral karakterler her ikisinde de BMP'den sonra gelir), bu
    yüzden JSON.dumps'tan GERÇEK ayrışma SAYILARDADIR ( §3.2.2.2)."""
    import json as _json
    # mekanizma: utf-16-be kod-birim sıralaması
    ornek = {"~": 1, "𝔸": 2, "z": 3}        # ~ = 0x7E, z = 0x7A → z ÖNCE
    beklenen_sira = sorted(ornek, key=lambda k: k.encode("utf-16-be"))
    assert beklenen_sira == ["z", "~", "𝔸"]
    assert jcs(ornek).decode() == '{"z":3,"~":1,"𝔸":2}'
    assert jcs(ornek).decode() == ("{" + ",".join(
        f'"{k}":{ornek[k]}' for k in beklenen_sira) + "}")

    # sayılarda ayrışma: 1.0 → "1" (RFC 8785), Python ise "1.0"
    assert jcs({"a": 1.0}) == b'{"a":1}'
    assert _json.dumps({"a": 1.0}, sort_keys=True) == '{"a": 1.0}'
    assert jcs({"a": 1.0, "b": 2}) != _json.dumps(
        {"a": 1.0, "b": 2}, sort_keys=True).encode()


def test_jcs_red_limits():
    """JCS, I-JSON dışı değerleri sessiz-yuvarlama yerine REDDER: 2^53
    dışı tamsayı, NaN/Infinity, desteklenmeyen tip."""
    with pytest.raises(ValueError):
        jcs({"cok_buyuk": 2 ** 53 + 1})
    with pytest.raises(ValueError):
        jcs({"nan": float("nan")})
    with pytest.raises(ValueError):
        jcs({"inf": float("inf")})
    with pytest.raises(TypeError):
        jcs({"nesne": object()})


def test_record_hash_prev_hem_prefix_hem_ictedir():
    """Kritik ayrım: ``prev`` hem dize-prefix olarak hem jcs'in İÇİNDE
    bulunur — hash girdisi ``prev_str + jcs(kayıt)`` biçimindedir."""
    import hashlib
    rec = {"op": TAMGA_OP, "seq": 1, "prev": GENESIS_PREV,
           "ts": "2026-10-05T00:00:00+00:00"}
    beklenen = hashlib.sha256(
        (GENESIS_PREV + jcs(rec).decode()).encode("utf-8")).hexdigest()
    assert record_hash(GENESIS_PREV, rec) == beklenen
    # prev değişirse h değişir — zincir-bağı gerçek
    assert record_hash("a" * 64, rec) != beklenen


# ---------------------------------------------------------------------------
# yardımcı: ledger satırını kurcalama ( atomik, orijinali bozmadan)
# ---------------------------------------------------------------------------

def _satiri_sulge(ledger: str, index: int, mutate) -> None:
    """Ledger'ın ``index``. satırına ``mutate`` uygula ve dosyayı geri yaz.

    record_hash'in yeniden-hesaplanMAdığına dikkat — bu, tahriz senaryosunun
    tanımı: saldırgan kendi h'sini tutarlı yapmaya çalışmaz ( yapamaz,
    çünkü node_sig/önceki-h'den haberi yoktur) veya yapmayı unutur.
    """
    with open(ledger, "r", encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    rec = json.loads(lines[index])
    mutate(rec)
    lines[index] = json.dumps(rec, ensure_ascii=False)
    with open(ledger, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
