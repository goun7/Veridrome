"""
Veridrome → Tamga çapa-katmanı: bir test-geçişi sertifikasını Tamga
hash-zincirli ledger'ına sabitler.

KÖPRÜ: 73-Veridrome ( 01_unicorn, AI ajan test-sertifikasyon platformu) ↔
TamgaProtocol ( 05_acik_kaynak, mesh'in bağımsız açık-kaynak kanıt-anchor
katmanı).

``certificate/core.py`` bir CI koşumunu did:key-imzalı, bağımsız-doğrulanabilir
bir **sertifikaya** dönüştürür. Bu modül o sertifikanın *kendisini* — yani
"hangi testler, hangi sürümde, ne zaman, kim imzaladı" bağını — Tamga'nın
**kendi** ledger modelinde bir hash-zinciri kaydı olarak commitment altına alır.
Amaç: test-geçişi iddiasının tek-bir-parti tarafından (bizi silerek /
kurcalayarak) gizlice değiştirilmesini imkânsızlaştırmak; sertifika, Tamga'nın
bağımsız zincirinde de değiştirilemez biçimde paralel yaşamış olur —mesh'in
kalıcı proof-anchor katmanında.

TAMGA LEDGER MODELİ (normatif — TamgaProtocol ``tamga_runner._verify_chain`` ve
``_ledger_append_impl`` ile birebir; RFC-003 D5/D7/D8):

    kayıt   = {op, <yük>, seq, prev, ts[, node_id], h[, node_sig]}
    seq     : 1-based artan tamsayı
    prev    : önceki kaydın ``h`` değeri; İLK kayıt için 64×'0' ( genesis)
    h       = sha256( prev ‖ jcs( kayıt − {h, node_sig}))
    node_sig: hash'in DIŞINDA ( imza kendini hash'leyemez); ``node_id`` İÇERİDE
              ( zincir, ortak-imzalayan düğüm kimliğini kayda bağlar)

İki kritik ayrım ( YANLIŞ anlaşılırsa digest uyuşmaz):

1. ``prev`` hem **dize-prefix** olarak hem de jcs'in **içinde** bulunur — yani
   hash girdisi ``prev_str + jcs(kayıt)`` biçimindedir ( bayt-düzeyinde).
2. Canonicalization **RFC 8785 (JCS)** ile yapılır —
   ``json.dumps(sort_keys=True)`` DEĞİL. RFC 8785: üye-adları UTF-16 kod-birim
   dizisine göre sıralanır ( §3.2.3) ve sayılar ECMAScript
   ``Number.prototype.toString`` algoritmasıyla yazılır ( §3.2.2.2: ``1.0`` →
   ``"1"``, ``2.93e-07`` → ``"2.93e-7"``). Bu, başka bir dilde yazılmış bir
   verifier'ın aynı baytları yeniden türetmesini sağlar; ``json.dumps``
   yalnızca Python'da çalışır.

JCS bu modüle **bağımlılıksız** ( stdlib-only) olarak gömülmüştür —
TamgaProtocol'ün ``tamga_canon.py``'siyle **bayt-bayt uyumlu** olacak biçimde
RFC 8785'den sıfırdan yazılmıştır; parite testi hem gerçek ``tamga_canon.jcs``
üzerinden, hem de bu modülün yazdığı ledger'ın **Tamga'nın kendi CLI'ı**
( ``tamga_runner.py ledger-verify``) ile yeniden-doğrulanması üzerinden çalışır
( mevcutsa; değilse skip — bu repo'nun public CI'ında mesh-kardeşleri yoktur).

Yazı-kapısı sınırı ( dürüst). Tamga'nın kendi append yolu, emitter
registry'sinde olmayan op'ları reddeder ( triple-scope layer 1). Bu modül
ledger dosyasını doğrudan yazar ve bir Tamga emitter'i TAKLİT ETMEZ: kendi
etiketli op'unu ( ``veridrome.cert.anchor``) kullanır, böylece zinciri
taramış bir denetçi o satırın ne olduğunu birebir görür. Tamga'nın
``_verify_chain`` ``op`` alanını opak-veri olarak hash'ler, bu yüzden zincir
YEŞİL doğrulanır; alıcı taraf ``unknown_ops()`` politikasıyla yabancı op'u
görür ve kendi abstain/warn/reject kararını verir ( alıcı-kararı, tasarım
gereği). Mesh operatörü bu kayıtların Tamga-yönetilen bir package ledger'ında
olmasını istiyorsa emitter'ı orada kaydetmelidir.

KULLANIM:

    from veridrome.certificate.tamga_anchor import publish, verify

    # 1) test-geçişi sertifikası üret ( CertificateBuilder)
    cert = CertificateBuilder(seed).build(
        test_results=results, repo_url=url, commit_sha=sha)

    # 2) sertifikayı Tamga zincirine sabitle
    sidecar = publish(cert, "tamga-ledger.jsonl")

    # 3) bağımsız doğrula — Tamga'nın zincir-matematiği + çapraz-çapa bütünlüğü
    rapor = verify(sidecar, cert)
    assert rapor["valid"]

GÜVENLİK-MODELİ: ``verify`` kötü-veride asla hata fırlatmaz —
``{valid, errors, summary}`` döner. Tüm zincir genesisten yeniden-doğrulanır:
kurcalanmış bir ledger satırı, değiştirilmiş bir seq veya sahte bir ``h``
hepsi fail-closed RED olur. "Hiçbir-kanıt INCONCLUSIVE-değil" felsefesi:
zayıf-kanıt > kanıt-yok, dürüst-etiketlenmiş.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
from decimal import Decimal
from typing import Any, Dict, List, Optional, Sequence, Tuple

from veridrome.certificate.didkey import sign as _ed25519_sign
from veridrome.certificate.didkey import verify as _ed25519_verify

# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

TAMGA_ANCHOR_VERSION = "veridrome-anchor-tamga-1"
TAMGA_OP = "veridrome.cert.anchor"
GENESIS_PREV = "0" * 64

# Hash girdisinden çıkarılan alanlar: ``h`` kendini hash'leyemez;
# ``node_sig`` imza-katmanıdır ve ``h``'yi imzaladığı için dışarıda kalmalıdır.
_HASH_DISI_ALANLAR = frozenset({"h", "node_sig"})

# Tamga ile aynı satır-bombası panzehiri (Audit-11 D1): 1 MiB üstü ledger
# satırı okunmadan sentinel'e düşürülür — zincir-denetimi onu kırık işaretler
# ( fail-closed), RAM sınırlı kalır.
MAX_LINE_BYTES = 1 * 1024 * 1024

# RFC 8785 / I-JSON (RFC 7493) güvenli-tamsayı sınırı: ECMAScript Number
# (IEEE-754) sınır-aşan değeri temsil edemediğinden Node yuvarlar, digest
# uyuşmaz. Sessiz-yuvarlama yerine RED.
_SAFE_INT_LIMIT = 2 ** 53


class BozukTamgaZinciriError(RuntimeError):
    """Tamga zincir-bütünlüğü ihlali ( seq/prev/hash uyuşmazlığı) — fail-closed."""


# ---------------------------------------------------------------------------
# RFC 8785 (JCS) — stdlib-only, TamgaProtocol tamga_canon.jcs ile bayt-uyumlu
# ---------------------------------------------------------------------------

_ESCAPE = {
    '"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f",
    "\n": "\\n", "\r": "\\r", "\t": "\\t",
}


def es_number(x: float) -> str:
    """ECMAScript ``Number.prototype.toString`` (RFC 8785 §3.2.2.2).

    NaN/Infinity reddedilir ( I-JSON altkümesi, RFC 7493). ``1.0`` → ``"1"``,
    ``2.93e-07`` → ``"2.93e-7"``, ``1e16`` → ``"10000000000000000"``.
    """
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError(
            "ijson_number_not_finite: NaN/Infinity I-JSON altkümesinde değil (RFC 7493)"
        )
    if x == 0:                       # -0.0 dahil "0" (ECMAScript "0" basar)
        return "0"
    neg = x < 0
    digits, exp = Decimal(repr(abs(x))).as_tuple()[-2:]
    # repr(1.0) → digits '10'; en-kısa gösterime kadar sondaki sıfırları at
    while len(digits) > 1 and digits[-1] == 0:
        digits, exp = digits[:-1], exp + 1
    k = len(digits)
    n = exp + k                      # değer = s × 10^(n-k), 10^(k-1) ≤ s < 10^k
    s = "".join(map(str, digits))
    if k <= n <= 21:
        body = s + "0" * (n - k)
    elif 0 < n <= 21:
        body = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + s
    else:
        e = n - 1
        mant = s if k == 1 else s[0] + "." + s[1:]   # "1e+21", asla "1.e+21"
        body = mant + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return ("-" if neg else "") + body


def _enc_string(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _ESCAPE:
            out.append(_ESCAPE[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)           # raw UTF-8; non-ASCII kaçışlanMAZ
    out.append('"')
    return "".join(out)


def _encode(o: Any, out: List[str]) -> None:
    if o is None:
        out.append("null")
    elif o is True:
        out.append("true")
    elif o is False:
        out.append("false")
    elif isinstance(o, bool):        # savunma: bool, int'ın alt-sınıfıdır
        out.append("true" if o else "false")
    elif isinstance(o, int):
        if not (-_SAFE_INT_LIMIT <= o <= _SAFE_INT_LIMIT):
            raise ValueError(
                "ijson_number_out_of_range: [−2^53, 2^53] dışı tamsayı I-JSON "
                "altkümesinde değil; dize olarak serileştirin"
            )
        out.append(str(o))
    elif isinstance(o, float):
        out.append(es_number(o))
    elif isinstance(o, str):
        out.append(_enc_string(o))
    elif isinstance(o, dict):
        out.append("{")
        first = True
        # §3.2.3: üye-adları UTF-16 kod-birim dizisine göre artan sıralanır.
        for key in sorted(o, key=lambda k: str(k).encode("utf-16-be")):
            if not first:
                out.append(",")
            first = False
            out.append(_enc_string(str(key)))
            out.append(":")
            _encode(o[key], out)
        out.append("}")
    elif isinstance(o, (list, tuple)):
        out.append("[")
        first = True
        for item in o:
            if not first:
                out.append(",")
            first = False
            _encode(item, out)
        out.append("]")
    else:
        raise TypeError(f"jcs-desteklenmeyen-tip: {type(o).__name__}")


def jcs(obj: Any) -> bytes:
    """RFC 8785 canonical serialization ( JCS) — UTF-8 baytları olarak.

    TamgaProtocol ``tamga_canon.jcs`` ile bayt-bayt uyumlu ( parite-testi).
    """
    out: List[str] = []
    _encode(obj, out)
    return "".join(out).encode("utf-8")


def jcs_str(obj: Any) -> str:
    """Aynı canonicalization, ``str`` olarak ( Tamga hash kuralının birebir
    taklidi: digest'lar metin olarak birleştirilir)."""
    return jcs(obj).decode("utf-8")


# ---------------------------------------------------------------------------
# Sertifika-bağlama — gerçek sertifikasyon modelinden çıkar
# ---------------------------------------------------------------------------

def bound_fields(cert: Dict[str, Any]) -> Dict[str, Any]:
    """Bir Veridrome test-geçişi sertifikasından anchor-bağını çıkarır.

    Bağ, sertifikanın **kanıta dayalı** alanlarıdır — yani "hangi testler,
    hangi sürümde, ne zaman, kim imzaladı" sorusunu cevaplayan ve herhangi
    bir bağımsız doğrulayıcı tarafından ``verify_certificate`` ile
    yeniden-hesaplanabilir olan alanlar:

      - ``cert_id``       : sha256(content_hash ‖ imza) — tek-rakam-değişiklik-kırar
      - ``content_hash``  : sha256(kanonik-gövde) — tek-bayt-değişiklik-kırar
      - ``merkle_root``   : geçen-testlerin sıralı-hash kökü
      - ``leaf_count``    : Merkle yaprak sayısı ( özet-tutarlılığı)
      - ``issuer``        : did:key — kim imzaladı ( self-resolving)
      - ``commit``        : testlerin koştuğu commit ( fail-closed-zorunlusu)

    Bu alanlar gövdeden ZORUNLU olarak çıkarılır; eksikleri RED olur —
    "bağlamı-olmayan-çapa" üretmeyiz ( core.py'nin fail-closed felsefesi).
    """
    if not isinstance(cert, dict):
        raise ValueError("sertifika bir JSON nesnesi değil")
    subject = cert.get("credentialSubject")
    if not isinstance(subject, dict):
        raise ValueError("credentialSubject eksik — bu bir Veridrome sertifikası değil")
    repo = subject.get("repo") or {}
    bound = {
        "cert_id": cert.get("cert_id"),
        "content_hash": cert.get("content_hash"),
        "merkle_root": subject.get("merkle_root"),
        "leaf_count": subject.get("merkle_leaf_count"),
        "issuer": cert.get("issuer"),
        "commit": repo.get("commit"),
    }
    missing = [k for k, v in bound.items() if v is None]
    if missing:
        raise ValueError(
            f"sertifikada anchor-bağı için gerekli alanlar eksik: {missing} "
            f"— bağlamı-olmayan-çapa-üretilmez ( fail-closed)"
        )
    return bound


def anchor_digest(bound: Dict[str, Any]) -> str:
    """Bağın kanonik digest'ı: sha256( jcs( bound)).

    Bağın TAMAMI ( sıralı-anahtar değil, RFC 8785 sıralı) üzerinden alınır;
    herhangi bir alandaki tek-bayt-değişiklik digest'ı kırar. Bu, başka bir
    dilde yazılmış bir verifier'ın aynı digest'ı yeniden-türetmesini sağlar.
    """
    return hashlib.sha256(jcs(bound)).hexdigest()


# ---------------------------------------------------------------------------
# Tamga zincir-çekirdeği ( tamga_runner._verify_chain / _ledger_append ile
# bayt-uyumlu)
# ---------------------------------------------------------------------------

def record_hash(prev: str, rec: Dict[str, Any]) -> str:
    """D5 kuralı: ``h = sha256(prev ‖ jcs(kayıt − {h, node_sig}))``.

    ``prev`` hem dize-prefix hem jcs içindedir — Tamga'nın birebir kuralı.
    """
    govde = {k: v for k, v in rec.items() if k not in _HASH_DISI_ALANLAR}
    return hashlib.sha256((prev + jcs_str(govde)).encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def verify_node_sig(rec: Dict[str, Any]) -> bool:
    """L1 düğüm-ortak-imzası: ``node_sig``, ``h``'yi ``node_id``'nin
    Ed25519 anahtarıyla imzalamış mı?

    Veridrome'un kendi ``didkey`` katmanıyla doğrulanır ( stdlib-fallback'li,
    RFC 8032). Tamga kendi tarafında PyNaCl kullanır — ikisi de düz RFC 8032
    Ed25519 olduğu için imzalar çapraz-doğrulanır ( parite-testi kanıtlar).
    """
    try:
        node_id = rec.get("node_id")
        sig = rec.get("node_sig")
        h = rec.get("h")
        if not (isinstance(node_id, str) and isinstance(sig, str)
                and isinstance(h, str)):
            return False
        return _ed25519_verify(bytes.fromhex(node_id), h.encode("utf-8"),
                               bytes.fromhex(sig))
    except Exception:
        return False


def read_ledger(path: str) -> List[Dict[str, Any]]:
    """Ledger'ı kayıt-listesi olarak okur ( Tamga'nın ``_ledger_lines`` aynası).

    Çözülemeyen veya 1 MiB üstü bir satır sentinel ``{}`` olur — zincir
    denetimi onu kırık işaretler ( fail-closed) ve okuyucu çökmez.
    """
    recs: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                if len(line.encode("utf-8")) > MAX_LINE_BYTES:
                    recs.append({})    # satır-bombası: yutmadan sentinel
                    continue
                recs.append(json.loads(line))
            except Exception:
                recs.append({})        # bozuk-satır → zincir-denetimi yakalar
    return recs


def verify_chain(records: Sequence[Dict[str, Any]]) -> Tuple[Optional[str], List[str]]:
    """Tamga'nın ``_verify_chain``'i birebir: genesisten sıkı seq/prev/h denetimi.

    ``(tip, errors)`` döner. Herhangi bir kırılma TÜM zinciri reddeder —
    kırık-bağdan sonraki bir kayıta güvenilmez ( Tamga'nın kendi kararları).
    """
    prev_h: Optional[str] = GENESIS_PREV
    errors: List[str] = []
    n = 0
    for rec in records:
        n += 1
        if not isinstance(rec, dict) or "h" not in rec:
            errors.append(f"zincir kırıldı, seq {n}: h alanı yok")
            return None, errors
        if rec.get("prev") != prev_h:
            errors.append(f"zincir kırıldı, seq {n}: prev uyuşmuyor")
            return None, errors
        if rec.get("seq") != n:
            errors.append(
                f"zincir kırıldı, seq {n}: beklenen {n}, kayıt {rec.get('seq')!r}"
            )
            return None, errors
        if rec["h"] != record_hash(prev_h, rec):
            errors.append(f"zincir kırıldı, seq {n}: h yeniden-hesaplanmıyor")
            return None, errors
        if "node_sig" in rec and not verify_node_sig(rec):
            errors.append(f"zincir kırıldı, seq {n}: node_sig geçersiz")
            return None, errors
        prev_h = rec["h"]
    return prev_h, errors


# ---------------------------------------------------------------------------
# Append — akışkan, kırık-zinciri-uzatmaz
# ---------------------------------------------------------------------------

def _append_record(ledger_path: str, payload: Dict[str, Any], *,
                   node_key: Optional[bytes] = None,
                   now: Optional[str] = None) -> Dict[str, Any]:
    """Tamga gramerinde bir kayıt ekle: seq/prev/ts/h[/node_id/node_sig].

    Akışkan, Tamga'nın append'i gibi: önceki tip, ``h`` taşıyan son kayıt
    aranır; dosyada satırlar var ama geçerli tip yoksa append RED edilir
    ( kırık bir zincir uzatılmaz — fail-closed).
    """
    rec: Dict[str, Any] = dict(payload)
    last_h: Optional[str] = None
    n = 0
    if os.path.exists(ledger_path):
        with open(ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                n += 1
                try:
                    cand = json.loads(line)
                    if isinstance(cand, dict) and cand.get("h"):
                        last_h = cand["h"]
                except Exception:
                    pass
    if last_h is None and n > 0:
        raise BozukTamgaZinciriError(
            "tamga ledger kuyruğunda geçerli head-kayıtı yok — kırık zincir "
            "uzatılmaz ( fail-closed)"
        )
    prev = last_h if last_h is not None else GENESIS_PREV
    rec["seq"] = n + 1
    rec["prev"] = prev
    rec["ts"] = now if now is not None else _now_iso()
    if node_key is not None:
        # node_id, h'den ÖNCE atanır: zincir düğüm-kimliğini kayda bağlar.
        pub = _ed25519_pubkey(node_key)
        rec["node_id"] = pub
        h = record_hash(prev, rec)
        rec["node_sig"] = _ed25519_sign(node_key, h.encode("utf-8")).hex()
        rec["h"] = h
    else:
        rec["h"] = record_hash(prev, rec)

    with open(ledger_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    try:
        os.chmod(ledger_path, 0o600)       # Tamga'nın kendi ledger'ı 0600'dir
    except OSError:
        pass
    return rec


def _ed25519_pubkey(seed: bytes) -> str:
    """Bir 32-bayt Ed25519 seed'inden düğüm kimliğini ( ham açık-anahtar, hex)
    üretir. Tamga'nın ``node_id`` formatıyla aynı: ``VerifyKey`` ham baytları."""
    from veridrome.certificate.didkey import derive_public_key
    return derive_public_key(seed).hex()


# ---------------------------------------------------------------------------
# publish — sertifikayı Tamga zincirine sabitle
# ---------------------------------------------------------------------------

def publish(cert: Dict[str, Any], ledger_path: str, *,
            node_key: Optional[bytes] = None,
            op: str = TAMGA_OP,
            now: Optional[str] = None) -> Dict[str, Any]:
    """Veridrome test-geçişi sertifikasını Tamga gramerli ledger'a sabitle.

    Sertifikanın **bağını** ( ``bound_fields``) bir Tamga kaydının yükü olarak
    yazar; kayıt, bağın **kendi digest'ını** ( ``anchor_digest``) taşıdığı
    için Tamga zincirinde yapılan her kurcalama VEYA sertifikanın
    geriye-dönük her değişikliği ``verify`` ile yakalanır — çapraz-çapa
    ( cross-anchor) bütünlüğü.

    ``node_key`` ( 32-bayt Ed25519 seed) verilirse L1 düğüm-ortak-imzası
    eklenir — Tamga'nın node-cosign katmanının birebir aynısı.

    "sidecar" adı: bu sözlük, sertifika ile birlikte saklanan ve bağımsız
    olarak yeniden-doğrulamaya yeten anchor-makbuzudur.
    """
    bound = bound_fields(cert)
    digest = anchor_digest(bound)
    rec = _append_record(
        ledger_path,
        {
            "op": op,
            "anchor_version": TAMGA_ANCHOR_VERSION,
            "bound": bound,
            "digest": digest,
        },
        node_key=node_key,
        now=now,
    )
    return {
        "anchor_version": TAMGA_ANCHOR_VERSION,
        "tamga": {
            "ledger": ledger_path,
            "seq": rec["seq"],
            "h": rec["h"],
            "node_signed": "node_sig" in rec,
        },
        "bound": bound,
        "digest": digest,
    }


# ---------------------------------------------------------------------------
# verify — offline; yalnızca ledger'ın kendi zincir-matematiğine güvenilir
# ---------------------------------------------------------------------------

def verify(sidecar: Dict[str, Any],
           cert: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Bir anchor sidecar'ı, adını verdiği ledger dosyasına karşı doğrula.

    Kötü-veride asla hata fırlatmaz — ``{valid, errors, summary}`` döner.
    Ledger yeniden-okunur ve TÜM zincir genesisten yeniden-doğrulanır:
    kurcalanmış bir ledger satırı, değiştirilmiş bir seq veya sahte bir ``h``
    hepsi fail-closed RED olur.
    """
    errors: List[str] = []
    if not isinstance(sidecar, dict) \
            or sidecar.get("anchor_version") != TAMGA_ANCHOR_VERSION:
        return {
            "valid": False,
            "errors": [
                f"bu bir tamga anchor sidecar'ı değil "
                f"(anchor_version={sidecar.get('anchor_version')!r})"
            ],
            "summary": {},
        }

    t = sidecar.get("tamga") or {}
    bound = sidecar.get("bound") or {}
    digest = sidecar.get("digest", "")

    if cert is not None:
        # sidecar, eldeki sertifikadan bağımsız olarak yeniden-hesaplanan
        # bağla uyuşmak zorunda — aksi halde önceki bir sertifikaya çapa
        # yanlış bir sertifikaya "geçerli" diye damgalıyor olabilir.
        try:
            expected = bound_fields(cert)
        except ValueError as exc:
            return {"valid": False, "errors": [str(exc)], "summary": {}}
        if bound != expected:
            errors.append(
                "anchor-bağı sertifikayla uyuşmuyor "
                f"(sidecar cert_id={bound.get('cert_id')} "
                f"sertifika cert_id={expected['cert_id']})"
            )
        if digest and digest != anchor_digest(expected):
            errors.append("anchor digest, bağdan yeniden-hesaplanmıyor")

    ledger_path = t.get("ledger")
    seq = t.get("seq")
    if not ledger_path:
        return {"valid": False,
                "errors": errors + ["sidecar bir ledger belirtmiyor"],
                "summary": {}}

    try:
        records = read_ledger(ledger_path)
    except OSError as exc:
        return {"valid": False,
                "errors": errors + [f"ledger-okunamadı: {exc}"],
                "summary": {}}

    # 1) TÜM zincir doğrulanmalı — kırık zincirin içindeki bir kayıta
    # güvenilmez ve geldiğimiz kayıda atlanmaz
    tip, chain_errors = verify_chain(records)
    if chain_errors:
        return {"valid": False, "errors": errors + chain_errors, "summary": {}}

    # 2) adı geçen kayıt var VE sidecar'ın iddia ettiğinin tam olarak kendisi
    rec = next((r for r in records if r.get("seq") == seq), None)
    if rec is None:
        return {"valid": False,
                "errors": errors + [
                    f"{ledger_path} içinde seq {seq} bir kayıt yok"],
                "summary": {}}
    if not isinstance(seq, int) or seq < 1:
        errors.append("sidecar seq pozitif bir tamsayı olmalı")
    if rec.get("h") != t.get("h"):
        errors.append("anchorlanan seq'deki kayıt h'si sidecar ile uyuşmuyor")
    if rec.get("bound") != bound:
        errors.append("ledger kaydı bu sertifikanın bağını taşımıyor")
    if rec.get("digest") != digest:
        errors.append("ledger kaydının digest'ı sidecar ile uyuşmuyor")

    summary = {
        "cert_id": bound.get("cert_id"),
        "content_hash": bound.get("content_hash"),
        "merkle_root": bound.get("merkle_root"),
        "leaf_count": bound.get("leaf_count"),
        "issuer": bound.get("issuer"),
        "commit": bound.get("commit"),
        "digest": anchor_digest(bound) if bound else digest,
        "ledger": ledger_path,
        "seq": seq,
        "h": rec.get("h"),
        "tip": tip,
        "records": len(records),
        "node_signed": "node_sig" in rec,
        "anchor_op": rec.get("op"),
    }
    return {"valid": not errors, "errors": errors, "summary": summary}


__all__ = [
    "TAMGA_ANCHOR_VERSION",
    "TAMGA_OP",
    "GENESIS_PREV",
    "BozukTamgaZinciriError",
    "es_number",
    "jcs",
    "jcs_str",
    "bound_fields",
    "anchor_digest",
    "record_hash",
    "read_ledger",
    "verify_chain",
    "verify_node_sig",
    "publish",
    "verify",
]
