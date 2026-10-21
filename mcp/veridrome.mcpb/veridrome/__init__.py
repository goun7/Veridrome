"""
Veridrome: Autonomous AI Agent Live Evaluation & Certification Arena.
"""

# Surum-artik TEK-KAYNAKLI: pyproject.toml tek-gercegi. Onceden burada-da
# ayri "0.1.0" vardi ( cift-kaynak). Asagidaki desen OncE-kaynak-agacindaki
# pyproject.toml'i-okur; YOKSA-importlib.metadata'ye-duser ( kurlu-paket).
# Neden-importlib-degil-oncelikli: kaynak-gelistirme-modunda metadata
# site-packages'taki-ESKI-kurulu-surumu-bulur ( yanlis-deger).
from pathlib import Path

# mcpb-demeti ( mcp/veridrome.mcpb/veridrome) icin pyproject-bir-ustteki-
# repo-kokunde: parents[3] -> 73-Veridrome/pyproject.toml.
_PYPROJECT = Path(__file__).resolve().parents[3] / "pyproject.toml"


def _kaynak_surumu():
    """Kaynak-agacindaki-pyproject.toml'den-version-okur ( yoksa-None)."""
    if not _PYPROJECT.exists():
        return None
    for ln in _PYPROJECT.read_text(encoding="utf-8").splitlines():
        if ln.startswith("version ="):
            return ln.split('"')[1]
    return None


_kaynak = _kaynak_surumu()
if _kaynak is not None:
    __version__ = _kaynak
else:  # kurlu-paket ( site-packages) - pyproject-agacta-yok
    from importlib.metadata import PackageNotFoundError, version as _dist_version

    try:
        __version__ = _dist_version("veridrome")
    except PackageNotFoundError:
        __version__ = "0.0.0-dev"
