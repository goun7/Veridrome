"""
Veridrome Credentials: VAPAP (Agent-to-Product Attestation Protocol) Middleware
Kurumsal API'ler ve SaaS ağ geçitleri için otonom ajan yetkilendirme ve doğrulama katmanı.
"""

from __future__ import annotations
import base64
import json
import time
from typing import Any, Callable, Dict, Optional
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from veridrome.core.crypto import VeridromeAuthoritySigner


class VAPAPAuthMiddleware(BaseHTTPMiddleware):
    """
    HTTP isteklerinde 'X-Veridrome-VAPAP-Token' veya 'Authorization: VAPAP <token>'
    başlığını denetleyen, sahte veya akredite edilmemiş ajanları engelleyen ara yazılım.
    """

    def __init__(
        self,
        app: Any,
        authority_public_key: bytes,
        required_min_score: float = 0.85,
        exempt_paths: Optional[list[str]] = None,
    ):
        super().__init__(app)
        self.authority_public_key = authority_public_key
        self.required_min_score = required_min_score
        self.exempt_paths = exempt_paths or ["/healthz", "/docs", "/openapi.json", "/"]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Muaf tutulan yolları doğrudan geçir
        if request.url.path in self.exempt_paths:
            return await call_next(request)

        token_raw = request.headers.get("X-Veridrome-VAPAP-Token")
        if not token_raw:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("VAPAP "):
                token_raw = auth_header.split(" ", 1)[1]

        if not token_raw:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "error": "VAPAP_TOKEN_MISSING",
                    "detail": "Bu uç nokta Veridrome VAPAP ajan tasdik sertifikası gerektirir.",
                },
            )

        try:
            claims, is_valid = self._verify_token(token_raw)
            if not is_valid:
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={
                        "error": "VAPAP_INVALID_SIGNATURE",
                        "detail": "VAPAP tasdik imzası geçersiz veya tahrif edilmiş.",
                    },
                )

            # Süre kontrolü
            now = int(time.time())
            if claims.get("expires_at", 0) < now:
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={
                        "error": "VAPAP_TOKEN_EXPIRED",
                        "detail": "Ajan sertifikasının geçerlilik süresi dolmuştur.",
                    },
                )

            # Skor eşiği kontrolü
            agent_score = float(claims.get("score_median", 0.0))
            if agent_score < self.required_min_score:
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={
                        "error": "VAPAP_INSUFFICIENT_SCORE",
                        "detail": f"Ajan başarı puanı (%{agent_score*100:.1f}) asgari barajın (%{self.required_min_score*100:.1f}) altındadır.",
                    },
                )

            # İsteğin durumuna ajan kimliğini ekle
            request.state.agent_id = claims.get("agent_id")
            request.state.vapap_claims = claims

        except Exception as e:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "VAPAP_MALFORMED_TOKEN", "detail": str(e)},
            )

        return await call_next(request)

    def _verify_token(self, token_str: str) -> tuple[Dict[str, Any], bool]:
        """Token'ı parçalarına ayırır ve Ed25519 imzasını doğrular."""
        payload_bytes = base64.b64decode(token_str)
        token_data = json.loads(payload_bytes.decode("utf-8"))

        sig_b64 = token_data.get("signature")
        if not sig_b64:
            return {}, False

        token_body = dict(token_data)
        del token_body["signature"]
        canonical_bytes = json.dumps(token_body, sort_keys=True).encode("utf-8")
        sig_bytes = base64.b64decode(sig_b64)

        is_valid = VeridromeAuthoritySigner.verify(
            self.authority_public_key,
            canonical_bytes,
            sig_bytes,
        )
        return token_body, is_valid
