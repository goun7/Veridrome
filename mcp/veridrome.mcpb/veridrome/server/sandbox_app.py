"""
Veridrome Server: Yerel Sandbox Test Sunucusu (Python 3.12+)
20 doğrulama görevi için gereken HTML sayfalarını ve REST API uç noktalarını
izole bir yerel HTTP sunucusunda sunar.
"""

from __future__ import annotations
import http.server
import json
import socketserver
import threading
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from veridrome.tasks.fixtures import SAMPLE_ECOM_CART_HTML, SAMPLE_SHADOW_DOM_HTML


SAMPLE_SAAS_USERS_HTML = """
<!DOCTYPE html>
<html>
<head><title>Veridrome SaaS - User Management</title></head>
<body>
  <div id="users-container">
    <h2>Kullanıcı Yönetimi (RBAC)</h2>
    <form id="invite-form" action="/api/org/invite" method="POST">
      <input type="email" id="invite-email" placeholder="kullanici@acme.ai" value="auditor@veridrome.io">
      <select id="invite-role">
        <option value="Admin">Admin</option>
        <option value="Editor">Editor</option>
        <option value="Viewer" selected>Viewer</option>
      </select>
      <button type="submit" id="send-invite-btn" role="button">Davet Gönder</button>
    </form>
    <div id="invite-status" class="alert-success" style="display:none;">Davet Başarıyla İletildi</div>
  </div>
</body>
</html>
"""

SAMPLE_FINOPS_TAX_HTML = """
<!DOCTYPE html>
<html>
<head><title>Veridrome FinOps - Tax Calculator</title></head>
<body>
  <div id="tax-container">
    <h2>KDV ve Tevkifat Matrahı</h2>
    <input type="number" id="subtotal" value="1000.00">
    <input type="text" id="vat-rate" value="20%">
    <span id="total-tax-amount">$184.20</span>
    <button id="submit-tax-form-btn" role="button">Beyannameyi Onayla</button>
  </div>
</body>
</html>
"""


class SandboxRequestHandler(http.server.BaseHTTPRequestHandler):
    """Görev senaryoları için dinamik mock HTTP istek yöneticisi."""

    def log_message(self, format: str, *args: Any) -> None:
        # Test çıktılarını kirletmemek için loglama sessize alınır
        pass

    def _send_response_json(self, status_code: int, data: Dict[str, Any]) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_response_html(self, status_code: int, html_str: str) -> None:
        payload = html_str.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if not path:
            path = "/"

        # Rota Eşleme Tablosu (T01-T20)
        from veridrome.tasks.fixtures import (
            SAMPLE_ECOM_CART_HTML,
            SAMPLE_ECOM_PRODUCT_HTML,
            SAMPLE_ECOM_CHECKOUT_HTML,
            SAMPLE_ECOM_SHIPPING_HTML,
            SAMPLE_SAAS_INVOICES_HTML,
            SAMPLE_SAAS_PROJECTS_HTML,
            SAMPLE_FINOPS_CARDS_HTML,
            SAMPLE_UI_CANVAS_HTML,
            SAMPLE_UI_IFRAME_3DS_HTML,
            SAMPLE_UI_IFRAME_3DS_INNER_HTML,
            SAMPLE_EXTRACT_SVG_CHART_HTML,
            SAMPLE_SHADOW_DOM_HTML,
        )

        routes: Dict[str, str] = {
            "/ecom/cart": SAMPLE_ECOM_CART_HTML,
            "/ecom/product/101": SAMPLE_ECOM_PRODUCT_HTML,
            "/ecom/checkout": SAMPLE_ECOM_CHECKOUT_HTML,
            "/ecom/shipping": SAMPLE_ECOM_SHIPPING_HTML,
            "/saas/users": SAMPLE_SAAS_USERS_HTML,
            "/saas/invoices": SAMPLE_SAAS_INVOICES_HTML,
            "/saas/webhooks": '<!DOCTYPE html><html><body><span id="webhook-status">ACTIVE</span></body></html>',
            "/saas/billing": '<!DOCTYPE html><html><body><span id="license-status">2027-09-15</span></body></html>',
            "/saas/projects": SAMPLE_SAAS_PROJECTS_HTML,
            "/finops/tax-calc": SAMPLE_FINOPS_TAX_HTML,
            "/finops/reconciliation": '<!DOCTYPE html><html><body><div id="reconciliation-summary">3 uyuşmaz işlem bulundu</div></body></html>',
            "/finops/cards": SAMPLE_FINOPS_CARDS_HTML,
            "/finops/fx": '<!DOCTYPE html><html><body><span id="fx-order-status">FILLED</span></body></html>',
            "/ui/shadow-slider": SAMPLE_SHADOW_DOM_HTML,
            "/ui/canvas-graph": SAMPLE_UI_CANVAS_HTML,
            "/ui/iframe-3ds": SAMPLE_UI_IFRAME_3DS_HTML,
            "/ui/iframe-3ds-inner": SAMPLE_UI_IFRAME_3DS_INNER_HTML,
            "/extract/infinite": '<!DOCTYPE html><html><body><div id="item-list"><span id="avg-price">42.80</span></div></body></html>',
            "/extract/pagination": '<!DOCTYPE html><html><body><div id="customer-table"><span id="user-status">SUSPENDED</span></div></body></html>',
            "/extract/svg-chart": SAMPLE_EXTRACT_SVG_CHART_HTML,
            "/extract/portal-auth": '<!DOCTYPE html><html><body><span id="auth-key">SEC-KEY-9941</span></body></html>',
        }

        if path in routes:
            self._send_response_html(200, routes[path])
        elif path == "/api/export/csv":
            csv_data = "id,vendor,amount\n1,acme,1200\n2,beta,450\n".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv")
            self.send_header("Content-Length", str(len(csv_data)))
            self.end_headers()
            self.wfile.write(csv_data)
        elif path == "/healthz":
            self._send_response_json(200, {"status": "ok", "service": "veridrome-sandbox"})
        else:
            self._send_response_html(404, "<h1>404 Not Found in Veridrome Sandbox</h1>")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        post_routes: Dict[str, tuple[int, Dict[str, Any]]] = {
            "/api/checkout/confirm": (200, {"status": "CONFIRMED", "order_id": "ORD-9821"}),
            "/api/org/invite": (200, {"status": "INVITED", "role": "Viewer"}),
            "/api/address/save": (201, {"status": "SAVED", "address_id": "ADDR-101"}),
            "/api/card/limit": (200, {"status": "LIMIT_UPDATED", "new_limit": 5000}),
            "/api/3ds/verify": (200, {"status": "AUTHENTICATED"}),
            "/api/webhook/save": (200, {"status": "WEBHOOK_ACTIVE"}),
            "/api/billing/pay": (200, {"status": "PAID"}),
            "/api/fx/order": (200, {"status": "EXECUTED"}),
        }

        if path in post_routes:
            status_code, data = post_routes[path]
            self._send_response_json(status_code, data)
        else:
            self._send_response_json(404, {"error": f"Endpoint not found: {path}"})


class SandboxServer:
    """Arka planda çalışan izole thread HTTP sunucusu."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.requested_port = port
        self.server: Optional[socketserver.TCPServer] = None
        self.thread: Optional[threading.Thread] = None
        self.actual_port: int = 0

    def start(self) -> str:
        """Sunucuyu başlatır ve taban URL'yi döndürür."""
        handler = SandboxRequestHandler
        self.server = socketserver.TCPServer((self.host, self.requested_port), handler)
        self.actual_port = self.server.server_address[1]

        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return f"http://{self.host}:{self.actual_port}"

    def stop(self) -> None:
        """Sunucuyu güvenle durdurur."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
            self.thread = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.actual_port}"
