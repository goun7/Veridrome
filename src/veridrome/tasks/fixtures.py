"""
Veridrome Tasks: Test ve Mock HTML/DB Fixture'ları
Playwright olmadan veya izole birim testlerinde W1a doğrulamasını simüle etmek için şablonlar.
"""

from __future__ import annotations
from typing import Any, Dict


SAMPLE_ECOM_CART_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Veridrome Sandbox - Cart</title>
</head>
<body>
  <div id="cart-container" class="checkout-box">
    <h1>Alışveriş Sepeti</h1>
    <div id="cart-items" class="item-list">
      <div class="item-row" data-sku="LAPTOP-PRO-16">
        <span class="item-title">Enterprise Laptop</span>
        <span class="item-price">$1,200.00</span>
      </div>
    </div>
    <div class="coupon-section">
      <input type="text" id="coupon-input" placeholder="Kupon Kodu" value="SPRING26">
      <button id="apply-coupon-btn" role="button" aria-label="Kupon Uygula">Uygula</button>
      <span class="coupon-badge-success" role="status">Kupon Başarıyla Uygulandı</span>
    </div>
    <div class="summary-section">
      <span id="cart-total-amount">$74.50</span>
      <button id="confirm-checkout-btn" role="button">Ödemeyi Tamamla</button>
    </div>
  </div>
</body>
</html>
"""

SAMPLE_SHADOW_DOM_HTML = """
<!DOCTYPE html>
<html>
<body>
  <div id="slider-host">
    <span id="slider-value-output">75%</span>
  </div>
</body>
</html>
"""

SAMPLE_ECOM_PRODUCT_HTML = """
<!DOCTYPE html>
<html>
<head><title>E-Com Product Alternative</title></head>
<body>
  <div id="product-card">
    <h1 id="product-title">Tükenen Ürün Muadili</h1>
    <span id="item-status">Stokta Muadil (SKU: ALT-92)</span>
    <button id="add-substitute-btn">Sepete Ekle</button>
  </div>
</body>
</html>
"""

SAMPLE_ECOM_CHECKOUT_HTML = """
<!DOCTYPE html>
<html>
<head><title>E-Com Checkout</title></head>
<body>
  <form id="checkout-form" action="/api/address/save" method="POST">
    <input type="checkbox" id="billing-same-as-shipping">
    <label for="billing-same-as-shipping">Fatura adresi teslimat adresiyle aynı</label>
    <button type="submit" id="save-address-btn">Adresi Kaydet</button>
  </form>
</body>
</html>
"""

SAMPLE_ECOM_SHIPPING_HTML = """
<!DOCTYPE html>
<html>
<head><title>E-Com Shipping</title></head>
<body>
  <div id="shipping-options">
    <span id="shipping-tier-selected">EXPRESS</span>
  </div>
</body>
</html>
"""

SAMPLE_SAAS_INVOICES_HTML = """
<!DOCTYPE html>
<html>
<head><title>SaaS Invoices</title></head>
<body>
  <div id="invoices-filter">
    <span id="filtered-count">14</span>
    <a href="/api/export/csv" id="export-csv-link">CSV İndir</a>
  </div>
</body>
</html>
"""

SAMPLE_SAAS_PROJECTS_HTML = """
<!DOCTYPE html>
<html>
<head><title>SaaS Projects</title></head>
<body>
  <div id="projects-list">
    <span id="public-project-counter">0</span>
    <button id="make-all-private-btn">Tümünü Gizli Yap</button>
  </div>
</body>
</html>
"""

SAMPLE_FINOPS_CARDS_HTML = """
<!DOCTYPE html>
<html>
<head><title>FinOps Cards</title></head>
<body>
  <div id="card-manager">
    <span id="card-limit-display">$5,000</span>
    <form action="/api/card/limit" method="POST">
      <input type="number" id="new-limit-input" value="5000">
      <button type="submit" id="update-limit-btn">Limiti Güncelle</button>
    </form>
  </div>
</body>
</html>
"""

SAMPLE_UI_CANVAS_HTML = """
<!DOCTYPE html>
<html>
<head><title>UI Canvas Graph</title></head>
<body>
  <canvas id="graph-canvas" width="800" height="600"></canvas>
  <div class="canvas-node-inspector-open">
    <h3>Düğüm Ayrıntıları (Node #12)</h3>
  </div>
</body>
</html>
"""

SAMPLE_UI_IFRAME_3DS_HTML = """
<!DOCTYPE html>
<html>
<head><title>3DS Secure Payment</title></head>
<body>
  <iframe id="3ds-frame" src="/ui/iframe-3ds-inner"></iframe>
</body>
</html>
"""

SAMPLE_UI_IFRAME_3DS_INNER_HTML = """
<!DOCTYPE html>
<html>
<body>
  <form action="/api/3ds/verify" method="POST">
    <input type="text" id="otp-input" value="987654">
    <button type="submit" id="otp-submit-btn">Onayla</button>
  </form>
</body>
</html>
"""

SAMPLE_EXTRACT_SVG_CHART_HTML = """
<!DOCTYPE html>
<html>
<head><title>SVG Chart Extraction</title></head>
<body>
  <svg width="400" height="200" id="sales-chart">
    <rect x="10" y="20" width="30" height="150" data-month="OCTOBER_2025"></rect>
  </svg>
  <div id="agent-selected-month">OCTOBER_2025</div>
</body>
</html>
"""

SAMPLE_DB_SNAPSHOTS: Dict[str, Dict[str, Any]] = {
    "T02": {
        "cart.items[0].sku": "ALT-92",
        "cart.total": 45.0,
    },
    "T04": {
        "order.shipping_tier": "EXPRESS",
        "order.carrier": "FedEx",
    },
    "T05": {
        "audit.latest_action": "USER_INVITED_VIEWER",
        "users.count": 12,
    },
    "T07": {
        "webhook.active": True,
        "webhook.url": "https://api.acme.ai/webhook",
    },
    "T08": {
        "license.valid_until": "2027-09-15",
        "license.tier": "ENTERPRISE",
    },
    "T10": {
        "invoice.tax_total": 184.20,
        "invoice.status": "AUDITED",
    },
    "T11": {
        "reconciliation.flagged_count": 3,
        "reconciliation.status": "RESOLVED",
    },
    "T13": {
        "fx.order_status": "FILLED",
        "fx.amount": 100000,
    },
    "T17": {
        "extraction.computed_average": 42.80,
    },
    "T18": {
        "extraction.user_status": "SUSPENDED",
    },
    "T20": {
        "extraction.auth_key": "SEC-KEY-9941",
    },
}
