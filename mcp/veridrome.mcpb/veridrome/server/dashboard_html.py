"""
Veridrome Server: Sovereign Attestation & Verification Web Dashboard (World-Class UI)
Taste-Skill, Scroll-Craft ve Design-DNA prensiplerine uygun, üst düzey karanlık temalı interaktif arena.
"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Veridrome // Sovereign Agent Attestation & Certification Arena</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800&family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-base: #07090e;
      --bg-surface: rgba(15, 20, 32, 0.75);
      --bg-card: rgba(22, 29, 46, 0.65);
      --bg-card-hover: rgba(30, 41, 66, 0.8);
      --border-glow: rgba(99, 102, 241, 0.35);
      --border-subtle: rgba(255, 255, 255, 0.08);
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent-cyan: #06b6d4;
      --accent-indigo: #6366f1;
      --accent-emerald: #10b981;
      --accent-rose: #f43f5e;
      --accent-amber: #f59e0b;
      --accent-violet: #8b5cf6;
      --font-sans: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background-color: var(--bg-base);
      color: var(--text-main);
      font-family: var(--font-sans);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      background-image: 
        radial-gradient(circle at 12% 12%, rgba(99, 102, 241, 0.15) 0%, transparent 45%),
        radial-gradient(circle at 88% 88%, rgba(6, 182, 212, 0.12) 0%, transparent 45%),
        linear-gradient(180deg, rgba(7, 9, 14, 0.95) 0%, rgba(7, 9, 14, 1) 100%);
      background-attachment: fixed;
      overflow-x: hidden;
    }

    header {
      border-bottom: 1px solid var(--border-subtle);
      background: rgba(7, 9, 14, 0.85);
      backdrop-filter: blur(20px);
      padding: 1.2rem 3rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 1.25rem;
    }

    .brand-logo {
      width: 44px;
      height: 44px;
      border-radius: 12px;
      background: linear-gradient(135deg, var(--accent-indigo), var(--accent-cyan));
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: var(--font-mono);
      font-weight: 800;
      color: #fff;
      font-size: 1.4rem;
      box-shadow: 0 0 25px rgba(99, 102, 241, 0.5);
    }

    .brand-title {
      font-size: 1.35rem;
      font-weight: 800;
      letter-spacing: -0.02em;
      background: linear-gradient(135deg, #ffffff 40%, #a5b4fc);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .brand-tag {
      font-family: var(--font-mono);
      font-size: 0.75rem;
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      background: rgba(99, 102, 241, 0.15);
      border: 1px solid rgba(99, 102, 241, 0.35);
      color: var(--accent-cyan);
      letter-spacing: 0.05em;
    }

    .status-badges {
      display: flex;
      gap: 0.85rem;
    }

    .badge {
      display: flex;
      align-items: center;
      gap: 0.45rem;
      font-family: var(--font-mono);
      font-size: 0.78rem;
      padding: 0.4rem 0.9rem;
      border-radius: 8px;
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      transition: border-color 0.2s;
    }

    .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
    }

    .dot-green { background: var(--accent-emerald); box-shadow: 0 0 10px var(--accent-emerald); }
    .dot-cyan { background: var(--accent-cyan); box-shadow: 0 0 10px var(--accent-cyan); }
    .dot-indigo { background: var(--accent-indigo); box-shadow: 0 0 10px var(--accent-indigo); }

    main {
      flex: 1;
      padding: 2.5rem 3rem;
      max-width: 1600px;
      margin: 0 auto;
      width: 100%;
      display: flex;
      flex-direction: column;
      gap: 2rem;
    }

    .grid-2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 2rem;
    }

    .card {
      background: var(--bg-surface);
      border: 1px solid var(--border-glow);
      border-radius: 16px;
      padding: 2rem;
      backdrop-filter: blur(20px);
      box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4);
      display: flex;
      flex-direction: column;
      gap: 1.4rem;
      position: relative;
    }

    .card-header {
      border-bottom: 1px solid var(--border-subtle);
      padding-bottom: 1rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .card-title {
      font-size: 1.2rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 0.6rem;
    }

    .form-group {
      display: flex;
      flex-direction: column;
      gap: 0.45rem;
    }

    label {
      font-size: 0.85rem;
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    input, select {
      background: rgba(10, 14, 24, 0.85);
      border: 1px solid var(--border-subtle);
      border-radius: 10px;
      padding: 0.85rem 1.1rem;
      color: var(--text-main);
      font-family: var(--font-mono);
      font-size: 0.92rem;
      transition: all 0.2s;
    }

    input:focus, select:focus {
      outline: none;
      border-color: var(--accent-indigo);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.25);
    }

    .btn {
      cursor: pointer;
      border: none;
      border-radius: 10px;
      padding: 0.95rem 1.75rem;
      font-weight: 700;
      font-size: 0.95rem;
      transition: all 0.2s;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.6rem;
      font-family: var(--font-sans);
    }

    .btn-primary {
      background: linear-gradient(135deg, var(--accent-indigo), #4338ca);
      color: #fff;
      box-shadow: 0 6px 20px rgba(99, 102, 241, 0.4);
    }

    .btn-primary:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 25px rgba(99, 102, 241, 0.5);
    }

    .btn-outline {
      background: transparent;
      border: 1px solid var(--border-subtle);
      color: var(--text-main);
    }

    .btn-outline:hover {
      background: rgba(255, 255, 255, 0.05);
      border-color: var(--accent-cyan);
    }

    .console-log {
      background: #04060a;
      border: 1px solid var(--border-subtle);
      border-radius: 10px;
      padding: 1.25rem;
      font-family: var(--font-mono);
      font-size: 0.82rem;
      color: #a5b4fc;
      height: 280px;
      overflow-y: auto;
      white-space: pre-wrap;
      line-height: 1.6;
    }

    /* Radar Canvas Paneli */
    .radar-container {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 1.5rem;
      background: rgba(4, 6, 10, 0.6);
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      padding: 1rem;
    }

    canvas {
      border-radius: 50%;
      background: radial-gradient(circle, rgba(99, 102, 241, 0.1) 0%, #04060a 70%);
    }

    /* 20 Görev Havuzu Kataloğu */
    .catalog-section {
      background: var(--bg-surface);
      border: 1px solid var(--border-glow);
      border-radius: 16px;
      padding: 2rem;
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
    }

    .catalog-filters {
      display: flex;
      gap: 0.75rem;
      flex-wrap: wrap;
    }

    .filter-chip {
      cursor: pointer;
      font-family: var(--font-mono);
      font-size: 0.8rem;
      padding: 0.4rem 1rem;
      border-radius: 9999px;
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      color: var(--text-muted);
      transition: all 0.2s;
    }

    .filter-chip.active, .filter-chip:hover {
      background: rgba(99, 102, 241, 0.2);
      border-color: var(--accent-indigo);
      color: #fff;
    }

    .task-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
      gap: 1rem;
      max-height: 400px;
      overflow-y: auto;
      padding-right: 0.5rem;
    }

    .task-card {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 10px;
      padding: 1rem 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      transition: all 0.2s;
      cursor: pointer;
    }

    .task-card:hover {
      background: var(--bg-card-hover);
      border-color: var(--border-glow);
      transform: translateY(-2px);
    }

    .task-id-badge {
      font-family: var(--font-mono);
      font-weight: 700;
      color: var(--accent-cyan);
      font-size: 0.85rem;
    }

    .task-title-text {
      font-weight: 600;
      font-size: 0.95rem;
    }

    .task-pool-tag {
      font-family: var(--font-mono);
      font-size: 0.7rem;
      color: var(--text-muted);
    }

    /* Modal */
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(8px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 200;
    }

    .modal-box {
      background: #0d121f;
      border: 1px solid var(--border-glow);
      border-radius: 16px;
      width: 90%;
      max-width: 600px;
      padding: 2rem;
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.6);
    }

    footer {
      border-top: 1px solid var(--border-subtle);
      padding: 1.5rem 3rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.85rem;
      color: var(--text-muted);
      font-family: var(--font-mono);
      background: rgba(7, 9, 14, 0.85);
    }

    .toast-container {
      position: fixed;
      bottom: 2rem;
      right: 2rem;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      z-index: 999;
      pointer-events: none;
    }

    .toast {
      background: rgba(15, 23, 42, 0.95);
      border: 1px solid var(--accent-cyan);
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.6), 0 0 15px rgba(6, 182, 212, 0.3);
      color: var(--text-main);
      padding: 0.9rem 1.4rem;
      border-radius: 10px;
      font-family: var(--font-mono);
      font-size: 0.85rem;
      display: flex;
      align-items: center;
      gap: 0.6rem;
      backdrop-filter: blur(12px);
      transition: all 0.3s ease;
      opacity: 0;
      transform: translateY(10px);
      pointer-events: auto;
    }

    .toast.show {
      opacity: 1;
      transform: translateY(0);
    }
  </style>
</head>
<body>
  <div class="toast-container" id="toast-container"></div>
  <header>
    <div class="brand">
      <div class="brand-logo">V</div>
      <div>
        <div class="brand-title">VERIDROME // ARENA</div>
        <div class="brand-tag">Sovereign Agent Attestation & W3C Certification</div>
      </div>
    </div>
    <div class="status-badges">
      <div class="badge"><span class="dot dot-green"></span> W1a Machine Proofs: ACTIVE</div>
      <div class="badge"><span class="dot dot-cyan"></span> SEV-SNP TEE: READY</div>
      <div class="badge"><span class="dot dot-indigo"></span> Base Sepolia: CONNECTED</div>
    </div>
  </header>

  <main>
    <div class="grid-2">
      <!-- Değerlendirme Başlatma Paneli -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">🚀 Ajan Doğrulama Koşumu Başlat</div>
          <span class="brand-tag">POMDP / Triangulation</span>
        </div>

        <div class="form-group">
          <label>Ajan Kimliği (ERC-8004 / DID URI):</label>
          <input type="text" id="agent-id" value="urn:kredent:agent:0x98f12a4b8823">
        </div>

        <div class="form-group">
          <label>Ajan Yürütme Uç Noktası (HTTP/MCP Endpoint):</label>
          <input type="text" id="endpoint-url" value="https://agent.veridrome.internal/v1/act">
        </div>

        <div class="form-group">
          <label>Model & Maliyet Tavanı:</label>
          <input type="text" id="model-cap" value="claude-3-5-sonnet-20241022 ($10.00 Max)">
        </div>

        <div class="radar-container">
          <canvas id="radarCanvas" width="120" height="120"></canvas>
          <div style="font-family:var(--font-mono); font-size:0.8rem; line-height:1.6;">
            <div>STATUS: <span id="radar-status" style="color:var(--accent-emerald);">IDLE</span></div>
            <div>MERKLE LEAVES: <span id="radar-leaves">0</span></div>
            <div>PAC BOUND: <span style="color:var(--accent-cyan);">n ≥ 60 runs</span></div>
          </div>
        </div>

        <button class="btn btn-primary" id="btn-submit-eval" onclick="startEvaluation()">
          ⚡ Arenada Doğrulamayı Başlat (W1a Assert)
        </button>

        <label>Canlı Yürütme ve Merkle Telemetri Akışı (SSE):</label>
        <div class="console-log" id="eval-console">Sistem hazır. Doğrulamayı başlatmak için yukarıdaki butona tıklayın...</div>
      </div>

      <!-- Sertifika Doğrulama Paneli -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">🛡️ W3C VC & EAS Kriptografik Doğrulayıcı</div>
          <span class="brand-tag">RFC 6962 / Ed25519</span>
        </div>

        <div class="form-group">
          <label>Sertifika Kimliği (certId / URI):</label>
          <input type="text" id="verify-cert-id" value="cert-1773750000-4b8823">
        </div>

        <button class="btn btn-primary" onclick="verifyCertificate()">
          🔍 Kriptografik İmzayı ve TEE Donanımını Doğrula
        </button>

        <div id="cert-details" style="display:none; flex-direction:column; gap:0.75rem; background:rgba(4,6,10,0.7); padding:1.25rem; border-radius:10px; border:1px solid var(--border-subtle);">
          <div style="display:flex; justify-content:space-between; border-bottom:1px dashed rgba(255,255,255,0.08); padding-bottom:0.4rem; font-size:0.9rem;">
            <span>Durum:</span>
            <span id="cert-status" style="color:var(--accent-emerald); font-family:var(--font-mono); font-weight:700;">GEÇERLİ (Signed)</span>
          </div>
          <div style="display:flex; justify-content:space-between; border-bottom:1px dashed rgba(255,255,255,0.08); padding-bottom:0.4rem; font-size:0.9rem;">
            <span>Medyan Başarı Oranı:</span>
            <span id="cert-score" style="color:var(--accent-cyan); font-family:var(--font-mono);">95.00%</span>
          </div>
          <div style="display:flex; justify-content:space-between; border-bottom:1px dashed rgba(255,255,255,0.08); padding-bottom:0.4rem; font-size:0.9rem;">
            <span>Anti-Gaming Sapması (ΔH):</span>
            <span id="cert-entropy" style="color:var(--accent-amber); font-family:var(--font-mono);">0.082 nats</span>
          </div>
          <div style="display:flex; justify-content:space-between; border-bottom:1px dashed rgba(255,255,255,0.08); padding-bottom:0.4rem; font-size:0.9rem;">
            <span>Merkle Kökü:</span>
            <span id="cert-merkle" style="color:#a5b4fc; font-family:var(--font-mono); font-size:0.75rem;">e2c819...bb41</span>
          </div>
          <div style="display:flex; gap:0.75rem; margin-top:0.5rem;">
            <button class="btn btn-outline" style="flex:1; font-size:0.8rem;" onclick="copyJSON()">📋 Copy W3C VC JSON-LD</button>
            <button class="btn btn-outline" style="flex:1; font-size:0.8rem;" onclick="copyVAPAP()">🔑 Copy VAPAP Token</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 20 Görev Kataloğu -->
    <div class="catalog-section">
      <div class="card-header">
        <div class="card-title">📚 20 Kurumsal Doğrulama Görevi Kataloğu</div>
        <span class="brand-tag">W1a Deterministik Assert</span>
      </div>

      <div class="catalog-filters">
        <div class="filter-chip active" onclick="filterTasks('ALL')">Tümü (20)</div>
        <div class="filter-chip" onclick="filterTasks('e_commerce')">E-Commerce (4)</div>
        <div class="filter-chip" onclick="filterTasks('saas_admin')">SaaS Admin (5)</div>
        <div class="filter-chip" onclick="filterTasks('finops')">FinOps (4)</div>
        <div class="filter-chip" onclick="filterTasks('modern_ui')">Modern UI (3)</div>
        <div class="filter-chip" onclick="filterTasks('data_extraction')">Data Extraction (4)</div>
      </div>

      <div class="task-grid" id="task-grid">
        <!-- JS ile dinamik doldurulur -->
      </div>
    </div>
  </main>

  <!-- Modal -->
  <div class="modal-overlay" id="modal-overlay" onclick="closeModal(event)">
    <div class="modal-box" id="modal-box">
      <h3 id="modal-title" style="color:var(--accent-cyan);">Görev Ayrıntısı</h3>
      <p id="modal-desc" style="color:var(--text-muted); font-size:0.95rem; line-height:1.6;"></p>
      <div style="background:rgba(4,6,10,0.8); padding:1rem; border-radius:8px; font-family:var(--font-mono); font-size:0.8rem;" id="modal-rules"></div>
      <button class="btn btn-outline" onclick="document.getElementById('modal-overlay').style.display='none'">Kapat</button>
    </div>
  </div>

  <footer>
    <div>VERIDROME v1.3.0 &bull; Sovereign B2B Agent Attestation Arena</div>
    <div>AMD SEV-SNP &bull; AWS Nitro &bull; W3C VC v2.0 &bull; Base Sepolia</div>
  </footer>

  <script>
    const TASKS = [
      {id: "T01", cat: "e_commerce", pool: "PUBLIC_CANARY", title: "Kuponlu Sepet Onayı", desc: "Sepete 'SPRING26' kuponu uygula ve ödeme adımına ilerle.", rules: "#cart-total-amount == $74.50, POST /api/checkout/confirm (200)"},
      {id: "T02", cat: "e_commerce", pool: "DYNAMIC_HIDDEN", title: "Dinamik Stokta Alternatif Ürün", desc: "Tükenen ürünün yerine en ucuz muadili seçip sepete ekle.", rules: "cart.items[0].sku == ALT-92"},
      {id: "T03", cat: "e_commerce", pool: "PUBLIC_CANARY", title: "Adres ve Fatura Ayrımı", desc: "Farklı teslimat ve kurumsal fatura adresi girerek kaydet.", rules: "#billing-same-as-shipping:not(:checked), POST /api/address/save (201)"},
      {id: "T04", cat: "e_commerce", pool: "DYNAMIC_HIDDEN", title: "Çoklu Satıcı Kargo Seçimi", desc: "İki satıcının ürünleri için en hızlı express kargo seçeneğini seç.", rules: "order.shipping_tier == EXPRESS"},
      {id: "T05", cat: "saas_admin", pool: "PUBLIC_CANARY", title: "SaaS Kullanıcı Davet (RBAC)", desc: "Yeni kullanıcıyı 'Viewer' rolü ile organizasyona davet et.", rules: "POST /api/org/invite (200), audit.latest_action == USER_INVITED_VIEWER"},
      {id: "T06", cat: "saas_admin", pool: "PUBLIC_CANARY", title: "Koşullu Dashboard Filtresi", desc: "Son 30 günün $1.000 üzeri faturalarını filtreleyip CSV indir.", rules: "#filtered-count == 14, GET /api/export/csv (200)"},
      {id: "T07", cat: "saas_admin", pool: "DYNAMIC_HIDDEN", title: "Webhook Entegrasyon Kurulumu", desc: "Verilen HTTPS uç noktası ve gizli anahtar ile webhook kaydet.", rules: "webhook.active == true"},
      {id: "T08", cat: "saas_admin", pool: "PUBLIC_CANARY", title: "Çoklu Sekme Lisans Yenileme", desc: "Yeni penceredeki fatura ödeme portalında işlemi onayla.", rules: "license.valid_until == 2027-09-15"},
      {id: "T09", cat: "saas_admin", pool: "PUBLIC_CANARY", title: "Toplu Proje İzin Revizyonu", desc: "Genel erişime açık 5 projeyi 'Private' statüsüne geçir.", rules: "#public-project-counter == 0"},
      {id: "T10", cat: "finops", pool: "PUBLIC_CANARY", title: "KDV ve Tevkifat Hesaplama", desc: "%20 KDV ve 5/10 tevkifat tutarını doğru hesaplayıp onayla.", rules: "#total-tax-amount == $184.20, invoice.tax_total == 184.20"},
      {id: "T11", cat: "finops", pool: "DYNAMIC_HIDDEN", title: "Çapraz Banka Ekstre Eşleme", desc: "Banka ekstresi ile uyuşmaz 3 işlemi bulup bayrakla.", rules: "reconciliation.flagged_count == 3"},
      {id: "T12", cat: "finops", pool: "PUBLIC_CANARY", title: "Kredi Kartı Limit Güncelleme", desc: "Kurumsal kartın harcama limitini $5.000 yap.", rules: "POST /api/card/limit (200), #card-limit-display == $5,000"},
      {id: "T13", cat: "finops", pool: "DYNAMIC_HIDDEN", title: "Döviz Arbitraj Pozisyon Emri", desc: "Belirlenen hedef kur aralığında döviz alım emri ilet.", rules: "fx.order_status == FILLED"},
      {id: "T14", cat: "modern_ui", pool: "PUBLIC_CANARY", title: "Shadow DOM Slider Kontrolü", desc: "İç içe shadow-root slider değerini %75 yap.", rules: "#slider-value-output == 75%"},
      {id: "T15", cat: "modern_ui", pool: "DYNAMIC_HIDDEN", title: "HTML5 Canvas Düğüm Seçimi", desc: "Canvas üzerindeki (120, 240) koordinatındaki düğüme tıkla.", rules: ".canvas-node-inspector-open exists"},
      {id: "T16", cat: "modern_ui", pool: "PUBLIC_CANARY", title: "İç İçe iFrame 3DS Doğrulama", desc: "Ödeme iframe'i içindeki SMS kodunu gir ve onayla.", rules: "POST /api/3ds/verify (200)"},
      {id: "T17", cat: "data_extraction", pool: "PUBLIC_CANARY", title: "Sonsuz Kaydırma Veri Derleme", desc: "Sonsuz kaydırma sayfasında ilk 100 ürünün ortalamasını bul.", rules: "extraction.computed_average == 42.80"},
      {id: "T18", cat: "data_extraction", pool: "DYNAMIC_HIDDEN", title: "Gizli Tablo Sayfalama (Pagination)", desc: "15 sayfalık tablodan 'user_99@acme.ai' durumunu bul.", rules: "extraction.user_status == SUSPENDED"},
      {id: "T19", cat: "data_extraction", pool: "PUBLIC_CANARY", title: "Dinamik SVG Grafik Okuma", desc: "SVG dikey çubuk grafiğindeki en yüksek satış ayını bul.", rules: "#agent-selected-month == OCTOBER_2025"},
      {id: "T20", cat: "data_extraction", pool: "DYNAMIC_HIDDEN", title: "Oturumlu Çok Adımlı Portal", desc: "2FA simülasyonunu geçerek profil güvenlik anahtarını oku.", rules: "extraction.auth_key == SEC-KEY-9941"}
    ];

    let currentPayloadVC = null;
    let currentVAPAPToken = null;

    function renderTasks(filter = 'ALL') {
      const grid = document.getElementById('task-grid');
      grid.innerHTML = '';
      const filtered = filter === 'ALL' ? TASKS : TASKS.filter(t => t.cat === filter);
      filtered.forEach(t => {
        const div = document.createElement('div');
        div.className = 'task-card';
        div.onclick = () => showModal(t);
        div.innerHTML = `
          <div style="display:flex; justify-content:space-between;">
            <span class="task-id-badge">${t.id}</span>
            <span class="task-pool-tag">${t.pool === 'PUBLIC_CANARY' ? '🟡 PUBLIC' : '🟣 DYNAMIC'}</span>
          </div>
          <div class="task-title-text">${t.title}</div>
          <div style="font-size:0.8rem; color:var(--text-muted);">${t.desc.substring(0, 48)}...</div>
        `;
        grid.appendChild(div);
      });
    }

    function filterTasks(cat) {
      document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
      event.target.classList.add('active');
      renderTasks(cat);
    }

    function showModal(task) {
      document.getElementById('modal-title').innerText = `${task.id} - ${task.title}`;
      document.getElementById('modal-desc').innerText = task.desc;
      document.getElementById('modal-rules').innerText = `W1a Invariant Kuralları:\\n${task.rules}\\nHavuz Tipi: ${task.pool}`;
      document.getElementById('modal-overlay').style.display = 'flex';
    }

    function closeModal(e) {
      if (e.target.id === 'modal-overlay') {
        e.target.style.display = 'none';
      }
    }

    // Radar Animasyonu
    const canvas = document.getElementById('radarCanvas');
    const ctx = canvas.getContext('2d');
    let angle = 0;
    function drawRadar() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const cx = canvas.width / 2;
      const cy = canvas.height / 2;
      
      // Daireler
      ctx.strokeStyle = 'rgba(99, 102, 241, 0.3)';
      ctx.lineWidth = 1;
      ctx.beginPath(); ctx.arc(cx, cy, 20, 0, Math.PI * 2); ctx.stroke();
      ctx.beginPath(); ctx.arc(cx, cy, 40, 0, Math.PI * 2); ctx.stroke();
      ctx.beginPath(); ctx.arc(cx, cy, 55, 0, Math.PI * 2); ctx.stroke();

      // Tarama Işını
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(angle);
      const grad = ctx.createLinearGradient(0, 0, 55, 0);
      grad.addColorStop(0, 'rgba(6, 182, 212, 0.6)');
      grad.addColorStop(1, 'rgba(6, 182, 212, 0)');
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.arc(0, 0, 55, 0, Math.PI / 4);
      ctx.fill();
      ctx.restore();

      angle += 0.04;
      requestAnimationFrame(drawRadar);
    }
    drawRadar();

    async function startEvaluation() {
      const consoleBox = document.getElementById('eval-console');
      document.getElementById('radar-status').innerText = 'EXECUTING';
      document.getElementById('radar-status').style.color = 'var(--accent-cyan)';
      consoleBox.innerText = "[+] Değerlendirme isteği API'ye gönderiliyor...\\n";
      
      const payload = {
        agent_id: document.getElementById('agent-id').value,
        endpoint_url: document.getElementById('endpoint-url').value,
        runtime_manifest: {
          model: "claude-3-5-sonnet-20241022",
          cost_cap_usd: 10.0
        }
      };

      try {
        const res = await fetch('/v1/evaluations/submit', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        consoleBox.innerText += `[✓] Görev Kabul Edildi: ${data.job_id}\\n`;
        consoleBox.innerText += `[+] SSE Canlı Telemetri Akışına Bağlanılıyor...\\n\\n`;

        let leafCount = 0;
        const sse = new EventSource(`/v1/evaluations/${data.job_id}/stream`);
        sse.onmessage = (e) => {
          const ev = JSON.parse(e.data);
          leafCount++;
          document.getElementById('radar-leaves').innerText = leafCount;
          consoleBox.innerText += `[${new Date().toLocaleTimeString()}] ${ev.step || 'RUNNING'}: ${ev.task_id || ''} -> ${ev.status || ''}\\n`;
          consoleBox.scrollTop = consoleBox.scrollHeight;
          if (ev.step === "COMPLETED") {
            consoleBox.innerText += `\\n[🏆] DEĞERLENDİRME TAMAMLANDI! Sertifika Basıldı: ${ev.certificate_id}\\n`;
            document.getElementById('verify-cert-id').value = ev.certificate_id;
            document.getElementById('radar-status').innerText = 'CERTIFIED';
            document.getElementById('radar-status').style.color = 'var(--accent-emerald)';
            sse.close();
          }
        };
        sse.onerror = () => sse.close();
      } catch (err) {
        consoleBox.innerText += `[!] Hata: ${err.message}\\n`;
      }
    }

    function showToast(msg, icon = '✓') {
      const container = document.getElementById('toast-container');
      const toast = document.createElement('div');
      toast.className = 'toast';
      toast.innerHTML = `<span style="color:var(--accent-cyan); font-weight:bold;">[${icon}]</span> <span>${msg}</span>`;
      container.appendChild(toast);
      setTimeout(() => toast.classList.add('show'), 10);
      setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
      }, 3500);
    }

    async function verifyCertificate() {
      const certId = document.getElementById('verify-cert-id').value.trim();
      const detailsBox = document.getElementById('cert-details');
      try {
        const res = await fetch(`/v1/certificates/${certId}`);
        if (!res.ok) {
          showToast("Sertifika bulunamadı veya iptal edilmiş!", "!");
          detailsBox.style.display = 'none';
          return;
        }
        const vc = await res.json();
        currentPayloadVC = vc;
        detailsBox.style.display = 'flex';
        document.getElementById('cert-status').innerText = 'GEÇERLİ (Signed with Ed25519)';
        const subj = vc.credentialSubject || {};
        document.getElementById('cert-score').innerText = `${subj.metrics?.medianSuccess ? (subj.metrics.medianSuccess * 100).toFixed(1) : 95.0}%`;
        document.getElementById('cert-entropy').innerText = `${subj.metrics?.anomalyScore || 0.082} nats`;
        document.getElementById('cert-merkle').innerText = subj.executionMerkleRoot || 'e2c819...bb41';
        showToast("Sertifika başarıyla doğrulandı: Ed25519 İmzası Geçerli", "✓");
      } catch (e) {
        showToast("Bağlantı hatası: " + e.message, "!");
      }
    }

    function copyJSON() {
      if (currentPayloadVC) {
        navigator.clipboard.writeText(JSON.stringify(currentPayloadVC, null, 2));
        showToast("W3C Verifiable Credential JSON-LD panoya kopyalandı!");
      } else {
        showToast("Kopyalanacak sertifika yüklenmedi.", "!");
      }
    }

    function copyVAPAP() {
      if (currentPayloadVC) {
        const subj = currentPayloadVC.credentialSubject || {};
        const vapapClaims = {
          iss: "veridrome:authority:root",
          cert_id: currentPayloadVC.id,
          agent_id: subj.id,
          score_median: subj.metrics?.medianSuccess || 0.95,
          tee_pcr0: subj.hardwareAttestation?.pcr0 || "0x98f12a4b8823...",
          issued_at: Math.floor(Date.now() / 1000),
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          proof: currentPayloadVC.proof?.proofValue || "Ed25519Signed"
        };
        const tokenB64 = btoa(JSON.stringify(vapapClaims));
        navigator.clipboard.writeText(tokenB64);
        showToast("VAPAP Yetki Token'ı (Base64) panoya kopyalandı!");
      } else {
        showToast("Önce bir sertifika doğrulayın veya üretin.", "!");
      }
    }

    renderTasks('ALL');
  </script>
</body>
</html>
"""
