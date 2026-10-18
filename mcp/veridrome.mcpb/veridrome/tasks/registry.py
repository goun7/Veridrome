"""
Veridrome Tasks: Görev Kütüğü (Registry)
T01-T20 arasındaki 20 kurumsal doğrulama görevinin tam sözleşmeleri.
"""

from __future__ import annotations
from typing import Dict, List, Optional
from veridrome.tasks.models import EnvironmentSpec, InvariantSpec, PoolType, TaskCategory, TaskSpec


class TaskRegistry:
    """Tüm Veridrome görevlerini barındıran ve filtreleyen kütüphane."""

    def __init__(self):
        self._tasks: Dict[str, TaskSpec] = {}
        self._initialize_tasks()

    def _initialize_tasks(self) -> None:
        raw_specs = [
            # --- 1. E-COMMERCE ---
            TaskSpec(
                task_id="T01",
                title="Kuponlu Sepet Onayı",
                category=TaskCategory.E_COMMERCE,
                pool_type=PoolType.PUBLIC_CANARY,
                objective="Kullanıcı sepetine 'SPRING26' kuponunu uygula ve ödeme adımına ilerle.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/ecom/cart"),
                invariants=[
                    InvariantSpec(rule_type="dom_selector_text", selector="#cart-total-amount", expected_regex=r"^\$74\.50$"),
                    InvariantSpec(rule_type="dom_element_state", selector=".coupon-badge-success", must_exist=True),
                    InvariantSpec(rule_type="network_assert", selector="/api/checkout/confirm", status_code=200),
                ],
            ),
            TaskSpec(
                task_id="T02",
                title="Dinamik Stokta Alternatif Ürün",
                category=TaskCategory.E_COMMERCE,
                pool_type=PoolType.DYNAMIC_HIDDEN,
                objective="Tükenen ürünün yerine en ucuz muadili seçip sepete ekle.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/ecom/product/101"),
                invariants=[
                    InvariantSpec(rule_type="db_assert", selector="cart.items[0].sku", expected_db_value="ALT-92"),
                    InvariantSpec(rule_type="dom_selector_text", selector="#item-status", expected_regex=r"Stokta Muadil"),
                ],
            ),
            TaskSpec(
                task_id="T03",
                title="Adres ve Fatura Ayrımı",
                category=TaskCategory.E_COMMERCE,
                pool_type=PoolType.PUBLIC_CANARY,
                objective="Farklı teslimat ve kurumsal fatura adresi girerek kaydet.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/ecom/checkout"),
                invariants=[
                    InvariantSpec(rule_type="dom_element_state", selector="#billing-same-as-shipping:not(:checked)", must_exist=True),
                    InvariantSpec(rule_type="network_assert", selector="/api/address/save", status_code=201),
                ],
            ),
            TaskSpec(
                task_id="T04",
                title="Çoklu Satıcı Kargo Seçimi",
                category=TaskCategory.E_COMMERCE,
                pool_type=PoolType.DYNAMIC_HIDDEN,
                objective="Farklı iki satıcının ürünleri için en hızlı express kargo seçeneğini seç.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/ecom/shipping"),
                invariants=[
                    InvariantSpec(rule_type="db_assert", selector="order.shipping_tier", expected_db_value="EXPRESS"),
                ],
            ),

            # --- 2. SAAS ADMINISTRATION ---
            TaskSpec(
                task_id="T05",
                title="SaaS Kullanıcı Davet (RBAC)",
                category=TaskCategory.SAAS_ADMIN,
                pool_type=PoolType.PUBLIC_CANARY,
                objective="Yeni kullanıcıyı 'Viewer' rolü ile organizasyona davet et.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/saas/users"),
                invariants=[
                    InvariantSpec(rule_type="network_assert", selector="/api/org/invite", status_code=200),
                    InvariantSpec(rule_type="db_assert", selector="audit.latest_action", expected_db_value="USER_INVITED_VIEWER"),
                ],
            ),
            TaskSpec(
                task_id="T06",
                title="Koşullu Dashboard Filtresi",
                category=TaskCategory.SAAS_ADMIN,
                pool_type=PoolType.PUBLIC_CANARY,
                objective="Son 30 günün $1.000 üzeri faturalarını filtreleyip CSV raporu oluştur.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/saas/invoices"),
                invariants=[
                    InvariantSpec(rule_type="dom_selector_text", selector="#filtered-count", expected_regex=r"^14$"),
                    InvariantSpec(rule_type="network_assert", selector="/api/export/csv", status_code=200),
                ],
            ),
            TaskSpec(
                task_id="T07",
                title="Webhook Entegrasyon Kurulumu",
                category=TaskCategory.SAAS_ADMIN,
                pool_type=PoolType.DYNAMIC_HIDDEN,
                objective="Verilen HTTPS uç noktası ve gizli anahtar ile webhook kaydet.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/saas/webhooks"),
                invariants=[
                    InvariantSpec(rule_type="db_assert", selector="webhook.active", expected_db_value=True),
                ],
            ),
            TaskSpec(
                task_id="T08",
                title="Çoklu Sekme Lisans Yenileme",
                category=TaskCategory.SAAS_ADMIN,
                pool_type=PoolType.PUBLIC_CANARY,
                objective="Yeni açılan penceredeki fatura ödeme portalında işlemi onayla.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/saas/billing"),
                invariants=[
                    InvariantSpec(rule_type="db_assert", selector="license.valid_until", expected_db_value="2027-09-15"),
                ],
            ),
            TaskSpec(
                task_id="T09",
                title="Toplu Proje İzin Revizyonu",
                category=TaskCategory.SAAS_ADMIN,
                pool_type=PoolType.PUBLIC_CANARY,
                objective="Genel erişime açık 5 projeyi 'Private' statüsüne geçir.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/saas/projects"),
                invariants=[
                    InvariantSpec(rule_type="dom_selector_text", selector="#public-project-counter", expected_regex=r"^0$"),
                ],
            ),

            # --- 3. FINOPS & ACCOUNTING ---
            TaskSpec(
                task_id="T10",
                title="KDV ve Tevkifat Hesaplama",
                category=TaskCategory.FINOPS,
                pool_type=PoolType.PUBLIC_CANARY,
                objective="Fatura kalemlerindeki %20 KDV ve 5/10 tevkifat tutarını doğru hesaplayıp onayla.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/finops/tax-calc"),
                invariants=[
                    InvariantSpec(rule_type="dom_selector_text", selector="#total-tax-amount", expected_regex=r"^\$184\.20$"),
                    InvariantSpec(rule_type="db_assert", selector="invoice.tax_total", expected_db_value=184.20),
                ],
            ),
            TaskSpec(
                task_id="T11",
                title="Çapraz Banka Ekstre Eşleme",
                category=TaskCategory.FINOPS,
                pool_type=PoolType.DYNAMIC_HIDDEN,
                objective="Banka ekstresi ile genel muhasebe tablosundaki uyuşmaz 3 işlemi bulup bayrakla.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/finops/reconciliation"),
                invariants=[
                    InvariantSpec(rule_type="db_assert", selector="reconciliation.flagged_count", expected_db_value=3),
                ],
            ),
            TaskSpec(
                task_id="T12",
                title="Kredi Kartı Limit Güncelleme",
                category=TaskCategory.FINOPS,
                pool_type=PoolType.PUBLIC_CANARY,
                objective="Kurumsal kartın aylık harcama limitini onay adımlarını geçerek $5.000 yap.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/finops/cards"),
                invariants=[
                    InvariantSpec(rule_type="network_assert", selector="/api/card/limit", status_code=200),
                    InvariantSpec(rule_type="dom_selector_text", selector="#card-limit-display", expected_regex=r"^\$5,000$"),
                ],
            ),
            TaskSpec(
                task_id="T13",
                title="Döviz Arbitraj Pozisyon Emri",
                category=TaskCategory.FINOPS,
                pool_type=PoolType.DYNAMIC_HIDDEN,
                objective="Belirlenen hedef kur aralığında döviz alım emri ilet.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/finops/fx"),
                invariants=[
                    InvariantSpec(rule_type="db_assert", selector="fx.order_status", expected_db_value="FILLED"),
                ],
            ),

            # --- 4. MODERN UI & SHADOW DOM ---
            TaskSpec(
                task_id="T14",
                title="Shadow DOM Slider Kontrolü",
                category=TaskCategory.MODERN_UI,
                pool_type=PoolType.PUBLIC_CANARY,
                objective="Web component içindeki iç içe shadow-root slider değerini %75 yap.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/ui/shadow-slider"),
                invariants=[
                    InvariantSpec(rule_type="dom_selector_text", selector="#slider-value-output", expected_regex=r"^75%$"),
                ],
            ),
            TaskSpec(
                task_id="T15",
                title="HTML5 Canvas Düğüm Seçimi",
                category=TaskCategory.MODERN_UI,
                pool_type=PoolType.DYNAMIC_HIDDEN,
                objective="Canvas üzerindeki (120, 240) koordinatındaki düğüme tıkla ve paneli aç.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/ui/canvas-graph"),
                invariants=[
                    InvariantSpec(rule_type="dom_element_state", selector=".canvas-node-inspector-open", must_exist=True),
                ],
            ),
            TaskSpec(
                task_id="T16",
                title="İç İçe iFrame 3DS Doğrulama",
                category=TaskCategory.MODERN_UI,
                pool_type=PoolType.PUBLIC_CANARY,
                objective="Ödeme iframe'i içindeki SMS kodunu gir ve onayla.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/ui/iframe-3ds"),
                invariants=[
                    InvariantSpec(rule_type="network_assert", selector="/api/3ds/verify", status_code=200),
                ],
            ),

            # --- 5. DATA EXTRACTION & ANALYSIS ---
            TaskSpec(
                task_id="T17",
                title="Sonsuz Kaydırma Veri Derleme",
                category=TaskCategory.DATA_EXTRACTION,
                pool_type=PoolType.PUBLIC_CANARY,
                objective="Sonsuz kaydırma sayfasında ilk 100 ürünün fiyat ortalamasını bul.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/extract/infinite"),
                invariants=[
                    InvariantSpec(rule_type="db_assert", selector="extraction.computed_average", expected_db_value=42.80),
                ],
            ),
            TaskSpec(
                task_id="T18",
                title="Gizli Tablo Sayfalama (Pagination)",
                category=TaskCategory.DATA_EXTRACTION,
                pool_type=PoolType.DYNAMIC_HIDDEN,
                objective="15 sayfalık müşteri tablosundan 'user_99@acme.ai' durumunu tespit et.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/extract/pagination"),
                invariants=[
                    InvariantSpec(rule_type="db_assert", selector="extraction.user_status", expected_db_value="SUSPENDED"),
                ],
            ),
            TaskSpec(
                task_id="T19",
                title="Dinamik SVG Grafik Okuma",
                category=TaskCategory.DATA_EXTRACTION,
                pool_type=PoolType.PUBLIC_CANARY,
                objective="SVG dikey çubuk grafiğindeki en yüksek satış ayı değerini tespit et.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/extract/svg-chart"),
                invariants=[
                    InvariantSpec(rule_type="dom_selector_text", selector="#agent-selected-month", expected_regex=r"^OCTOBER_2025$"),
                ],
            ),
            TaskSpec(
                task_id="T20",
                title="Oturumlu Çok Adımlı Portal",
                category=TaskCategory.DATA_EXTRACTION,
                pool_type=PoolType.DYNAMIC_HIDDEN,
                objective="2FA simülasyonunu geçerek profil güvenlik anahtarını oku.",
                environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/extract/portal-auth"),
                invariants=[
                    InvariantSpec(rule_type="db_assert", selector="extraction.auth_key", expected_db_value="SEC-KEY-9941"),
                ],
            ),
        ]

        for spec in raw_specs:
            self._tasks[spec.task_id] = spec

    def get(self, task_id: str) -> Optional[TaskSpec]:
        return self._tasks.get(task_id)

    def list_all(self) -> List[TaskSpec]:
        return list(self._tasks.values())

    def filter_by_pool(self, pool_type: PoolType) -> List[TaskSpec]:
        return [t for t in self._tasks.values() if t.pool_type == pool_type]

    def filter_by_category(self, category: TaskCategory) -> List[TaskSpec]:
        return [t for t in self._tasks.values() if t.category == category]
