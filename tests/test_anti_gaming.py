import pytest
from veridrome.core.anti_gaming import AntiGamingEngine


def test_anti_gaming_honest_agent_passes():
    # Dürüst ajan: açık ve gizli havuzda tutarlı başarı (%90-%95)
    pub_scores = [0.95, 0.90, 0.92, 0.95, 0.88, 0.91, 0.93, 0.90, 0.94, 0.92, 0.91, 0.95]
    priv_scores = [0.92, 0.89, 0.90, 0.94, 0.87, 0.90, 0.91, 0.93]

    pub_actions = ["click", "type", "submit", "click", "submit"] * 10
    priv_actions = ["click", "type", "submit", "click", "submit"] * 10

    metrics = AntiGamingEngine.evaluate(
        public_scores=pub_scores,
        private_scores=priv_scores,
        public_actions=pub_actions,
        private_actions=priv_actions,
    )

    assert metrics.verdict == "PASSED"
    assert metrics.anomaly_score < AntiGamingEngine.ANOMALY_THRESHOLD
    assert metrics.is_overfit is False


def test_anti_gaming_overfit_agent_rejected():
    # Ezberci ajan: açık havuzda %100, gizli havuzda %30
    pub_scores = [1.0] * 12
    priv_scores = [0.25, 0.30, 0.20, 0.35, 0.20, 0.30, 0.25, 0.40]

    pub_actions = ["click", "type"] * 20
    priv_actions = ["guess_1", "guess_2", "guess_3", "scroll_down", "error_retry"] * 10

    metrics = AntiGamingEngine.evaluate(
        public_scores=pub_scores,
        private_scores=priv_scores,
        public_actions=pub_actions,
        private_actions=priv_actions,
    )

    assert metrics.verdict == "OVERFIT_REJECT"
    assert metrics.anomaly_score > AntiGamingEngine.ANOMALY_THRESHOLD
    assert metrics.is_overfit is True


def test_anti_gaming_sandbagging_detection():
    # Ajan gizli havuzda kasıtlı 5 kat yavaşlıyor
    pub_scores = [0.90] * 12
    priv_scores = [0.90] * 8

    pub_latencies = [10.0, 10.2, 9.8, 10.1, 10.0]
    priv_latencies = [55.0, 56.2, 54.8, 55.5, 54.9]

    metrics = AntiGamingEngine.evaluate(
        public_scores=pub_scores,
        private_scores=priv_scores,
        public_latencies=pub_latencies,
        private_latencies=priv_latencies,
    )

    assert metrics.is_sandbagging is True
    assert metrics.verdict == "SANDBAGGING_ALERT"
