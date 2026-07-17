"""
Unit + behavioural tests for the adaptive anomaly detection pipeline.

Fast, deterministic, no external services — everything runs against fakeredis
and the in-process AnomalyScorer. Run:  pytest tests/test_anomaly.py -q
"""
import os

os.environ.setdefault("AEGIS_ENUM_WINDOW", "60")

import random

import fakeredis
import pytest

from app.anomaly import config as cfg
from app.anomaly.features import FeatureEvent, template_path
from app.anomaly.risk_engine import (
    ACTION_ALLOW, ACTION_BLOCK, ACTION_TARPIT, fuse,
)
from app.anomaly.worker import AnomalyScorer


# --- path templating ---------------------------------------------------------

@pytest.mark.parametrize("path,expected_t,expected_id", [
    ("/users/123", "/users/{id}", "123"),
    ("/users/123/orders/456", "/users/{id}/orders/{id}", "456"),
    ("/products", "/products", None),
    ("/u/550e8400-e29b-41d4-a716-446655440000", "/u/{id}",
     "550e8400-e29b-41d4-a716-446655440000"),
    ("/", "/", None),
])
def test_template_path(path, expected_t, expected_id):
    t, oid = template_path(path)
    assert t == expected_t
    assert oid == expected_id


# --- risk engine fusion ------------------------------------------------------

def test_fuse_weighted_sum_normal_is_allow():
    d = fuse(g=0.2, p=0.1, e=0.1, a=0.0, ts=0.0)
    assert d.action == ACTION_ALLOW
    assert d.risk < cfg.THRESHOLD_LOG


def test_fuse_strong_single_detector_floor():
    # A single confident per-key detector must be able to flag on its own,
    # which a plain weighted sum (weight 0.2) never could.
    d = fuse(g=0.0, p=0.0, e=0.95, a=0.0, ts=0.0)
    assert d.risk >= cfg.THRESHOLD_TARPIT
    assert d.action in (ACTION_TARPIT, ACTION_BLOCK)


def test_fuse_global_alone_cannot_trip_floor():
    # HST is not discriminative for per-key attacks; g must not flag alone.
    d = fuse(g=1.0, p=0.1, e=0.1, a=0.0, ts=0.0)
    assert d.action == ACTION_ALLOW


def test_fuse_serialization_roundtrip():
    d = fuse(g=0.5, p=0.9, e=0.2, a=0.1, ts=123.0)
    from app.anomaly.risk_engine import RiskDecision
    assert RiskDecision.from_json(d.to_json()).risk == d.risk


# --- scoring behaviour -------------------------------------------------------

def _scorer():
    return AnomalyScorer(fakeredis.FakeRedis(decode_responses=True))


def _warm(scorer, key, n=60, start=1_700_000_000.0, interval=5.0):
    """Feed benign traffic to establish a baseline for one key."""
    ts = start
    for i in range(n):
        scorer.process_event(FeatureEvent(
            api_key_id=key, service_id=1, ts=ts, method="GET",
            path=f"/users/{1000 + (i % 20)}", status=200, payload_size=300,
        ))
        ts += interval
    return ts


def test_cold_start_is_never_high_risk():
    scorer = _scorer()
    ts = 1_700_000_000.0
    for i in range(5):  # brand-new key, only a handful of requests
        d = scorer.process_event(FeatureEvent(
            api_key_id=999, service_id=1, ts=ts + i, method="GET",
            path=f"/users/{i}", status=200, payload_size=300,
        ))
        assert d.action == ACTION_ALLOW, "new keys must not be blocked (cold start)"


def test_credential_stuffing_is_detected():
    scorer = _scorer()
    ts = _warm(scorer, key=1)
    flagged = False
    for i in range(60):
        d = scorer.process_event(FeatureEvent(
            api_key_id=1, service_id=1, ts=ts + i * 0.2, method="POST",
            path="/login", status=401, payload_size=180,
        ))
        flagged = flagged or d.action in (ACTION_TARPIT, ACTION_BLOCK)
    assert flagged, "sustained 401 flood should be flagged"


def test_enumeration_is_detected():
    scorer = _scorer()
    ts = _warm(scorer, key=2)
    flagged = False
    for i in range(120):
        d = scorer.process_event(FeatureEvent(
            api_key_id=2, service_id=1, ts=ts + i * 0.5, method="GET",
            path=f"/users/{50000 + i}", status=200, payload_size=350,
        ))
        flagged = flagged or d.action in (ACTION_TARPIT, ACTION_BLOCK)
    assert flagged, "sequential object-id sweep should be flagged"


def test_normal_traffic_stays_allowed():
    scorer = _scorer()
    ts = _warm(scorer, key=3, n=100)
    actions = []
    for i in range(200):  # continued benign traffic
        d = scorer.process_event(FeatureEvent(
            api_key_id=3, service_id=1, ts=ts + i * 5.0, method="GET",
            path=f"/users/{1000 + (i % 20)}", status=200, payload_size=300,
        ))
        actions.append(d.action)
    assert all(a == ACTION_ALLOW for a in actions), "benign traffic must not flag"


def test_poisoning_guard_keeps_detecting_sustained_attack():
    # The whole point of the observe/learn split: a long attack must NOT
    # normalise its own baseline and slip back to 'allow'.
    scorer = _scorer()
    ts = _warm(scorer, key=4)
    late_flags = 0
    for i in range(300):
        d = scorer.process_event(FeatureEvent(
            api_key_id=4, service_id=1, ts=ts + i * 0.2, method="POST",
            path="/login", status=401, payload_size=180,
        ))
        if i >= 250 and d.action in (ACTION_TARPIT, ACTION_BLOCK):
            late_flags += 1
    assert late_flags > 0, "attack must still be flagged late (no self-poisoning)"


def test_evaluation_meets_quality_bar():
    """The synthetic harness should hold precision high with real recall."""
    from simulator.evaluate import run
    rep = run(seed=7, verbose=False)
    hard = rep["hard_flag (risk >= tarpit 0.7)"]
    assert hard["precision"] >= 0.95, hard
    assert hard["recall"] >= 0.75, hard
    assert hard["fpr"] <= 0.02, hard
