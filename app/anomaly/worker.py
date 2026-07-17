"""
Async ML worker — consumes feature events from the Redis Stream, scores them,
and caches risk decisions for the gateway.

Run standalone:  python -m app.anomaly.worker

The scoring core (``AnomalyScorer``) is deliberately decoupled from the stream
loop so the synthetic evaluation harness can drive it in-process with fakeredis
and a simulated clock.
"""
from __future__ import annotations

import logging
import socket
import time

from app.anomaly import config as cfg
from app.anomaly.features import FeatureEvent
from app.anomaly.global_model import GlobalModel, global_features
from app.anomaly.per_key import PerKeyBaseline
from app.anomaly.risk_engine import (
    ACTION_TARPIT, ACTION_BLOCK, RiskDecision, cache_decision, fuse,
)

logger = logging.getLogger("aegis.anomaly.worker")


class AnomalyScorer:
    """The full pipeline for one event: per-key stats -> global model -> fusion."""

    def __init__(self, redis_client):
        self.r = redis_client
        self.per_key = PerKeyBaseline(redis_client)
        self.global_model = GlobalModel()

    def process_event(self, ev: FeatureEvent) -> RiskDecision:
        # Layer 2: measure against the CURRENT per-key baseline (read-only —
        # baselines are not moved here, so a sustained attack can't self-normalise).
        obs = self.per_key.observe(ev)

        # Layer 1: global model (scored using features derived by observe).
        x = global_features(ev, obs.rate, obs.inter_arrival_ms, obs.diversity_ratio)
        g, g_raw = self.global_model.score(x)
        # Population baseline updates on every request (attack-robust, ungated).
        self.global_model.observe_raw(g_raw)

        # Fusion of the four bounded sub-scores.
        decision = fuse(g=g, p=obs.p, e=obs.e, a=obs.a, ts=ev.ts)

        # Poisoning guard: BOTH the online model and the per-key baselines learn
        # only from low-risk traffic. High-risk events still advance last_ts /
        # count (so inter-arrival stays valid) and taint the enum window.
        if decision.risk < cfg.LEARN_GATE:
            self.global_model.learn(x)
            self.per_key.learn(ev, obs)
        else:
            self.per_key.touch_last_ts(ev, obs)

        # Publish for the gateway hot path (single GET, bounded TTL).
        cache_decision(self.r, ev.api_key_id, decision)
        return decision


def _persist_elevated(decision: RiskDecision, ev: FeatureEvent) -> None:
    """Audit trail: persist scores at/above the LOG threshold to the database."""
    if decision.risk < cfg.THRESHOLD_LOG:
        return
    try:
        from app.database import SessionLocal
        from app.models import AnomalyScoreLog

        db = SessionLocal()
        try:
            db.add(AnomalyScoreLog(
                api_key_id=ev.api_key_id,
                service_id=ev.service_id,
                risk=decision.risk,
                score_global=decision.g,
                score_perkey=decision.p,
                score_enum=decision.e,
                score_auth=decision.a,
                action=decision.action,
                endpoint=ev.path,
            ))
            db.commit()
        finally:
            db.close()
    except Exception as exc:  # audit must never take down scoring
        logger.warning("failed to persist anomaly score: %s", exc)


def run_worker() -> None:
    """Blocking consumer-group loop with a liveness heartbeat."""
    import redis

    r = redis.Redis.from_url(cfg.REDIS_URL, decode_responses=True)
    consumer = f"{socket.gethostname()}-{int(time.time())}"

    try:
        r.xgroup_create(cfg.FEATURE_STREAM, cfg.CONSUMER_GROUP, id="0", mkstream=True)
    except redis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise

    scorer = AnomalyScorer(r)
    logger.info("anomaly worker %s consuming %s", consumer, cfg.FEATURE_STREAM)

    while True:
        r.set(cfg.KEY_HEARTBEAT, str(time.time()), ex=cfg.HEARTBEAT_TTL_SECONDS)
        entries = r.xreadgroup(
            cfg.CONSUMER_GROUP, consumer,
            {cfg.FEATURE_STREAM: ">"}, count=100, block=1000,
        )
        if not entries:
            continue
        for _stream, messages in entries:
            for msg_id, fields in messages:
                try:
                    ev = FeatureEvent.from_stream(fields)
                    decision = scorer.process_event(ev)
                    _persist_elevated(decision, ev)
                except Exception as exc:
                    logger.exception("failed to score event %s: %s", msg_id, exc)
                finally:
                    r.xack(cfg.FEATURE_STREAM, cfg.CONSUMER_GROUP, msg_id)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    run_worker()
