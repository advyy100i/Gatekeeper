"""
Gateway-side integration: the only anomaly code on the request hot path.

Two operations, both fail-open:

- ``get_decision``  : one Redis GET of the cached risk decision.
- ``publish_event`` : fire-and-forget XADD of the feature event.

If Redis or the worker is unavailable, static controls (auth, rate limiting,
ACLs) keep enforcing; the gateway treats missing scores as neutral-low, enters
degraded mode, and logs an operational alert (rate-limited to avoid log spam).
"""
from __future__ import annotations

import logging
import time
from typing import Optional, Tuple

import redis.asyncio as aioredis

from app.anomaly import config as cfg
from app.anomaly.features import FeatureEvent
from app.anomaly.risk_engine import ACTION_ALLOW, RiskDecision

logger = logging.getLogger("aegis.anomaly.gateway")

_client: Optional[aioredis.Redis] = None
_degraded_since: Optional[float] = None
_last_alert: float = 0.0
_ALERT_INTERVAL = 30.0  # seconds between degraded-mode log alerts


def _get_client() -> aioredis.Redis:
    global _client
    if _client is None:
        _client = aioredis.Redis.from_url(
            cfg.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=0.5,
            socket_timeout=0.5,
        )
    return _client


def _enter_degraded(exc: Exception) -> None:
    global _degraded_since, _last_alert
    now = time.time()
    if _degraded_since is None:
        _degraded_since = now
    if now - _last_alert >= _ALERT_INTERVAL:
        _last_alert = now
        logger.warning(
            "ANOMALY DEGRADED MODE: scoring unavailable (%s). "
            "Static controls remain active; failing open.", exc,
        )


def _exit_degraded() -> None:
    global _degraded_since
    if _degraded_since is not None:
        logger.info("anomaly scoring recovered after %.1fs degraded",
                    time.time() - _degraded_since)
        _degraded_since = None


def is_degraded() -> bool:
    return _degraded_since is not None


async def get_decision(api_key_id: int) -> Tuple[str, Optional[float]]:
    """
    Read the cached risk decision for this key. Fail-open: any error or a
    missing/expired score yields ("allow", None).
    """
    try:
        raw = await _get_client().get(cfg.KEY_RISK.format(key=api_key_id))
        _exit_degraded()
    except Exception as exc:
        _enter_degraded(exc)
        return ACTION_ALLOW, None
    if not raw:
        return ACTION_ALLOW, None
    try:
        decision = RiskDecision.from_json(raw)
        return decision.action, decision.risk
    except Exception:
        return ACTION_ALLOW, None


async def publish_event(ev: FeatureEvent) -> None:
    """Fire-and-forget publish to the feature stream (never raises)."""
    try:
        await _get_client().xadd(
            cfg.FEATURE_STREAM,
            ev.to_stream(),
            maxlen=cfg.STREAM_MAXLEN,
            approximate=True,
        )
        _exit_degraded()
    except Exception as exc:
        _enter_degraded(exc)


async def worker_alive() -> bool:
    """True when the ML worker's heartbeat key is present."""
    try:
        return bool(await _get_client().exists(cfg.KEY_HEARTBEAT))
    except Exception:
        return False
