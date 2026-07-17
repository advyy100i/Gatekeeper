"""
Risk engine — calibrated weighted fusion of bounded [0, 1] sub-scores.

    risk = 0.3*g + 0.3*p + 0.2*e + 0.2*a

Every input is already bounded (HST is ~[0,1]; z-scores are clamped upstream),
so fixed hand-chosen weights are safe — no detector can dominate via a fat tail.

Actions only ever *add* restriction on top of static controls (auth, rate
limits, ACLs), never relax them.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict

from app.anomaly import config as cfg

ACTION_ALLOW = "allow"
ACTION_LOG = "log"
ACTION_TARPIT = "tarpit"
ACTION_BLOCK = "block"


@dataclass
class RiskDecision:
    risk: float
    action: str
    g: float  # global model
    p: float  # per-key behavioral
    e: float  # enumeration
    a: float  # auth abuse
    ts: float

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, raw: str) -> "RiskDecision":
        return cls(**json.loads(raw))


def fuse(g: float, p: float, e: float, a: float, ts: float) -> RiskDecision:
    weighted = (
        cfg.WEIGHT_GLOBAL * g
        + cfg.WEIGHT_PERKEY * p
        + cfg.WEIGHT_ENUM * e
        + cfg.WEIGHT_AUTH * a
    )
    # Strong-single-detector floor: a weighted sum alone caps a single-vector
    # attack at that detector's weight and can never flag it. When one detector
    # is highly confident (>= STRONG_SIGNAL), it overrides the conservative sum.
    # Only the clean per-key detectors (p, e, a) may trip the floor — the global
    # HST score is not discriminative enough for per-key attacks and would cause
    # false positives; it contributes to the weighted sum only.
    strongest = max(p, e, a)
    floor = strongest if strongest >= cfg.STRONG_SIGNAL else 0.0
    risk = min(max(max(weighted, floor), 0.0), 1.0)

    if risk >= cfg.THRESHOLD_BLOCK:
        action = ACTION_BLOCK
    elif risk >= cfg.THRESHOLD_TARPIT:
        action = ACTION_TARPIT
    elif risk >= cfg.THRESHOLD_LOG:
        action = ACTION_LOG
    else:
        action = ACTION_ALLOW

    return RiskDecision(risk=risk, action=action, g=g, p=p, e=e, a=a, ts=ts)


def cache_decision(redis_client, api_key_id: int, decision: RiskDecision) -> None:
    """Write the decision where the gateway hot path can GET it (bounded TTL)."""
    redis_client.set(
        cfg.KEY_RISK.format(key=api_key_id),
        decision.to_json(),
        ex=cfg.RISK_TTL_SECONDS,
    )


def read_decision(redis_client, api_key_id: int):
    """Sync read of the cached decision; None when absent/expired."""
    raw = redis_client.get(cfg.KEY_RISK.format(key=api_key_id))
    return RiskDecision.from_json(raw) if raw else None
