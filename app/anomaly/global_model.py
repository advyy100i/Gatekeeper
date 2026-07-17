"""
Layer 1 — Global anomaly model (population-level outliers).

River's HalfSpaceTrees requires every feature in [0, 1] and does not
standardize internally, so the model is a pipeline with an online
MinMaxScaler in front. HST's score is already ~[0, 1], so it enters
fusion directly — no extra calibration.

Poisoning guard: ``learn`` is gated on the *fused* risk score — the model
only trains on low-risk traffic, so attackers (or the evaluation harness's
own injected attacks) cannot drag the baseline. The scaler sits inside the
pipeline, so gated learning protects it too.
"""
from __future__ import annotations

import math
from typing import Tuple

from river import anomaly, compose, preprocessing

from app.anomaly import config as cfg
from app.anomaly.features import FeatureEvent


def build_global_model() -> compose.Pipeline:
    return compose.Pipeline(
        preprocessing.MinMaxScaler(),  # online scaling -> [0, 1]
        anomaly.HalfSpaceTrees(
            seed=cfg.HST_SEED,
            n_trees=cfg.HST_N_TREES,
            height=cfg.HST_HEIGHT,
            window_size=cfg.HST_WINDOW,
        ),
    )


def global_features(
    ev: FeatureEvent, rate: float, inter_arrival_ms: float, diversity_ratio: float
) -> dict:
    """
    Numeric-only feature vector for the global model.

    Identity / high-cardinality categoricals are intentionally excluded —
    they belong to the per-key layer, not a population model.
    """
    hour = (ev.ts % 86_400) / 3_600.0
    sc = ev.status_class
    return {
        "rate": math.log1p(rate),
        "inter_arrival": math.log1p(inter_arrival_ms),
        "payload_size": math.log1p(max(ev.payload_size, 0)),
        "sin_hour": math.sin(2 * math.pi * hour / 24.0),
        "cos_hour": math.cos(2 * math.pi * hour / 24.0),
        "diversity": diversity_ratio,
        "status_2xx": 1.0 if sc == "2xx" else 0.0,
        "status_4xx": 1.0 if sc == "4xx" else 0.0,
        "status_5xx": 1.0 if sc == "5xx" else 0.0,
    }


class GlobalModel:
    """
    Thin wrapper around the River pipeline with online score standardization.

    HalfSpaceTrees' raw score is not naturally spread over [0, 1] — in practice
    it clusters high for *all* traffic, so the raw value is a useless offset.
    We standardize it against a gated EWMA baseline of recent raw scores, so a
    request only registers as anomalous when its raw score sits well *above*
    what this stream normally produces. The baseline updates only on low-risk
    traffic (same poisoning guard as everything else), passed in via ``learn``.
    """

    def __init__(self):
        self.pipeline = build_global_model()
        self.n_scored = 0
        self._mean = 0.0
        self._var = 0.0
        self._n = 0  # number of baseline samples committed

    def score(self, x: dict) -> Tuple[float, float]:
        """Return (standardized g in [0,1], raw HST score) — does not learn."""
        self.n_scored += 1
        raw = min(max(float(self.pipeline.score_one(x)), 0.0), 1.0)
        if self._n < cfg.HST_WINDOW:
            return 0.0, raw  # warming: don't trust the baseline yet
        # Floored denominator: HST raw is near-constant for stable traffic, so a
        # pure std in the divisor would collapse to ~0 and amplify noise to 1.0.
        denom = math.sqrt(max(self._var, cfg.GNORM_VAR_FLOOR))
        z = (raw - self._mean) / denom
        g = min(max(z, 0.0), cfg.Z_CLAMP) / cfg.Z_CLAMP
        return g, raw

    def observe_raw(self, raw: float) -> None:
        """
        Update the raw-score baseline on EVERY request (ungated).

        Unlike the per-key baselines, this is a *population* statistic: even
        during an attack the overwhelming majority of traffic is normal, so a
        single abusive key barely moves the mean. Updating it ungated avoids the
        self-inflicted catch-22 where g -> 1.0 blocks its own baseline learning.
        """
        diff = raw - self._mean
        incr = cfg.GNORM_ALPHA * diff
        self._mean += incr
        self._var = (1.0 - cfg.GNORM_ALPHA) * (self._var + diff * incr)
        self._n += 1

    def learn(self, x: dict) -> None:
        """Train the online model — gated on low risk by the caller."""
        self.pipeline.learn_one(x)
