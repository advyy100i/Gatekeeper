"""
Layer 2 — Per-key behavioral baselines (constant memory per key, all in Redis).

Not a model per key. For each API key we keep:

- EWMA mean/variance (recency-biased, adapts to legitimate drift) of
  request rate and inter-arrival time  -> behavioral deviation score ``p``
- fast/slow EWMA of auth-failure ratio -> credential-stuffing score ``a``
- time-windowed HyperLogLog of distinct endpoints and object ids
  -> enumeration score ``e`` (windowed because HLL only ever counts up)

Poisoning guard (critical): scoring is split into ``observe`` (read-only w.r.t.
baselines — measures the request against the *current* baseline) and ``learn``
(commits baseline updates). The worker calls ``learn`` only when the fused risk
is low, so a sustained attack can never normalise its own baseline. Without this
split, EWMA means absorb the attack within seconds and every z-score collapses.

All z-scores are clamped to [0, 1] before fusion so no single fat-tailed
detector can dominate the weighted sum. Cold-start guard: below N_MIN samples we
emit a small fixed "warming" score, never a high one, and variance floors
(``var + eps``) prevent divide-by-~0 on young keys.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from app.anomaly import config as cfg
from app.anomaly.features import FeatureEvent, template_path

# Fields stored in the per-key stats hash (all floats; missing -> 0.0)
_FIELDS = (
    "count", "last_ts",
    "rate_mean", "rate_var",
    "ia_mean", "ia_var",
    "auth_fast", "auth_slow",
    "enum_mean", "enum_var", "enum_n",
    "cur_wbucket", "prev_obj_card", "wflagged",
)


def _ewma_update(mean: float, var: float, x: float, alpha: float) -> tuple:
    """One step of exponentially-weighted mean/variance (recency-biased)."""
    diff = x - mean
    incr = alpha * diff
    mean = mean + incr
    var = (1.0 - alpha) * (var + diff * incr)
    return mean, var


def _clamped_z(x: float, mean: float, var: float, eps: float) -> float:
    """Directional z-score, clamped to [0, 1] (the one-line fusion guard)."""
    z = (x - mean) / math.sqrt(var + eps)
    return min(max(z, 0.0), cfg.Z_CLAMP) / cfg.Z_CLAMP


@dataclass
class PerKeyObservation:
    """Sub-scores plus the transient state ``learn`` needs to commit baselines."""

    p: float               # behavioral deviation (rate / inter-arrival)
    e: float               # enumeration (windowed HLL)
    a: float               # auth-failure abuse
    # features handed to the global model
    rate: float
    inter_arrival_ms: float
    diversity_ratio: float
    warming: bool
    # transient state for the (possibly gated) learn step
    _stats: dict
    _obj_card: float
    _wbucket: int


class PerKeyBaseline:
    """Streaming per-key statistics backed by a Redis client."""

    def __init__(self, redis_client):
        self.r = redis_client

    # -- read-only scoring (safe to run on every request) ---------------------

    def observe(self, ev: FeatureEvent) -> PerKeyObservation:
        """
        Measure this event against the key's *current* baseline and update only
        the live, self-expiring counters (rate window, HLLs) and the fast auth
        EWMA. The persistent EWMA baselines are left untouched — ``learn`` commits
        those, and only when the caller deems the request safe.
        """
        key = ev.api_key_id
        s = self._load(key)
        count = int(s["count"])

        # --- inter-arrival (event time, so the simulator's clock works too)
        ia_ms = 0.0
        if s["last_ts"] > 0:
            ia_ms = max((ev.ts - s["last_ts"]) * 1000.0, 0.0)

        # --- request rate: requests observed so far in the current minute
        minute = int(ev.ts // 60)
        rate_key = cfg.KEY_RATE.format(key=key, bucket=minute)
        rate = float(self.r.incr(rate_key))
        self.r.expire(rate_key, 180)

        # --- windowed HLLs (enumeration + endpoint diversity)
        wbucket = int(ev.ts // cfg.ENUM_WINDOW_SECONDS)
        template, object_id = template_path(ev.path)
        ep_key = cfg.KEY_HLL_EP.format(key=key, bucket=wbucket)
        obj_key = cfg.KEY_HLL_OBJ.format(key=key, bucket=wbucket)
        wreq_key = cfg.KEY_WREQ.format(key=key, bucket=wbucket)

        self.r.pfadd(ep_key, f"{ev.method} {template}")
        if object_id is not None:
            self.r.pfadd(obj_key, object_id)
        wreq = float(self.r.incr(wreq_key))
        ttl = cfg.ENUM_WINDOW_SECONDS * 2
        self.r.expire(ep_key, ttl)
        self.r.expire(obj_key, ttl)
        self.r.expire(wreq_key, ttl)

        ep_card = float(self.r.pfcount(ep_key))
        obj_card = float(self.r.pfcount(obj_key))
        diversity = min(ep_card / max(wreq, 1.0), 1.0)

        # trailing sliding window: distinct object ids over the last K buckets,
        # via HLL merge (smooth, no per-window sawtooth). Requests over the same
        # span give the uniqueness ratio (== 1.0 means every request is a new
        # object, i.e. scanning).
        trail_distinct, trail_reqs = self._trailing(key, wbucket)

        # --- behavioral deviation p (rate + inter-arrival) --------------------
        warming = count < cfg.N_MIN
        if warming:
            p = cfg.WARMING_SCORE
        else:
            z_rate = _clamped_z(rate, s["rate_mean"], s["rate_var"], cfg.VAR_EPS_RATE)
            # faster-than-normal (small inter-arrival) is the suspicious direction
            z_ia = _clamped_z(s["ia_mean"] - ia_ms, 0.0, s["ia_var"], cfg.VAR_EPS_IA) \
                if ia_ms > 0 else 0.0
            p = max(z_rate, z_ia)

        # --- enumeration e ----------------------------------------------------
        # Two signals combined by max():
        #  (1) baseline-free absolute scan signal — large trailing distinct-id
        #      count AND high uniqueness ratio. Independent of any learnable
        #      baseline, so it breaks the "attack stays low -> baseline learns
        #      it -> stays low" catch-22 for low-and-slow scraping.
        #  (2) deviation of the key's per-window distinct count from its own
        #      learned baseline (catches a key that ramps up vs its history).
        uniq_ratio = trail_distinct / max(trail_reqs, 1.0)
        scan_signal = min(trail_distinct / cfg.ENUM_ABS_CARD, 1.0) * uniq_ratio
        if s["enum_n"] >= 1 and not warming:
            z_card = _clamped_z(obj_card, s["enum_mean"], s["enum_var"], cfg.VAR_EPS_ENUM)
        else:
            z_card = min(obj_card / cfg.ENUM_REF_CARD, 1.0) * (obj_card / max(wreq, 1.0))
        e = max(scan_signal, z_card)

        # --- auth abuse a -----------------------------------------------------
        # fast EWMA tracks the *current* failure rate and updates every request;
        # the slow baseline is gated (only learn() moves it), so a sustained
        # attack keeps fast high while the baseline stays low -> a stays high.
        fail = 1.0 if ev.is_auth_failure else 0.0
        s["auth_fast"] += cfg.AUTH_FAST_ALPHA * (fail - s["auth_fast"])
        if count >= cfg.AUTH_N_MIN:
            a = min(max((s["auth_fast"] - s["auth_slow"]) * 2.0, 0.0), 1.0)
        else:
            a = 0.0

        # persist only the live fast-auth EWMA + counters snapshot; baselines
        # remain as loaded until learn() runs.
        s["_live_fast"] = s["auth_fast"]
        self.r.hset(cfg.KEY_STATS.format(key=key), "auth_fast", repr(s["auth_fast"]))

        return PerKeyObservation(
            p=p, e=e, a=a,
            rate=rate, inter_arrival_ms=ia_ms,
            diversity_ratio=diversity, warming=warming,
            _stats=s, _obj_card=obj_card, _wbucket=wbucket,
        )

    # -- gated baseline commit (only for low-risk traffic) --------------------

    def learn(self, ev: FeatureEvent, obs: PerKeyObservation) -> None:
        """Commit EWMA baseline updates. Called only when fused risk is low."""
        key = ev.api_key_id
        s = obs._stats

        # window rollover: fold the finished window's cardinality into the
        # enum baseline (skip windows tainted by an earlier flag).
        if s["cur_wbucket"] > 0 and obs._wbucket != int(s["cur_wbucket"]):
            if not (s["wflagged"] > 0):
                s["enum_mean"], s["enum_var"] = _ewma_update(
                    s["enum_mean"], s["enum_var"], s["prev_obj_card"], cfg.EWMA_ALPHA)
                s["enum_n"] += 1
            s["wflagged"] = 0.0
        s["cur_wbucket"] = float(obs._wbucket)
        s["prev_obj_card"] = obs._obj_card

        # rate + inter-arrival baselines
        s["rate_mean"], s["rate_var"] = _ewma_update(
            s["rate_mean"], s["rate_var"], obs.rate, cfg.EWMA_ALPHA)
        if obs.inter_arrival_ms > 0:
            s["ia_mean"], s["ia_var"] = _ewma_update(
                s["ia_mean"], s["ia_var"], obs.inter_arrival_ms, cfg.EWMA_ALPHA)

        # slow auth baseline (fast was already updated in observe)
        fail = 1.0 if ev.is_auth_failure else 0.0
        s["auth_slow"] += cfg.AUTH_SLOW_ALPHA * (fail - s["auth_slow"])

        s["count"] += 1
        s["last_ts"] = ev.ts
        self._save(key, s)

    def touch_last_ts(self, ev: FeatureEvent, obs: PerKeyObservation) -> None:
        """
        For high-risk (not learned) events: still advance last_ts and count so
        inter-arrival stays meaningful, but do NOT move the behavioral baselines.
        Also taints the current enum window so it is never folded in later.
        """
        key = ev.api_key_id
        s = obs._stats
        s["count"] += 1
        s["last_ts"] = ev.ts
        s["cur_wbucket"] = float(obs._wbucket)
        s["prev_obj_card"] = obs._obj_card
        s["wflagged"] = 1.0
        self._save(key, s)

    # -- internal ---------------------------------------------------------------

    def _trailing(self, key: int, wbucket: int) -> tuple:
        """
        Distinct object ids and request count over the last K windows.

        Distinct ids come from an HLL merge of the K most recent object-id
        buckets (probabilistic union — no per-id storage); requests are the sum
        of the K window counters. Smooths the per-window sawtooth so the scan
        signal is stable within an attack.
        """
        k = cfg.ENUM_MERGE_BUCKETS
        obj_keys, req_keys = [], []
        for b in range(wbucket - k + 1, wbucket + 1):
            if b < 0:
                continue
            obj_keys.append(cfg.KEY_HLL_OBJ.format(key=key, bucket=b))
            req_keys.append(cfg.KEY_WREQ.format(key=key, bucket=b))

        if len(obj_keys) == 1:
            distinct = float(self.r.pfcount(obj_keys[0]))
        else:
            merged = f"anom:hll:objmerge:{key}:{wbucket}"
            self.r.pfmerge(merged, *obj_keys)
            distinct = float(self.r.pfcount(merged))
            self.r.expire(merged, cfg.ENUM_WINDOW_SECONDS)

        reqs = 0.0
        for rk in req_keys:
            v = self.r.get(rk)
            if v:
                reqs += float(v)
        return distinct, reqs

    def _load(self, key: int) -> dict:
        raw = self.r.hgetall(cfg.KEY_STATS.format(key=key)) or {}
        return {f: float(raw.get(f, 0.0)) for f in _FIELDS}

    def _save(self, key: int, s: dict) -> None:
        self.r.hset(
            cfg.KEY_STATS.format(key=key),
            mapping={f: repr(s[f]) for f in _FIELDS},
        )
