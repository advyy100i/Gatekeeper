"""
Configuration for the adaptive anomaly detection pipeline.

All values are overridable via environment variables so the same code runs in
production (real Redis, hour-long windows) and in the synthetic evaluation
harness (fakeredis, short windows, simulated clock).
"""
import os


def _f(name: str, default: float) -> float:
    return float(os.getenv(name, default))


def _i(name: str, default: int) -> int:
    return int(os.getenv(name, default))


# --- Redis -----------------------------------------------------------------
REDIS_URL = os.getenv("AEGIS_REDIS_URL", "redis://localhost:6379/0")

# Redis Stream carrying feature events from the gateway to the ML worker
FEATURE_STREAM = os.getenv("AEGIS_FEATURE_STREAM", "aegis:features")
STREAM_MAXLEN = _i("AEGIS_STREAM_MAXLEN", 100_000)  # approximate cap
CONSUMER_GROUP = os.getenv("AEGIS_CONSUMER_GROUP", "anomaly-workers")

# --- Key namespaces ----------------------------------------------------------
KEY_STATS = "anom:stats:{key}"          # per-key EWMA statistics (hash)
KEY_RATE = "anom:rate:{key}:{bucket}"   # per-minute request counter
KEY_WREQ = "anom:wreq:{key}:{bucket}"   # requests in current enum window
KEY_HLL_EP = "anom:hll:ep:{key}:{bucket}"   # distinct endpoints (HLL)
KEY_HLL_OBJ = "anom:hll:obj:{key}:{bucket}"  # distinct object ids (HLL)
KEY_RISK = "anom:risk:{key}"            # cached risk decision (JSON string)
KEY_HEARTBEAT = "anom:worker:heartbeat"  # worker liveness marker

# --- Risk score cache ---------------------------------------------------------
RISK_TTL_SECONDS = _i("AEGIS_RISK_TTL", 60)      # bounded staleness (fail-open)
HEARTBEAT_TTL_SECONDS = _i("AEGIS_HEARTBEAT_TTL", 15)

# --- Risk engine: fixed weights (sum to 1.0) and action thresholds -----------
WEIGHT_GLOBAL = _f("AEGIS_W_GLOBAL", 0.3)   # g : HalfSpaceTrees score
WEIGHT_PERKEY = _f("AEGIS_W_PERKEY", 0.3)   # p : per-key behavioral z-score
WEIGHT_ENUM = _f("AEGIS_W_ENUM", 0.2)       # e : enumeration (windowed HLL)
WEIGHT_AUTH = _f("AEGIS_W_AUTH", 0.2)       # a : auth-failure abuse

THRESHOLD_LOG = _f("AEGIS_T_LOG", 0.5)      # >= : log / shadow-observe
THRESHOLD_TARPIT = _f("AEGIS_T_TARPIT", 0.7)  # >= : inject latency
THRESHOLD_BLOCK = _f("AEGIS_T_BLOCK", 0.9)  # >= : hard block

TARPIT_SECONDS = _f("AEGIS_TARPIT_SECONDS", 2.0)

# Poisoning guard: the online model + per-key baselines learn ONLY from traffic
# scored below this gate, so a sustained attack can never normalise its baseline.
# Set at the LOG threshold — conservatively, don't learn from anything suspicious.
LEARN_GATE = _f("AEGIS_LEARN_GATE", 0.5)

# --- Per-key baselines ---------------------------------------------------------
EWMA_ALPHA = _f("AEGIS_EWMA_ALPHA", 0.05)        # recency bias of baselines
AUTH_FAST_ALPHA = _f("AEGIS_AUTH_FAST_ALPHA", 0.3)
AUTH_SLOW_ALPHA = _f("AEGIS_AUTH_SLOW_ALPHA", 0.02)

Z_CLAMP = _f("AEGIS_Z_CLAMP", 10.0)   # z-scores clamped to [0, Z_CLAMP] -> [0, 1]
N_MIN = _i("AEGIS_N_MIN", 30)         # cold-start: min samples before z-scoring
WARMING_SCORE = _f("AEGIS_WARMING_SCORE", 0.2)  # mild fixed risk while warming
AUTH_N_MIN = _i("AEGIS_AUTH_N_MIN", 5)

# Variance shrinkage floors (var + eps) so tiny samples never divide by ~0
VAR_EPS_RATE = _f("AEGIS_VAR_EPS_RATE", 1.0)       # requests/min
VAR_EPS_IA = _f("AEGIS_VAR_EPS_IA", 10_000.0)      # ms^2 (100 ms std floor)
VAR_EPS_ENUM = _f("AEGIS_VAR_EPS_ENUM", 4.0)       # distinct ids per window

# --- Enumeration window ----------------------------------------------------------
ENUM_WINDOW_SECONDS = _i("AEGIS_ENUM_WINDOW", 3600)  # HLL bucket size
ENUM_MERGE_BUCKETS = _i("AEGIS_ENUM_MERGE", 5)       # trailing sliding window (K buckets)
ENUM_ABS_CARD = _f("AEGIS_ENUM_ABS_CARD", 60.0)      # baseline-free "this is a scan" scale
ENUM_REF_CARD = _f("AEGIS_ENUM_REF_CARD", 100.0)     # cold-start reference scale

# --- Global-model score standardization ------------------------------------------
GNORM_ALPHA = _f("AEGIS_GNORM_ALPHA", 0.02)      # EWMA of raw HST scores
GNORM_VAR_FLOOR = _f("AEGIS_GNORM_VAR_FLOOR", 0.0025)  # denom floor (std >= 0.05)

# --- Fusion: strong-single-detector floor ----------------------------------------
# A weighted sum alone cannot flag a single-vector attack (one detector caps at
# its weight). When any one detector is highly confident, it overrides the sum.
STRONG_SIGNAL = _f("AEGIS_STRONG_SIGNAL", 0.85)

# --- Global model (River) ---------------------------------------------------------
HST_N_TREES = _i("AEGIS_HST_TREES", 25)
HST_HEIGHT = _i("AEGIS_HST_HEIGHT", 15)
HST_WINDOW = _i("AEGIS_HST_WINDOW", 250)
HST_SEED = _i("AEGIS_HST_SEED", 42)
