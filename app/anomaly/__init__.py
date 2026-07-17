"""
AEGIS Adaptive Behavioral Anomaly Detection.

Two-detector pipeline fused into a single risk score:

- Global model  : River MinMaxScaler -> HalfSpaceTrees (population-level outliers)
- Per-key layer : EWMA statistics + windowed HyperLogLog in Redis (per-entity drift)

Scoring is fully asynchronous (Redis Streams). The gateway's only hot-path cost
is a single Redis GET of the latest cached risk score, with fail-open semantics.
"""
