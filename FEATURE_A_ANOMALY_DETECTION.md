# FEATURE A — Adaptive Behavioral Anomaly Detection

> AEGIS Gateway — AI-native API security layer
> Status: **implemented & evaluated** · `app/anomaly/` + `simulator/`

## Measured results (synthetic evaluation harness)

Run: `python -m simulator.evaluate` — 8 normal clients + 3 attacker keys, ~5.8k
warmup events, ~3.1k evaluation events, all on a simulated clock.

| Metric (risk ≥ 0.7, tarpit/block) | Value |
|---|---|
| **Precision** | **1.000** |
| **Recall** | **0.896** |
| **False-positive rate** | **0.0000** (0 / 2171 normal events) |

| Attack scenario | Recall | First detection |
|---|---|---|
| Credential stuffing | 0.995 | 2 events |
| Endpoint enumeration | 0.907 | 29 events |
| Low-and-slow scraping | 0.838 | 66 events |

The misses are the *early* events of each attack before its signal ramps —
i.e. detection latency, not blindness. Loud attacks are caught in a couple of
requests; stealthy scraping within ~60. Zero false positives on benign traffic.
Verified by 15 tests (`pytest tests/test_anomaly.py`).

## Measured results on REAL traffic (NASA-HTTP)

The synthetic harness proves the *mechanism*; this proves it on traffic **nobody
on this project authored**. Substrate: the NASA-HTTP access log (July 1995,
1.9M real requests). Attacks are injected from **previously-benign real client
IPs** — the account-takeover shape — so a real client with a real baseline turns
malicious mid-trace. Run: `python -m simulator.evaluate_real`.

- Warmup: 60,000 real events · Eval: 40,000 real events across **3,401 real clients** · 900 injected attack events.

| Metric | Value |
|---|---|
| **Precision** | **0.955** |
| **Recall** | **0.926** |
| **False-positive rate** | **0.00097** (39 / 40,000 real events) |

| Attack (from a real client) | Recall | First detection |
|---|---|---|
| Credential stuffing | 0.995 | 2 events |
| Endpoint enumeration | 0.893 | 17 events |
| Low-and-slow scraping | 0.915 | 18 events |

**The false positives are the honest, interesting part.** 37 of the 39 FPs come
from just **two client IPs** — both high-volume automated clients (620–923
requests over the trace, 10–12 req/min bursts, redirect-heavy 302/304 patterns:
crawler/proxy behavior, not human browsing). Those flags are defensible
gray-zone, not clean errors. **Excluding those two borderline clients, 2 false
positives remain across 40,000 real events.** This is exactly the messy reality a
synthetic-only eval hides: real traffic contains real automation the detector
correctly reacts to, and the "FPR" number needs that context to be read honestly.

Caveats stated up front: real logs have no API keys, so **client IP is the
identity**; and the NASA trace is old static-file traffic, so the enumeration
signal is if anything *harder* to fire cleanly here than on a modern REST API.

---

---

## 1. Vision

Traditional API gateways enforce **static** controls — authentication, rate limiting, and access control lists. These are effective against known, well-defined threats but blind to attacks that use **valid credentials and well-formed requests**.

AEGIS adds an **adaptive behavioral security layer** that continuously learns normal API usage and assigns every request a dynamic **risk score**. This layer does not replace existing controls — it complements them, catching anomalies that rule-based systems structurally cannot see.

---

## 2. Problem

Modern API attacks frequently use valid API keys and mimic legitimate clients, so they stay below rate limits and produce syntactically valid requests. Conventional gateways cannot detect:

- Credential stuffing using valid API keys
- Low-and-slow scraping
- Resource / object enumeration
- Account takeover
- Business-logic abuse
- Sudden behavioral deviations

Viewed one request at a time, these attacks look completely legitimate. The signal only appears in **behavior over time**, relative to either the whole platform or an individual client.

---

## 3. Solution

A two-detector pipeline whose outputs are fused into a single risk score:

| Layer | Question it answers | Technology |
|-------|--------------------|------------|
| **Global model** | "Is this request unusual vs. the entire platform?" | River `MinMaxScaler → HalfSpaceTrees` |
| **Per-key baseline** | "Is this key behaving unlike *its own* history?" | Redis: EWMA statistics + windowed HyperLogLog |

Population-level outliers and per-entity behavioral drift are **different signals** — the design needs both. A calibrated risk engine fuses them and the gateway enforces a graduated response.

---

## 4. Architecture

```text
                    Client
                       │
                 AEGIS Gateway  ──(reads cached risk score, O(1))──┐
     Auth • Rate Limit • ACL                                        │
                       │                                            │
              Feature Extraction                                    │
                       │                                            │
                Redis Stream  ("request_features")                  │
                       │                                            │
          ┌────────────┴────────────┐                              │
          │                         │                              │
  Global Worker             Per-Key Worker                         │
  Scaler → HalfSpaceTrees   EWMA + windowed HLL (Redis)            │
          │                         │                              │
    g ∈ [0,1]              p, e, a ∈ [0,1]                         │
          └────────────┬────────────┘                              │
                       │                                            │
                  Risk Engine ──> writes score + TTL to Redis ─────┘
                       │
        Allow • Log • Tarpit • Block
                       │
                 Upstream Service
                       │
            PostgreSQL (audit, metrics, offline evaluation)
```

**Key property:** anomaly scoring is fully **asynchronous**. The gateway's only hot-path cost is one Redis `GET` of the latest cached score. The ML workers never sit on the request path.

---

## 5. Feature Extraction (metadata only)

For each request, the gateway emits a lightweight event to the Redis Stream:

```
api_key_id, ip, timestamp, method, endpoint_template,
status_class (2xx / 4xx / 5xx), payload_size,
inter_arrival_ms, object_id (optional)
```

- **No request or response bodies are ever stored.** Only metadata.
- `endpoint_template` and `object_id` require path templating (`/users/123` → `/users/{id}`, id = `123`).
  - **v1:** cheap heuristic — replace numeric / UUID / hash-looking path segments with `{id}` and capture the raw value.
  - **Later:** replace with the learned templates from Feature B (Shadow API Discovery). *This is a soft dependency — v1 does not block on it.*

---

## 6. Layer 1 — Global Model

River's `HalfSpaceTrees` **requires every feature to be in `[0, 1]`** — it does not standardize internally. The global detector is therefore a pipeline with an online scaler in front:

```python
from river import anomaly, preprocessing, compose

model = compose.Pipeline(
    preprocessing.MinMaxScaler(),                 # online scaling → [0, 1]
    anomaly.HalfSpaceTrees(
        seed=42, n_trees=25, height=15, window_size=250
    ),
)
```

**Features (numeric only — no identity/categorical fields, avoiding high-cardinality blowup):**

- request rate (windowed)
- inter-arrival time
- `log(payload_size + 1)`
- hour of day, encoded as `sin(hour)` and `cos(hour)`
- endpoint diversity ratio
- HTTP status class as 3 binary flags (2xx / 4xx / 5xx)

**Output:** `g = model.score_one(x)`. River's HST score is already bounded in roughly `[0, 1]`, so it is used **directly** in fusion — no additional calibration needed.

**Poisoning guard (one line, kept in v1):** the model only learns from low-risk traffic, so an attacker (or the evaluation harness's own injected attack) cannot gradually drag the baseline:

```python
g = model.score_one(x)
if risk < BLOCK_THRESHOLD:      # do not learn from likely-attacks
    model.learn_one(x)
```

> This is not premature optimization — without it, the online model trains on attacks during the evaluation run and detection silently decays. It protects the benchmark.

---

## 7. Layer 2 — Per-Key Behavioral Baselines

Many attacks are anomalous only **relative to a specific key**, not the global population. Instead of a full ML model per key (unbounded memory, cold-start pain), AEGIS keeps **lightweight streaming statistics** per key in Redis — constant memory each.

### 7.1 EWMA statistics (recency-biased)

Exponentially Weighted Moving Average mean + variance are used instead of plain running averages so that the baseline **adapts to legitimate drift** while still reacting to sudden change:

- request rate and inter-arrival time → **behavioral deviation score `p`**
- 401 ratio, 403 ratio, 5xx ratio → **auth-abuse score `a`** (credential stuffing spikes 401/403)

Deviation is expressed as a z-score against the key's EWMA mean/variance.

**Bounding (one line — keeps fusion honest):** z-scores are unbounded, so they are clamped before entering the risk engine, otherwise a single fat-tailed detector dominates the weighted sum:

```python
p = min(z, 10) / 10      # bound to [0, 1]
```

### 7.2 Windowed HyperLogLog (enumeration)

HLL only ever counts **up**, so a lifetime counter saturates. Cardinality is tracked in **time-windowed** HLL keys:

```
hll:{key}:endpoints:{hour_bucket}
hll:{key}:objids:{hour_bucket}
```

- **enumeration score `e`** = current-window distinct count vs. the key's typical window (EWMA of past windows)
- buckets expire via Redis TTL — no manual cleanup

### 7.3 Cold-start guard

A brand-new key has near-zero variance; the first slightly-off request would otherwise produce a huge z-score and false-positive storm the newest customers. Mitigations:

- only score deviations once `n ≥ n_min` (e.g. 30 samples)
- variance shrinkage (`var + ε`) so tiny sample sizes don't divide by ~0
- below `n_min`, emit a small fixed "warming" risk — **never high**

---

## 8. Risk Engine

Each detector emits a bounded `[0, 1]` sub-score. The engine combines them with **fixed, hand-chosen weights** — no hyperparameter search:

```
risk = 0.3·g + 0.3·p + 0.2·e + 0.2·a
```

| risk score | action |
|-----------|--------|
| `< 0.5`   | **Allow** |
| `0.5 – 0.7` | **Log** (observe / shadow mode) |
| `0.7 – 0.9` | **Tarpit** (inject latency + reduce rate limit) |
| `≥ 0.9`   | **Block** |

**Static controls always run first and independently.** The risk engine can only *add* restriction — it never relaxes authentication, rate limiting, or ACLs.

---

## 9. Enforcement — Tarpitting (primary action)

There is no CAPTCHA for machine-to-machine API traffic. AEGIS's primary graduated response is **tarpitting** — fully enforceable by the gateway with no client cooperation:

- inject artificial response latency (slows automated abuse to a crawl)
- temporarily reduce the key's rate limit
- escalate to hard **block** at the top threshold

> Cooperative challenges (API-key revalidation, JWT refresh, signed nonce) require the client to support them and are considered **future work**, not v1.

---

## 10. Fail-Open Strategy

Anomaly scoring is an asynchronous subsystem. If a worker becomes unavailable:

- authentication, rate limiting, and ACLs **remain fully active**
- the gateway uses the **last cached risk score until its TTL expires**
- once the score is stale/missing, requests are treated as neutral-low
- the gateway enters **degraded mode and emits an operational alert**

Bounded staleness + alerting keeps the platform available without silently letting attackers walk in indefinitely.

---

## 11. Privacy

AEGIS analyzes **request metadata only**:

- timing, payload size, endpoint, status codes, request frequency

Request and response **bodies are never stored** — this improves privacy and reduces storage cost. Payload-**content** inspection is deliberately delegated to separate modules (Prompt Firewall, Response DLP) — a clean separation of concerns.

---

## 12. Synthetic Evaluation Framework

Because anomaly detection is unsupervised, effectiveness must be measured against **generated ground truth**. A traffic simulator replays normal API traffic while injecting labeled attack scenarios.

**v1 attack scenarios:**

- credential stuffing (401/403 spike)
- endpoint / object enumeration (HLL burst)
- low-and-slow scraping

**Later:** burst floods, resource scanning, account takeover.

**Measured metrics:**

- precision
- recall
- false-positive rate
- detection latency (requests-to-detect)

This turns "it uses AI" into "here is precision/recall on labeled injected attacks" — it is both the correctness proof and the live demo. **Build it in week 1, alongside the pipeline.**

---

## 13. Technology Stack

| Area | Tools |
|------|-------|
| Gateway | FastAPI, httpx |
| Infrastructure | PostgreSQL, Redis, Redis Streams, Docker Compose |
| Machine Learning | River, NumPy |
| Observability | OpenTelemetry, Prometheus, Grafana |
| CI/CD | GitHub Actions |

**Why Redis Streams over Kafka:** simpler to deploy, ideal operational footprint for a solo project, and still demonstrates asynchronous, decoupled scoring. Interviewers do not penalize this choice.

**Why River:** purpose-built for online / streaming ML — incremental updates, constant memory, no full retraining. The correct tool for per-request scoring.

---

## 14. Scope & Timeline (solo, realistic)

### v1 — the version that impresses (≈3–4 weeks)

1. Feature extraction + Redis Stream + async worker skeleton + fail-open cache — *week 1*
2. Global `MinMaxScaler → HalfSpaceTrees`, used directly, with the `fit_one` poisoning gate — *week 1–2*
3. Per-key EWMA (rate, inter-arrival, 401 ratio) + clamped z-scores + cold-start guard — *week 2*
4. Windowed HLL enumeration score — *week 3*
5. Weighted risk engine + Allow / Log / Tarpit / Block — *week 3*
6. Synthetic injector (credential stuffing + enumeration + low-and-slow) reporting precision/recall — *week 1 & 4*

### Future work (only if time allows)

- Feature-B-driven endpoint templating
- ADWIN / explicit concept-drift detection
- `OneClassSVM` comparison model
- Full Grafana dashboards
- Cooperative step-up (nonce / JWT refresh)
- Additional attack scenarios (ATO, resource scanning)

---

## 15. Why This Design Is Impressive (and defensible)

It spans, with **only open-source tools and no proprietary data**:

- **Online / streaming ML** — HalfSpaceTrees, incremental learning, poisoning awareness
- **Probabilistic data structures** — windowed HyperLogLog for enumeration detection
- **Detector fusion** — combining heterogeneous, bounded signals into one risk score
- **Asynchronous system design** — Redis Streams, fail-open with bounded staleness, O(1) hot path
- **Evaluation of an unsupervised system** — reproducible precision/recall via synthetic attacks

Every design choice has a "why not the simpler thing" answer — which is exactly what a system-design interview rewards. The philosophy throughout: **"I can build it, demo it, and defend every decision."**

---

## 16. Implementation map

| Module | Responsibility |
|---|---|
| `app/anomaly/config.py` | All tunables (weights, thresholds, EWMA α, windows), env-overridable |
| `app/anomaly/features.py` | `FeatureEvent` schema + v1 path templating (`/users/123` → `/users/{id}`) |
| `app/anomaly/global_model.py` | River `MinMaxScaler → HalfSpaceTrees` + gated raw-score standardization |
| `app/anomaly/per_key.py` | EWMA baselines, windowed+sliding HLL, `observe`/`learn` split |
| `app/anomaly/risk_engine.py` | Weighted fusion + strong-single-detector floor, decision cache |
| `app/anomaly/worker.py` | `AnomalyScorer` (pipeline) + Redis Streams consumer loop |
| `app/anomaly/gateway_hook.py` | Hot-path integration: `get_decision`, `publish_event`, fail-open |
| `simulator/traffic.py` · `evaluate.py` | Synthetic traffic + labeled attacks + precision/recall runner |
| `simulator/access_log_loader.py` | Common Log Format → `FeatureEvent` (real NASA-HTTP traffic) |
| `simulator/evaluate_real.py` | Real-traffic eval: NASA-HTTP normal + injected ATO attacks |
| `scripts/smoke_live_loop.py` | Live end-to-end test against a **real** Redis server |
| `tests/test_anomaly.py` | 15 unit + behavioural tests (incl. a quality-bar gate) |

## 17. Run it

```bash
# Full stack (gateway + Redis + async worker)
docker compose up --build

# Reproduce the SYNTHETIC evaluation (no services needed — uses fakeredis)
python -m simulator.evaluate

# Reproduce the REAL-traffic evaluation (downloads NASA-HTTP once, ~20 MB)
curl -sSL -o data/nasa_jul95.gz https://ita.ee.lbl.gov/traces/NASA_access_log_Jul95.gz
python -m simulator.evaluate_real

# Live end-to-end loop against a REAL Redis (proves the production async path)
docker run -d --rm -p 6380:6379 redis:7-alpine
AEGIS_REDIS_URL=redis://localhost:6380/0 python -m scripts.smoke_live_loop

# Tests
pytest tests/test_anomaly.py -q

# Live dashboard demo — drives attack traffic through the REAL scorer so the
# "Threat Detection" page populates with blocked/tarpitted decisions. This is
# also wired to the "Simulate attack" button on that page.
curl -X POST $API/security/anomaly/simulate -H 'Content-Type: application/json' -d '{"scenario":"all"}'

# Live subsystem health / recent decisions
curl localhost:8000/security/anomaly/status
curl localhost:8000/security/anomaly/scores
```

## 18. Calibration lessons (discovered during the build — the honest part)

These are the non-obvious failures found *by running the harness*, and how they
were fixed. They are the strongest interview material because each is a concrete
"the naive version silently fails" story:

1. **Sustained attacks self-normalise.** With a single always-learning model,
   recall collapsed as the attack became the baseline. Fixed by the
   **`observe`/`learn` split** — baselines commit only when fused risk is below
   `LEARN_GATE`, so an ongoing attack can never train itself into "normal".

2. **A weighted sum cannot flag a single-vector attack.** Enumeration lights up
   only one detector (weight 0.2), so its risk capped at ~0.3 forever. Fixed
   with a **strong-single-detector floor**: when one clean per-key detector is
   ≥ 0.85 it overrides the conservative sum. (The design doc had flagged
   "weighted-mean vs max" as an open call — the data made the decision.)

3. **HalfSpaceTrees' raw score is not discriminative for per-key attacks and
   clusters near 1.0 for everyone.** Standardizing it against a *gated* baseline
   created a catch-22 (g=1.0 → high risk → never learns → g stays 1.0). Fixed by
   updating g's baseline **ungated** (it's a population statistic — one bad key
   barely moves it), flooring the variance, and **excluding g from the floor**
   so it only ever contributes to the weighted sum.

4. **Windowed HLL sawtooths.** Per-window distinct-id counts reset each window,
   so enumeration signal flickered. Fixed with a **sliding window** (HLL merge of
   the last K buckets) plus a **baseline-free absolute scan signal**
   (`distinct/scale × uniqueness_ratio`) that breaks the low-and-slow catch-22.

5. **Cold start would storm new keys.** Near-zero variance on young keys makes
   the first odd request look extreme. Fixed with an `N_MIN` sample floor +
   variance shrinkage; below the floor a key emits a small fixed "warming" score,
   never a high one. Verified by `test_cold_start_is_never_high_risk`.
