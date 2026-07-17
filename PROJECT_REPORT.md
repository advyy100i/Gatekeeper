# AEGIS — Project Report (plain-language)

## What it is, in one line

AEGIS is an **API gateway** that also works as an **AI security layer**: it sits
in front of any web API and, on top of normal gateway features (API keys, rate
limits, billing), it watches *how each client behaves* and stops attacks that use
a valid key but behave abnormally.

---

## The problem it solves

APIs get abused by clients that already have a valid key — credential stuffing,
scraping, ID enumeration, slow "low-and-slow" theft. Ordinary gateways can't
catch these, because **each request looks perfectly fine on its own**. You only
see the attack in the *pattern of behaviour over time*.

AEGIS learns each key's normal behaviour and reacts when behaviour drifts.

---

## How it works (the request flow)

1. A client sends its request to **AEGIS**, not to the real API.
2. AEGIS checks the **API key** and the **rate limit** (the classic static rules).
3. AEGIS **forwards** the request to the real backend API and returns the answer
   — the backend is never touched or changed.
4. For every request, AEGIS grabs **lightweight metadata only** (timing, size,
   endpoint, status code — never the request body) and drops it on a queue.
5. A **background worker** scores that request and updates a risk score for the
   key. High risk → the key's *next* requests are **slowed down (tarpit)** or
   **blocked (403)**.
6. Everything is logged and shown on a **live dashboard**.

The scoring runs **off to the side**, so it never slows down normal traffic, and
if it ever breaks, traffic keeps flowing (the static rules still protect you).

---

## Main features

- **API gateway / reverse proxy** — register any API, get a proxy URL.
- **API-key authentication**, **per-key rate limiting**, **usage-based billing**.
- **Adaptive behavioural anomaly detection** — the AI security layer (see below).
- **Tamper-evident audit log** — request hashes in a Merkle tree (optional
  blockchain anchor).
- **Bot detection** and **response watermarking**.
- **Dashboard** (Next.js) with a live "Threat Detection" page, including
  "Replay real traffic" and "Simulate attack" demos.

---

## Architecture (plain)

| Piece | What it is |
|---|---|
| Backend | FastAPI (Python) — the gateway + APIs |
| Database | SQLite locally, PostgreSQL in production |
| Redis | message stream + per-key stats + score cache |
| Worker | background process that scores requests |
| Frontend | Next.js dashboard |
| Deploy | Docker → Render (backend) + Vercel (frontend) |

---

## How we know it actually works

- **Synthetic attack simulator** — precision ~1.0, recall ~0.9 on labelled attacks.
- **Real-traffic replay** (NASA-HTTP web logs, 4,000+ real requests from
  hundreds of real client IPs) — **97.9% allowed, ~0 false positives**, and one
  attack injected from a real client was caught at **~70%** (the misses are the
  first few requests, before the signal crosses the threshold — honest, not a
  scripted 100%).
- **Live proxy attack** — a real credential-stuffing burst sent *through* the
  gateway was **blocked from request #3, 118 of 120 requests returned 403**, with
  the origin API untouched.

---

## Honest limitations

- It is **not deep learning** — it's online statistical anomaly detection. That's
  the correct tool here, but it's not a neural network.
- It identifies clients by **API key** (great for APIs; anonymous website traffic
  would need IP-based keying — a small change).
- The global model **resets on restart** (per-key stats survive in Redis).
- Runs as a **single instance** in the demo; real scale wants the dedicated
  worker split (already prepared in the deploy config).
- A few inherited features (blockchain anchor, watermarking) are **tangential**
  to the core security story.

---

# The ML / detection model (detailed)

## What kind of model it is

**Not** a neural network. It is **online (streaming) anomaly detection** — models
that learn continuously from each request, use tiny memory, and need **no
labelled attack data**. That's exactly right for this problem: it works in real
time and adapts as traffic changes.

## Two layers working together

1. **Global model** — *"Is this request weird compared to ALL traffic?"*
   Uses **River HalfSpaceTrees**, a streaming anomaly-detection algorithm. It
   only sees bounded numeric features: request rate, time between requests,
   payload size, hour of day (as sin/cos), and status class (2xx/4xx/5xx).

2. **Per-key baselines** — *"Is this key acting unlike ITS OWN normal?"*
   For every API key it keeps a few tiny running stats in Redis:
   - **EWMA** (recency-weighted average) of request rate and gap between requests
     → catches sudden **speed-ups**.
   - **HyperLogLog** sketches (memory-cheap "distinct counters") of how many
     distinct endpoints / object-IDs the key touched → catches **enumeration /
     scraping**.
   - **EWMA of the failed-login (401/403) ratio** → catches **credential stuffing**.

## The four signals (the sub-scores you see on every decision)

Each is a number between 0 and 1:

- **Global** — overall unusualness vs. the whole platform.
- **Per-key** — deviation from this key's normal rate & timing.
- **Enumeration** — the key sweeping through many distinct IDs/endpoints.
- **Auth abuse** — a spike in failed logins.

## Combining them (fusion) → one risk score

```
risk = 0.3·global + 0.3·per-key + 0.2·enumeration + 0.2·auth-abuse
```

Plus one rule: if any single per-key signal is **very confident**, it can override
the weighted average — so a one-type attack still fires (a plain weighted sum
would cap it below the threshold).

## The response ladder (graduated, not on/off)

| risk | action |
|---|---|
| `< 0.5` | **Allow** |
| `0.5 – 0.7` | **Log** (watch) |
| `0.7 – 0.9` | **Tarpit** (add delay) |
| `≥ 0.9` | **Block** (403) |

## Key design choices (and why they matter)

- **Async + fail-open:** scoring runs in a background worker; the request path
  only does one fast cache read. If scoring dies, traffic still flows and static
  controls still protect — a broken detector never blocks real users.
- **Cold-start guard:** new keys need a minimum number of samples before they can
  be flagged, so brand-new customers aren't falsely blocked.
- **Poisoning guard:** the model only learns from **low-risk** traffic, so an
  attacker can't slowly "train" it into accepting abuse.
- **Bounded scores:** z-scores are clamped to [0, 1] so no single signal can
  dominate the sum via a fat tail.

## Why it isn't (and shouldn't be) 100%

Detection has **latency by design**: the first few requests of an attack slip
through before the behavioural signal crosses the threshold. A detector that
reacted to a single request would constantly false-positive on legitimate bursts.

## How it's evaluated

- Synthetic attack injector → precision / recall on labelled attacks.
- Real NASA-HTTP traffic replay → false-positive rate on genuine traffic.
- Live proxy attack → end-to-end block on real proxied traffic.

## Libraries used

**River** (online ML), **NumPy**, **Redis** (streams + HyperLogLog + score
cache), **FastAPI**, **fakeredis** (tests + offline evaluation).
