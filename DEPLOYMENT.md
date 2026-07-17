# Deploying AEGIS Gateway

Backend (gateway + embedded anomaly worker + Redis + Postgres) → **Render**.
Frontend (Next.js dashboard) → **Vercel**.

Everything is already deploy-ready: the DB layer auto-switches to Postgres when
`DATABASE_URL` is a Postgres DSN, the scorer runs in-process via
`AEGIS_EMBED_WORKER=1`, CORS is env-driven, and `render.yaml` provisions all
backend services in one blueprint.

> These final steps use **your** accounts (GitHub, Render, Vercel). They involve
> browser OAuth logins and cannot be automated for you — but they are ~10 minutes.

---

## Prerequisites

1. Push this repo to GitHub (Render + Vercel deploy from a repo):
   ```bash
   git add -A && git commit -m "Feature A: adaptive anomaly detection + deploy config"
   git push origin main
   ```
2. Free accounts: [render.com](https://render.com) and [vercel.com](https://vercel.com).

---

## 1. Backend on Render (one blueprint)

1. Render dashboard → **New → Blueprint** → connect your GitHub repo.
2. Render detects [`render.yaml`](render.yaml) and shows the plan:
   `aegis-postgres` (Postgres), `aegis-redis` (Key Value), `aegis-gateway` (web).
3. Click **Apply**. First build takes a few minutes (Docker image + deps).
4. When live, the gateway is at `https://aegis-gateway.onrender.com` (your name
   may differ). Verify:
   ```bash
   curl https://aegis-gateway.onrender.com/health
   curl https://aegis-gateway.onrender.com/security/anomaly/status
   ```
   `status` should report `"worker_alive": true` once traffic warms it up.

`DATABASE_URL` and `AEGIS_REDIS_URL` are wired automatically by the blueprint.
Tables are created on first startup (`init_db()`), so no migration step is needed.

> **Free-tier notes:** the web service sleeps after ~15 min idle (first request
> after wakes it, ~30 s). Free Postgres expires after 30 days. The scorer runs
> embedded; to split it into its own always-on worker, uncomment the
> `aegis-anomaly-worker` block in `render.yaml` and move to a paid instance.

---

## 2. Frontend on Vercel

1. Vercel dashboard → **Add New → Project** → import the same GitHub repo.
2. Set **Root Directory** to `frontend`.
3. Add an environment variable:
   `NEXT_PUBLIC_API_URL = https://aegis-gateway.onrender.com` (your gateway URL).
4. **Deploy.** Vercel gives you `https://<project>.vercel.app`.

---

## 3. Connect the two (CORS)

1. Back in Render → `aegis-gateway` → **Environment** → set
   `CORS_ALLOW_ORIGINS = https://<project>.vercel.app` (your Vercel URL; comma-
   separate multiple origins). Save → the service redeploys.
2. Open the Vercel URL → **Threat Detection** page → it should load live status
   from the gateway.

---

## 4. Prove it works in production

Drive some abusive traffic and watch the dashboard populate:

```bash
# (optional) replay the evaluator's attack shapes against the live gateway
#            — or just hammer a proxied endpoint with a bad client.
curl https://aegis-gateway.onrender.com/security/anomaly/scores
```

---

## Local production parity

Run the whole stack locally exactly as it runs in the cloud:

```bash
docker compose up --build      # gateway + worker + Redis (see docker-compose.yml)
```

For a local Postgres instead of SQLite:
```bash
export DATABASE_URL=postgresql://user:pass@localhost:5432/aegis
```

---

## What is and isn't done

**Done:** Postgres-ready DB layer, env-driven CORS, embedded/standalone worker,
Render blueprint, Vercel config, health checks, fail-open scoring.

**Known limitations (honest):**
- Free-tier web service sleeps when idle; the in-memory HalfSpaceTrees model
  resets on restart (per-key baselines survive in Redis). For always-on scoring
  and model persistence, use the paid split-worker shape + add model
  checkpointing to Redis/S3.
- `AnomalyScoreLog` history lives in Postgres (durable); the live score cache is
  Redis with a bounded TTL (fail-open by design).
