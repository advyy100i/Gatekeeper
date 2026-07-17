"""
Live end-to-end smoke test of the anomaly loop against a REAL Redis server
(not fakeredis). Proves the exact production async path:

    gateway_hook.publish_event  ->  Redis Stream
                                ->  worker consumer group (real subprocess)
                                ->  risk decision cached with TTL
                                ->  gateway_hook.get_decision

Usage:
    AEGIS_REDIS_URL=redis://localhost:6380/0 python -m scripts.smoke_live_loop

Exits non-zero on failure so it can gate CI.
"""
import asyncio
import os
import subprocess
import sys
import time

os.environ.setdefault("AEGIS_REDIS_URL", "redis://localhost:6380/0")
# Short enum window so the loop is quick; short heartbeat for a fast liveness check.
os.environ.setdefault("AEGIS_ENUM_WINDOW", "60")

from app.anomaly import config as cfg  # noqa: E402
from app.anomaly import gateway_hook as gh  # noqa: E402
from app.anomaly.features import FeatureEvent  # noqa: E402


def _require_redis():
    import redis
    r = redis.Redis.from_url(cfg.REDIS_URL, decode_responses=True,
                             socket_connect_timeout=2)
    r.ping()
    # clean slate so repeated runs are deterministic
    for k in r.scan_iter("anom:*"):
        r.delete(k)
    try:
        r.delete(cfg.FEATURE_STREAM)
    except Exception:
        pass
    return r


async def main() -> int:
    try:
        r = _require_redis()
    except Exception as exc:
        print(f"FAIL: cannot reach Redis at {cfg.REDIS_URL}: {exc}")
        return 2
    print(f"[1/5] connected to real Redis at {cfg.REDIS_URL}")

    # Start the real worker as a subprocess (its own process, real consumer group).
    worker = subprocess.Popen([sys.executable, "-m", "app.anomaly.worker"],
                              env=os.environ.copy())
    try:
        # Wait for the worker heartbeat to appear.
        for _ in range(30):
            if await gh.worker_alive():
                break
            await asyncio.sleep(0.5)
        else:
            print("FAIL: worker heartbeat never appeared")
            return 3
        print("[2/5] worker subprocess is alive (heartbeat present)")

        KEY = 4242
        # Warmup: benign traffic so the key gets a baseline (publish via the
        # ACTUAL gateway code path).
        ts = time.time()
        for i in range(80):
            await gh.publish_event(FeatureEvent(
                api_key_id=KEY, service_id=1, ts=ts + i * 5.0, method="GET",
                path=f"/users/{1000 + (i % 20)}", status=200, payload_size=300,
            ))
        print("[3/5] published 80 benign warmup events through gateway_hook")

        # Attack: sustained credential stuffing from the same key.
        base = ts + 80 * 5.0
        for i in range(120):
            await gh.publish_event(FeatureEvent(
                api_key_id=KEY, service_id=1, ts=base + i * 0.2, method="POST",
                path="/login", status=401, payload_size=180,
            ))
        print("[4/5] published 120 credential-stuffing events")

        # Poll the cached decision the gateway would read on the next request.
        deadline = time.time() + 20
        final_action, final_risk = "allow", None
        while time.time() < deadline:
            action, risk = await gh.get_decision(KEY)
            if risk is not None:
                final_action, final_risk = action, risk
            if action in ("tarpit", "block"):
                break
            await asyncio.sleep(0.3)

        depth = r.xlen(cfg.FEATURE_STREAM)
        print(f"[5/5] gateway_hook.get_decision -> action={final_action} "
              f"risk={final_risk} (stream depth now {depth})")

        if final_action in ("tarpit", "block") and (final_risk or 0) >= cfg.THRESHOLD_TARPIT:
            print("\nPASS: real-Redis loop works end to end "
                  "(publish -> worker -> cache -> get_decision), attack flagged.")
            return 0
        print("\nFAIL: attack was not flagged via the live loop.")
        return 4
    finally:
        worker.terminate()
        try:
            worker.wait(timeout=5)
        except Exception:
            worker.kill()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
