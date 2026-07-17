"""
Sense 2 demo: put AEGIS in front of a REAL website's traffic.

Registers a real public API (jsonplaceholder) as a backend, then drives genuine
HTTP traffic THROUGH the gateway proxy:

  1. warmup  — normal, paced requests that establish the key's behavioral baseline
  2. attack  — a rapid enumeration/scrape burst from the same key

Every proxied request is scored live by the embedded worker (via the Redis
stream), exactly as production traffic would be. We watch the key's risk climb
and — the money shot — the gateway itself start returning 403 (blocked by
adaptive security) on the real traffic, with zero changes to the origin API.

Usage:  AEGIS_GW=http://127.0.0.1:8080 python -m scripts.live_proxy_demo
"""
import os
import time
from collections import Counter

import httpx

GW = os.getenv("AEGIS_GW", "http://127.0.0.1:8080")
# A real backend behind the gateway. Defaults to a fast local origin so a
# third-party API's rate-limiting doesn't confound the demo; point it at any
# real API by setting AEGIS_TARGET.
TARGET = os.getenv("AEGIS_TARGET", "http://127.0.0.1:9099/")


def _risk(client, key_id):
    try:
        d = client.get(f"{GW}/security/anomaly/risk/{key_id}", timeout=5).json()
        return d.get("action"), d.get("risk")
    except Exception:
        return "?", None


def main():
    c = httpx.Client(timeout=15)

    # --- provision a real service + per-service key -------------------------
    sid = c.post(f"{GW}/register-api",
                 json={"name": "Live Proxy Demo", "target_url": TARGET}).json()["service_id"]
    key = c.post(f"{GW}/services/{sid}/keys").json()["api_key"]
    keys = c.get(f"{GW}/services/{sid}/keys").json()["api_keys"]
    key_id = max(k["id"] for k in keys)   # the ApiKey row id == anomaly key id
    hdr = {"X-API-Key": key}

    # Raise the static rate limit out of the way so the *behavioral* layer is the
    # thing that decides — anomaly detection targets abuse that stays UNDER the
    # rate limit (valid keys, low-and-slow, enumeration within limits).
    c.put(f"{GW}/api-keys/{key_id}/rate-limit",
          json={"requests": 100000, "window_seconds": 60})
    print(f"service_id={sid}  api_key_id={key_id}  target={TARGET}")
    print(f"proxy base: {GW}/proxy/{sid}/...\n")

    # --- phase 1: warmup — normal, paced real traffic ----------------------
    print("[warmup] 40 normal requests (~0.8s apart) through the proxy...")
    warm_status = Counter()
    for i in range(40):
        r = c.get(f"{GW}/proxy/{sid}/posts/{(i % 15) + 1}", headers=hdr)
        warm_status[r.status_code] += 1
        time.sleep(0.8)
    act, risk = _risk(c, key_id)
    print(f"[warmup] done. statuses={dict(warm_status)}  risk after warmup: "
          f"action={act} risk={risk}\n")

    # --- phase 2: attack — credential stuffing from the same valid key ------
    # A wall of failed logins (401s) against a real endpoint — the classic
    # attack that stays under rate limits with a valid key. The auth-abuse
    # detector ramps fast; once risk crosses the block threshold the gateway
    # returns 403 itself (status 403 = gateway block; 401 = a real upstream
    # rejection that reached the origin).
    print("[attack] credential-stuffing burst against /login (real 401s)...")
    atk_status = Counter()
    first_block_at = None
    risk_trace = []
    for i in range(120):
        r = c.post(f"{GW}/proxy/{sid}/login", headers=hdr,
                   json={"user": "admin", "pass": f"guess{i}"})
        atk_status[r.status_code] += 1
        if r.status_code == 403 and first_block_at is None:
            first_block_at = i + 1
        if i % 10 == 0:
            act, risk = _risk(c, key_id)
            risk_trace.append((i + 1, act, risk))
        time.sleep(0.05)
    act, risk = _risk(c, key_id)

    print(f"[attack] done. statuses={dict(atk_status)}")
    print("[attack] risk trajectory (req#, action, risk):")
    for n, a, rk in risk_trace:
        print(f"    after {n:>3} attack reqs: action={a} risk={rk}")
    print(f"    final: action={act} risk={risk}")
    print()

    blocked = atk_status.get(403, 0)
    if blocked:
        print(f"RESULT: the gateway BLOCKED {blocked} real proxied requests "
              f"(first block at attack request #{first_block_at}) — live enforcement "
              f"on genuine traffic, origin API untouched.")
    else:
        print("RESULT: real traffic was scored live (risk elevated), but did not "
              "cross the block threshold in this short window. See notes.")
    c.close()


if __name__ == "__main__":
    main()
