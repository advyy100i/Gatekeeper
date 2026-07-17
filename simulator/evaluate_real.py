"""
Real-traffic evaluation: NASA-HTTP as the *normal* substrate, with labeled
attacks injected from previously-benign real clients (the account-takeover
shape). This is the evaluation that answers "is this just synthetic data?" —
the normal traffic here was authored by nobody on this project.

  normal substrate : ~15k real client IPs, real paths/status/bytes/timing
  attacks          : credential stuffing / enumeration / low-and-slow, injected
                     from a few real client IDs during the eval window
  precision/recall : measured on the injected (labeled) events
  false-positive   : measured across all real events in the eval window

Honest caveats (printed with the report):
  - real logs have no API keys -> client IP is the identity
  - real logs contain real crawlers/bots we did NOT label; some "false
    positives" may be genuine anomalies the detector correctly caught

Run:  python -m simulator.evaluate_real
"""
from __future__ import annotations

import os

os.environ.setdefault("AEGIS_ENUM_WINDOW", "300")  # 5-min windows on a 68h trace

import sys  # noqa: E402
from collections import Counter  # noqa: E402

import fakeredis  # noqa: E402

from app.anomaly import config as cfg  # noqa: E402
from app.anomaly.risk_engine import ACTION_BLOCK, ACTION_TARPIT  # noqa: E402
from app.anomaly.worker import AnomalyScorer  # noqa: E402
from simulator.access_log_loader import iter_access_log  # noqa: E402
from simulator.traffic import (  # noqa: E402
    LABEL_NORMAL, credential_stuffing, enumeration, low_and_slow,
)

DATA = os.getenv("AEGIS_ACCESS_LOG", "data/nasa_jul95.gz")
WARMUP_EVENTS = int(os.getenv("AEGIS_EVAL_WARMUP", "60000"))
EVAL_EVENTS = int(os.getenv("AEGIS_EVAL_EVENTS", "40000"))
FLAG_ACTIONS = (ACTION_TARPIT, ACTION_BLOCK)


def run(verbose: bool = True) -> dict:
    if not os.path.exists(DATA):
        print(f"dataset not found: {DATA}\n"
              f"download NASA-HTTP: curl -sSL -o {DATA} "
              f"https://ita.ee.lbl.gov/traces/NASA_access_log_Jul95.gz")
        sys.exit(1)

    r = fakeredis.FakeRedis(decode_responses=True)
    scorer = AnomalyScorer(r)

    # --- load a real slice, split into warmup + eval by arrival order --------
    stream = iter_access_log(DATA, limit=WARMUP_EVENTS + EVAL_EVENTS)
    warmup, evalset = [], []
    for i, ev in enumerate(stream):
        (warmup if i < WARMUP_EVENTS else evalset).append(ev)

    # --- choose "compromised" real clients: frequent in warmup, so they have a
    #     genuine baseline before turning malicious --------------------------
    freq = Counter(ev.api_key_id for ev in warmup)
    frequent = [k for k, c in freq.most_common(50) if c >= cfg.N_MIN + 10]
    if len(frequent) < 3:
        print("not enough high-volume clients for the ATO scenario")
        sys.exit(1)
    compromised = {
        "credential_stuffing": frequent[0],
        "enumeration": frequent[1],
        "low_and_slow": frequent[2],
    }

    # --- phase 1: warmup on real traffic -------------------------------------
    for ev in warmup:
        scorer.process_event(ev)

    # --- phase 2: real eval traffic + injected attacks (merge by event time) --
    t_start = evalset[0].ts + 5.0
    attacks = []
    attacks += [(le.ev, le.label) for le in
                credential_stuffing(compromised["credential_stuffing"], 1, t_start, n=200)]
    attacks += [(le.ev, le.label) for le in
                enumeration(compromised["enumeration"], 1, t_start + 30, n=300)]
    attacks += [(le.ev, le.label) for le in
                low_and_slow(compromised["low_and_slow"], 1, t_start, n=400)]

    timeline = [(ev, LABEL_NORMAL) for ev in evalset] + attacks
    timeline.sort(key=lambda pair: pair[0].ts)

    # --- score + collect ------------------------------------------------------
    tp = fp = fn = 0
    real_flagged = 0
    real_total = 0
    per_scen = {k: {"events": 0, "flagged": 0, "first": None, "seen": 0, "maxr": 0.0}
                for k in compromised}
    fp_clients = Counter()

    for ev, label in timeline:
        d = scorer.process_event(ev)
        flagged = d.action in FLAG_ACTIONS
        if label == LABEL_NORMAL:
            real_total += 1
            if flagged:
                fp += 1
                real_flagged += 1
                fp_clients[ev.api_key_id] += 1
        else:
            ps = per_scen[label]
            ps["events"] += 1
            ps["seen"] += 1
            ps["maxr"] = max(ps["maxr"], d.risk)
            if flagged:
                tp += 1
                ps["flagged"] += 1
                if ps["first"] is None:
                    ps["first"] = ps["seen"]
            else:
                fn += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / real_total if real_total else 0.0

    report = {
        "warmup_events": len(warmup),
        "eval_real_events": real_total,
        "distinct_real_clients": len(set(ev.api_key_id for ev in evalset)),
        "injected_attack_events": len(attacks),
        "precision": precision, "recall": recall, "fpr": fpr,
        "tp": tp, "fp": fp, "fn": fn,
        "per_scenario": per_scen,
        "top_fp_clients": fp_clients.most_common(5),
    }
    if verbose:
        _print(report)
    return report


def _print(rep: dict) -> None:
    print("=" * 74)
    print("AEGIS — Anomaly Detection on REAL traffic (NASA-HTTP + injected attacks)")
    print("=" * 74)
    print(f"warmup (real): {rep['warmup_events']}   "
          f"eval real events: {rep['eval_real_events']}   "
          f"distinct real clients: {rep['distinct_real_clients']}")
    print(f"injected attack events: {rep['injected_attack_events']}")
    print(f"\nPrecision: {rep['precision']:.3f}   Recall: {rep['recall']:.3f}   "
          f"False-positive rate: {rep['fpr']:.5f}")
    print(f"  tp={rep['tp']}  fp={rep['fp']}  fn={rep['fn']}")
    print("\n[per-scenario]  (attacker = a previously-benign REAL client)")
    for scen, m in rep["per_scenario"].items():
        rc = m["flagged"] / m["events"] if m["events"] else 0.0
        first = f"{m['first']} events" if m["first"] else "not flagged"
        print(f"  {scen:<22} events={m['events']:<5} recall={rc:.3f}  "
              f"max_risk={m['maxr']:.3f}  first-detection={first}")
    print("\n[honest caveats]")
    print("  - client IP is used as identity (real logs have no API keys)")
    print("  - some false positives may be REAL crawlers/bots we didn't label;")
    print(f"    top FP client ids: {rep['top_fp_clients']}")
    print("=" * 74)


if __name__ == "__main__":
    run()
