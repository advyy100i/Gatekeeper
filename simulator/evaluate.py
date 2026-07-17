"""
Evaluation runner: drives the full scoring pipeline in-process (fakeredis,
simulated clock) against normal traffic + labeled injected attacks, and
reports precision / recall / false-positive rate / detection latency.

Run:  python -m simulator.evaluate
"""
from __future__ import annotations

import os

# Simulation-friendly knobs MUST be set before app.anomaly.config is imported:
# short enumeration windows so multi-window baselines form in simulated minutes.
os.environ.setdefault("AEGIS_ENUM_WINDOW", "60")

import random  # noqa: E402
from collections import defaultdict  # noqa: E402

import fakeredis  # noqa: E402

from app.anomaly import config as cfg  # noqa: E402
from app.anomaly.risk_engine import ACTION_TARPIT, ACTION_BLOCK  # noqa: E402
from app.anomaly.worker import AnomalyScorer  # noqa: E402
from simulator.traffic import (  # noqa: E402
    LABEL_NORMAL, NormalClient, credential_stuffing, enumeration,
    low_and_slow, merge_timelines,
)

SERVICE_ID = 1
WARMUP_SECONDS = 40 * 60      # simulated: builds baselines + HST warm-up
ATTACK_PHASE_SECONDS = 20 * 60

FLAG_ACTIONS = (ACTION_TARPIT, ACTION_BLOCK)   # headline detection: risk >= 0.7


def run(seed: int = 7, verbose: bool = True) -> dict:
    rng = random.Random(seed)
    r = fakeredis.FakeRedis(decode_responses=True)
    scorer = AnomalyScorer(r)

    # --- population: 8 normal clients + 3 attacker keys (normal during warmup)
    normals = [NormalClient(100 + i, SERVICE_ID, rng, base_interval=rng.uniform(3, 8))
               for i in range(8)]
    attackers = {  # scenario -> key id (behaves normally through warmup)
        "credential_stuffing": 201,
        "enumeration": 202,
        "low_and_slow": 203,
    }
    attacker_clients = [NormalClient(k, SERVICE_ID, rng, base_interval=5.0)
                        for k in attackers.values()]

    # --- phase 1: warmup (all traffic benign, baselines + model learn) --------
    t0 = 1_700_000_000.0
    warm_end = t0 + WARMUP_SECONDS
    warmup = merge_timelines(*(c.events(t0, warm_end)
                               for c in normals + attacker_clients))
    for le in warmup:
        scorer.process_event(le.ev)

    # --- phase 2: attacks injected over continuing normal traffic -------------
    atk_end = warm_end + ATTACK_PHASE_SECONDS
    timeline = merge_timelines(
        *(c.events(warm_end, atk_end) for c in normals),
        credential_stuffing(attackers["credential_stuffing"], SERVICE_ID, warm_end + 60),
        enumeration(attackers["enumeration"], SERVICE_ID, warm_end + 120),
        low_and_slow(attackers["low_and_slow"], SERVICE_ID, warm_end + 30),
    )

    results = []  # (label, risk, action)
    first_flag_idx = {}   # scenario -> attack-event ordinal of first flag
    attack_seen = defaultdict(int)
    for le in timeline:
        decision = scorer.process_event(le.ev)
        results.append((le.label, decision.risk, decision.action))
        if le.label != LABEL_NORMAL:
            attack_seen[le.label] += 1
            if le.label not in first_flag_idx and decision.action in FLAG_ACTIONS:
                first_flag_idx[le.label] = attack_seen[le.label]

    # --- metrics -----------------------------------------------------------------
    def _metrics(flag_fn):
        tp = sum(1 for l, _, a in results if l != LABEL_NORMAL and flag_fn(a, _))
        fp = sum(1 for l, _, a in results if l == LABEL_NORMAL and flag_fn(a, _))
        fn = sum(1 for l, _, a in results if l != LABEL_NORMAL and not flag_fn(a, _))
        n_norm = sum(1 for l, _, _a in results if l == LABEL_NORMAL)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / n_norm if n_norm else 0.0
        return dict(tp=tp, fp=fp, fn=fn, precision=precision, recall=recall, fpr=fpr)

    hard = _metrics(lambda a, _r: a in FLAG_ACTIONS)               # >= tarpit
    observed = _metrics(lambda _a, r: r >= cfg.THRESHOLD_LOG)      # >= log

    per_scenario = {}
    for scen in attackers:
        evs = [(r_, a) for l, r_, a in results if l == scen]
        flagged = sum(1 for _r, a in evs if a in FLAG_ACTIONS)
        logged = sum(1 for r_, _a in evs if r_ >= cfg.THRESHOLD_LOG)
        per_scenario[scen] = {
            "events": len(evs),
            "recall_hard": flagged / len(evs) if evs else 0.0,
            "recall_observed": logged / len(evs) if evs else 0.0,
            "detection_latency_events": first_flag_idx.get(scen),
            "max_risk": max((r_ for r_, _ in evs), default=0.0),
        }

    report = {
        "warmup_events": len(warmup),
        "eval_events": len(results),
        "hard_flag (risk >= tarpit 0.7)": hard,
        "observed (risk >= log 0.5)": observed,
        "per_scenario": per_scenario,
    }

    if verbose:
        _print_report(report)
    return report


def _print_report(rep: dict) -> None:
    print("=" * 72)
    print("AEGIS — Adaptive Anomaly Detection: Synthetic Evaluation")
    print("=" * 72)
    print(f"warmup events: {rep['warmup_events']:>6}   "
          f"evaluation events: {rep['eval_events']}")
    for name in ("hard_flag (risk >= tarpit 0.7)", "observed (risk >= log 0.5)"):
        m = rep[name]
        print(f"\n[{name}]")
        print(f"  precision: {m['precision']:.3f}   recall: {m['recall']:.3f}   "
              f"false-positive rate: {m['fpr']:.4f}")
        print(f"  tp={m['tp']}  fp={m['fp']}  fn={m['fn']}")
    print("\n[per-scenario]")
    for scen, m in rep["per_scenario"].items():
        lat = m["detection_latency_events"]
        lat_s = f"{lat} events" if lat is not None else "not flagged"
        print(f"  {scen:<22} events={m['events']:<5} "
              f"recall(hard)={m['recall_hard']:.3f}  "
              f"recall(observed)={m['recall_observed']:.3f}  "
              f"max_risk={m['max_risk']:.3f}  first-detection={lat_s}")
    print("=" * 72)


if __name__ == "__main__":
    run()
