"""
Traffic generators: normal API clients and labeled attack scenarios.

Everything runs on a simulated clock (event timestamps), which the whole
pipeline honors — bucketing, inter-arrival, and EWMA updates all use event
time, never wall time — so a full multi-hour scenario evaluates in seconds.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Iterator, List, Tuple

from app.anomaly.features import FeatureEvent

LABEL_NORMAL = "normal"


@dataclass
class LabeledEvent:
    ev: FeatureEvent
    label: str      # "normal" or the attack scenario name


class NormalClient:
    """
    A well-behaved API consumer: steady jittered arrivals, a small set of
    endpoints, object ids drawn from a bounded pool, overwhelmingly 2xx.
    """

    def __init__(self, api_key_id: int, service_id: int, rng: random.Random,
                 base_interval: float = 5.0):
        self.key = api_key_id
        self.service = service_id
        self.rng = rng
        self.base_interval = base_interval
        self.id_pool = [str(1000 + i) for i in range(20)]
        self.endpoints = ["/users/{}", "/products", "/orders/{}", "/status"]

    def events(self, start: float, end: float) -> Iterator[LabeledEvent]:
        ts = start + self.rng.uniform(0, self.base_interval)
        while ts < end:
            path_t = self.rng.choice(self.endpoints)
            path = path_t.format(self.rng.choice(self.id_pool)) \
                if "{}" in path_t else path_t
            roll = self.rng.random()
            status = 200 if roll < 0.97 else (404 if roll < 0.99 else 401)
            yield LabeledEvent(
                FeatureEvent(
                    api_key_id=self.key, service_id=self.service, ts=ts,
                    method="GET", path=path, status=status,
                    payload_size=int(self.rng.lognormvariate(6.0, 0.6)),
                ),
                LABEL_NORMAL,
            )
            ts += self.rng.uniform(0.5, 1.5) * self.base_interval


# --- attack scenarios ---------------------------------------------------------
# Each attacker key behaves normally first (warmup establishes its baseline),
# then turns malicious — the realistic account-takeover shape.

def credential_stuffing(key: int, service: int, start: float,
                        n: int = 200, interval: float = 0.2) -> List[LabeledEvent]:
    """Rapid brute-force with a valid key identity: a wall of 401s."""
    return [
        LabeledEvent(
            FeatureEvent(api_key_id=key, service_id=service,
                         ts=start + i * interval, method="POST",
                         path="/login", status=401, payload_size=180),
            "credential_stuffing",
        )
        for i in range(n)
    ]


def enumeration(key: int, service: int, start: float,
                n: int = 300, interval: float = 0.5) -> List[LabeledEvent]:
    """Sequential object-id sweep: /users/10000, /users/10001, ..."""
    return [
        LabeledEvent(
            FeatureEvent(api_key_id=key, service_id=service,
                         ts=start + i * interval, method="GET",
                         path=f"/users/{10_000 + i}", status=200,
                         payload_size=350),
            "enumeration",
        )
        for i in range(n)
    ]


def low_and_slow(key: int, service: int, start: float,
                 n: int = 400, interval: float = 2.0) -> List[LabeledEvent]:
    """
    Patient scraping: moderate rate (no rate-limit trip), but every request
    touches a *new* object id — the per-window uniqueness is the giveaway.
    """
    return [
        LabeledEvent(
            FeatureEvent(api_key_id=key, service_id=service,
                         ts=start + i * interval, method="GET",
                         path=f"/products/{50_000 + i}", status=200,
                         payload_size=900),
            "low_and_slow",
        )
        for i in range(n)
    ]


def merge_timelines(*iterables) -> List[LabeledEvent]:
    """Interleave all generators into one timeline ordered by event time."""
    events: List[LabeledEvent] = []
    for it in iterables:
        events.extend(it)
    events.sort(key=lambda le: le.ev.ts)
    return events
