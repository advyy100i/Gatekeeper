"""
Real HTTP access-log loader — turns a Common Log Format trace into a stream of
``FeatureEvent``s so the anomaly pipeline can be evaluated on traffic nobody at
this project authored.

Default source: NASA-HTTP (ita.ee.lbl.gov) — 1.9M real requests, July 1995.
Format:  host - - [dd/Mon/yyyy:HH:MM:SS -0000] "METHOD path HTTP/x.x" status bytes

Mapping to FeatureEvent (documented, imperfect, honest):
  - client host/IP  -> api_key_id   (client IP == client identity; real logs
                                      have no API keys — stated caveat)
  - timestamp       -> ts
  - method / path   -> method / path (the path templater handles ids)
  - status          -> status
  - response bytes  -> payload_size
"""
from __future__ import annotations

import gzip
import re
import zlib
from datetime import datetime
from typing import Iterator, Optional

from app.anomaly.features import FeatureEvent

# host ... [time] "request" status bytes   (request/bytes may be malformed)
_LINE = re.compile(
    r'^(?P<host>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<req>[^"]*)"\s+(?P<status>\d{3}|-)\s+(?P<bytes>\d+|-)'
)
def host_to_key_id(host: str) -> int:
    """Stable positive 31-bit id for a client host (IP or DNS name)."""
    return zlib.crc32(host.encode("utf-8")) & 0x7FFFFFFF


def _parse_time(s: str) -> Optional[float]:
    # "05/Jul/1995:07:38:35 -0400" -> epoch seconds (tz offset ignored; the
    # pipeline only uses relative event time, so a constant offset is harmless).
    date_part = s.split(" ", 1)[0]
    try:
        return datetime.strptime(date_part, "%d/%b/%Y:%H:%M:%S").timestamp()
    except Exception:
        return None


def _open(path: str):
    return gzip.open(path, "rt", errors="replace") if path.endswith(".gz") \
        else open(path, "r", errors="replace")


def iter_access_log(
    path: str,
    limit: Optional[int] = None,
    service_id: int = 1,
    methods: Optional[set] = None,
) -> Iterator[FeatureEvent]:
    """
    Yield FeatureEvents parsed from a Common Log Format file (optionally gzip).

    Malformed lines are skipped. ``limit`` caps the number of *emitted* events.
    """
    emitted = 0
    with _open(path) as fh:
        for line in fh:
            m = _LINE.match(line)
            if not m:
                continue
            req = m.group("req").split()
            if len(req) < 2:
                continue
            method, rawpath = req[0], req[1]
            if methods and method not in methods:
                continue
            ts = _parse_time(m.group("time"))
            if ts is None:
                continue
            status = m.group("status")
            status = int(status) if status.isdigit() else 200
            nbytes = m.group("bytes")
            payload = int(nbytes) if nbytes.isdigit() else 0

            yield FeatureEvent(
                api_key_id=host_to_key_id(m.group("host")),
                service_id=service_id,
                ts=ts,
                method=method,
                path=rawpath,
                status=status,
                payload_size=payload,
            )
            emitted += 1
            if limit and emitted >= limit:
                return


def summarize(path: str, limit: int = 200_000) -> dict:
    """Quick corpus stats — useful to sanity-check a new dataset."""
    from collections import Counter
    n = 0
    hosts = set()
    status = Counter()
    methods = Counter()
    t_min = t_max = None
    for ev in iter_access_log(path, limit=limit):
        n += 1
        hosts.add(ev.api_key_id)
        status[ev.status_class] += 1
        methods[ev.method] += 1
        t_min = ev.ts if t_min is None else min(t_min, ev.ts)
        t_max = ev.ts if t_max is None else max(t_max, ev.ts)
    return {
        "events": n,
        "distinct_clients": len(hosts),
        "status_classes": dict(status),
        "methods": dict(methods.most_common(6)),
        "span_hours": round((t_max - t_min) / 3600, 1) if t_min else 0,
    }


if __name__ == "__main__":
    import sys
    src = sys.argv[1] if len(sys.argv) > 1 else "data/nasa_jul95.gz"
    print(summarize(src))
