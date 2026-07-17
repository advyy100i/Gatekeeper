"""
Feature extraction: event schema and path templating.

The gateway publishes *metadata only* (never request/response bodies) as a
lightweight event on a Redis Stream. The ML worker enriches it (templating,
inter-arrival, rates) so the gateway hot path stays as thin as possible.

Path templating (v1 heuristic): numeric / UUID / long-hex path segments are
replaced with ``{id}`` and the *last* raw value is captured as the object id.
Feature B (Shadow API Discovery) can later replace this with learned templates.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Optional, Tuple

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_NUM_RE = re.compile(r"^\d+$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")  # long hex tokens (hashes, keys)


def template_path(path: str) -> Tuple[str, Optional[str]]:
    """
    Normalize a request path into an endpoint template and extract an object id.

    ``/users/123/orders/456`` -> (``/users/{id}/orders/{id}``, ``456``)

    Returns:
        (endpoint_template, object_id) — object_id is the last raw id seen,
        or None if the path contains no id-like segment.
    """
    segments = path.strip("/").split("/") if path.strip("/") else []
    out = []
    object_id: Optional[str] = None
    for seg in segments:
        if _NUM_RE.match(seg) or _UUID_RE.match(seg) or _HEX_RE.match(seg):
            out.append("{id}")
            object_id = seg
        else:
            out.append(seg)
    return "/" + "/".join(out), object_id


@dataclass
class FeatureEvent:
    """One request's metadata, as published by the gateway."""

    api_key_id: int
    service_id: int
    ts: float               # epoch seconds (event time, not worker wall time)
    method: str
    path: str                # raw path; worker derives template + object id
    status: int
    payload_size: int

    def to_stream(self) -> dict:
        """Serialize for XADD (Redis streams carry flat string maps)."""
        d = asdict(self)
        return {k: str(v) for k, v in d.items()}

    @classmethod
    def from_stream(cls, fields: dict) -> "FeatureEvent":
        """Deserialize from an XREADGROUP entry (decode_responses=True)."""
        return cls(
            api_key_id=int(fields["api_key_id"]),
            service_id=int(fields["service_id"]),
            ts=float(fields["ts"]),
            method=fields["method"],
            path=fields["path"],
            status=int(fields["status"]),
            payload_size=int(fields["payload_size"]),
        )

    @property
    def status_class(self) -> str:
        """'2xx' / '4xx' / '5xx' / 'other'"""
        if 200 <= self.status < 300:
            return "2xx"
        if 400 <= self.status < 500:
            return "4xx"
        if 500 <= self.status < 600:
            return "5xx"
        return "other"

    @property
    def is_auth_failure(self) -> bool:
        return self.status in (401, 403)
