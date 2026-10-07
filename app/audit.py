"""Optional per-session sequence-number continuity audit.

Enabled per collection session at creation time. The pinned protocol must
declare ``sequence_field`` naming an unsigned integer field with an effective
bit width of at least two bits, otherwise the session is rejected.

Only frames newly confirmed by an append are judged, in stream order. Each
frame's raw sequence is compared against the previous valid frame's raw
sequence modulo ``2**bit_width``:

* ``delta == 0``                — duplicate;
* ``delta == 1``                — normal advance, no anomaly;
* ``1 < delta < modulus / 2``   — suspected gap, ``delta - 1`` frames missing;
* ``delta == modulus / 2``      — exactly half a turn, direction indeterminate;
* ``delta > modulus / 2``       — backward jump.

Backward and indeterminate jumps infer no missing frames. Every valid frame
becomes the baseline for the next comparison, whatever the outcome; discarded
bytes (bad frames) and the pending tail never move the baseline.
"""
from __future__ import annotations

from .models import ProtocolDefinition

MIN_BIT_WIDTH = 2

DUPLICATE = "duplicate"
SUSPECTED_GAP = "suspected_gap"
BACKWARD = "backward"
INDETERMINATE = "indeterminate"

ANOMALY_TYPES = (DUPLICATE, SUSPECTED_GAP, BACKWARD, INDETERMINATE)


def sequence_bit_width(proto: ProtocolDefinition) -> int | None:
    """Effective bit width of the protocol's declared sequence field.

    Returns None when the protocol has no usable unsigned integer sequence
    field: ``sequence_field`` unset, naming no declared field, or naming a
    signed field. For bit-fields the declared ``bit_width`` wins over the
    storage type width.
    """
    if proto.sequence_field is None:
        return None
    for f in proto.fields_:
        if f.name == proto.sequence_field:
            if f.type.startswith("s") or f.signed:
                return None
            return f.bit_width if f.bit_width is not None else f.size_bytes * 8
    return None


def audit_frames(
    frames: list[dict],
    last_sequence: int | None,
    bit_width: int,
) -> tuple[list[dict], int | None, dict[str, int]]:
    """Classify newly confirmed frames against the running baseline.

    ``frames`` are the valid frames of one append (session offsets already
    applied). Returns ``(anomalies, new_baseline, counter_deltas)`` where
    ``counter_deltas`` maps each anomaly type plus ``"missing"`` (inferred
    missing frames from suspected gaps) to the amounts to add to the
    persisted cumulative counters. The first valid frame of a session only
    establishes the baseline and cannot be an anomaly.
    """
    modulus = 1 << bit_width
    half = modulus >> 1
    anomalies: list[dict] = []
    deltas = {t: 0 for t in ANOMALY_TYPES} | {"missing": 0}
    for frame in frames:
        seq = frame.get("sequence")
        if seq is None:
            continue
        if last_sequence is not None:
            delta = (seq - last_sequence) % modulus
            kind: str | None = None
            missing: int | None = None
            if delta == 0:
                kind = DUPLICATE
            elif delta == 1:
                kind = None
            elif delta < half:
                kind, missing = SUSPECTED_GAP, delta - 1
            elif delta == half:
                kind = INDETERMINATE
            else:
                kind = BACKWARD
            if kind is not None:
                deltas[kind] += 1
                deltas["missing"] += missing or 0
                anomalies.append(
                    {
                        "type": kind,
                        "frame_start": frame["start"],
                        "frame_end": frame["end"],
                        "previous_sequence": last_sequence,
                        "sequence": seq,
                        "missing": missing,
                    }
                )
        # Every valid frame rebases the next comparison, anomaly or not.
        last_sequence = seq
    return anomalies, last_sequence, deltas
