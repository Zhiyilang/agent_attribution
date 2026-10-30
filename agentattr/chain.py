"""Tamper-evident chain for behavioral event logs.

Design note
-----------
This is a self-contained re-implementation of the hash-chain idea originally
built for the ``swarmbox`` project (Apache/MIT compatible). It lets a later
auditor answer: given a log handed over after the fact, was any line edited,
dropped, inserted, or was the tail quietly cut off? Each record carries the
digest of the record before it, so corruption is detectable *and localisable*.

It does **integrity, not authenticity**: it proves the log was not altered
since it was written, not who wrote it. That is exactly what an attribution
engine needs - the trace itself is trusted; identity is established separately
by the attributor.
"""

import hashlib
import json

GENESIS = "0" * 64
FIELD_PREV = "_prev"
FIELD_HASH = "_h"


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def row_digest(prev: str, row: dict) -> str:
    payload = dict(row)
    payload.pop(FIELD_HASH, None)
    h = hashlib.sha256()
    h.update(prev.encode("ascii"))
    h.update(b"|")
    h.update(canonical(payload))
    return h.hexdigest()


def chain_rows(rows):
    """Return ``(chained_rows, tail_digest)`` for an iterable of plain records."""
    out, prev = [], GENESIS
    for row in rows:
        payload = dict(row)
        payload[FIELD_PREV] = prev
        payload[FIELD_HASH] = row_digest(prev, payload)
        prev = payload[FIELD_HASH]
        out.append(payload)
    return out, prev


def verify_chain(rows, expected_tail=None):
    """Verify an already-chained iterable.

    Returns ``(True, "")`` when every link is intact, otherwise
    ``(False, "index N: <reason>")`` naming the first failing record.
    """
    prev = GENESIS
    last = GENESIS
    if not isinstance(rows, list):
        rows = list(rows)
    for i, row in enumerate(rows):
        if FIELD_PREV not in row or FIELD_HASH not in row:
            return False, f"index {i}: record is not chained"
        if row[FIELD_PREV] != prev:
            return False, (f"index {i}: predecessor digest does not match "
                           "(inserted/removed/reordered)")
        expected = row_digest(row[FIELD_PREV], row)
        if row[FIELD_HASH] != expected:
            return False, f"index {i}: digest does not match contents (edited)"
        prev = row[FIELD_HASH]
        last = row[FIELD_HASH]
    if expected_tail is not None and rows:
        if last != expected_tail:
            return False, "tail digest does not match anchor (tail truncated)"
    return True, ""


def summarise(rows) -> dict:
    prev = GENESIS
    for row in rows:
        prev = row.get(FIELD_HASH, prev) or prev
    return {"records": len(rows), "tail": prev}
