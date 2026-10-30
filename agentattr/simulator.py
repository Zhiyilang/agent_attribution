"""Simulate track: deterministic multi-agent trace generator.

Builds a reproducible behavioral trace with several honest agents and one
*planted* rogue agent. The rogue sometimes:
  - performs an operation outside its allowed set (policy violation), or
  - masquerades, emitting events under a victim agent's id while keeping its
    own behavioral fingerprint, or
  - exfiltrates to an out-of-scope resource.

A fixed seed makes the trace byte-for-byte reproducible, so eval.py can assert
the detector catches exactly what was planted.
"""

import hashlib
import json
import random


# Fingerprint = the behavioral signature an agent is expected to show.
HONEST = {
    "agent_a": {"ops": {"read", "write"}, "resources": {"db_a", "cache"}},
    "agent_b": {"ops": {"read"}, "resources": {"db_b"}},
    "agent_c": {"ops": {"read", "compute"}, "resources": {"db_c", "queue"}},
}
ROGUE_ID = "agent_r"
ROGUE_FP = {"ops": {"read"}, "resources": {"db_r"}}

# Globally forbidden operations for any identity.
FORBIDDEN_OPS = {"exfiltrate", "delete_all"}


def fingerprint_hash(fp: dict) -> str:
    blob = json.dumps({"ops": sorted(fp["ops"]),
                       "resources": sorted(fp["resources"])},
                      sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def known_fingerprints():
    """Map agent_id -> expected fingerprint hash (the ground truth registry)."""
    reg = {aid: fingerprint_hash(fp) for aid, fp in HONEST.items()}
    reg[ROGUE_ID] = fingerprint_hash(ROGUE_FP)
    return reg


def _fp_event(agent_id, op, resource, rng, rogue_act=False):
    """Build one event dict. ``rogue_act`` forces a violation/masquerade."""
    if rogue_act and rng.random() < 0.5:
        # Masquerade: claim victim id, keep rogue fingerprint.
        victim = rng.choice(list(HONEST.keys()))
        return {
            "agent_id": victim,
            "op": "read",
            "resource": "db_r",  # rogue-only resource leaks the real identity
            "fp": fingerprint_hash(ROGUE_FP),
        }
    if rogue_act:
        # Outright forbidden op.
        return {
            "agent_id": ROGUE_ID,
            "op": "exfiltrate",
            "resource": "external_drop",
            "fp": fingerprint_hash(ROGUE_FP),
        }
    # Honest behavior.
    fp = HONEST.get(agent_id, ROGUE_FP)
    op = rng.choice(sorted(fp["ops"]))
    res = rng.choice(sorted(fp["resources"]))
    return {
        "agent_id": agent_id,
        "op": op,
        "resource": res,
        "fp": fingerprint_hash(fp),
    }


def generate(seed=1234, n_events=120, rogue_fraction=0.12):
    """Return a list of event dicts (the trace), deterministically."""
    rng = random.Random(seed)
    ids = list(HONEST.keys()) + [ROGUE_ID]
    trace = []
    for i in range(n_events):
        if rng.random() < rogue_fraction:
            ev = _fp_event(ROGUE_ID, None, None, rng, rogue_act=True)
        else:
            aid = rng.choice(ids[:3])  # honest agents only for clean events
            ev = _fp_event(aid, None, None, rng, rogue_act=False)
        ev["seq"] = i
        ev["ts"] = 1_700_000_000 + i * 7
        trace.append(ev)
    return trace
