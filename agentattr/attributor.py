"""Detect track: attribute each action and flag rogue behavior.

Given a trace (list of events with a claimed ``agent_id`` and a behavioral
``fp`` fingerprint), the attributor checks three things per event:

1. **Forbidden operation** - any globally denied op is rogue regardless of id.
2. **Identity violation** - the claimed ``agent_id``'s expected fingerprint
   (from the trusted registry) must match the event's actual ``fp``. A mismatch
   means the actor is not who it claims to be.
3. **Out-of-scope resource** - an operation on a resource outside the claimed
   identity's allowed set is a policy breach.

The output is a verdict per event plus aggregate rogue-agent rollup.
"""

from .simulator import (FORBIDDEN_OPS, HONEST, ROGUE_FP, ROGUE_ID,
                       fingerprint_hash, known_fingerprints)

# Ground-truth expected fingerprint per agent id.
EXPECTED = known_fingerprints()
ALLOWED = {aid: fp for aid, fp in HONEST.items()}
ALLOWED[ROGUE_ID] = ROGUE_FP


def attribute(trace):
    """Return (verdicts, rogue_agents).

    ``verdicts`` is a list of dicts: one per event with decision/rule/reason.
    ``rogue_agents`` is a set of agent ids flagged as rogue at least once.
    """
    verdicts = []
    rogue_agents = set()
    for ev in trace:
        aid = ev["agent_id"]
        op = ev["op"]
        res = ev["resource"]
        fp = ev.get("fp")
        reasons = []

        if op in FORBIDDEN_OPS:
            reasons.append(f"forbidden op '{op}'")

        expected_fp = EXPECTED.get(aid)
        if expected_fp is None:
            reasons.append(f"unknown claimed identity '{aid}'")
        elif fp != expected_fp:
            reasons.append("fingerprint mismatch: claimed identity does not "
                           "match observed behavior (masquerade/spoof)")

        allowed = ALLOWED.get(aid)
        if allowed is not None and res not in allowed["resources"]:
            reasons.append(f"resource '{res}' outside scope for '{aid}'")

        if reasons:
            rogue_agents.add(aid)
            verdicts.append({"seq": ev.get("seq"), "agent_id": aid,
                             "decision": "rogue", "rule": "detect",
                             "reason": "; ".join(reasons)})
        else:
            verdicts.append({"seq": ev.get("seq"), "agent_id": aid,
                             "decision": "ok", "rule": "detect",
                             "reason": "consistent with claimed identity"})
    return verdicts, rogue_agents
