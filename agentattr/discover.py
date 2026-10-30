"""Discover track: behavioral fingerprinting and anomaly discovery.

Given a trace, build a behavioral profile per *observed fingerprint* (not per
claimed id - because ids can be spoofed). Then:

1. **Anomaly** - flag fingerprints whose op-mix or resource-mix deviates strongly
   from the median honest profile (e.g. a fingerprint that does ``exfiltrate``).
2. **Masquerade** - when two or more *different claimed agent ids* share the
   *same* fingerprint, at least one of them is impersonating the other.

This is the "who is actually behind this behavior" layer that complements the
per-event Detect layer.
"""

from collections import Counter, defaultdict


def _profile(events):
    by_fp = defaultdict(lambda: {"ops": Counter(), "resources": Counter(),
                                 "ids": set()})
    for ev in events:
        fp = ev.get("fp", "unknown")
        slot = by_fp[fp]
        slot["ops"][ev["op"]] += 1
        slot["resources"][ev["resource"]] += 1
        slot["ids"].add(ev["agent_id"])
    return by_fp


def discover(trace, forbidden_ops):
    """Return dict with ``anomalous_fps`` and ``masquerade_groups``."""
    by_fp = _profile(trace)

    # Median honest op-count as the baseline. A fingerprint is anomalous if it
    # performs any globally forbidden op, or touches resources no other profile
    # touches while claiming a benign identity.
    anomalous = set()
    for fp, slot in by_fp.items():
        if any(op in forbidden_ops for op in slot["ops"]):
            anomalous.add(fp)
            continue
        res_set = set(slot["resources"])
        # A profile whose resource set is unique and disjoint from every other
        # profile is suspicious (a hidden actor operating out-of-scope).
        if res_set and all(
            res_set.isdisjoint(set(other["resources"]))
            for other_fp, other in by_fp.items() if other_fp != fp
        ):
            if len(slot["ops"]) >= 1 and len(slot["ids"]) >= 1:
                anomalous.add(fp)

    # Masquerade: same fingerprint, multiple claimed ids.
    masquerade = {fp: sorted(slot["ids"]) for fp, slot in by_fp.items()
                  if len(slot["ids"]) > 1}

    return {
        "profiles": {fp: {"ops": dict(slot["ops"]),
                          "resources": sorted(slot["resources"]),
                          "ids": sorted(slot["ids"])}
                     for fp, slot in by_fp.items()},
        "anomalous_fps": sorted(anomalous),
        "masquerade_groups": masquerade,
    }
