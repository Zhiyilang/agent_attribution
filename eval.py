"""Deterministic evaluation for the agent attribution toolkit.

Run:  python eval.py
Exits non-zero on any failed assertion. All inputs are seeded so the result is
byte-for-byte reproducible - the same property the ledger chain guarantees.
"""

import sys

from agentattr import attributor, discover, ledger, simulator

ROGUE_FP_HASH = simulator.fingerprint_hash(simulator.ROGUE_FP)
SEED = 1234
N_EVENTS = 120
ROGUE_FRACTION = 0.12

_CHECKS = 0
_FAILS = 0


def check(name, cond, detail=""):
    global _CHECKS, _FAILS
    _CHECKS += 1
    if cond:
        print(f"  [ok] {name}")
    else:
        _FAILS += 1
        print(f"  [FAIL] {name}  {detail}")


def main():
    print("== Generate trace ==")
    trace = simulator.generate(seed=SEED, n_events=N_EVENTS,
                               rogue_fraction=ROGUE_FRACTION)
    check("trace length == N_EVENTS", len(trace) == N_EVENTS, f"got {len(trace)}")

    print("== Detect track ==")
    verdicts, rogue_agents = attributor.attribute(trace)
    rogue_verdicts = [v for v in verdicts if v["decision"] == "rogue"]
    check("ROGUE_ID flagged as rogue", simulator.ROGUE_ID in rogue_agents,
          f"rogue_agents={rogue_agents}")
    check("at least 5 rogue verdicts emitted",
          len(rogue_verdicts) >= 5, f"got {len(rogue_verdicts)}")
    check("every rogue verdict has a reason",
          all(v["reason"] for v in rogue_verdicts))

    print("== Discover track ==")
    disc = discover.discover(trace, simulator.FORBIDDEN_OPS)
    check("rogue fingerprint in anomalous_fps",
          ROGUE_FP_HASH in disc["anomalous_fps"],
          f"anomalous={disc['anomalous_fps']}")
    check("masquerade group contains rogue fingerprint",
          ROGUE_FP_HASH in disc["masquerade_groups"],
          f"masq={list(disc['masquerade_groups'])}")
    if ROGUE_FP_HASH in disc["masquerade_groups"]:
        ids = disc["masquerade_groups"][ROGUE_FP_HASH]
        check("masquerade group spans >1 claimed id", len(ids) > 1, f"ids={ids}")
        check("masquerade group includes ROGUE_ID", simulator.ROGUE_ID in ids)

    print("== Ledger + chain integrity ==")
    led = ledger.Ledger(path="run_eval.jsonl", chained=True)
    for ev in trace:
        led.event(ev["agent_id"], ev["op"], ev["resource"],
                  args={"seq": ev.get("seq")}, fingerprint=ev.get("fp"))
    rows = ledger.read_ledger("run_eval.jsonl")
    from agentattr.chain import verify_chain
    ok, reason = verify_chain(rows)
    check("ledger chain verifies", ok, reason)

    print("== Determinism ==")
    trace2 = simulator.generate(seed=SEED, n_events=N_EVENTS,
                                rogue_fraction=ROGUE_FRACTION)
    v2, _ = attributor.attribute(trace2)
    check("rerun yields identical rogue verdict count",
          len([x for x in v2 if x["decision"] == "rogue"]) ==
          len(rogue_verdicts))

    print(f"\nSUMMARY: {_CHECKS - _FAILS}/{_CHECKS} checks passed, "
          f"{_FAILS} failed; rogue verdicts={len(rogue_verdicts)}, "
          f"anomalous_fps={len(disc['anomalous_fps'])}, "
          f"masquerade_groups={len(disc['masquerade_groups'])}")
    sys.exit(1 if _FAILS else 0)


if __name__ == "__main__":
    main()
