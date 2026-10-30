# agentattr — Agent Behavior Attribution Toolkit

A zero-dependency toolkit for **attributing autonomous-agent behavior and
surfacing rogue / masquerading agents** in a multi-agent system. Built for the
Apart *Agent Attribution* research sprint (tracks: **Detect / Simulate /
Discover**).

It answers three questions a trust-and-safety reviewer actually asks:

| Track | Question | Module |
|-------|----------|--------|
| **Simulate** | Can I reproduce a realistic multi-agent trace with a planted rogue? | `simulator.py` |
| **Detect**   | For each action, is the actor who it claims to be, and is the action allowed? | `attributor.py` |
| **Discover** | Across many traces, which behavioral fingerprints are anomalous or impersonating others? | `discover.py` |

## Why it is trustworthy

Every event is written to an **append-only, tamper-evident ledger** (a hash
chain: each record carries the digest of the record before it). Any later edit,
drop, insertion, or tail-truncation is detected *and localised*. This is a
self-contained re-implementation of the chain design from the `swarmbox`
project — integrity, not authenticity (it proves the log was not altered since
it was written; identity is established separately by the attributor).

## Quick start

```bash
python eval.py          # runs all checks, exits 0 on success
```

- `agentattr/simulator.py` — `generate(seed=...)` → deterministic trace with a
  planted rogue (forbidden op **and** masquerade).
- `agentattr/attributor.py` — `attribute(trace)` → per-event verdicts + set of
  rogue agent ids.
- `agentattr/discover.py` — `discover(trace, forbidden_ops)` → per-fingerprint
  profiles, anomalous fingerprints, and masquerade groups.
- `agentattr/ledger.py` / `chain.py` — the tamper-evident event log.

## What the evaluation proves

`eval.py` (seeded, reproducible) asserts:

- the planted rogue id is flagged,
- ≥5 rogue verdicts are emitted, each with a human-readable reason,
- the rogue fingerprint is reported as **anomalous**,
- the rogue fingerprint forms a **masquerade group** spanning >1 claimed id
  (including the true rogue id),
- the ledger hash-chain verifies,
- a re-run with the same seed yields identical rogue counts.

## Design notes

- **No third-party dependencies** — standard library only, so judges can run it
  anywhere.
- **Fingerprints, not ids, are the unit of identity.** An agent can lie about
  its `agent_id`, but its behavioral signature (`fp`) is harder to fake; the
  Detect and Discover layers cross-check claimed id against observed `fp`.
- **Reproducibility is a feature.** A run is identified by the sha256 of its
  ledger, so another team can rerun exactly what was submitted.

## License

MIT — see `LICENSE`.
