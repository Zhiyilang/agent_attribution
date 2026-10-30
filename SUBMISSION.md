# Submission — Apart "Agent Attribution" sprint

> Copy-paste ready. Repo is public on GitHub; the user signs up on Apart and
> pastes the repo URL + this summary into the sprint submission form.

## Project
**agentattr** — Agent Behavior Attribution Toolkit

## Repo URL
https://github.com/Zhiyilang/agent_attribution

## Track(s)
All three: **Detect / Simulate / Discover** (one toolkit, three modules).

## One-line summary
A zero-dependency toolkit that simulates a multi-agent trace with a planted
rogue, attributes every action to a (possibly spoofed) identity, and discovers
anomalous / masquerading behavioral fingerprints — backed by a tamper-evident
event ledger.

## How to run / reproduce
```bash
python eval.py     # 10/10 checks pass, exits 0
```

## What it does (per track)
- **Simulate** — `generate(seed)` builds a deterministic trace with one planted
  rogue that both (a) issues a globally forbidden op (`exfiltrate`) and (b)
  masquerades under a victim id while keeping its own fingerprint.
- **Detect** — `attribute(trace)` emits a per-event verdict (ok / rogue) with a
  reason; flags forbidden ops, fingerprint↔claimed-id mismatch, and out-of-scope
  resources. Returns the set of rogue agent ids.
- **Discover** — `discover(trace, forbidden_ops)` builds a per-fingerprint
  behavioral profile, flags anomalous fingerprints (forbidden ops or a uniquely
  disjoint resource set), and reports masquerade groups (one fingerprint claimed
  by multiple ids).

## Trust property
Append-only, hash-chained ledger (`chain.py` + `ledger.py`): any edit, drop,
insertion, or tail-truncation is detected and localised. A run is identified by
the sha256 of its ledger, so another team can rerun exactly what was submitted.

## Team
Solo — Zhi Yilang (GitHub `Zhiyilang`).

## Notes
- No third-party dependencies (stdlib only).
- The chain design is a self-contained re-implementation of the one in the
  `swarmbox` project (MIT compatible).
