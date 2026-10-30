"""Append-only behavioral event ledger.

Every agent action is written *before* any decision about it, so the trace
supports re-running and external auditing. The ledger is JSONL and its sha256
is the identity of a run.
"""

import hashlib
import json
import os


def _dump(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


class Ledger:
    def __init__(self, path=None, chained=True):
        self.path = path
        self.chained = chained
        self._rows = []
        self._tail = None
        if path and os.path.exists(path):
            os.remove(path)

    def _append(self, row):
        if self.chained:
            from .chain import GENESIS, row_digest
            prev = self._tail or GENESIS
            row[FIELD_PREV_LOCAL] = prev
            row[FIELD_HASH_LOCAL] = row_digest(prev, row)
            self._tail = row[FIELD_HASH_LOCAL]
        self._rows.append(row)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(_dump(row) + "\n")

    # event types -----------------------------------------------------
    def event(self, agent_id, op, resource, args=None, result=None,
              fingerprint=None):
        self._append({
            "t": "event", "agent_id": agent_id, "op": op,
            "resource": resource, "args": args or {}, "result": result,
            "fp": fingerprint,
        })

    def verdict(self, agent_id, decision, reason, rule=None):
        self._append({
            "t": "verdict", "agent_id": agent_id, "decision": decision,
            "reason": reason, "rule": rule,
        })

    def summary(self, metrics):
        self._append({"t": "summary", "metrics": metrics})

    # reading ---------------------------------------------------------
    @property
    def rows(self):
        return list(self._rows)

    def lines(self):
        return [_dump(r) for r in self._rows]

    def digest(self):
        h = hashlib.sha256()
        for line in self.lines():
            h.update(line.encode("utf-8"))
            h.update(b"\n")
        return h.hexdigest()

    def counts(self):
        out = {"events": 0, "verdicts": 0, "refuse": 0, "allow": 0}
        for r in self._rows:
            if r.get("t") == "event":
                out["events"] += 1
            elif r.get("t") == "verdict":
                out["verdicts"] += 1
                out[r["decision"]] = out.get(r["decision"], 0) + 1
        return out


FIELD_PREV_LOCAL = "_prev"
FIELD_HASH_LOCAL = "_h"


def read_ledger(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    return rows
