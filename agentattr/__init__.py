"""agentattr - agent behavior attribution toolkit.

Three capabilities mirror the Apart "Agent Attribution" sprint tracks:
  - Simulate: generate a reproducible multi-agent trace with a planted rogue.
  - Detect:   attribute each action and flag rogue behavior / masquerade.
  - Discover: build behavioral fingerprints and surface anomalies / impersonation.

Zero third-party dependencies; standard library only.
"""

from . import attributor, discover, ledger, simulator

__all__ = ["attributor", "discover", "ledger", "simulator"]
