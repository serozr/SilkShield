"""Combine the model's decision with check results; assign priority and a recommended action.

Decision precedence:
1. any FORCE_MALICIOUS hit (deny-list, forcing rule)    -> malicious
2. else any FORCE_CLEAN hit (exact-hash allow-list)     -> clean
3. else any FORCE_REVIEW hit (e.g. not a PE file)       -> suspicious   (fail-closed: never clean)
4. else the model's three-zone decision                 -> malicious | suspicious | clean
                                                           (inconclusive / error if analysis was incomplete)
EVIDENCE hits never change the decision; they raise the priority and are listed as reasons.
A check ERROR never makes a file clean.

Priority (rule-based, not a learned "threat level") and action:
  P1  malicious and (forced by a check, or a HIGH/CRITICAL hit, or a high-impact type tag)  -> quarantine_and_alert
  P2  malicious, or suspicious with a high-impact type (stage 2 / check tag)               -> quarantine_and_review
  P3  suspicious / inconclusive / error, or a MEDIUM+ evidence hit on a clean file          -> review
  P4  clean                                                                                 -> allow
"""

from __future__ import annotations

from typing import Any, Iterable

from silkscan.checks.base import CheckResult, Effect, Outcome, Severity

HIGH_IMPACT_TAGS = frozenset({"ransomware", "ransom", "backdoor", "rat", "wiper", "stealer", "rootkit", "worm"})
ACTIONS = {"P1": "quarantine_and_alert", "P2": "quarantine_and_review", "P3": "review", "P4": "allow"}


def combine(model_decision: str, results: Iterable[CheckResult], extra_tags: Iterable[str] = ()
            ) -> dict[str, Any]:
    """`extra_tags`: e.g. stage-2 threat categories; they affect priority like check tags."""
    results = list(results)
    hits = [r for r in results if r.outcome == Outcome.HIT]
    forced_bad = [r for r in hits if r.effect == Effect.FORCE_MALICIOUS]
    forced_good = [r for r in hits if r.effect == Effect.FORCE_CLEAN]
    forced_review = [r for r in hits if r.effect == Effect.FORCE_REVIEW]
    evidence = [r for r in hits if r.effect == Effect.EVIDENCE]
    reasons: list[str] = []
    if forced_bad:
        decision = "malicious"
        reasons += [f"{r.check}: {', '.join(r.evidence[:3]) or 'hit'} (forces malicious)" for r in forced_bad]
        if forced_good:
            reasons.append("allow-list hit overridden by a deny/forcing rule")
    elif forced_good:
        decision = "clean"
        reasons += [f"{r.check}: allow-listed" for r in forced_good]
        if model_decision in ("malicious", "suspicious"):
            reasons.append(f"model said {model_decision}; allow-list takes precedence")
    elif forced_review:
        decision = "suspicious"
        reasons += [f"{r.check}: {r.message or ', '.join(r.evidence[:3])} (sent to review)" for r in forced_review]
    else:
        decision = model_decision
        reasons.append(f"model: {model_decision}")
    reasons += [f"{r.check}: {', '.join(r.evidence[:3])} ({r.severity.name.lower()})" for r in evidence]
    errors = [r.check for r in results if r.outcome == Outcome.ERROR]
    if errors:
        reasons.append(f"check error(s): {', '.join(errors)} (not treated as clean)")

    max_sev = max((r.severity for r in hits if r.effect != Effect.FORCE_CLEAN), default=Severity.INFO)
    tags = {t.lower() for r in hits for t in r.tags} | {t.lower() for t in extra_tags}
    high_impact = bool(tags & HIGH_IMPACT_TAGS)
    if decision == "malicious" and (forced_bad or max_sev >= Severity.HIGH or high_impact):
        priority = "P1"
    elif decision == "malicious" or (decision == "suspicious" and high_impact):
        priority = "P2"   # a suspicious file typed as ransomware/backdoor/stealer is escalated
    elif decision in ("suspicious", "inconclusive", "error") or max_sev >= Severity.MEDIUM or errors:
        priority = "P3"
    else:
        priority = "P4"
    return {"decision": decision, "reasons": reasons, "priority": priority, "action": ACTIONS[priority],
            "max_check_severity": max_sev.name.lower(), "tags": sorted(tags)}
