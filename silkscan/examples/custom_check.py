"""Writing a check: a cheap rule over EMBER raw features (no file bytes needed).

Run:  python examples/custom_check.py
In the project: put the class in src/silkscan/checks/ (or your own module), add
`register_check(HighEntropyOverlay)` to src/silkscan/checks/__init__.py, then enable it under
`checks:` in configs/serving.yaml. The model, its schema and the feature cache are unaffected.
"""

from __future__ import annotations

from silkscan.checks import Check, CheckContext, Outcome, Severity, register_check


class HighEntropyOverlay(Check):
    name = "high_entropy_overlay"
    version = "1"
    needs_bytes = False          # True if run() reads ctx.data (YARA-like byte rules)
    needs_raw = True             # reads parsed features -> runs after static analysis, not before

    def setup(self) -> None:     # read params once
        self.min_entropy = float(self.params.get("min_entropy", 7.5))
        self.min_ratio = float(self.params.get("min_size_ratio", 0.3))

    def run(self, ctx: CheckContext):
        overlay = (ctx.raw.get("section") or {}).get("overlay") or {}
        if not overlay:
            return self.result(Outcome.SKIPPED, message="no section/overlay info")
        if overlay.get("entropy", 0) >= self.min_entropy and overlay.get("size_ratio", 0) >= self.min_ratio:
            return self.result(Outcome.HIT, severity=Severity.LOW, tags=["encrypted-or-packed-overlay"],
                               evidence=[f"overlay entropy {overlay['entropy']:.2f}, "
                                         f"{100 * overlay['size_ratio']:.0f}% of file"])
        return self.result(Outcome.MISS)


register_check(HighEntropyOverlay)

if __name__ == "__main__":
    from silkscan.checks.decision import combine
    from silkscan.synthetic import make_records

    chk = HighEntropyOverlay(min_entropy=0.0, min_size_ratio=0.0)  # thresholds lowered to show a hit
    chk.setup()
    rec = make_records(1)[0]
    res = chk(CheckContext.from_record(rec.id, rec.inputs))
    print(res.to_dict())
    print(combine("clean", [res]))
