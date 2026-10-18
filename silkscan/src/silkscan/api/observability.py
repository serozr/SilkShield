"""Content-free JSON logging and small dependency-free Prometheus counters."""
from __future__ import annotations

import json
import logging
from collections import Counter

LOG = logging.getLogger("silkscan.api")


def log_event(event, **fields):
    LOG.info(json.dumps({"event": event, **fields}, separators=(",", ":")))


class Metrics:
    def __init__(self):
        self.decisions = Counter()
        self.priorities = Counter()
        self.short_circuits = 0
        self.overrides = 0
        self.cache_hits = 0
        self.failures = 0
        self.bounds = (0.1, 0.5, 1, 5, 10, 20, 100, 500, 1000, 10000)
        self.histograms = {}

    def observe(self, verdict, api_ms):
        self.decisions[verdict["decision"]] += 1
        self.priorities[verdict["priority"]] += 1
        self.short_circuits += verdict["model_decision"] == "skipped"
        self.overrides += verdict["decision"] != verdict["model_decision"]
        for stage, duration in {**verdict["timing_ms"], "api": api_ms}.items():
            histogram = self.histograms.setdefault(stage, [0, 0.0, [0] * len(self.bounds)])
            histogram[0] += 1
            histogram[1] += duration
            for i, bound in enumerate(self.bounds):
                histogram[2][i] += duration <= bound

    def render(self, depth):
        lines = ["# TYPE silkscan_verdicts_total counter"]
        lines += [f'silkscan_verdicts_total{{decision="{k}"}} {v}' for k, v in sorted(self.decisions.items())]
        lines += ["# TYPE silkscan_priority_total counter"]
        lines += [f'silkscan_priority_total{{priority="{k}"}} {v}' for k, v in sorted(self.priorities.items())]
        for name, value in (("short_circuits", self.short_circuits), ("overrides", self.overrides),
                            ("cache_hits", self.cache_hits), ("failures", self.failures)):
            lines += [f"# TYPE silkscan_{name}_total counter", f"silkscan_{name}_total {value}"]
        lines += ["# TYPE silkscan_queue_depth gauge", f"silkscan_queue_depth {depth}",
                  "# TYPE silkscan_stage_ms histogram"]
        for stage, (count, total, buckets) in sorted(self.histograms.items()):
            for bound, n in zip(self.bounds, buckets):
                lines.append(f'silkscan_stage_ms_bucket{{stage="{stage}",le="{bound}"}} {n}')
            lines += [f'silkscan_stage_ms_bucket{{stage="{stage}",le="+Inf"}} {count}',
                      f'silkscan_stage_ms_count{{stage="{stage}"}} {count}',
                      f'silkscan_stage_ms_sum{{stage="{stage}"}} {total}']
        return "\n".join(lines) + "\n"
