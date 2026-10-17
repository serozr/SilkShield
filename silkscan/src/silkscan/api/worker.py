"""Spawned scoring workers; no OpenMP fork, no model work on the ASGI loop."""
from __future__ import annotations

import hashlib
import json
import multiprocessing
import time
from dataclasses import asdict
from pathlib import Path


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def _main(connection, config):
    try:
        from silkscan.checks import create_checks
        from silkscan.config import load_serving_config
        from silkscan.data.records import split_record
        from silkscan.inference.bundle import ModelBundle
        from silkscan.inference.predict import Submission, scan, VERDICT_SCHEMA_VERSION
        from silkscan.utils.env import runtime_info
        from silkscan.api.isolation import ParserProcess

        serving = load_serving_config(config.serving)
        bundle = ModelBundle(serving.run)
        backend = bundle.backend(serving.backend)
        checks = create_checks(serving.checks)
        stage2 = None
        stage2_assets: dict[str, str] = {}
        if serving.stage2:
            # Stage 2 (threat category/family): same model the CLI uses; its files are part of
            # the cache namespace so a retrained stage 2 never reuses old verdicts.
            from silkscan.stage2 import Stage2Model
            stage2 = Stage2Model(Path(serving.stage2))
            stage2.require_compatible(bundle.schema.fingerprint())
            stage2_assets = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in sorted(Path(serving.stage2).iterdir()) if p.suffix in (".txt", ".json")}
        bundle.pipeline()
        bundle.threshold(backend.name)  # reject an uncalibrated backend at startup
        if type(serving.max_file_mb) is not int or serving.max_file_mb <= 0:
            raise ValueError("serving.max_file_mb must be a positive integer")
        if type(serving.explain_top) is not int or serving.explain_top < 0:
            raise ValueError("serving.explain_top must be a nonnegative integer")
        if type(serving.short_circuit) is not bool:
            raise ValueError("serving.short_circuit must be a boolean")
        versions = {c.name: {"version": c.version, **c.tool_versions()} for c in checks}
        assets = {name: hashlib.sha256((Path(serving.run) / name).read_bytes()).hexdigest()
                  for name in ("model.txt", "feature_schema.json", "extractor_states.json",
                               "threshold.json", "config.resolved.yaml")}
        metadata = {
            "run": bundle.run_dir.name, "schema_fingerprint": bundle.schema.fingerprint(),
            "backend": backend.name, "threshold_policy": (bundle.policy(backend.name) or {}).get("mode", "global"),
            "thresholds": bundle.thresholds, "target_fpr": bundle.config.evaluation.target_fpr,
            "checks": versions, "short_circuit": serving.short_circuit,
            "stage2": stage2.id if stage2 else None,
            "verdict_schema_version": VERDICT_SCHEMA_VERSION, "runtime": runtime_info(),
        }
        package_root = Path(__file__).resolve().parents[1]
        implementation = {str(p.relative_to(package_root)): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in sorted(package_root.rglob("*.py"))}
        namespace = fingerprint({"run": str(Path(serving.run).resolve()), "assets": assets,
                                 "serving": asdict(serving), "checks": versions, "stage2": stage2_assets,
                                 "parse_timeout_s": config.parse_timeout_s,
                                 "parse_memory_mb": config.parse_memory_mb,
                                 "implementation": implementation})
        connection.send({"metadata": metadata, "namespace": namespace,
                         "max_bytes": serving.max_file_mb * 1024 * 1024,
                         "explain_top": serving.explain_top})
    except Exception as exc:
        connection.send({"error": f"Worker initialization failed: {type(exc).__name__}: {exc}"})
        connection.close()
        return
    parse = ParserProcess(config.parse_timeout_s, config.parse_memory_mb, config.parse_recycle_after,
                          config.worker_start_timeout_s)
    parse.start()
    try:
        while True:
            work = connection.recv()
            if work is None:
                break
            try:
                items = [Submission(data=w.get("data"),
                                    record=split_record(w["raw"]) if "raw" in w else None,
                                    filename=w.get("filename")) for w in work]
                started = time.perf_counter()
                result = scan(bundle, backend, items, checks, work[0]["explain"], serving.short_circuit, parse,
                              stage2=stage2)
                scan_ms = 1000 * (time.perf_counter() - started)
                if any(v["check_versions"] != versions for v in result):
                    raise RuntimeError("Check files changed: restart the service with immutable rules")
                connection.send({"verdicts": result, "scan_ms": scan_ms})
            except Exception as exc:
                # Input-derived exception text may include file content. Expose only the type.
                connection.send({"error": f"Scan failed: {type(exc).__name__}"})
    except (EOFError, BrokenPipeError):
        pass
    finally:
        parse.close()
        connection.close()


class Worker:
    def __init__(self, config):
        self.config = config
        self.process = None
        self.connection = None

    def start(self):
        ctx = multiprocessing.get_context("spawn")
        self.connection, child = ctx.Pipe()
        self.process = ctx.Process(target=_main, args=(child, self.config), daemon=False)
        self.process.start()
        child.close()
        if not self.connection.poll(self.config.worker_start_timeout_s):
            self.close()
            raise RuntimeError("Worker initialization timed out")
        result = self.connection.recv()
        if "error" in result:
            self.close()
            raise RuntimeError(result["error"])
        self.info = result
        return result

    @property
    def alive(self):
        return self.process is not None and self.process.is_alive()

    def scan(self, payloads):
        self.connection.send(payloads)
        if not self.connection.poll(self.config.worker_timeout_s):
            self.close()
            raise TimeoutError("Scoring worker exceeded its time limit")
        response = self.connection.recv()
        if "error" in response:
            raise RuntimeError(response["error"])
        return response

    def close(self):
        if self.process is not None:
            if self.process.is_alive():
                self.process.terminate()
            self.process.join(timeout=2)
            if self.process.is_alive():
                self.process.kill()
                self.process.join()
        if self.connection is not None:
            self.connection.close()
