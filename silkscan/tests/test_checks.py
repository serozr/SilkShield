"""Rule-based checks (hash lists, YARA, custom) and how they combine with the model."""

import json
from pathlib import Path

import pytest
import yaml

from silkscan.checks import Check, CheckContext, Effect, Outcome, Severity, create_checks
from silkscan.checks.builtin import HashList, Yara
from silkscan.checks.decision import combine
from silkscan.cli.main import main
from silkscan.config import CheckConfig, load_serving_config
from silkscan.errors import ConfigError

ROOT = Path(__file__).resolve().parents[1]
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
A, B = "a" * 64, "b" * 64


def _ctx(sha=A, data=None):
    return CheckContext.from_record(sha, {"general": {"size": 10}}, data)


def test_hash_lists_and_precedence(tmp_path):
    (tmp_path / "deny.txt").write_text(f"# comment\n{A}\n")
    (tmp_path / "allow.txt").write_text(f"{A}\n{B}  # both lists\n")
    chk = HashList(deny=str(tmp_path / "deny.txt"), allow=str(tmp_path / "allow.txt"))
    chk.setup()
    deny_hit, allow_hit = chk(_ctx(A)), chk(_ctx(B))
    assert deny_hit.effect == Effect.FORCE_MALICIOUS and deny_hit.severity == Severity.CRITICAL
    assert allow_hit.effect == Effect.FORCE_CLEAN
    assert chk(_ctx("c" * 64)).outcome == Outcome.MISS
    assert combine("clean", [deny_hit])["decision"] == "malicious"
    assert combine("malicious", [allow_hit])["decision"] == "clean"
    assert combine("clean", [deny_hit, allow_hit])["decision"] == "malicious"  # deny wins
    (tmp_path / "bad.txt").write_text("not-a-hash\n")
    with pytest.raises(ConfigError):
        HashList(deny=str(tmp_path / "bad.txt")).setup()


def test_yara_rules_from_repo():
    pytest.importorskip("yara")
    chk = Yara(rules_dir=str(ROOT / "rules" / "yara"), allow_force=True)
    chk.setup()
    hit = chk(_ctx(data=b"junk" + EICAR + b"junk"))
    assert hit.outcome == Outcome.HIT and hit.effect == Effect.FORCE_MALICIOUS and "EICAR_Test_File" in hit.evidence
    upx = chk(_ctx(data=b"MZ" + b"\0" * 100 + b"UPX0" + b"\0" * 30 + b"UPX1"))
    assert upx.severity == Severity.LOW and "upx" in upx.tags and upx.effect == Effect.EVIDENCE
    assert chk(_ctx(data=b"MZ nothing here")).outcome == Outcome.MISS
    assert chk(_ctx(data=None)).outcome == Outcome.SKIPPED   # only features, no bytes
    no_force = Yara(rules_dir=str(ROOT / "rules" / "yara"))
    no_force.setup()
    assert no_force(_ctx(data=EICAR)).effect == Effect.EVIDENCE


def test_broken_check_is_an_error_not_clean():
    class Broken(Check):
        name, version = "broken", "1"

        def run(self, ctx):
            raise RuntimeError("bad rule")

    res = Broken()(_ctx())
    assert res.outcome == Outcome.ERROR and "bad rule" in res.message
    out = combine("clean", [res])
    assert out["decision"] == "clean" and out["priority"] == "P3"
    assert any("not treated as clean" in r for r in out["reasons"])


def test_priority_rules():
    from silkscan.checks.base import CheckResult
    hi = CheckResult("yara", "1", Outcome.HIT, Severity.HIGH, Effect.EVIDENCE, evidence=["R"])
    ransom = CheckResult("yara", "1", Outcome.HIT, Severity.LOW, Effect.EVIDENCE, tags=["ransomware"])
    med = CheckResult("yara", "1", Outcome.HIT, Severity.MEDIUM, Effect.EVIDENCE)
    assert combine("malicious", [])["priority"] == "P2"
    assert combine("malicious", [hi])["priority"] == "P1"
    assert combine("malicious", [ransom])["priority"] == "P1"
    assert combine("clean", [med])["priority"] == "P3" and combine("clean", [med])["decision"] == "clean"
    assert combine("inconclusive", [])["priority"] == "P3"
    assert combine("clean", [])["priority"] == "P4"


def test_serving_config_validation(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text(yaml.safe_dump({"run": "x", "checks": [{"name": "hash_list", "effect": "explode"}]}))
    with pytest.raises(ConfigError, match="effect"):
        load_serving_config(p)
    with pytest.raises(ConfigError, match="Unknown check"):
        create_checks([CheckConfig("nope")])


def test_predict_with_serving_config(trained_run, tmp_path, capsys):
    pytest.importorskip("yara")
    run, cfg = trained_run
    deny = tmp_path / "deny.txt"
    data = Path(cfg.data.root) / "synthetic_Win64_test.jsonl"
    deny.write_text("")  # synthetic ids are not SHA-256 values, so the list stays empty here
    serving = tmp_path / "serving.yaml"
    serving.write_text(yaml.safe_dump({
        "run": str(run),
        "checks": [{"name": "hash_list", "params": {"deny": str(deny)}},
                   {"name": "yara", "params": {"rules_dir": str(ROOT / "rules" / "yara")}}],
    }))
    assert main(["predict", "--serving", str(serving), "--jsonl", str(data), "--limit", "3"]) == 0
    verdicts = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    v = verdicts[0]
    assert v["schema_version"] == "1" and v["priority"] in ("P1", "P2", "P3", "P4")
    assert {c["check"]: c["outcome"] for c in v["checks"]} == {"hash_list": "skipped", "yara": "skipped"}  # synthetic ids
    assert v["model"]["schema_fingerprint"] and "yara" in v["check_versions"]
    assert v["decision"] == v["model_decision"]


# --- ordering: cheap checks before static analysis and the model ------------------------------------
import hashlib  # noqa: E402

import silkscan.inference.predict as P  # noqa: E402
from silkscan.inference.bundle import ModelBundle  # noqa: E402


class _Seen(Check):
    """Records what it saw; pre (needs_raw False) or post (needs_raw True)."""
    version = "1"

    def __init__(self, name, needs_raw, effect=None, hit=False):
        super().__init__(effect=effect)
        self.name, self.needs_raw, self.hit, self.saw_raw = name, needs_raw, hit, []

    def run(self, ctx):
        self.saw_raw.append(bool(ctx.raw))
        return self.result(Outcome.HIT if self.hit else Outcome.MISS, severity=Severity.HIGH)


def _bundle(trained_run):
    run, _ = trained_run
    b = ModelBundle(run)
    return b, b.backend()


def test_forced_pre_check_skips_parse_and_model(trained_run, monkeypatch):
    b, backend = _bundle(trained_run)
    calls = {"parse": 0, "model": 0}
    monkeypatch.setattr(P, "record_from_bytes", lambda d: calls.__setitem__("parse", calls["parse"] + 1))
    orig = P._score
    monkeypatch.setattr(P, "_score", lambda *a, **k: (calls.__setitem__("model", calls["model"] + len(a[2])),
                                                      orig(*a, **k))[1])
    deny = _Seen("deny", needs_raw=False, effect=Effect.FORCE_MALICIOUS, hit=True)
    post = _Seen("post", needs_raw=True)
    [v] = P.scan(b, backend, [P.Submission(b"MZ" + b"\0" * 64)], [deny, post])
    assert v["decision"] == "malicious" and v["model_decision"] == "skipped" and v["priority"] == "P1"
    assert calls == {"parse": 0, "model": 0} and post.saw_raw == []        # nothing expensive ran
    assert v["id"] == hashlib.sha256(b"MZ" + b"\0" * 64).hexdigest() and v["score"] is None
    assert any("short-circuit" in r for r in v["reasons"])


def test_no_short_circuit_and_evidence_hits_still_run_the_model(trained_run):
    from silkscan.synthetic import make_records
    b, backend = _bundle(trained_run)
    rec = make_records(1, seed=3)[0]
    deny = _Seen("deny", needs_raw=False, effect=Effect.FORCE_MALICIOUS, hit=True)
    [v] = P.scan(b, backend, [P.Submission(None, rec)], [deny], short_circuit=False)
    assert v["decision"] == "malicious" and v["model_decision"] in ("clean", "malicious", "inconclusive")
    assert v["score"] is not None                                          # audit / shadow mode
    ev = _Seen("ev", needs_raw=False, effect=Effect.EVIDENCE, hit=True)
    post = _Seen("post", needs_raw=True)
    [v] = P.scan(b, backend, [P.Submission(None, rec)], [ev, post])
    assert v["score"] is not None and post.saw_raw == [True]               # evidence does not short-circuit


def test_pre_checks_see_no_raw_features_for_bytes_and_parse_errors_are_errors(trained_run, monkeypatch):
    b, backend = _bundle(trained_run)

    def boom(data):
        raise ValueError("truncated PE")

    monkeypatch.setattr(P, "record_from_bytes", boom)
    pre, post = _Seen("pre", needs_raw=False), _Seen("post", needs_raw=True)
    [v] = P.scan(b, backend, [P.Submission(b"not a pe")], [pre, post])
    assert pre.saw_raw == [False] and post.saw_raw == []                   # pre ran before parsing
    assert v["decision"] == "error" and v["priority"] == "P3"
    assert any("static analysis failed" in r for r in v["reasons"])


def test_real_pe_bytes_are_parsed_only_when_needed(trained_run, tmp_path):
    pytest.importorskip("yara")
    try:
        from silkscan.features.groups.ember_v3 import load_thrember_features
        load_thrember_features()
    except Exception:
        pytest.skip("thrember not installed")
    import pip
    exe = (Path(pip.__file__).parent / "_vendor" / "distlib" / "w64.exe").read_bytes()
    b, backend = _bundle(trained_run)
    yara_chk = Yara(rules_dir=str(ROOT / "rules" / "yara"), allow_force=True)
    yara_chk.setup()
    clean, eicar = P.scan(b, backend, [P.Submission(exe), P.Submission(exe + EICAR)], [yara_chk])
    assert clean["timing_ms"]["parse"] > 0 and clean["score"] is not None
    assert eicar["decision"] == "malicious" and eicar["model_decision"] == "skipped"
    assert eicar["timing_ms"]["parse"] == 0 and eicar["timing_ms"]["model"] == 0


def test_binary_hash_list_matches_text_list(tmp_path):
    import numpy as np
    digests = sorted({bytes([i]) * 32 for i in range(1, 50)})
    np.save(tmp_path / "k.npy", np.array(digests, dtype="S32"))
    hand = (b"\xee" * 32).hex()
    (tmp_path / "t.txt").write_text(hand + "  # hand-written\n")
    chk = HashList(deny=[str(tmp_path / "k.npy"), str(tmp_path / "t.txt")])
    chk.setup()
    assert len(chk.deny) == 50
    for d in (digests[0], digests[-1], digests[17], b"\xee" * 32):
        assert chk(_ctx(d.hex())).effect == Effect.FORCE_MALICIOUS
    assert chk(_ctx((b"\x00" * 32).hex())).outcome == Outcome.MISS
    assert chk(_ctx((b"\xff" * 32).hex())).outcome == Outcome.MISS
    np.save(tmp_path / "unsorted.npy", np.array(digests[::-1], dtype="S32"))
    with pytest.raises(ConfigError, match="sorted"):
        HashList(deny=str(tmp_path / "unsorted.npy")).setup()


def test_hash_lists_handle_digests_ending_in_zero_bytes(tmp_path):
    """numpy S32 drops trailing NULs on read; ~1/256 SHA-256 values end in 0x00."""
    import numpy as np
    from silkscan.data.manifest import SplitData
    from silkscan.hashlist import write_hash_list

    ending_zero = [bytes([7]) * 31 + b"\x00", bytes([9]) * 30 + b"\x00\x00", bytes([1]) * 32]
    hexes = np.array([d.hex().encode() for d in ending_zero], dtype="S64")

    class _M:  # minimal manifest stand-in
        fingerprint = "f" * 64

        def split(self, name):
            n = len(hexes)
            return SplitData(name, hexes, np.ones(n, np.int8), np.zeros(n, np.int64), np.zeros(n, np.int32),
                             np.arange(n, dtype=np.int64))

    for suffix in (".npy", ".txt"):
        out = tmp_path / f"k{suffix}"
        assert write_hash_list(_M(), ["train"], 1, out) == 3
        chk = HashList(deny=str(out))
        chk.setup()
        for d in ending_zero:
            assert chk(_ctx(d.hex())).outcome == Outcome.HIT, (suffix, d.hex())
        assert chk(_ctx((bytes([7]) * 31 + b"\x01").hex())).outcome == Outcome.MISS
