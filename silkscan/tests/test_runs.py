"""Run directories are never overwritten."""

import datetime as dt

import pytest

import silkscan.runs as runs
from silkscan.errors import RunExistsError


def test_existing_run_directory_is_not_overwritten(tmp_path, monkeypatch):
    class Frozen(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 1, 1, 12, 0, 0)

    monkeypatch.setattr(runs, "datetime", Frozen)
    first = runs.create_run_dir(tmp_path, "abcdef0123")
    (first / "model.txt").write_text("original")
    with pytest.raises(RunExistsError):
        runs.create_run_dir(tmp_path, "abcdef0123")
    assert (first / "model.txt").read_text() == "original"
    runs.create_subdir(first, "evaluations")
    with pytest.raises(RunExistsError):
        runs.create_subdir(first, "evaluations")
