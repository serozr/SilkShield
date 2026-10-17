"""Adapter for the official EMBER feature version 3 vectorizer (thrember).

The feature format is not re-implemented: each record's raw feature dicts are
passed to `thrember.PEFeatureExtractor.process_raw_features`.

`import thrember` also imports polars, scikit-learn, matplotlib and
huggingface_hub through `thrember/__init__.py`. Only `thrember/features.py` is
needed here, so if the full package import fails (e.g. no polars wheel on
s390x) the module is loaded directly from its file.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping

import numpy as np

from silkscan.errors import DependencyError
from silkscan.features.base import Extraction, FeatureExtractor
from silkscan.features.hashing import make_portable

INSTALL_HINT = (
    "pip install 'thrember @ git+https://github.com/FutureComputing4AI/EMBER2024@"
    "0ef753e81d98bf209f71b03cd331dfc190b5b54d' 'signify==0.8.1'   (or: pip install -e '.[ember]')"
)
# Order of PEFeatureExtractor.features in thrember 0.1.0 (commit 0ef753e).
RAW_FIELDS = ("general", "histogram", "byteentropy", "strings", "header", "section", "imports", "exports",
              "datadirectories", "richheader", "authenticode", "pefilewarnings")
# Column indices thrember's own training code marks as categorical (model.py, train_model).
OFFICIAL_CATEGORICAL = (2, 3, 4, 5, 6, 701, 702)

_MODULE: ModuleType | None = None


def load_thrember_features() -> ModuleType:
    global _MODULE
    if _MODULE is not None:
        return _MODULE
    try:
        module = importlib.import_module("thrember.features")
        make_portable(module)
        _MODULE = module
        return module
    except ModuleNotFoundError as e:
        if e.name == "thrember":
            raise DependencyError(f"Feature group `ember_v3` needs thrember, which is not installed.\n  {INSTALL_HINT}")
        first_error: Exception = e
    except ImportError as e:
        first_error = e
    spec = importlib.util.find_spec("thrember")
    if spec is None or not spec.submodule_search_locations:
        raise DependencyError(f"thrember is not installed.\n  {INSTALL_HINT}")
    path = Path(list(spec.submodule_search_locations)[0]) / "features.py"
    try:
        fspec = importlib.util.spec_from_file_location("_silkscan_thrember_features", path)
        module = importlib.util.module_from_spec(fspec)
        sys.modules[fspec.name] = module
        fspec.loader.exec_module(module)
    except ImportError as e:
        raise DependencyError(
            f"thrember is installed but its feature module cannot be imported: {e}\n"
            f"(package import failed first with: {first_error}).\n"
            "thrember.features needs numpy, pefile, scikit-learn and signify==0.8.1."
        ) from None
    make_portable(module)
    _MODULE = module
    return module


class EmberV3(FeatureExtractor):
    name = "ember_v3"
    version = "1"
    required_inputs = RAW_FIELDS
    default_missing_policy = "error"

    def __init__(self, **params: Any) -> None:
        if params:
            raise TypeError(f"ember_v3 takes no params, got {sorted(params)}")
        super().__init__()
        mod = load_thrember_features()
        self._extractor = mod.PEFeatureExtractor()
        got = tuple(fe.name for fe in self._extractor.features)
        if got != RAW_FIELDS:
            raise DependencyError(f"Unexpected thrember feature layout {got}; expected {RAW_FIELDS}. {INSTALL_HINT}")
        self._names = [f"{self.name}.{fe.name}_{i:04d}" for fe in self._extractor.features for i in range(fe.dim)]
        self._tool = {
            "thrember_features_sha256": hashlib.sha256(Path(mod.__file__).read_bytes()).hexdigest(),
            "dim": str(self._extractor.dim),
        }

    def __getstate__(self) -> dict[str, Any]:
        return {"params": self.params}

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__init__(**state["params"])

    def tool_versions(self) -> dict[str, str]:
        return dict(self._tool)

    def get_feature_names(self) -> list[str]:
        return list(self._names)

    def categorical_feature_names(self) -> list[str]:
        return [self._names[i] for i in OFFICIAL_CATEGORICAL]

    def display_names(self) -> dict[str, str]:
        """Human-readable meaning of each column, for explanations and slides.

        Column names stay index-based so models remain compatible; this map is
        derived from thrember's own field lists and falls back to the index name
        for any block whose layout does not match.
        """
        out: dict[str, str] = {}
        start = 0
        for fe in self._extractor.features:
            labels = _block_labels(fe)
            cols = self._names[start:start + fe.dim]
            if labels is None or len(labels) != fe.dim:
                labels = [f"{fe.name}[{i}]" for i in range(fe.dim)]
            out.update(zip(cols, labels))
            start += fe.dim
        return out

    def extract_one(self, view: Mapping[str, Any]) -> Extraction:
        missing = [k for k in RAW_FIELDS if k not in view]
        if missing:
            return Extraction.missing(f"raw feature field(s) {missing} absent")
        vec = self._extractor.process_raw_features(dict(view))
        return Extraction(np.asarray(vec, dtype=np.float32))

    def raw_features_from_bytes(self, data: bytes) -> dict[str, Any]:
        """Run thrember's static PE analysis on file bytes (used for single-file prediction)."""
        return self._extractor.raw_features(data)


def _block_labels(fe: Any) -> list[str] | None:
    """Semantic labels for one thrember feature block, in vector order (commit 0ef753e layouts)."""
    n = fe.name
    if n == "general":
        return ["file size", "file entropy", "is PE (parsed)"] + [f"start byte {i}" for i in range(4)]
    if n == "histogram":
        return [f"byte 0x{i:02x} frequency" for i in range(256)]
    if n == "byteentropy":
        return [f"byte/entropy histogram (entropy bin {i // 16}, byte bin {i % 16})" for i in range(256)]
    if n == "strings":
        regexes = sorted(fe.regex_idxs, key=fe.regex_idxs.get)
        return (["number of strings", "mean string length", "printable characters"]
                + [f"printable char {chr(c)!r} share" for c in range(0x20, 0x80)]
                + ["string entropy"] + [f"strings matching {r!r}" for r in regexes])
    if n == "header":
        scalars = ["COFF timestamp", "COFF number of sections", "COFF number of symbols", "size of optional header",
                   "pointer to symbol table", "machine type", "subsystem", "major image version",
                   "minor image version", "major linker version", "minor linker version", "major OS version",
                   "minor OS version", "major subsystem version", "minor subsystem version", "size of code",
                   "size of headers", "size of image", "size of initialized data", "size of uninitialized data",
                   "stack reserve", "stack commit", "heap reserve", "heap commit", "entry point address",
                   "base of code", "image base", "section alignment", "checksum", "number of RVAs and sizes"]
        return (scalars + [f"characteristic {c}" for c in fe._image_characteristics]
                + [f"DLL characteristic {c}" for c in fe._dll_characteristics]
                + [f"DOS header {m}" for m in fe._dos_members])
    if n == "section":
        general = ["number of sections", "zero-size sections", "empty-name sections", "readable+executable sections",
                   "writable sections", "max section entropy", "min section entropy", "max section size ratio",
                   "min section size ratio", "max virtual/raw size ratio", "min virtual/raw size ratio"]
        hashed = [f"section {kind} (hash bucket {i})" for kind in ("size", "virtual size", "entropy", "flags")
                  for i in range(50)]
        return (general + hashed + [f"entry section name (hash bucket {i})" for i in range(10)]
                + ["overlay size", "overlay size ratio", "overlay entropy"])
    if n == "imports":
        return (["number of imported functions", "number of imported DLLs"]
                + [f"imported DLL (hash bucket {i})" for i in range(256)]
                + [f"imported function (hash bucket {i})" for i in range(1024)])
    if n == "exports":
        # thrember stores len(hashed vector), i.e. 128 whenever exports exist, not the export count.
        return ["has exports (128 if any, thrember quirk)"] + [f"exported name (hash bucket {i})" for i in range(128)]
    if n == "datadirectories":
        return ([f"data directory {d} {k}" for d in fe._name_order for k in ("size", "virtual address")]
                + ["has relocations", "has dynamic relocations"])
    if n == "richheader":
        return ["rich header entries"] + [f"rich header (hash bucket {i})" for i in range(32)]
    if n == "authenticode":
        return ["signature: number of certificates", "signature: self-signed", "signature: empty program name",
                "signature: no countersigner", "signature: parse error", "signature: chain depth",
                "signature: latest signing time", "signature: signing time - PE timestamp"]
    if n == "pefilewarnings":
        warnings = sorted(fe.warning_ids, key=fe.warning_ids.get)
        return [f"pefile warning: {w}" for w in warnings] + ["number of pefile warnings"]
    return None
