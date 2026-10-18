"""Stage 2: threat category and family for files the detector flags (malicious or suspicious)."""

from silkscan.stage2.model import Stage2Model, Taxonomy, load_taxonomy

__all__ = ["Stage2Model", "Taxonomy", "load_taxonomy"]
