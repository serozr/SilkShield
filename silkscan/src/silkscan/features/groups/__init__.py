"""Built-in feature groups. To add a group, register it here and enable it in the config."""

from silkscan.features.groups.ember_v3 import EmberV3
from silkscan.features.groups.import_semantics import ImportSemantics
from silkscan.features.groups.section_summary import SectionSummary
from silkscan.features.registry import register

register(EmberV3)
register(SectionSummary)
register(ImportSemantics)
