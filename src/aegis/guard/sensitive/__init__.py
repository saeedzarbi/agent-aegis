"""
Sensitive-data detection and masking (Phase 1).

Modular detectors live in ``detectors.DETECTOR_REGISTRY``. See
``docs/sanitization-phase1-problem.md``.
"""

from aegis.guard.sensitive.engine import (
    mask_structure_from_matches,
    mask_text,
    matches_to_signals,
    scan_structure,
    scan_text,
)

__all__ = [
    "mask_structure_from_matches",
    "mask_text",
    "matches_to_signals",
    "scan_structure",
    "scan_text",
]
