"""
SOC2 Gap Analysis Engine – Production Quality Implementation.

Performs evidence validation for SOC 2 Type II readiness,
detecting false positives, coverage gaps, and edge cases.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

from pydantic import BaseModel, Field, ValidationError, validator

# --------------------------------------------------------------------------- #
# Logging configuration
# --------------------------------------------------------------------------- #
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")


# --------------------------------------------------------------------------- #
# Enums and custom types
# --------------------------------------------------------------------------- #
class EvidenceType(str, Enum):
    """Distinguishes design from operating effectiveness evidence."""

    DESIGN = "design"
    OPERATING = "operating"


class EvidenceStatus(str, Enum):
    """Status of evidence."""

    EXISTS = "exists"
    PARTIAL = "partial"
    MISSING = "missing"


class VendorMethod(str, Enum):
    """Subservice organisation reporting method."""

    CARVE_OUT = "carve-out"
    INCLUSIVE = "inclusive"
    OTHER = "other"


# --------------------------------------------------------------------------- #
# Pydantic models with validation
# --------------------------------------------------------------------------- #
class EvidenceWindow(BaseModel):
    """Time range over which evidence is valid."""

    start: date = Field(..., description="Start date of evidence coverage.")
    end: date = Field(..., description="End date of evidence coverage.")

    @validator("end")
    def end_after_start(cls, v: date, values: Dict[str, Any]) -> date:
        if "start" in values and v < values["start"]:
            raise ValueError("EvidenceWindow end must be >= start.")
        return v

    def duration_days(self) -> int:
        """Return number of days in the window."""
        return (self.end - self.start).days


class DesignEvidence(BaseModel):
    """Evidence that a control exists (policy, procedure, configuration)."""

    description: str
    status: EvidenceStatus
    last_updated: Optional[date] = None


class OperatingEvidence(BaseModel):
    """Evidence that a control operates effectively over time."""

    description: str
    status: EvidenceStatus
    window: EvidenceWindow
    population_size: Optional[int] = None
    sample_size: Optional[int] = None
    exception_count: Optional[int] = None
    reviewer_sign_off: Optional[str] = None

    @validator("sample_size")
    def sample_within_population(
        cls, v: Optional[int], values: Dict[str, Any]
    ) -> Optional[int]:
        pop = values.get("population_size")
        if v is not None and pop is not None and v > pop:
            raise ValueError("sample_size cannot exceed population_size.")
        return v

    @validator("population_size", "sample_size", pre=True)
    def non_negative(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v < 0:
            raise ValueError("Size values must be non-negative.")
        return v


class VendorEvidence(BaseModel):
    """Evidence related to subservice organizations."""

    vendor_name: str
    method: VendorMethod
    soc_report_date: date
    has_cuec_mapping: bool = False
    has_csoc_mapping: bool = False
    bridge_letter_available: bool = False
    covered_service_mapping_ok: bool = False

    @property
    def is_complete(self) -> bool:
        if self.method == VendorMethod.CARVE_OUT:
            return (
                self.has_cuec_mapping
                and self.has_csoc_mapping
                and self.bridge_letter_available
            )
        elif self.method == VendorMethod.INCLUSIVE:
            return self.covered_service_mapping_ok
        return False

    @validator("soc_report_date")
    def report_not_in_future(cls, v: date) -> date:
        if v > date.today():
            raise ValueError("SOC report date cannot be in the future.")
        return v


class Control(BaseModel):
    """Represents a single SOC 2 control with design and operating evidence."""

    criterion: str  # e.g. "CC6.1"
    control_description: str
    evidence_type: EvidenceType
    design_evidence: Optional[DesignEvidence] = None
    operating_evidence: Optional[OperatingEvidence] = None
    vendor_evidence: Optional[VendorEvidence] = None

    @validator("operating_evidence", always=True)
    def check_type_consistency(
        cls, v: Optional[OperatingEvidence], values: Dict[str, Any]
    ) -> Optional[OperatingEvidence]:
        if v is not None and values.get("evidence_type") == EvidenceType.DESIGN:
            raise ValueError("Design controls cannot have operating evidence.")
        return v

    @validator("criterion")
    def criterion_format(cls, v: str) -> str:
        if not v or len(v) > 10:
            raise ValueError("Criterion must be non-empty and <=10 characters.")
        return v.upper()


class AnalysisResult(BaseModel):
    """Output of the gap analysis for one control."""

    criterion: str
    design_ready: bool
    operating_ready: bool
    vendor_ready: bool
    overall_ready: bool
    issues: List[str] = Field(default_factory=list)
    score: int  # 0-100


# --------------------------------------------------------------------------- #
# Helper dataclass for internal issue tracking
# --------------------------------------------------------------------------- #
@dataclass
class _ControlAnalysis:
    """Mutable analysis state for a single control."""
    design_ready: bool = False
    operating_ready: bool = False
    vendor_ready: bool = False
    issues: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
_MIN_OBSERVATION_DAYS = 30  # Minimum days for meaningful operating evidence


# --------------------------------------------------------------------------- #
# Analysis engine
# --------------------------------------------------------------------------- #
class SOC2GapAnalyzer:
    """
    Analyzes evidence for SOC 2 Type II readiness.

    Features:
    - Separate evaluation of design and operating effectiveness.
    - Detection of insufficient evidence windows.
    - Subservice organization CUEC/CSOC mapping validation.
    - Edge case handling for control changes and qualified reports.
    """

    def __init__(self, audit_window: EvidenceWindow) -> None:
        """
        Initialize analyzer with the intended audit observation period.

        Args:
            audit_window: The Type II observation period start and end dates.

        Raises:
            TypeError: If audit_window is not an EvidenceWindow instance.
            ValueError: If audit_window duration is less than one day.
        """
        if not isinstance(audit_window, EvidenceWindow):
            raise TypeError("audit_window must be an EvidenceWindow instance.")
        if audit_window.duration_days() < 1:
            raise