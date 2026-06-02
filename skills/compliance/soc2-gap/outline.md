"""
SOC 2 Type II Gap Assessment Engine.

Evaluates evidence payloads for design and operating effectiveness readiness
over a specified observation period, including subservice organization mapping.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pydantic
from pydantic import BaseModel, Field, field_validator, model_validator

# --------------------------------------------------------------------------- #
#  Logging Setup
# --------------------------------------------------------------------------- #

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
#  Enums & Constants
# --------------------------------------------------------------------------- #

class DesignMaturity(Enum):
    """Design maturity level (0 = undefined, 3 = fully documented)."""
    UNDEFINED = 0
    INFORMAL = 1
    DOCUMENTED = 2
    FULLY_DOCUMENTED = 3


class OperatingEffectiveness(Enum):
    """Operating effectiveness readiness (0 = no evidence, 3 = full coverage)."""
    NONE = 0
    PARTIAL = 1
    MOSTLY = 2
    FULL = 3


class GapSeverity(Enum):
    """Severity of the gap."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Minimum observation period in days for Type II (e.g., 6 months ≈ 183 days)
MIN_OBSERVATION_DAYS: int = 183

# --------------------------------------------------------------------------- #
#  Pydantic Models (Input Validation & Serialisation)
# --------------------------------------------------------------------------- #

class EvidenceItem(BaseModel):
    """A single evidence piece attached to a control criterion.

    Attributes:
        description: Short textual evidence description.
        date_created: When the evidence was generated (optional).
        reviewer: Who reviewed this evidence (optional).
        exception_notes: Exceptions or deviation notes (optional).
    """
    description: str = Field(..., min_length=1, max_length=500)
    date_created: Optional[date] = None
    reviewer: Optional[str] = None
    exception_notes: Optional[str] = None

    @field_validator("description")
    @classmethod
    def description_not_empty(cls, v: str) -> str:
        """Strip and reject empty/whitespace descriptions."""
        if not v.strip():
            raise ValueError("Description cannot be empty or whitespace")
        return v.strip()


class SubserviceOrganization(BaseModel):
    """Vendor / subservice organisation data.

    Attributes:
        vendor_name: Name of the subservice provider.
        report_date: Date of the current SOC report.
        service_boundary: 'carve-out' or 'inclusive'.
        current_soc_report: Is the SOC report for the latest period?
        cuec_mapped: Are complementary user entity controls defined?
        csoc_mapped: Are complementary subservice organization controls defined?
        bridge_letter_available: Is a bridge letter available?
        covered_service_mapping: Optional description of services covered.
    """
    vendor_name: str = Field(..., min_length=1, max_length=200)
    report_date: date
    service_boundary: str = "carve-out"
    current_soc_report: bool = True
    cuec_mapped: bool = False
    csoc_mapped: bool = False
    bridge_letter_available: bool = False
    covered_service_mapping: Optional[str] = None

    @field_validator("service_boundary")
    @classmethod
    def validate_boundary(cls, v: str) -> str:
        allowed = ("carve-out", "inclusive")
        if v not in allowed:
            raise ValueError(f"Boundary must be {allowed}, got {v}")
        return v

    @field_validator("vendor_name")
    @classmethod
    def vendor_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Vendor name cannot be empty")
        return v.strip()

    @field_validator("covered_service_mapping")
    @classmethod
    def optional_trim(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not v:
                v = None
        return v


class ObservationWindow(BaseModel):
    """Defines the Type II observation period.

    Attributes:
        start: Start date of the observation period.
        end: End date of the observation period.
    """
    start: date
    end: date

    @model_validator(mode="after")
    def validate_window(self) -> "ObservationWindow":
        if self.end <= self.start:
            raise ValueError("Observation end must be after start.")
        duration = (self.end - self.start).days
        if duration < MIN_OBSERVATION_DAYS:
            logger.warning(
                "Observation window is less than %d days (%d days). "
                "Type II readiness may be insufficient.",
                MIN_OBSERVATION_DAYS, duration,
            )
        return self

    @property
    def duration_days(self) -> int:
        """Return integer number of days in the observation window."""
        return (self.end - self.start).days


class ControlEvidence(BaseModel):
    """Evaluated control with design and operating evidence.

    Attributes:
        criterion_id: SOC 2 criterion ID (e.g., CC6.1).
        claimed_score: Self‑assessed score (0–3).
        evidence_items: List of evidence pieces.
        observation_window: The window this control's evidence covers (optional).
        sample_population: Number of items in the sample (0 if unknown).
        exception_list: List of exception descriptions.
        reviewer_signoff: Whether a reviewer officially signed off.
        reviewer_date: Date of sign‑off.
        subservice_orgs: Related subservice organizations.
    """
    criterion_id: str = Field(pattern=r"^CC\d+\.\d+$")
    claimed_score: int = Field(ge=0, le=3)
    evidence_items: List[EvidenceItem] = []
    observation_window: Optional[ObservationWindow] = None
    sample_population: int = 0
    exception_list: List[str] = []
    reviewer_signoff: bool = False
    reviewer_date: Optional[date] = None
    subservice_orgs: List[SubserviceOrganization] = []

    @field_validator("claimed_score")
    @classmethod
    def validate_score(cls, v: int) -> int:
        if v not in (0, 1, 2, 3):