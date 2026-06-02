"""
SOC 2 Type II Readiness Gap Analyzer

Evaluates evidence files against SOC 2 criteria (CC series) for Type II
readiness.  Checks design existence, operating effectiveness window,
population coverage, exception handling, and reviewer approval.
Supports subservice organisation reliance with CUEC/CSOC mapping.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

import yaml
from pydantic import BaseModel, Field, ValidationError, validator

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
))
logger.addHandler(_handler)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class EvidenceValidationError(Exception):
    """Raised when evidence data is invalid or incomplete."""


class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing."""


class AnalysisError(Exception):
    """Raised when an analysis step fails unexpectedly."""


# ---------------------------------------------------------------------------
# Data models (Pydantic)
# ---------------------------------------------------------------------------


class Evidence(BaseModel):
    """A single piece of evidence for a control.

    Attributes:
        source: File path or identifier.
        collected_date: Date evidence was collected.
        population: Description of the population (e.g. "all employees").
        sample_size: Number of items sampled if sampling applied.
        exceptions: List of exceptions found.
        reviewer: Person who reviewed / signed off.
        scope: In-scope systems, locations, etc.
        period_start: Start of the observation period this evidence covers.
        period_end: End of the observation period.
        cuerc_mapped: Whether complementary user entity controls are mapped.
        csoc_mapped: Whether complementary subservice organisation controls
            are mapped.
        vendor_report_date: Date of vendor SOC 2 report, if applicable.
    """

    source: str = Field(..., description="File path or identifier")
    collected_date: date = Field(..., description="Date evidence was collected")
    population: Optional[str] = Field(None, description="Population description (e.g. all employees)")
    sample_size: Optional[int] = Field(None, ge=1, description="Sample size if sampling applied")
    exceptions: Optional[List[str]] = Field(default_factory=list, description="List of exceptions found")
    reviewer: Optional[str] = Field(None, description="Who reviewed / signed off")
    scope: Optional[str] = Field(None, description="e.g. in-scope systems, locations")
    period_start: Optional[date] = Field(None, description="Start of the observation period this evidence covers")
    period_end: Optional[date] = Field(None, description="End of the observation period")
    cuerc_mapped: Optional[bool] = Field(False, description="Whether complementary user entity controls are mapped")
    csoc_mapped: Optional[bool] = Field(False, description="Whether complementary subservice organisation controls are mapped")
    vendor_report_date: Optional[date] = Field(None, description="Date of vendor SOC 2 report, if applicable")

    @validator("period_end")
    def period_end_after_start(cls, v: Optional[date], values: Dict[str, Any]) -> Optional[date]:
        if v and values.get("period_start") and v < values["period_start"]:
            raise ValueError("period_end must be after period_start")
        return v

    @validator("exceptions", pre=True, always=True)
    def ensure_list(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        return list(v)


class Criterion(BaseModel):
    """SOC 2 criterion (e.g. CC6.1) with its evidence.

    Attributes:
        id: Criterion identifier (e.g. "CC6.1").
        description: Short description of the control.
        evidence: List of associated evidence objects.
        required_population: Expected population for this control.
        required_frequency: Expected control performance frequency.
        required_reviewer: Whether reviewer sign‑off is mandatory.
    """

    id: str = Field(..., pattern=r"^CC\d+\.\d+$", description="Criterion identifier")
    description: str = Field("", description="Criterion description")
    evidence: List[Evidence] = Field(default_factory=list, description="Associated evidence")
    required_population: Optional[str] = Field(None, description="Expected population for this control")
    required_frequency: Optional[str] = Field(None, description="Expected control performance frequency")
    required_reviewer: Optional[bool] = Field(False, description="Whether reviewer sign‑off is mandatory")


class Config(BaseModel):
    """Configuration for the gap analysis run.

    Attributes:
        evidence_dir: Directory containing evidence YAML files.
        audit_period_start: Start of the intended Type II audit period.
        audit_period_end: End of the intended Type II audit period.
        criteria: List of criteria to assess.
        min_evidence_coverage_days: Minimum number of days of evidence
            required for operating effectiveness.
        max_evidence_age_days: Maximum days since evidence collection for it
            to be considered fresh (scored higher).
    """

    evidence_dir: Path = Field(..., description="Directory containing evidence files")
    audit_period_start: date = Field(..., description="Start of the intended Type II audit period")
    audit_period_end: date = Field(..., description="End of the intended Type II audit period")
    criteria: List[Criterion] = Field(..., description="List of criteria to assess")
    min_evidence_coverage_days: int = Field(90, ge=1, description="Minimum days of evidence required")
    max_evidence_age_days: int = Field(
        14, ge=1, description="Maximum days since evidence collection for it to be considered fresh"
    )

    @validator("audit_period_end")
    def period_valid(cls, v: date, values: Dict[str, Any]) -> date:
        if v <= values.get("audit_period_start", v):
            raise ValueError("audit_period_end must be after audit_period_start")
        return v


# ---------------------------------------------------------------------------
# Analysis result
# ---------------------------------------------------------------------------


@dataclass
class CriterionResult:
    """Result for a single criterion.

    Attributes:
        id: Criterion identifier.
        design_exists: Evidence of control design exists.
        operating_effectiveness_sufficient: Evidence covers the required
            observation period.
        population_complete: Population covered matches expected.
        exceptions_handled: Exceptions have been documented.
        reviewer_approved: Evidence has reviewer sign‑off (if required).
        evidence_window_covered: Evidence covers the full audit period or
            min_evidence_coverage_days.
        subservice_cuerc_mapped: CUECs mapped (for subservice