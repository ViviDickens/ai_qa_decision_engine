from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from enum import Enum

class ThreatSeverity(str, Enum):
    """OWASP LLM threat severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class OWASPThreat(str, Enum):
    """OWASP LLM Top 10 (2025) threats."""
    LLM01_PROMPT_INJECTION = "LLM01"
    LLM02_INSECURE_OUTPUT = "LLM02"
    LLM03_DATA_POISONING = "LLM03"
    LLM04_MODEL_DENIAL = "LLM04"
    LLM05_SUPPLY_CHAIN = "LLM05"
    LLM06_DISCLOSURE = "LLM06"
    LLM07_CROSS_PLUGIN = "LLM07"
    LLM08_EXCESSIVE_AGENCY = "LLM08"
    LLM09_OVERRELIANCE = "LLM09"
    LLM10_TRAINING_DATA = "LLM10"

class DetectionResult(BaseModel):
    """Detection result for a single threat."""
    threat_id: OWASPThreat = Field(..., description="OWASP LLM threat ID")
    detected: bool = Field(..., description="Whether threat was detected")
    severity: ThreatSeverity = Field(..., description="Severity if detected")
    confidence: float = Field(..., ge=0, le=1, description="Confidence score 0-1")
    description: str = Field(..., description="Human-readable finding")
    evidence: Optional[str] = Field(None, description="Evidence of the threat")
    recommendation: Optional[str] = Field(None, description="Mitigation recommendation")

class ValidationRequest(BaseModel):
    """Request to validate LLM input/output."""
    input_text: str = Field(..., description="User input to validate")
    output_text: Optional[str] = Field(None, description="LLM output to validate")
    context: Optional[Dict[str, Any]] = Field(None, description="Additional context")
    detectors: Optional[List[OWASPThreat]] = Field(
        None, description="Specific detectors to run (None = run all)"
    )

class ValidationResponse(BaseModel):
    """Response from validation."""
    request_id: str = Field(..., description="Unique request ID")
    is_safe: bool = Field(..., description="Overall safety verdict")
    results: List[DetectionResult] = Field(..., description="Per-detector results")
    overall_severity: ThreatSeverity = Field(..., description="Highest severity found")
    blocks_execution: bool = Field(..., description="Should execution be blocked?")
    summary: str = Field(..., description="Human-readable summary")