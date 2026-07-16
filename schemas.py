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
    """
    OWASP Top 10 for LLM Applications (2025).

    Official list: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    """
    LLM01_PROMPT_INJECTION = "LLM01"
    LLM02_SENSITIVE_INFO_DISCLOSURE = "LLM02"
    LLM03_SUPPLY_CHAIN = "LLM03"
    LLM04_DATA_MODEL_POISONING = "LLM04"
    LLM05_IMPROPER_OUTPUT_HANDLING = "LLM05"
    LLM06_EXCESSIVE_AGENCY = "LLM06"
    LLM07_SYSTEM_PROMPT_LEAKAGE = "LLM07"
    LLM08_VECTOR_EMBEDDING_WEAKNESSES = "LLM08"
    LLM09_MISINFORMATION = "LLM09"
    LLM10_UNBOUNDED_CONSUMPTION = "LLM10"

# Human-readable names for the official 2025 list, keyed by the enum's string
# value (e.g. "LLM01"). Kept separate from the enum member names so API
# responses can surface the real category name without relying on Python
# identifier formatting.
THREAT_NAMES: Dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

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
