from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from schemas import OWASPThreat, ThreatSeverity, DetectionResult

class BaseDetector(ABC):
    """Abstract base class for OWASP LLM threat detectors."""
    
    def __init__(self):
        self.threat_id: OWASPThreat = None
        self.threat_name: str = None
        
    @abstractmethod
    async def detect(
        self,
        input_text: str,
        output_text: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """
        Detect if a specific threat is present.
        
        Args:
            input_text: User input to check
            output_text: LLM output to check (if applicable)
            context: Additional context for detection
            
        Returns:
            DetectionResult with findings
        """
        pass
    
    def _create_result(
        self,
        detected: bool,
        severity: ThreatSeverity,
        confidence: float,
        description: str,
        evidence: Optional[str] = None,
        recommendation: Optional[str] = None
    ) -> DetectionResult:
        """Helper to create a DetectionResult."""
        return DetectionResult(
            threat_id=self.threat_id,
            detected=detected,
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )