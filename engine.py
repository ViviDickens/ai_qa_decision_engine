import uuid
from typing import List, Optional, Dict, Any
from schemas import OWASPThreat, ThreatSeverity, DetectionResult, ValidationResponse
from detectors import DETECTORS
from config import config

class QASecurityEngine:
    """
    Main engine for validating LLM-based QA systems against OWASP LLM Top 10.
    Coordinates multiple threat detectors and produces consolidated reports.
    """
    
    def __init__(self):
        self.detectors = {}
        self._initialize_detectors()
    
    def _initialize_detectors(self):
        """Instantiate all available detectors."""
        for threat_id, detector_class in DETECTORS.items():
            self.detectors[threat_id] = detector_class()
    
    async def validate(
        self,
        input_text: str,
        output_text: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        detectors: Optional[List[OWASPThreat]] = None
    ) -> ValidationResponse:
        """
        Validate input/output against all (or selected) OWASP LLM threats.
        
        Args:
            input_text: User input to validate
            output_text: LLM output to validate (optional)
            context: Additional context for detection
            detectors: Specific detectors to run (None = run all)
            
        Returns:
            ValidationResponse with detailed findings
        """
        request_id = str(uuid.uuid4())
        results = []
        
        # Determine which detectors to run
        if detectors:
            detectors_to_run = {
                threat_id: self.detectors[threat_id.value]
                for threat_id in detectors
                if threat_id.value in self.detectors
            }
        else:
            detectors_to_run = self.detectors
        
        # Run all detectors
        for threat_id, detector in detectors_to_run.items():
            result = await detector.detect(
                input_text=input_text,
                output_text=output_text,
                context=context
            )
            results.append(result)
        
        # Aggregate results
        detected_threats = [r for r in results if r.detected]
        is_safe = len(detected_threats) == 0
        
        # Determine overall severity
        if is_safe:
            overall_severity = ThreatSeverity.INFO
        else:
            severity_order = {
                ThreatSeverity.CRITICAL: 5,
                ThreatSeverity.HIGH: 4,
                ThreatSeverity.MEDIUM: 3,
                ThreatSeverity.LOW: 2,
                ThreatSeverity.INFO: 1,
            }
            overall_severity = max(
                detected_threats,
                key=lambda r: severity_order[r.severity]
            ).severity
        
        # Decide if execution should be blocked
        blocks_execution = overall_severity in [
            ThreatSeverity.CRITICAL,
            ThreatSeverity.HIGH
        ]
        
        # Generate summary
        if is_safe:
            summary = "No threats detected. Input appears safe for processing."
        else:
            threat_count = len(detected_threats)
            summary = (
                f"⚠️ {threat_count} threat(s) detected (severity: {overall_severity}). "
                f"Execution {'BLOCKED' if blocks_execution else 'ALLOWED with caution'}."
            )
        
        return ValidationResponse(
            request_id=request_id,
            is_safe=is_safe,
            results=results,
            overall_severity=overall_severity,
            blocks_execution=blocks_execution,
            summary=summary
        )

# Singleton instance
qa_engine = QASecurityEngine()
