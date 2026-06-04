import re
from typing import Optional, Dict, Any, List
from detectors.base import BaseDetector
from schemas import OWASPThreat, ThreatSeverity, DetectionResult

class DataPoisoningDetector(BaseDetector):
    """
    Detects LLM03: Training Data Poisoning / Input Poisoning.
    
    Identifies attempts to corrupt QA decision signals, inject false labels,
    or manipulate training/inference data through malicious inputs.
    """
    
    def __init__(self):
        super().__init__()
        self.threat_id = OWASPThreat.LLM03_DATA_POISONING
        self.threat_name = "Data Poisoning"
        
        # Patterns for data poisoning attempts
        self.poisoning_patterns = [
            # Label manipulation
            r"(?i)(label|tag|category|classification)\s*(is|=|should be|marked as)\s*['\"]?(false|true|invalid|bypass)",
            r"(?i)(mark|label|flag)\s+(this|it)\s+as\s+(pass|fail|critical|safe)",
            
            # Data corruption signals
            r"(?i)(corrupt|poison|inject|manipulate)\s+(data|label|signal|decision)",
            r"(?i)(force|make|ensure)\s+(it\s+)?(fails|passes|triggers|blocks)",
            
            # Ground truth override
            r"(?i)(actual|expected|correct)\s+(result|output|label)\s+(is|should be|was)",
            r"(?i)(ignore|override|replace)\s+(previous|actual)\s+(label|result)",
            
            # Test data contamination
            r"(?i)(add|inject|insert)\s+(this|fake|malicious)\s+(into|to)\s+(test|training)\s+data",
            r"(?i)(modify|alter|change)\s+(test|training)\s+(case|data|set)",
        ]
    
    async def detect(
        self,
        input_text: str,
        output_text: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """
        Detect data poisoning attempts in input.
        """
        if not input_text:
            return self._create_result(
                detected=False,
                severity=ThreatSeverity.INFO,
                confidence=0.0,
                description="Empty input"
            )
        
        # Check for poisoning patterns
        matches = []
        for pattern in self.poisoning_patterns:
            if re.search(pattern, input_text):
                matches.append(pattern)
        
        # Analyze input characteristics
        confidence = min(len(matches) * 0.3, 1.0)
        
        # Check for data structure manipulation
        has_json_injection = bool(re.search(r'[{}":\[\],].*(?:label|class|tag)', input_text))
        has_sql_data = bool(re.search(r"(?i)(INSERT|UPDATE|VALUES|SET)", input_text))
        
        if has_json_injection or has_sql_data:
            confidence = min(confidence + 0.25, 1.0)
        
        # Check for unusual character patterns (encoding attempts)
        unicode_escapes = len(re.findall(r"\\u[0-9a-f]{4}", input_text, re.IGNORECASE))
        if unicode_escapes > 2:
            confidence = min(confidence + 0.15, 1.0)
        
        detected = len(matches) > 0 or confidence > 0.5
        
        # Determine severity
        if not detected:
            severity = ThreatSeverity.INFO
            description = "No data poisoning patterns detected"
        elif confidence >= 0.8:
            severity = ThreatSeverity.CRITICAL
            description = "High-confidence data poisoning attack detected"
        elif confidence >= 0.6:
            severity = ThreatSeverity.HIGH
            description = "Probable attempt to corrupt training or test data"
        else:
            severity = ThreatSeverity.MEDIUM
            description = "Potential data poisoning - review recommended"
        
        evidence = None
        if matches:
            evidence = f"Matched patterns: {', '.join([p[:40] for p in matches[:2]])}"
        
        recommendation = (
            "Validate input data schema, implement data sanitization, "
            "use content addressable storage for test data, monitor for unexpected labels"
        ) if detected else None
        
        return self._create_result(
            detected=detected,
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
