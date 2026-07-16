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
        
        # Tier A: direct label/result manipulation (most severe - explicit falsification)
        self.critical_patterns = [
            r"(?i)\b(mark|label|flag)\b.{0,15}\bas\b\s*['\"]?(pass|fail|passed|failed|critical|safe|invalid|valid|bypass)\b",
            r"(?i)[\"']?\b(label|tag|category|classification)\b[\"']?\s*(?:is|=|:|should be|marked as)\s*['\"]?\b(true|false|pass|fail|passed|failed|invalid|valid|bypass)\b",
            r"(?i)\b(actual|expected|correct)\b.{0,25}\b(result|output|label)\b.{0,25}(?:\bis\b|\bwas\b|\bshould be\b|=)",
            r"(?i)\b(ignore|override|replace)\b.{0,15}\b(previous|actual)\b.{0,15}\b(label|result)\b",
        ]

        # Tier B: supporting/corroborating signals of data corruption
        self.supporting_patterns = [
            r"(?i)\b(corrupt|poison|inject|manipulate)\b.{0,15}\b(data|label|signal|decision)\b",
            r"(?i)\b(force|make|ensure)\b.{0,15}\b(fail(?:s|ed)?|pass(?:es|ed)?|trigger(?:s|ed)?|block(?:s|ed)?)\b",
            r"(?i)\b(add|inject|insert)\b.{0,40}\b(training|test)\s+data\b",
            r"(?i)\b(modify|alter|change)\b.{0,15}\b(test|training)\b.{0,15}\b(case|data|set)\b",
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
        
        # Check for poisoning patterns - critical matches carry more weight
        # since they represent explicit instructions to falsify a result/label
        matches = []
        confidence = 0.0

        for pattern in self.critical_patterns:
            if re.search(pattern, input_text):
                matches.append(pattern)
                confidence += 0.65

        for pattern in self.supporting_patterns:
            if re.search(pattern, input_text):
                matches.append(pattern)
                confidence += 0.3

        # Check for data structure manipulation
        has_json_injection = bool(re.search(r'[{}":\[\],].*(?:label|class|tag)', input_text))
        has_sql_data = bool(re.search(r"(?i)(INSERT|UPDATE|VALUES|SET)", input_text))

        if has_json_injection:
            confidence += 0.25
        if has_sql_data:
            confidence += 0.35

        # Check for unusual character patterns (encoding attempts)
        unicode_escapes = len(re.findall(r"\\u[0-9a-f]{4}", input_text, re.IGNORECASE))
        if unicode_escapes > 2:
            confidence += 0.15

        confidence = min(confidence, 1.0)
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
