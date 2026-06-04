import re
from typing import Optional, Dict, Any
from detectors.base import BaseDetector
from schemas import OWASPThreat, ThreatSeverity, DetectionResult

class PromptInjectionDetector(BaseDetector):
    """
    Detects LLM01: Prompt Injection attacks.
    
    Identifies instruction override attempts, context switching,
    and adversarial prompts designed to manipulate model behavior.
    """
    
    def __init__(self):
        super().__init__()
        self.threat_id = OWASPThreat.LLM01_PROMPT_INJECTION
        self.threat_name = "Prompt Injection"
        
        # Patterns for common injection techniques
        self.injection_patterns = [
            # Instruction overrides
            r"(?i)(ignore|forget|disregard)\s+(previous|prior|all)\s+(instructions|prompts|context)",
            r"(?i)(new\s+)?(instruction|system\s+prompt|directive):",
            r"(?i)override.*?(system|instruction|prompt|rule)",
            
            # Context switching
            r"(?i)(pretend|assume|imagine|you\s+are)\s+(now|that\s+you).*?:",
            r"(?i)(act\s+as|role\s+play|simulate)\s+[a-zA-Z0-9_]+",
            
            # Encoding/obfuscation attempts
            r"(?i)(base64|encoded|encrypted|hex|ROT13)",
            r"(?i)(decode|decrypt|unhash|deobfuscate)",
            
            # Meta-instruction attempts
            r"(?i)(print|show|display|output).*?(system\s+)?(prompt|instruction|rule)",
            r"(?i)(what|who|list|show).*?(is|are)\s+your.*?(instruction|prompt|rule)",
        ]
        
    async def detect(
        self,
        input_text: str,
        output_text: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """
        Detect prompt injection attempts in input.
        """
        if not input_text:
            return self._create_result(
                detected=False,
                severity=ThreatSeverity.INFO,
                confidence=0.0,
                description="Empty input - no injection detected"
            )
        
        # Check for injection patterns
        matches = []
        for pattern in self.injection_patterns:
            if re.search(pattern, input_text):
                matches.append(pattern)
        
        # Calculate detection metrics
        detected = len(matches) > 0
        confidence = min(len(matches) * 0.25, 1.0)  # Each match = 0.25 confidence
        
        # Analyze text characteristics
        suspicious_chars = len(re.findall(r"[<>{}[\]|&;`\$]", input_text))
        unusual_length = len(input_text) > 2000  # Abnormally long prompts
        
        if suspicious_chars > 5 or unusual_length:
            confidence = min(confidence + 0.2, 1.0)
        
        # Determine severity
        if not detected:
            severity = ThreatSeverity.INFO
            description = "No prompt injection patterns detected"
        elif confidence >= 0.8:
            severity = ThreatSeverity.CRITICAL
            description = "High-confidence prompt injection attack detected"
        elif confidence >= 0.6:
            severity = ThreatSeverity.HIGH
            description = "Probable prompt injection attempt"
        else:
            severity = ThreatSeverity.MEDIUM
            description = "Potential prompt injection - manual review recommended"
        
        # Extract evidence
        evidence = None
        if matches:
            evidence = f"Matched patterns: {', '.join(matches[:3])}"
        
        recommendation = (
            "Implement input validation, use prompt templates, "
            "employ guardrails, and monitor for anomalous queries"
        ) if detected else None
        
        return self._create_result(
            detected=detected,
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )