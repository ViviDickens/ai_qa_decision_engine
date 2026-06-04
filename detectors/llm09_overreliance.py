import re
from typing import Optional, Dict, Any
from detectors.base import BaseDetector
from schemas import OWASPThreat, ThreatSeverity, DetectionResult

class OverrelianceValidator(BaseDetector):
    """
    Detects LLM09: Overreliance on LLM Output.
    
    Identifies decisions made on incomplete context, hallucination risks,
    and situations where the LLM lacks sufficient information for reliable decisions.
    """
    
    def __init__(self):
        super().__init__()
        self.threat_id = OWASPThreat.LLM09_OVERRELIANCE
        self.threat_name = "Overreliance"
        
        # Patterns indicating incomplete context
        self.incomplete_context_patterns = [
            r"(?i)(i\s+don't\s+know|not\s+sure|unclear|uncertain|ambiguous)",
            r"(?i)(assume|guess|probably|likely|maybe|might be)",
            r"(?i)(unknown|missing|incomplete|partial|lack)",
            r"(?i)(can't\s+determine|can't\s+verify|unconfirmed)",
        ]
        
        # Patterns indicating risky decisions
        self.risky_decision_patterns = [
            r"(?i)(based\s+on|infer|deduce|extrapolate)\s+(only|just)\s+(this|that)",
            r"(?i)(without\s+checking|no\s+verification|no\s+confirmation)",
            r"(?i)(assume\s+.*?is\s+(true|correct|valid))",
        ]
    
    async def detect(
        self,
        input_text: str,
        output_text: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """
        Detect overreliance risks in LLM output.
        """
        # Primary: analyze OUTPUT for hallucination/confidence indicators
        analysis_text = output_text or input_text
        
        if not analysis_text:
            return self._create_result(
                detected=False,
                severity=ThreatSeverity.INFO,
                confidence=0.0,
                description="No output to analyze"
            )
        
        confidence = 0.0
        issues = []
        
        # Check 1: Incomplete context admission
        incomplete_matches = 0
        for pattern in self.incomplete_context_patterns:
            if re.search(pattern, analysis_text):
                incomplete_matches += 1
        
        if incomplete_matches > 0:
            confidence += incomplete_matches * 0.2
            issues.append(f"LLM admits uncertainty or incomplete knowledge ({incomplete_matches} indicators)")
        
        # Check 2: Risky decision making despite uncertainty
        risky_matches = 0
        for pattern in self.risky_decision_patterns:
            if re.search(pattern, analysis_text):
                risky_matches += 1
        
        if risky_matches > 0:
            confidence += risky_matches * 0.25
            issues.append(f"Making decisions despite limited context ({risky_matches} patterns)")
        
        # Check 3: Context completeness from provided context
        if context:
            required_fields = context.get("required_context", [])
            available_fields = context.get("available_context", [])
            
            missing = set(required_fields) - set(available_fields)
            if missing:
                confidence += len(missing) * 0.15
                issues.append(f"Missing critical context: {', '.join(missing)}")
        
        # Check 4: Confidence level analysis
        confidence_claims = re.findall(
            r"(?i)(highly|very|extremely|somewhat|slightly|not)?\s*(confident|certain|sure)",
            analysis_text
        )
        
        # If output claims low confidence but makes decisive statements
        low_confidence_claims = [c for c in confidence_claims if 'not' in str(c[0]).lower() or 'slightly' in str(c[0]).lower()]
        has_decisive_statements = bool(re.search(r"(?i)(definitely|certainly|must|will|always|never)", analysis_text))
        
        if low_confidence_claims and has_decisive_statements:
            confidence = min(confidence + 0.3, 1.0)
            issues.append("Claims low confidence but makes definitive statements (conflicting signals)")
        
        confidence = min(confidence, 1.0)
        detected = confidence > 0.5
        
        # Determine severity
        if not detected:
            severity = ThreatSeverity.INFO
            description = "Output shows appropriate confidence and context awareness"
        elif confidence >= 0.8:
            severity = ThreatSeverity.CRITICAL
            description = "Critical overreliance risk - decision should not proceed"
        elif confidence >= 0.6:
            severity = ThreatSeverity.HIGH
            description = "High risk of hallucination or unreliable output"
        else:
            severity = ThreatSeverity.MEDIUM
            description = "Moderate overreliance risk - manual review recommended"
        
        evidence = None
        if issues:
            evidence = "; ".join(issues)
        
        recommendation = (
            "Require human verification before execution, implement confidence thresholds, "
            "request explicit context validation, add fallback decision paths"
        ) if detected else None
        
        return self._create_result(
            detected=detected,
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
