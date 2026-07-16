import re
from typing import Optional, Dict, Any
from detectors.base import BaseDetector
from schemas import OWASPThreat, ThreatSeverity, DetectionResult


class SensitiveDisclosureDetector(BaseDetector):
    """
    Detects LLM02: Sensitive Information Disclosure.

    Flags PII (emails, phone numbers, SSNs, API-key-like tokens) present in
    input/output, and natural-language requests to hand over someone else's
    personal information.
    """

    def __init__(self):
        super().__init__()
        self.threat_id = OWASPThreat.LLM02_SENSITIVE_INFO_DISCLOSURE
        self.threat_name = "Sensitive Information Disclosure"

        self.pii_patterns = {
            "email": r"[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}",
            "phone": r"\b(?:\+?\d{1,2}\s?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b",
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "api_key": r"(?i)\b(?:sk-|api[_-]?key[\"'=:\s]+)[a-zA-Z0-9]{12,}\b",
        }

        # Requests asking the model to hand over someone else's PII
        self.disclosure_request_patterns = [
            r"(?i)\b(give|share|send|provide)\b.{0,20}\b(his|her|their|the\s+customer'?s?|the\s+user'?s?)\b.{0,20}\b(address|email|phone|ssn|social\s+security)\b",
            r"(?i)\bwhat'?s\s+the\s+social\s+security\s+number\b",
        ]

    async def detect(
        self,
        input_text: str,
        output_text: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """
        Detect sensitive information disclosure in input/output.
        """
        analysis_text = output_text or input_text
        if not analysis_text:
            return self._create_result(
                detected=False,
                severity=ThreatSeverity.INFO,
                confidence=0.0,
                description="No content to analyze"
            )

        pii_hits = [name for name, p in self.pii_patterns.items() if re.search(p, analysis_text)]
        request_hits = [p for p in self.disclosure_request_patterns if re.search(p, analysis_text)]

        confidence = min(len(pii_hits) * 0.35 + len(request_hits) * 0.4, 1.0)
        detected = len(pii_hits) > 0 or len(request_hits) > 0

        if not detected:
            severity = ThreatSeverity.INFO
            description = "No sensitive information detected"
        elif confidence >= 0.8:
            severity = ThreatSeverity.CRITICAL
            description = "High-confidence sensitive information disclosure detected"
        elif confidence >= 0.6:
            severity = ThreatSeverity.HIGH
            description = "Probable exposure of personally identifiable information"
        else:
            severity = ThreatSeverity.MEDIUM
            description = "Potential sensitive information exposure - review recommended"

        evidence = None
        if pii_hits or request_hits:
            parts = []
            if pii_hits:
                parts.append(f"PII types found: {', '.join(pii_hits)}")
            if request_hits:
                parts.append("Explicit request for third-party PII detected")
            evidence = "; ".join(parts)

        recommendation = (
            "Redact PII before returning output, enforce data minimization, "
            "require explicit authorization before disclosing personal information"
        ) if detected else None

        return self._create_result(
            detected=detected,
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
