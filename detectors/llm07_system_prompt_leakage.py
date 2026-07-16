import re
from typing import Optional, Dict, Any
from detectors.base import BaseDetector
from schemas import OWASPThreat, ThreatSeverity, DetectionResult


class SystemPromptLeakageDetector(BaseDetector):
    """
    Detects LLM07: System Prompt Leakage.

    Flags attempts to extract the system prompt / hidden instructions,
    including classic "print everything above this line" style jailbreaks.
    System prompts often carry sensitive operational details (internal
    rules, tool definitions, occasionally credentials), so getting the
    model to echo them back is treated as a real disclosure risk, not just
    a curiosity probe.
    """

    def __init__(self):
        super().__init__()
        self.threat_id = OWASPThreat.LLM07_SYSTEM_PROMPT_LEAKAGE
        self.threat_name = "System Prompt Leakage"

        self.leakage_patterns = [
            r"(?i)\bwhat\s+(?:is|are)\s+your\s+(?:system\s+prompt|instructions|initial\s+prompt|configuration)\b",
            r"(?i)\b(repeat|reveal|show|print|output)\b.{0,20}\byour\s+(?:instructions|system\s+prompt|initial\s+prompt|configuration)\b",
            r"(?i)\beverything\s+(?:above|before)\s+this\s+(?:line|point|message)\b",
            r"(?i)\bwhat\s+were\s+you\s+told\b.{0,20}\b(before|prior\s+to)\b",
            r"(?i)\bignore\b.{0,20}\b(the\s+above|previous)\b.{0,20}\b(and\s+)?(print|show|reveal)\b",
        ]

    async def detect(
        self,
        input_text: str,
        output_text: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """
        Detect system prompt extraction attempts in input.
        """
        if not input_text:
            return self._create_result(
                detected=False,
                severity=ThreatSeverity.INFO,
                confidence=0.0,
                description="Empty input"
            )

        matches = [p for p in self.leakage_patterns if re.search(p, input_text)]
        confidence = min(len(matches) * 0.45, 1.0)
        detected = len(matches) > 0

        if not detected:
            severity = ThreatSeverity.INFO
            description = "No system prompt extraction patterns detected"
        elif confidence >= 0.8:
            severity = ThreatSeverity.CRITICAL
            description = "High-confidence system prompt extraction attempt detected"
        elif confidence >= 0.6:
            severity = ThreatSeverity.HIGH
            description = "Probable attempt to extract the system prompt"
        else:
            severity = ThreatSeverity.MEDIUM
            description = "Potential system prompt leakage risk - review recommended"

        evidence = (
            f"Matched {len(matches)} system prompt extraction pattern(s)" if matches else None
        )

        recommendation = (
            "Never place credentials or authorization logic in the system "
            "prompt, instruct the model to refuse verbatim repetition of its "
            "instructions, and treat prompt-echo requests as a signal to log/alert"
        ) if detected else None

        return self._create_result(
            detected=detected,
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
