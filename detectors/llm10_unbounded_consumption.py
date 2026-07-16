import re
from collections import Counter
from typing import Optional, Dict, Any
from detectors.base import BaseDetector
from schemas import OWASPThreat, ThreatSeverity, DetectionResult


class UnboundedConsumptionDetector(BaseDetector):
    """
    Detects LLM10: Unbounded Consumption.

    Flags resource-exhaustion attempts: requests for unbounded/recursive
    generation, excessively long inputs, and repeated-token/character
    flooding that would drive uncontrolled compute/cost consumption.
    Repetition checks are done with plain string counting (not backtracking
    regex) so the detector itself can't be turned into a DoS vector.
    """

    MAX_SAFE_LENGTH = 4000
    CHAR_FLOOD_RATIO = 0.6
    WORD_FLOOD_MIN_REPEATS = 15

    def __init__(self):
        super().__init__()
        self.threat_id = OWASPThreat.LLM10_UNBOUNDED_CONSUMPTION
        self.threat_name = "Unbounded Consumption"

        # Requests for unbounded / recursive generation
        self.unbounded_patterns = [
            r"(?i)\b(repeat|generate|print|output)\b.{0,20}\b(forever|indefinitely|infinitely|without\s+(?:stopping|limit|end))\b",
            r"(?i)\b(infinite|unlimited|endless)\b.{0,15}\b(loop|list|recursion|generation|output)\b",
            r"(?i)\bnever\s+stop\b",
            r"(?i)\brecurse\b.{0,15}\b(indefinitely|forever|without\s+limit)\b",
            r"(?i)\ball\s+possible\s+(combinations|permutations)\b",
        ]

    def _has_char_flood(self, text: str) -> bool:
        """True if one character dominates most of a sufficiently long text."""
        if len(text) < 50:
            return False
        char, count = Counter(text).most_common(1)[0]
        return (count / len(text)) > self.CHAR_FLOOD_RATIO

    def _has_word_flood(self, text: str) -> bool:
        """True if any single word repeats an excessive number of times."""
        words = text.split()
        if len(words) < self.WORD_FLOOD_MIN_REPEATS:
            return False
        counts = Counter(w.lower() for w in words)
        return any(c >= self.WORD_FLOOD_MIN_REPEATS for c in counts.values())

    async def detect(
        self,
        input_text: str,
        output_text: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """
        Detect resource-exhaustion / unbounded-consumption attempts in input.
        """
        if not input_text:
            return self._create_result(
                detected=False,
                severity=ThreatSeverity.INFO,
                confidence=0.0,
                description="Empty input"
            )

        matches = [p for p in self.unbounded_patterns if re.search(p, input_text)]
        confidence = min(len(matches) * 0.4, 1.0)

        length_flag = len(input_text) > self.MAX_SAFE_LENGTH
        if length_flag:
            confidence = min(confidence + 0.4, 1.0)

        flood_flag = self._has_char_flood(input_text) or self._has_word_flood(input_text)
        if flood_flag:
            confidence = min(confidence + 0.5, 1.0)

        detected = len(matches) > 0 or length_flag or flood_flag

        if not detected:
            severity = ThreatSeverity.INFO
            description = "No resource-exhaustion patterns detected"
        elif confidence >= 0.8:
            severity = ThreatSeverity.CRITICAL
            description = "High-confidence unbounded consumption attempt detected"
        elif confidence >= 0.6:
            severity = ThreatSeverity.HIGH
            description = "Probable resource-exhaustion attempt"
        else:
            severity = ThreatSeverity.MEDIUM
            description = "Potential resource-exhaustion risk - review recommended"

        evidence_parts = []
        if matches:
            evidence_parts.append(f"Unbounded generation request matched ({len(matches)} pattern(s))")
        if length_flag:
            evidence_parts.append(f"Input length {len(input_text)} exceeds safe limit ({self.MAX_SAFE_LENGTH})")
        if flood_flag:
            evidence_parts.append("Repeated character/word flooding detected")
        evidence = "; ".join(evidence_parts) if evidence_parts else None

        recommendation = (
            "Enforce input length limits, rate-limit requests, reject recursive/"
            "unbounded generation instructions, add output token caps"
        ) if detected else None

        return self._create_result(
            detected=detected,
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
