import re
from typing import Optional, Dict, Any
from detectors.base import BaseDetector
from schemas import OWASPThreat, ThreatSeverity, DetectionResult


class ExcessiveAgencyDetector(BaseDetector):
    """
    Detects LLM06: Excessive Agency.

    Flags requests for the model to take consequential real-world actions
    (send messages, move money, delete data, publish content) without human
    confirmation, and attempts to chain/invoke plugins or tools beyond their
    intended scope (unsanitized passthrough, sandbox/permission bypass) -
    both are the same underlying failure: the model (or its tools) acting
    with more autonomy than it should.
    """

    def __init__(self):
        super().__init__()
        self.threat_id = OWASPThreat.LLM06_EXCESSIVE_AGENCY
        self.threat_name = "Excessive Agency"

        # Unsupervised high-impact actions
        self.agency_patterns = [
            r"(?i)\b(send|email|transfer|pay|purchase|buy|delete|remove|execute|post|publish)\b.{0,20}\b(automatically|immediately|without\s+(?:asking|confirmation|approval|checking|review))\b",
            r"(?i)\bdo\s+(?:this|it|that)\b.{0,15}\bwithout\s+(?:asking|telling|confirming|checking)\b.{0,20}\b(me|anyone|user|human)\b",
            r"(?i)\btransfer\b.{0,20}\b(funds|money|payment)\b",
            r"(?i)\bact\s+on\s+my\s+behalf\b.{0,30}\bwithout\b",
            r"(?i)\bskip\s+(?:human|manual)\s+(?:review|approval|confirmation)\b",
        ]

        # Insecure plugin/tool chaining - unchecked agency via tools
        self.plugin_patterns = [
            r"(?i)\b(chain|combine|pipe)\b.{0,20}\b(plugin|tool|extension)s?\b",
            r"(?i)\b(call|invoke|use)\b.{0,20}\bplugin\b.{0,30}\bwithout\s+(?:validation|checking|sanitizing|permission)\b",
            r"(?i)\bpass\b.{0,20}\b(output|result|data)\b.{0,40}\bdirectly\b.{0,20}\b(to|into)\b.{0,20}\b(shell|system|exec|another\s+plugin)\b",
            r"(?i)\b(bypass|skip|ignore)\b.{0,20}\bplugin\b.{0,20}\b(permission|scope|sandbox|restriction)\b",
            r"(?i)\bexecute\b.{0,20}\barbitrary\b.{0,20}\b(command|code)\b.{0,20}\b(via|through|using)\b.{0,20}\bplugin\b",
        ]

    async def detect(
        self,
        input_text: str,
        output_text: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """
        Detect requests for unsupervised, high-agency actions or insecure
        plugin/tool chaining.
        """
        analysis_text = input_text or ""
        if output_text:
            analysis_text = f"{analysis_text} {output_text}"

        if not analysis_text.strip():
            return self._create_result(
                detected=False,
                severity=ThreatSeverity.INFO,
                confidence=0.0,
                description="Empty input"
            )

        agency_matches = [p for p in self.agency_patterns if re.search(p, analysis_text)]
        plugin_matches = [p for p in self.plugin_patterns if re.search(p, analysis_text)]
        matches = agency_matches + plugin_matches

        confidence = min(len(matches) * 0.4, 1.0)
        detected = len(matches) > 0

        if not detected:
            severity = ThreatSeverity.INFO
            description = "No excessive agency patterns detected"
        elif confidence >= 0.8:
            severity = ThreatSeverity.CRITICAL
            description = "High-confidence unsupervised high-impact action requested"
        elif confidence >= 0.6:
            severity = ThreatSeverity.HIGH
            description = "Probable request to bypass human oversight or plugin isolation"
        else:
            severity = ThreatSeverity.MEDIUM
            description = "Potential excessive agency risk - review recommended"

        evidence_parts = []
        if agency_matches:
            evidence_parts.append(f"Unsupervised high-impact action pattern(s): {len(agency_matches)}")
        if plugin_matches:
            evidence_parts.append(f"Insecure plugin/tool chaining pattern(s): {len(plugin_matches)}")
        evidence = "; ".join(evidence_parts) if evidence_parts else None

        recommendation = (
            "Require explicit human confirmation for irreversible or high-impact "
            "actions, scope down agent/plugin permissions to least privilege, "
            "validate and sanitize all data passed between tools, add an "
            "approval step before execution"
        ) if detected else None

        return self._create_result(
            detected=detected,
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
