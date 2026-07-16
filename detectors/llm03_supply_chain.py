import re
from typing import Optional, Dict, Any
from detectors.base import BaseDetector
from schemas import OWASPThreat, ThreatSeverity, DetectionResult


class SupplyChainDetector(BaseDetector):
    """
    Detects LLM03: Supply Chain Vulnerabilities.

    Flags requests to install unverified/untrusted packages, pull code via
    curl-pipe-to-shell, disable signature/checksum verification, or load
    model weights/checkpoints from untrusted sources.
    """

    def __init__(self):
        super().__init__()
        self.threat_id = OWASPThreat.LLM03_SUPPLY_CHAIN
        self.threat_name = "Supply Chain Vulnerability"

        self.supply_chain_patterns = [
            r"(?i)\bpip\s+install\b.{0,30}https?://",
            r"(?i)\bcurl\b.{0,30}\|\s*(bash|sh)\b",
            r"(?i)\b(disable|skip|bypass|ignore)\b.{0,20}\b(ssl|checksum|signature|verification|certificate)\b",
            r"(?i)\b(unverified|untrusted|unsigned)\b.{0,20}\b(package|dependency|model|checkpoint|source|weights)\b",
            r"(?i)\b(download|load|import)\b.{0,20}\b(model|checkpoint|weights)\b.{0,20}\bfrom\b.{0,20}https?://",
        ]

    async def detect(
        self,
        input_text: str,
        output_text: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """
        Detect supply-chain risk indicators in input/output.
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

        matches = [p for p in self.supply_chain_patterns if re.search(p, analysis_text)]
        confidence = min(len(matches) * 0.4, 1.0)
        detected = len(matches) > 0

        if not detected:
            severity = ThreatSeverity.INFO
            description = "No supply-chain risk patterns detected"
        elif confidence >= 0.8:
            severity = ThreatSeverity.CRITICAL
            description = "High-confidence supply-chain compromise attempt detected"
        elif confidence >= 0.6:
            severity = ThreatSeverity.HIGH
            description = "Probable attempt to introduce an untrusted dependency"
        else:
            severity = ThreatSeverity.MEDIUM
            description = "Potential supply-chain risk - review recommended"

        evidence = (
            f"Matched {len(matches)} supply-chain risk pattern(s)" if matches else None
        )

        recommendation = (
            "Pin dependencies with verified hashes, use signed packages only, "
            "load models only from vetted registries, never pipe remote scripts to a shell"
        ) if detected else None

        return self._create_result(
            detected=detected,
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
