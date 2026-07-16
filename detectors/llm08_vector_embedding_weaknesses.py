import re
from typing import Optional, Dict, Any
from detectors.base import BaseDetector
from schemas import OWASPThreat, ThreatSeverity, DetectionResult


class VectorEmbeddingWeaknessDetector(BaseDetector):
    """
    Detects LLM08: Vector and Embedding Weaknesses.

    Flags risks specific to RAG/embedding pipelines: cross-tenant retrieval
    (reading another user's/customer's indexed documents), embedding
    inversion attempts (reconstructing source text from raw vectors),
    unvalidated inserts into a vector store, and bypassing
    tenant/namespace/metadata filters on a similarity search.
    """

    def __init__(self):
        super().__init__()
        self.threat_id = OWASPThreat.LLM08_VECTOR_EMBEDDING_WEAKNESSES
        self.threat_name = "Vector and Embedding Weaknesses"

        self.vector_patterns = [
            r"(?i)\b(show|retrieve|access|return)\b.{0,20}\b(documents|data|embeddings|vectors)\b.{0,20}\bfrom\b.{0,20}\b(other|another|all)\b.{0,20}\b(users?|tenants?|customers?|accounts?)\b",
            r"(?i)\b(reconstruct|invert|decode|recover)\b.{0,20}\b(the\s+)?(original\s+)?(text|data|document)\b.{0,20}\bfrom\b.{0,20}\b(this\s+)?embedding\b",
            r"(?i)\b(insert|add|inject)\b.{0,20}\b(vector|document|embedding)\b.{0,30}\binto\b.{0,20}\b(the\s+)?(index|vector\s+store|knowledge\s+base)\b.{0,20}\bwithout\b.{0,20}\b(validation|checking|review)\b",
            r"(?i)\b(bypass|ignore|skip)\b.{0,20}\b(the\s+)?(tenant|namespace|metadata)\b.{0,20}\bfilter\b",
            r"(?i)\bquery\b.{0,20}\bacross\b.{0,20}\ball\b.{0,20}\b(namespaces|tenants|indexes|indices)\b",
        ]

    async def detect(
        self,
        input_text: str,
        output_text: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """
        Detect RAG/vector-store abuse attempts in input.
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

        matches = [p for p in self.vector_patterns if re.search(p, analysis_text)]
        confidence = min(len(matches) * 0.45, 1.0)
        detected = len(matches) > 0

        if not detected:
            severity = ThreatSeverity.INFO
            description = "No vector/embedding abuse patterns detected"
        elif confidence >= 0.8:
            severity = ThreatSeverity.CRITICAL
            description = "High-confidence vector store / embedding abuse detected"
        elif confidence >= 0.6:
            severity = ThreatSeverity.HIGH
            description = "Probable attempt to bypass retrieval isolation or poison the index"
        else:
            severity = ThreatSeverity.MEDIUM
            description = "Potential vector/embedding risk - review recommended"

        evidence = (
            f"Matched {len(matches)} vector/embedding risk pattern(s)" if matches else None
        )

        recommendation = (
            "Enforce per-tenant/per-user access control on every retrieval, "
            "validate and sign documents before they're embedded and indexed, "
            "never expose raw embedding vectors to untrusted callers"
        ) if detected else None

        return self._create_result(
            detected=detected,
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )
