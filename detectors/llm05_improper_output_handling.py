import re
import json
from typing import Optional, Dict, Any
from detectors.base import BaseDetector
from schemas import OWASPThreat, ThreatSeverity, DetectionResult

class ImproperOutputHandlingDetector(BaseDetector):
    """
    Detects LLM05: Improper Output Handling.

    Validates that model outputs conform to expected schema,
    contain no unvalidated code, and don't expose sensitive information
    before being passed to downstream components (DB, shell, browser, etc.).
    """

    def __init__(self):
        super().__init__()
        self.threat_id = OWASPThreat.LLM05_IMPROPER_OUTPUT_HANDLING
        self.threat_name = "Improper Output Handling"

        # Patterns for dangerous output
        self.dangerous_patterns = [
            # SQL injection patterns
            r"(?i)(DROP|DELETE|INSERT|UPDATE|UNION|SELECT).*?(FROM|WHERE|TABLE)",
            r"(?i)(';|\" OR|-- |/\*)",

            # Code execution attempts
            r"(?i)(eval|exec|__import__|system|os\.)",
            r"(?i)(subprocess|popen|shell=True)",

            # Sensitive data
            r"(API[_-]?KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL)",
            r"(\d{3}-\d{2}-\d{4}|[0-9]{16})",  # SSN, credit card

            # Malicious URLs
            r"(?i)(javascript:|data:text/html|<iframe)",
        ]

    async def detect(
        self,
        input_text: str,
        output_text: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """
        Validate LLM output for schema compliance and safety.
        """
        if not output_text:
            return self._create_result(
                detected=False,
                severity=ThreatSeverity.INFO,
                confidence=0.0,
                description="No output to validate"
            )

        issues = []

        # Check 1: Dangerous patterns in output
        for pattern in self.dangerous_patterns:
            if re.search(pattern, output_text):
                issues.append(f"Dangerous pattern detected: {pattern[:30]}...")

        # Check 2: Output structure validation
        if context and "expected_schema" in context:
            schema_issue = self._validate_schema(output_text, context["expected_schema"])
            if schema_issue:
                issues.append(schema_issue)

        # Check 3: Length anomalies (truncation/continuation)
        if len(output_text) > 50000:
            issues.append("Output exceeds safe length (50KB+)")

        # Check 4: Unescaped HTML/JSON
        html_tags = len(re.findall(r"<[^>]+>", output_text))
        if html_tags > 5 and not self._is_valid_html(output_text):
            issues.append(f"Unvalidated HTML tags detected ({html_tags})")

        # Check 5: Invalid JSON if expected
        if context and context.get("expects_json"):
            json_issue = self._validate_json(output_text)
            if json_issue:
                issues.append(json_issue)

        detected = len(issues) > 0
        confidence = min(len(issues) * 0.25, 1.0)

        if not detected:
            severity = ThreatSeverity.INFO
            description = "Output passes schema validation"
        elif confidence >= 0.75:
            severity = ThreatSeverity.CRITICAL
            description = "Multiple critical output safety issues detected"
        elif confidence >= 0.5:
            severity = ThreatSeverity.HIGH
            description = "Output contains unsafe patterns or schema violations"
        else:
            severity = ThreatSeverity.MEDIUM
            description = "Output has potential safety concerns"

        evidence = None
        if issues:
            evidence = "; ".join(issues[:3])

        recommendation = (
            "Validate output schema before use, sanitize HTML/JSON, "
            "implement output filtering, use strict type checking"
        ) if detected else None

        return self._create_result(
            detected=detected,
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence,
            recommendation=recommendation
        )

    def _validate_schema(self, output: str, expected_schema: Dict[str, Any]) -> Optional[str]:
        """Validate output against expected schema."""
        try:
            data = json.loads(output)

            for key, expected_type in expected_schema.items():
                if key not in data:
                    return f"Missing required field: {key}"
                if not isinstance(data[key], expected_type):
                    return f"Type mismatch for {key}: expected {expected_type.__name__}"

            return None
        except json.JSONDecodeError:
            return "Output is not valid JSON"

    def _validate_json(self, output: str) -> Optional[str]:
        """Validate if output is valid JSON."""
        try:
            json.loads(output)
            return None
        except json.JSONDecodeError as e:
            return f"Invalid JSON: {str(e)[:50]}"

    def _is_valid_html(self, output: str) -> bool:
        """Check if HTML tags are properly formed."""
        open_tags = len(re.findall(r"<[a-zA-Z][^>]*>", output))
        close_tags = len(re.findall(r"</[a-zA-Z][^>]*>", output))
        return open_tags == close_tags
