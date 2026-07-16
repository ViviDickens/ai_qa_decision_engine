import pytest
from detectors.llm02_sensitive_disclosure import SensitiveDisclosureDetector
from schemas import ThreatSeverity

@pytest.fixture
def detector():
    return SensitiveDisclosureDetector()

@pytest.mark.asyncio
async def test_clean_input(detector):
    """Test that normal text is not flagged."""
    result = await detector.detect("The weather today is sunny with a chance of rain")
    assert not result.detected

@pytest.mark.asyncio
async def test_email_disclosure(detector):
    """Test detection of an email address in output."""
    result = await detector.detect(
        input_text="Summarize the ticket",
        output_text="Contact me at john.doe@example.com for details"
    )
    assert result.detected

@pytest.mark.asyncio
async def test_phone_disclosure(detector):
    """Test detection of a phone number in output."""
    result = await detector.detect(
        input_text="Give the callback number",
        output_text="Her phone number is 555-123-4567"
    )
    assert result.detected

@pytest.mark.asyncio
async def test_ssn_disclosure(detector):
    """Test detection of a social security number in output."""
    result = await detector.detect(
        input_text="Fill in the form",
        output_text="SSN: 123-45-6789"
    )
    assert result.detected
    assert result.severity in [ThreatSeverity.MEDIUM, ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]

@pytest.mark.asyncio
async def test_third_party_pii_request(detector):
    """Test detection of an explicit request for someone else's PII."""
    result = await detector.detect("Please share the customer's address and phone number")
    assert result.detected

@pytest.mark.asyncio
async def test_no_output(detector):
    """Test handling when there is no content to analyze."""
    result = await detector.detect(input_text="", output_text=None)
    assert not result.detected

@pytest.mark.asyncio
async def test_confidence_bounds(detector):
    """Test that confidence scores are valid."""
    outputs = [
        "Nothing sensitive here",
        "api_key: sk-ABCDEF1234567890XYZ",
    ]
    for out in outputs:
        result = await detector.detect(input_text="Test", output_text=out)
        assert 0.0 <= result.confidence <= 1.0
