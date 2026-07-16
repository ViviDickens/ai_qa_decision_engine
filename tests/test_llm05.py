import pytest
from detectors.llm05_improper_output_handling import ImproperOutputHandlingDetector
from schemas import ThreatSeverity

@pytest.fixture
def detector():
    return ImproperOutputHandlingDetector()

@pytest.mark.asyncio
async def test_clean_json_output(detector):
    """Test that a clean, valid JSON output is not flagged."""
    result = await detector.detect(
        input_text="Get status",
        output_text='{"status": "ok", "value": 42}'
    )
    assert not result.detected

@pytest.mark.asyncio
async def test_sql_injection_in_output(detector):
    """Test detection of SQL injection patterns in output."""
    result = await detector.detect(
        input_text="Run query",
        output_text="'; DROP TABLE users; --"
    )
    assert result.detected

@pytest.mark.asyncio
async def test_code_execution_attempt(detector):
    """Test detection of code execution patterns in output."""
    result = await detector.detect(
        input_text="Run command",
        output_text="os.system('rm -rf /')"
    )
    assert result.detected

@pytest.mark.asyncio
async def test_exposed_api_key(detector):
    """Test detection of an exposed API key in output."""
    result = await detector.detect(
        input_text="Show config",
        output_text="API_KEY=sk-1234567890abcdef"
    )
    assert result.detected

@pytest.mark.asyncio
async def test_credit_card_exposure(detector):
    """Test detection of a credit card number in output."""
    result = await detector.detect(
        input_text="Show payment details",
        output_text="Card number: 4111111111111111"
    )
    assert result.detected

@pytest.mark.asyncio
async def test_xss_in_output(detector):
    """Test detection of an XSS/malicious URL pattern in output."""
    result = await detector.detect(
        input_text="Render this",
        output_text="<iframe src='javascript:alert(1)'></iframe>"
    )
    assert result.detected

@pytest.mark.asyncio
async def test_invalid_json_when_expected(detector):
    """Test detection of malformed JSON when JSON output is expected."""
    result = await detector.detect(
        input_text="Return JSON",
        output_text="{not valid json",
        context={"expects_json": True}
    )
    assert result.detected

@pytest.mark.asyncio
async def test_schema_validation(detector):
    """Test detection of a schema mismatch (missing required field)."""
    result = await detector.detect(
        input_text="Return the record",
        output_text='{"status": "ok"}',
        context={"expected_schema": {"status": str, "code": int}}
    )
    assert result.detected

@pytest.mark.asyncio
async def test_no_output(detector):
    """Test handling when there is no output to validate."""
    result = await detector.detect(input_text="Some input", output_text=None)
    assert not result.detected
