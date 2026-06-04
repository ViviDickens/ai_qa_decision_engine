import pytest
from detectors.llm02_insecure_output import InsecureOutputValidator
from schemas import ThreatSeverity

@pytest.fixture
def validator():
    return InsecureOutputValidator()

@pytest.mark.asyncio
async def test_clean_json_output(validator):
    """Test that clean JSON output passes validation."""
    clean_output = '{"status": "pass", "severity": "low", "message": "Test passed"}'
    result = await validator.detect(
        input_text="Run test",
        output_text=clean_output
    )
    assert not result.detected or result.severity != ThreatSeverity.CRITICAL

@pytest.mark.asyncio
async def test_sql_injection_in_output(validator):
    """Test detection of SQL injection in output."""
    malicious_output = "SELECT * FROM users; DROP TABLE users; --"
    result = await validator.detect(
        input_text="Query",
        output_text=malicious_output
    )
    assert result.detected
    assert result.severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]

@pytest.mark.asyncio
async def test_code_execution_attempt(validator):
    """Test detection of code execution attempts."""
    malicious_output = "os.system('rm -rf /')"
    result = await validator.detect(
        input_text="Run command",
        output_text=malicious_output
    )
    assert result.detected

@pytest.mark.asyncio
async def test_exposed_api_key(validator):
    """Test detection of exposed sensitive data."""
    malicious_output = 'API_KEY="sk-1234567890abcdef"'
    result = await validator.detect(
        input_text="Connect",
        output_text=malicious_output
    )
    assert result.detected
    assert result.severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]

@pytest.mark.asyncio
async def test_credit_card_exposure(validator):
    """Test detection of credit card numbers."""
    malicious_output = "Card: 4532015112830366"
    result = await validator.detect(
        input_text="Payment",
        output_text=malicious_output
    )
    assert result.detected

@pytest.mark.asyncio
async def test_xss_in_output(validator):
    """Test detection of XSS attempts."""
    malicious_output = '<iframe src="javascript:alert(\'xss\')">'
    result = await validator.detect(
        input_text="Render",
        output_text=malicious_output
    )
    assert result.detected

@pytest.mark.asyncio
async def test_invalid_json_when_expected(validator):
    """Test detection of invalid JSON when JSON is expected."""
    invalid_json = '{"key": "value", incomplete}'
    result = await validator.detect(
        input_text="Parse JSON",
        output_text=invalid_json,
        context={"expects_json": True}
    )
    assert result.detected

@pytest.mark.asyncio
async def test_schema_validation(validator):
    """Test schema validation against expected structure."""
    output = '{"name": "Test", "severity": "high"}'
    result = await validator.detect(
        input_text="Validate",
        output_text=output,
        context={
            "expected_schema": {
                "name": str,
                "severity": str,
                "passed": bool
            }
        }
    )
    assert result.detected

@pytest.mark.asyncio
async def test_no_output(validator):
    """Test handling when no output is provided."""
    result = await validator.detect(
        input_text="Some input",
        output_text=None
    )
    assert not result.detected
