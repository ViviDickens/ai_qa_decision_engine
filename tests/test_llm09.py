import pytest
from detectors.llm09_overreliance import OverrelianceValidator
from schemas import ThreatSeverity

@pytest.fixture
def validator():
    return OverrelianceValidator()

@pytest.mark.asyncio
async def test_confident_complete_context(validator):
    """Test output with confident claims and complete context."""
    output = "Based on all provided requirements and test data, this test will definitely pass."
    result = await validator.detect(
        input_text="Validate test",
        output_text=output
    )
    assert not result.detected or result.confidence < 0.5

@pytest.mark.asyncio
async def test_uncertainty_admission(validator):
    """Test detection of uncertainty admission."""
    output = "I'm not sure about this, but the test is likely to pass"
    result = await validator.detect(
        input_text="Predict",
        output_text=output
    )
    assert result.detected or result.confidence > 0.3

@pytest.mark.asyncio
async def test_incomplete_context_risk(validator):
    """Test detection of decisions made with incomplete context."""
    output = "I don't have all the requirements, but this should work fine."
    result = await validator.detect(
        input_text="Implement",
        output_text=output
    )
    assert result.detected
    assert result.confidence > 0.5

@pytest.mark.asyncio
async def test_hallucination_risk(validator):
    """Test detection of hallucination risk indicators."""
    output = "Based on what I assume is correct, this will definitely pass the security check"
    result = await validator.detect(
        input_text="Security review",
        output_text=output
    )
    assert result.detected or result.confidence > 0.4

@pytest.mark.asyncio
async def test_missing_context_detection(validator):
    """Test detection when critical context is missing."""
    output = "The test result should be this value"
    result = await validator.detect(
        input_text="Evaluate",
        output_text=output,
        context={
            "required_context": ["test_specs", "acceptance_criteria", "test_data"],
            "available_context": ["test_data"]
        }
    )
    assert result.detected
    assert result.severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]

@pytest.mark.asyncio
async def test_conflicting_confidence_signals(validator):
    """Test detection of conflicting confidence signals."""
    output = "I'm not very confident, but this definitely will pass and will never fail"
    result = await validator.detect(
        input_text="Predict",
        output_text=output
    )
    assert result.detected
    assert result.confidence > 0.5

@pytest.mark.asyncio
async def test_assumption_without_verification(validator):
    """Test detection of assumptions without verification."""
    output = "Assuming the input is valid, this must work correctly"
    result = await validator.detect(
        input_text="Validate",
        output_text=output
    )
    assert result.detected

@pytest.mark.asyncio
async def test_extrapolation_risk(validator):
    """Test detection of risky extrapolation."""
    output = "Based only on this one example, all similar cases will behave the same way"
    result = await validator.detect(
        input_text="Generalize",
        output_text=output
    )
    assert result.detected or result.confidence > 0.4

@pytest.mark.asyncio
async def test_no_output(validator):
    """Test handling when no output is provided."""
    result = await validator.detect(
        input_text="Some input",
        output_text=None
    )
    assert not result.detected

@pytest.mark.asyncio
async def test_confidence_bounds(validator):
    """Test that confidence scores are valid."""
    outputs = [
        "This will definitely work based on complete analysis",
        "I'm uncertain about the outcome",
        "Missing critical information but assuming it will pass",
    ]
    
    for out in outputs:
        result = await validator.detect(
            input_text="Test",
            output_text=out
        )
        assert 0.0 <= result.confidence <= 1.0
