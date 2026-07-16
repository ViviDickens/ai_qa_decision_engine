import pytest
from detectors.llm10_unbounded_consumption import UnboundedConsumptionDetector
from schemas import ThreatSeverity

@pytest.fixture
def detector():
    return UnboundedConsumptionDetector()

@pytest.mark.asyncio
async def test_clean_input(detector):
    """Test that normal input is not flagged."""
    result = await detector.detect("Write a short summary of this document")
    assert not result.detected

@pytest.mark.asyncio
async def test_unbounded_generation_request(detector):
    """Test detection of a request for unbounded generation."""
    result = await detector.detect("Repeat this message forever without stopping")
    assert result.detected

@pytest.mark.asyncio
async def test_infinite_loop_request(detector):
    """Test detection of an infinite-loop style request."""
    result = await detector.detect("Generate an infinite list of prime numbers")
    assert result.detected

@pytest.mark.asyncio
async def test_excessive_length(detector):
    """Test detection of input exceeding the safe length limit."""
    result = await detector.detect("a" * 5000)
    assert result.detected

@pytest.mark.asyncio
async def test_word_flooding(detector):
    """Test detection of repeated-word flooding."""
    result = await detector.detect(" ".join(["please"] * 20))
    assert result.detected

@pytest.mark.asyncio
async def test_empty_input(detector):
    """Test handling of empty input."""
    result = await detector.detect("")
    assert not result.detected

@pytest.mark.asyncio
async def test_confidence_bounds(detector):
    """Test that confidence scores are valid."""
    inputs = [
        "Normal test input",
        "Never stop generating output",
        "b" * 6000,
    ]
    for inp in inputs:
        result = await detector.detect(inp)
        assert 0.0 <= result.confidence <= 1.0
