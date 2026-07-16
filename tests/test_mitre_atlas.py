from mitre_atlas import get_atlas_mapping, all_mapped_threats


def test_llm01_maps_to_prompt_injection_technique():
    """LLM01 should map to the real ATLAS prompt injection technique."""
    mapping = get_atlas_mapping("LLM01")
    ids = [t["id"] for t in mapping]
    assert "AML.T0051" in ids


def test_llm09_maps_to_hallucination_techniques():
    """LLM09 should map to the real ATLAS hallucination-exploitation techniques."""
    mapping = get_atlas_mapping("LLM09")
    ids = [t["id"] for t in mapping]
    assert "AML.T0062" in ids
    assert "AML.T0060" in ids


def test_unmapped_threat_returns_empty_list():
    """A threat without a curated mapping should return an empty list, not an error."""
    mapping = get_atlas_mapping("LLM04")
    assert mapping == []


def test_case_insensitive_lookup():
    """Lookup should work regardless of ID casing."""
    assert get_atlas_mapping("llm01") == get_atlas_mapping("LLM01")


def test_all_mapped_threats_lists_only_curated_entries():
    """The mapped-threats list should currently contain exactly LLM01 and LLM09."""
    mapped = all_mapped_threats()
    assert set(mapped) == {"LLM01", "LLM09"}
