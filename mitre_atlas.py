"""
MITRE ATLAS mapping for OWASP LLM Top 10 threats.

MITRE ATLAS (https://atlas.mitre.org/) catalogs real-world adversary tactics
and techniques against AI systems. This module links the OWASP threats this
engine detects to the specific ATLAS techniques an adversary would actually
use, so a detection can be traced to a concrete attacker technique instead of
just an internal severity label.

Scope: intentionally limited to the two threats requested for this pass -
LLM01 (Prompt Injection) and LLM09 (Misinformation / hallucination
exploitation). Every ID below is a real, currently-published ATLAS technique
(verified against the official ATLAS.yaml data set) - none of this is
invented.
"""

from typing import Dict, List, Optional, TypedDict


class AtlasTechnique(TypedDict):
    id: str
    name: str
    tactic_id: str
    tactic_name: str
    url: str
    relevance: str


ATLAS_MAPPING: Dict[str, List[AtlasTechnique]] = {
    "LLM01": [
        {
            "id": "AML.T0051",
            "name": "LLM Prompt Injection",
            "tactic_id": "AML.TA0005",
            "tactic_name": "Execution",
            "url": "https://atlas.mitre.org/techniques/AML.T0051",
            "relevance": (
                "The technique this detector exists to catch: an adversary crafts "
                "input that causes the LLM to ignore its original instructions and "
                "follow the attacker's instead."
            ),
        },
        {
            "id": "AML.T0051.000",
            "name": "Direct",
            "tactic_id": "AML.TA0005",
            "tactic_name": "Execution",
            "url": "https://atlas.mitre.org/techniques/AML.T0051.000",
            "relevance": (
                "Sub-technique for injections submitted directly by the user - the "
                "case this engine's LLM01 detector currently targets."
            ),
        },
        {
            "id": "AML.T0051.001",
            "name": "Indirect",
            "tactic_id": "AML.TA0005",
            "tactic_name": "Execution",
            "url": "https://atlas.mitre.org/techniques/AML.T0051.001",
            "relevance": (
                "Sub-technique for injections smuggled in through ingested data "
                "(documents, web pages, tool output). Not yet covered - the current "
                "detector only inspects direct user input, see Known Limitations."
            ),
        },
    ],
    "LLM09": [
        {
            "id": "AML.T0062",
            "name": "Discover LLM Hallucinations",
            "tactic_id": "AML.TA0008",
            "tactic_name": "Discovery",
            "url": "https://atlas.mitre.org/techniques/AML.T0062",
            "relevance": (
                "An adversary systematically probes a model to find hallucinated "
                "package names, URLs, or commands it invents with no real-world "
                "source. This is the reconnaissance step that misinformation/"
                "hallucination risk in an output makes possible in the first place."
            ),
        },
        {
            "id": "AML.T0060",
            "name": "Publish Hallucinated Entities",
            "tactic_id": "AML.TA0003",
            "tactic_name": "Resource Development",
            "url": "https://atlas.mitre.org/techniques/AML.T0060",
            "relevance": (
                "Once a hallucination is found (e.g. a fabricated package name), the "
                "adversary registers/publishes a real, malicious entity under that name "
                "so a user who trusts the LLM's output - the misinformation failure mode "
                "LLM09 flags - fetches attacker-controlled content instead. This is the "
                "real-world attack known as 'slopsquatting'."
            ),
        },
    ],
}


def get_atlas_mapping(threat_id: str) -> List[AtlasTechnique]:
    """Return the ATLAS techniques mapped to a given OWASP threat ID (e.g. 'LLM01')."""
    return ATLAS_MAPPING.get(threat_id.upper(), [])


def all_mapped_threats() -> List[str]:
    """Return the list of OWASP threat IDs that currently have an ATLAS mapping."""
    return list(ATLAS_MAPPING.keys())
