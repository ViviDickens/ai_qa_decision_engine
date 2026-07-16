from detectors.llm01_prompt_injection import PromptInjectionDetector
from detectors.llm02_sensitive_disclosure import SensitiveDisclosureDetector
from detectors.llm03_supply_chain import SupplyChainDetector
from detectors.llm04_data_poisoning import DataPoisoningDetector
from detectors.llm05_improper_output_handling import ImproperOutputHandlingDetector
from detectors.llm06_excessive_agency import ExcessiveAgencyDetector
from detectors.llm07_system_prompt_leakage import SystemPromptLeakageDetector
from detectors.llm08_vector_embedding_weaknesses import VectorEmbeddingWeaknessDetector
from detectors.llm09_misinformation import MisinformationDetector
from detectors.llm10_unbounded_consumption import UnboundedConsumptionDetector

# Registry of all available detectors - keys match the official OWASP Top 10
# for LLM Applications (2025) numbering. See schemas.THREAT_NAMES for the
# human-readable category name behind each code.
DETECTORS = {
    "LLM01": PromptInjectionDetector,
    "LLM02": SensitiveDisclosureDetector,
    "LLM03": SupplyChainDetector,
    "LLM04": DataPoisoningDetector,
    "LLM05": ImproperOutputHandlingDetector,
    "LLM06": ExcessiveAgencyDetector,
    "LLM07": SystemPromptLeakageDetector,
    "LLM08": VectorEmbeddingWeaknessDetector,
    "LLM09": MisinformationDetector,
    "LLM10": UnboundedConsumptionDetector,
}

__all__ = [
    "DETECTORS",
    "PromptInjectionDetector",
    "SensitiveDisclosureDetector",
    "SupplyChainDetector",
    "DataPoisoningDetector",
    "ImproperOutputHandlingDetector",
    "ExcessiveAgencyDetector",
    "SystemPromptLeakageDetector",
    "VectorEmbeddingWeaknessDetector",
    "MisinformationDetector",
    "UnboundedConsumptionDetector",
]
