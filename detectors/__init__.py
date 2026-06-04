from detectors.llm01_prompt_injection import PromptInjectionDetector
from detectors.llm02_insecure_output import InsecureOutputValidator
from detectors.llm03_data_poisoning import DataPoisoningDetector
from detectors.llm09_overreliance import OverrelianceValidator

# Registry of all available detectors
DETECTORS = {
    "LLM01": PromptInjectionDetector,
    "LLM02": InsecureOutputValidator,
    "LLM03": DataPoisoningDetector,
    "LLM09": OverrelianceValidator,
}

__all__ = [
    "DETECTORS",
    "PromptInjectionDetector",
    "InsecureOutputValidator",
    "DataPoisoningDetector",
    "OverrelianceValidator",
]