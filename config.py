import os
from dotenv import load_dotenv
from typing import Literal

load_dotenv()

class Config:
    """Project configuration."""
    
    # API Keys
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
    
    # Detector Settings
    DETECTOR_MODE: Literal["strict", "balanced", "lenient"] = os.getenv(
        "DETECTOR_MODE", "balanced"
    )
    
    # Guardrails
    ENABLE_GUARDRAILS = os.getenv("ENABLE_GUARDRAILS", "true").lower() == "true"
    
    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    
    # Server
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", 8000))
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"

config = Config()