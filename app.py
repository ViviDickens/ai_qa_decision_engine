from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from schemas import ValidationRequest, ValidationResponse, THREAT_NAMES
from engine import qa_engine
from config import config
from mitre_atlas import get_atlas_mapping, all_mapped_threats
import logging

# Setup logging
logging.basicConfig(level=config.LOG_LEVEL)
logger = logging.getLogger(__name__)

# Create app
app = FastAPI(
    title="AI QA Decision Engine",
    description="Security framework for validating LLM-based QA systems against OWASP LLM Top 10",
    version="0.1.0",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    logger.info("🚀 AI QA Decision Engine starting...")
    logger.info(f"Mode: {config.DETECTOR_MODE}")
    logger.info(f"Guardrails: {'enabled' if config.ENABLE_GUARDRAILS else 'disabled'}")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("🛑 AI QA Decision Engine shutting down...")

@app.get("/health", tags=["health"])
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "0.1.0",
        "detectors_loaded": len(qa_engine.detectors)
    }

@app.post(
    "/validate",
    response_model=ValidationResponse,
    summary="Validate LLM input/output",
    tags=["validation"]
)
async def validate(request: ValidationRequest) -> ValidationResponse:
    """
    Validate user input and/or LLM output against OWASP LLM Top 10 threats.
    
    **Request body:**
    - `input_text`: User input to check (required)
    - `output_text`: LLM model output (optional)
    - `context`: Additional context dict (optional)
    - `detectors`: List of specific OWASP threat IDs to check (optional, checks all if not specified)
    
    **Response:**
    - `is_safe`: Overall safety verdict
    - `results`: Detailed findings per detector
    - `blocks_execution`: Whether execution should be blocked
    - `summary`: Human-readable summary
    """
    try:
        response = await qa_engine.validate(
            input_text=request.input_text,
            output_text=request.output_text,
            context=request.context,
            detectors=request.detectors
        )
        
        logger.info(
            f"Validation completed - "
            f"Request ID: {response.request_id}, "
            f"Safe: {response.is_safe}, "
            f"Severity: {response.overall_severity}"
        )
        
        return response
    except Exception as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/detectors", tags=["info"])
async def list_detectors():
    """List all available detectors, with their official OWASP Top 10 (2025) name."""
    codes = list(qa_engine.detectors.keys())
    return {
        "detectors": [
            {"code": code, "name": THREAT_NAMES.get(code, "Unknown")}
            for code in codes
        ],
        "count": len(codes)
    }

@app.get("/mitre-atlas", tags=["info"])
async def list_mitre_atlas_mappings():
    """List OWASP threats that currently have a MITRE ATLAS technique mapping."""
    return {
        "mapped_threats": all_mapped_threats(),
        "note": "Only threats with a verified, real ATLAS technique are listed here."
    }

@app.get("/mitre-atlas/{threat_id}", tags=["info"])
async def get_mitre_atlas_mapping(threat_id: str):
    """Get the MITRE ATLAS technique(s) mapped to a given OWASP threat ID (e.g. LLM01)."""
    mapping = get_atlas_mapping(threat_id)
    if not mapping:
        raise HTTPException(
            status_code=404,
            detail=f"No MITRE ATLAS mapping available for '{threat_id}'"
        )
    return {"threat_id": threat_id.upper(), "atlas_techniques": mapping}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host=config.HOST,
        port=config.PORT,
        reload=config.DEBUG
    )
