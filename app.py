from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from schemas import ValidationRequest, ValidationResponse
from engine import qa_engine
from config import config
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
    """List all available detectors."""
    return {
        "detectors": list(qa_engine.detectors.keys()),
        "count": len(qa_engine.detectors)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host=config.HOST,
        port=config.PORT,
        reload=config.DEBUG
    )
