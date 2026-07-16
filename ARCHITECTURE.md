# Architecture & Technical Notes

## Design Principles

1. **Modular** - Each detector is independent, can be added/removed/modified without affecting others
2. **Testable** - Every component has comprehensive test coverage with adversarial payloads
3. **Observable** - Logging, request IDs, detailed results for debugging and audit trails
4. **Extensible** - BaseDetector abstract class allows new threat types to be added easily
5. **Production-Ready** - Proper error handling, configuration management, async support

## Core Components

### 1. Detectors (`detectors/`)

Each detector inherits from `BaseDetector` and implements threat detection for one category of the
[OWASP Top 10 for LLM Applications (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/).
All ten categories are implemented:

| Code | Category | File |
|------|----------|------|
| LLM01 | Prompt Injection | `llm01_prompt_injection.py` |
| LLM02 | Sensitive Information Disclosure | `llm02_sensitive_disclosure.py` |
| LLM03 | Supply Chain | `llm03_supply_chain.py` |
| LLM04 | Data and Model Poisoning | `llm04_data_poisoning.py` |
| LLM05 | Improper Output Handling | `llm05_improper_output_handling.py` |
| LLM06 | Excessive Agency | `llm06_excessive_agency.py` |
| LLM07 | System Prompt Leakage | `llm07_system_prompt_leakage.py` |
| LLM08 | Vector and Embedding Weaknesses | `llm08_vector_embedding_weaknesses.py` |
| LLM09 | Misinformation | `llm09_misinformation.py` |
| LLM10 | Unbounded Consumption | `llm10_unbounded_consumption.py` |

**Structure:**
```python
class XxxDetector(BaseDetector):
    async def detect(input_text, output_text, context) -> DetectionResult
```

**Key Considerations:**
- Async-first design for I/O operations (future: API calls for advanced analysis)
- Confidence scoring 0-1 (not binary)
- Evidence extraction for transparency
- Recommendations for mitigation
- Repetition/flooding checks (LLM10) use plain string counting, not backtracking
  regex, so the detector itself can't become a resource-exhaustion vector

### 2. Engine (`engine.py`)

The `QASecurityEngine` coordinates all detectors and aggregates results.

**Responsibilities:**
- Instantiate all available detectors
- Run selected/all detectors in parallel (future: concurrent execution)
- Aggregate severity levels (CRITICAL > HIGH > MEDIUM > LOW > INFO)
- Determine if execution should be blocked
- Generate human-readable summaries

**Decision Logic:**
```
Critical/High Threats → blocks_execution = true
Medium/Low/Info → blocks_execution = false (log/alert only)
```

### 3. API (`app.py`)

FastAPI application providing REST endpoints.

**Endpoints:**
- `POST /validate` - Main validation endpoint
- `GET /health` - Health check
- `GET /detectors` - List available detectors with their official OWASP name
- `GET /mitre-atlas` - List threats with a verified MITRE ATLAS mapping
- `GET /mitre-atlas/{threat_id}` - Get the ATLAS technique(s) for a threat

**Future Endpoints:**
- `POST /validate-batch` - Batch validation
- `GET /results/{request_id}` - Retrieve previous result by request ID
- `POST /explain/{threat_id}` - Get detailed threat explanation
- `GET /stats` - Detection statistics dashboard

### 4. Schemas (`schemas.py`)

Pydantic models for request/response validation and type safety.

**Key Enums / Maps:**
- `OWASPThreat` - Threat IDs (LLM01-LLM10), enum member names match the real 2025 category names
- `THREAT_NAMES` - `Dict[str, str]` mapping e.g. `"LLM01"` → `"Prompt Injection"`, used by the API so responses show the human-readable name, not just the code
- `ThreatSeverity` - Severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)

### 5. MITRE ATLAS mapping (`mitre_atlas.py`)

A small, deliberately narrow module linking detector output to real-world adversary technique IDs
from [MITRE ATLAS](https://atlas.mitre.org/). Every ID in it was verified against the official
`ATLAS.yaml` data set - none of it is invented. Currently covers:

- **LLM01 Prompt Injection** → `AML.T0051` (Execution), with sub-techniques `AML.T0051.000` Direct
  (covered by the current detector) and `AML.T0051.001` Indirect (not yet covered - the detector
  only inspects direct user input)
- **LLM09 Misinformation** → `AML.T0062` Discover LLM Hallucinations (Discovery) and `AML.T0060`
  Publish Hallucinated Entities (Resource Development) - together these describe "slopsquatting":
  an adversary finds a hallucinated package name, then publishes a real malicious package under
  that name for a user who trusts the LLM's (unreliable) output to fetch

### 6. Configuration (`config.py`)

Centralized configuration from environment variables.

**Modes:**
- `strict` - Low tolerance, more false positives
- `balanced` - Default, good balance
- `lenient` - High tolerance, may miss threats

## Data Flow

```
HTTP Request
    ↓
FastAPI validates ValidationRequest
    ↓
QASecurityEngine.validate()
    ├→ Detector.detect() [async]  (LLM01 ... LLM10)
    ↓
Aggregate Results
    ├→ Calculate overall severity
    ├→ Determine blocks_execution
    └→ Generate summary
    ↓
Return ValidationResponse (JSON)
```

## Testing Strategy

### Unit Tests (`tests/`)

One test file per detector (`test_llm01.py` ... `test_llm10.py`), plus `test_mitre_atlas.py`:

- **Positive Tests** - Clean inputs should pass
- **Negative Tests** - Malicious payloads should be detected
- **Edge Cases** - Empty strings, very long inputs, special characters
- **Confidence Scoring** - Verify scores are between 0-1

86 tests total, all passing (`pytest tests/ -v`).

### Coverage Goals

- 80%+ line coverage (enforced in CI)
- 100% coverage of detection paths
- Adversarial scenarios from OWASP/MITRE ATLAS documented

## Performance Considerations

### Current (Sequential)

Each detector runs sequentially:
```
Request → Detector1 (10ms) → Detector2 (10ms) → ... → Response
```

### Future (Concurrent)

Use `asyncio.gather()` for parallel execution across all ten detectors to cut total validation time.

### Scaling Strategies

1. **Caching** - Cache detector results for identical inputs
2. **Rate Limiting** - Protect against abuse
3. **Async I/O** - Detectors can call external APIs (e.g., LLM for semantic analysis)
4. **Database** - Store validation history for audit trails

## Security Considerations

### Input Validation

- Pydantic schemas enforce type safety
- Maximum input length limits (prevent DoS - see LLM10)
- No eval() or similar dangerous operations
- Repetition checks use `collections.Counter`, not backtracking regex, so the
  LLM10 detector can't itself be exploited for a ReDoS-style attack

### Output Safety

- Detectors cannot execute code
- Results are descriptive (no leakage of internals)
- Request IDs for tracking (no PII)

## Roadmap & Priorities

### Done
- [x] All ten OWASP LLM Top 10 (2025) detectors, correctly named and numbered
- [x] API endpoints (`/validate`, `/health`, `/detectors`, `/mitre-atlas`)
- [x] 86-test adversarial suite, one file per detector
- [x] MITRE ATLAS mapping for LLM01 and LLM09 (verified, real technique IDs)
- [x] README & setup

### Next
- [ ] MITRE ATLAS mapping for the remaining eight categories
- [ ] Indirect prompt injection detection (`AML.T0051.001`) - currently only direct input is inspected
- [ ] Batch validation endpoint
- [ ] Dashboard/analytics

### Later
- [ ] Database for audit trails
- [ ] Multi-model detection (Claude, GPT, Gemini)
- [ ] Interactive OWASP → MITRE ATLAS visualization
- [ ] Concurrent detector execution (`asyncio.gather`)

## Dependencies

### Core
- `fastapi` - Web framework
- `pydantic` - Data validation
- `uvicorn` - ASGI server

### AI/ML
- `openai` - GPT access (future advanced analysis)
- `anthropic` - Claude access (future advanced analysis)

### Testing
- `pytest` - Test framework
- `pytest-asyncio` - Async test support

### Utilities
- `python-dotenv` - Environment variable loading

## Known Limitations

1. **Pattern-based detection only** - all detectors use regex/heuristics, no semantic/ML analysis yet
2. **English-focused patterns** - injection/leakage patterns are optimized for English
3. **No real-time threat updates** - patterns are static
4. **LLM01 covers direct injection only** - indirect injection (malicious content smuggled in via
   retrieved documents/tool output, `AML.T0051.001`) is not yet detected
5. **MITRE ATLAS mapping is partial** - only LLM01 and LLM09 are mapped so far; extending to the
   rest is next on the roadmap

## Future Enhancement Ideas

1. **Semantic Analysis** - Use LLMs to analyze prompts for intent
2. **Behavioral Analysis** - Track user patterns over time
3. **Multi-Model Support** - Different models have different vulnerabilities
4. **Custom Rules** - Allow organizations to add domain-specific rules
5. **Telemetry** - Anonymous threat statistics
6. **Visualization** - Interactive dashboard of detected threats
7. **Integration SDK** - SDKs for Python, JavaScript, Go

## References

- [OWASP Top 10 for LLM Applications (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS Framework](https://atlas.mitre.org/)
- [Prompt Injection Taxonomy](https://simonwillison.net/2023/Oct/27/prompt-injection/)

---

**Last Updated:** July 2026
**Owner:** Viviana Pérez (ViviDickens)
