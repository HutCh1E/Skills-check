"""
API routes for the skills security check service.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, File, Form, UploadFile, HTTPException

from app.analyzers.static_analyzer import StaticAnalyzer
from app.analyzers.llm_analyzer import LLMAnalyzer
from app.analyzers.sandbox_analyzer import SandboxAnalyzer
from app.core.scoring import (
    calculate_risk_score,
    compute_stats,
    deduplicate_findings,
    generate_summary,
    get_risk_level,
)
from app.models.schemas import (
    Finding,
    HealthResponse,
    ScanRequest,
    ScanResult,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Security Scan"])

# Analyzer singletons (initialized lazily)
_static_analyzer: Optional[StaticAnalyzer] = None
_llm_analyzer: Optional[LLMAnalyzer] = None
_sandbox_analyzer: Optional[SandboxAnalyzer] = None

# In-memory result store (for simplicity; use a database in production)
_scan_results: dict[str, ScanResult] = {}


def _get_static_analyzer() -> StaticAnalyzer:
    global _static_analyzer
    if _static_analyzer is None:
        _static_analyzer = StaticAnalyzer()
    return _static_analyzer


def _get_llm_analyzer() -> LLMAnalyzer:
    global _llm_analyzer
    if _llm_analyzer is None:
        _llm_analyzer = LLMAnalyzer()
    return _llm_analyzer


def _get_sandbox_analyzer() -> SandboxAnalyzer:
    global _sandbox_analyzer
    if _sandbox_analyzer is None:
        _sandbox_analyzer = SandboxAnalyzer()
    return _sandbox_analyzer


@router.get("/health", response_model=HealthResponse, summary="Health check")
async def health_check():
    """Check API health and dependent service availability."""
    llm = _get_llm_analyzer()
    sandbox = _get_sandbox_analyzer()
    return HealthResponse(
        status="ok",
        docker_available=sandbox.is_available,
        llm_configured=llm.is_available,
    )


@router.post("/scan", response_model=ScanResult, summary="Submit code for security scan")
async def scan_code(request: ScanRequest):
    """
    Submit skill source code for security analysis.

    The service runs up to three layers of analysis:
    1. **Static Analysis** — AST-based pattern detection (always runs)
    2. **LLM Analysis** — Qwen 3.5 Plus deep semantic analysis (optional, enabled by default)
    3. **Sandbox Analysis** — Docker-based dynamic execution (optional, disabled by default)
    """
    all_findings: list[Finding] = []
    analyzers_used: list[str] = []

    # --- Layer 1: Static analysis (always runs) ---
    logger.info("Running static analysis...")
    static = _get_static_analyzer()
    static_findings = static.analyze(request.source_code)
    all_findings.extend(static_findings)
    analyzers_used.append("static")
    logger.info(f"Static analysis found {len(static_findings)} issue(s).")

    # --- Layer 2: LLM analysis (if enabled) ---
    if request.enable_llm:
        llm = _get_llm_analyzer()
        if llm.is_available:
            logger.info("Running LLM analysis...")
            llm_findings = llm.analyze(request.source_code, request.filename)
            all_findings.extend(llm_findings)
            analyzers_used.append("llm")
            logger.info(f"LLM analysis found {len(llm_findings)} issue(s).")
        else:
            logger.warning("LLM analysis requested but not configured (missing API key).")

    # --- Layer 3: Sandbox analysis (if enabled) ---
    if request.enable_sandbox:
        sandbox = _get_sandbox_analyzer()
        if sandbox.is_available:
            logger.info("Running sandbox analysis...")
            sandbox_findings = sandbox.analyze(request.source_code, request.filename)
            all_findings.extend(sandbox_findings)
            analyzers_used.append("sandbox")
            logger.info(f"Sandbox analysis found {len(sandbox_findings)} issue(s).")
        else:
            logger.warning("Sandbox analysis requested but Docker is not available.")

    # --- Scoring ---
    all_findings = deduplicate_findings(all_findings)
    risk_score = calculate_risk_score(all_findings)
    risk_level = get_risk_level(risk_score)
    summary = generate_summary(all_findings, risk_level, risk_score)
    lines_count = len(request.source_code.splitlines())
    stats = compute_stats(all_findings, lines_count, analyzers_used)

    result = ScanResult(
        risk_score=risk_score,
        risk_level=risk_level,
        summary=summary,
        findings=all_findings,
        stats=stats,
    )

    # Store result for later retrieval
    _scan_results[result.scan_id] = result

    return result


@router.post(
    "/scan/file",
    response_model=ScanResult,
    summary="Upload a file for security scan",
)
async def scan_file(
    file: UploadFile = File(..., description="Python source file to analyze"),
    enable_llm: bool = Form(default=True),
    enable_sandbox: bool = Form(default=False),
):
    """
    Upload a Python source file for security analysis.
    Accepts .py files up to 500KB.
    """
    if file.size and file.size > 500_000:
        raise HTTPException(status_code=413, detail="File too large (max 500KB)")

    content = await file.read()
    try:
        source_code = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded text")

    request = ScanRequest(
        source_code=source_code,
        filename=file.filename,
        enable_llm=enable_llm,
        enable_sandbox=enable_sandbox,
    )
    return await scan_code(request)


@router.get(
    "/scan/{scan_id}",
    response_model=ScanResult,
    summary="Get scan result by ID",
)
async def get_scan_result(scan_id: str):
    """Retrieve a previously completed scan result by its ID."""
    result = _scan_results.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan result not found: {scan_id}")
    return result
