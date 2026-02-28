"""
Pydantic models for API request/response schemas.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk level classification."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Severity(str, Enum):
    """Finding severity level."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(str, Enum):
    """Threat category classification."""
    REVERSE_SHELL = "reverse_shell"
    DATA_EXFILTRATION = "data_exfiltration"
    FILE_SYSTEM_ABUSE = "file_system_abuse"
    CODE_INJECTION = "code_injection"
    CRYPTO_MINING = "crypto_mining"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    NETWORK_ABUSE = "network_abuse"
    OBFUSCATION = "obfuscation"
    SUPPLY_CHAIN = "supply_chain"
    OTHER = "other"


class AnalyzerType(str, Enum):
    """Source of the finding."""
    STATIC = "static"
    LLM = "llm"
    SANDBOX = "sandbox"


class ScanRequest(BaseModel):
    """Request body to submit code for security scanning."""
    source_code: str = Field(
        ...,
        description="Source code content to analyze",
        min_length=1,
        max_length=500_000,
    )
    language: str = Field(
        default="python",
        description="Programming language of the source code"
    )
    filename: Optional[str] = Field(
        default=None,
        description="Original filename for context"
    )
    enable_sandbox: bool = Field(
        default=False,
        description="Whether to enable sandbox dynamic analysis (requires Docker)"
    )
    enable_llm: bool = Field(
        default=True,
        description="Whether to enable LLM deep analysis"
    )


class Finding(BaseModel):
    """Individual security finding."""
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    category: ThreatCategory
    severity: Severity
    analyzer: AnalyzerType
    title: str = Field(..., description="Short summary of the finding")
    description: str = Field(..., description="Detailed explanation")
    line_number: Optional[int] = Field(
        default=None,
        description="Line number in source code where the issue was found"
    )
    code_snippet: Optional[str] = Field(
        default=None,
        description="Relevant code snippet"
    )
    recommendation: Optional[str] = Field(
        default=None,
        description="Suggested fix or remediation"
    )


class ScanResult(BaseModel):
    """Complete scan result."""
    scan_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    status: str = Field(default="completed")
    created_at: datetime = Field(default_factory=datetime.now)
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Overall risk score (0=safe, 100=critical)"
    )
    risk_level: RiskLevel
    summary: str = Field(..., description="Human-readable summary of the analysis")
    findings: list[Finding] = Field(default_factory=list)
    stats: ScanStats = Field(default=None)
    package_info: Optional[PackageInfo] = Field(default=None)

    model_config = {"ser_json_timedelta": "iso8601"}


class ScanStats(BaseModel):
    """Scan statistics."""
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    lines_analyzed: int = 0
    analyzers_used: list[str] = Field(default_factory=list)


class PackageInfo(BaseModel):
    """Package metadata from registry."""
    name: str = ""
    version: str = ""
    source: str = ""
    metadata: dict = Field(default_factory=dict)
    files_count: int = 0
    total_size: int = 0


class PackageScanRequest(BaseModel):
    """Request body to scan a package via install command."""
    command: str = Field(
        ...,
        description="Install command, e.g. 'pip install requests' or 'npm install lodash'",
        min_length=1,
        max_length=500,
    )
    enable_llm: bool = Field(default=True, description="Enable LLM deep analysis")
    enable_sandbox: bool = Field(default=False, description="Enable sandbox dynamic analysis")


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "ok"
    version: str = "1.0.0"
    docker_available: bool = False
    llm_configured: bool = False
