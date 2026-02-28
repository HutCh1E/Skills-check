"""
Risk scoring algorithm.

Combines findings from all analyzers, deduplicates, calculates
an overall risk score (0-100), and maps it to a risk level.
"""

from __future__ import annotations

from app.models.schemas import (
    Finding,
    RiskLevel,
    Severity,
    ScanStats,
)

# Points per finding severity
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 1,
}

# Risk level thresholds
RISK_THRESHOLDS = [
    (0, 10, RiskLevel.SAFE),
    (11, 30, RiskLevel.LOW),
    (31, 60, RiskLevel.MEDIUM),
    (61, 85, RiskLevel.HIGH),
    (86, 100, RiskLevel.CRITICAL),
]


def calculate_risk_score(findings: list[Finding]) -> int:
    """
    Calculate an overall risk score (0-100) based on findings.
    Uses a weighted sum capped at 100.
    """
    if not findings:
        return 0

    total = 0
    for f in findings:
        total += SEVERITY_WEIGHTS.get(f.severity, 1)

    return min(total, 100)


def get_risk_level(score: int) -> RiskLevel:
    """Map a numeric risk score to a risk level enum."""
    for low, high, level in RISK_THRESHOLDS:
        if low <= score <= high:
            return level
    return RiskLevel.CRITICAL


def generate_summary(findings: list[Finding], risk_level: RiskLevel, risk_score: int) -> str:
    """Generate a human-readable summary of the scan results."""
    if not findings:
        return "✅ No security issues detected. The code appears safe."

    # Count by severity
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parts = []
    if risk_level == RiskLevel.CRITICAL:
        parts.append("🚨 **CRITICAL RISK** — Severe security threats detected!")
    elif risk_level == RiskLevel.HIGH:
        parts.append("⚠️ **HIGH RISK** — Significant security issues found.")
    elif risk_level == RiskLevel.MEDIUM:
        parts.append("⚡ **MEDIUM RISK** — Potential security concerns identified.")
    elif risk_level == RiskLevel.LOW:
        parts.append("ℹ️ **LOW RISK** — Minor issues found, generally safe.")
    else:
        parts.append("✅ **SAFE** — No significant security issues.")

    detail_parts = []
    if counts.get(Severity.CRITICAL, 0):
        detail_parts.append(f"{counts[Severity.CRITICAL]} critical")
    if counts.get(Severity.HIGH, 0):
        detail_parts.append(f"{counts[Severity.HIGH]} high")
    if counts.get(Severity.MEDIUM, 0):
        detail_parts.append(f"{counts[Severity.MEDIUM]} medium")
    if counts.get(Severity.LOW, 0):
        detail_parts.append(f"{counts[Severity.LOW]} low")
    if counts.get(Severity.INFO, 0):
        detail_parts.append(f"{counts[Severity.INFO]} info")

    parts.append(f"Found {len(findings)} issue(s): {', '.join(detail_parts)}.")
    parts.append(f"Risk score: {risk_score}/100.")

    return " ".join(parts)


def compute_stats(findings: list[Finding], lines_count: int, analyzers_used: list[str]) -> ScanStats:
    """Compute scan statistics from findings."""
    return ScanStats(
        total_findings=len(findings),
        critical_count=sum(1 for f in findings if f.severity == Severity.CRITICAL),
        high_count=sum(1 for f in findings if f.severity == Severity.HIGH),
        medium_count=sum(1 for f in findings if f.severity == Severity.MEDIUM),
        low_count=sum(1 for f in findings if f.severity == Severity.LOW),
        info_count=sum(1 for f in findings if f.severity == Severity.INFO),
        lines_analyzed=lines_count,
        analyzers_used=analyzers_used,
    )


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Remove duplicate findings based on category + line_number + title similarity.
    Keeps the finding with the higher severity.
    """
    seen: dict[str, Finding] = {}

    for f in findings:
        key = f"{f.category}:{f.line_number}:{f.title[:50]}"
        if key in seen:
            existing = seen[key]
            existing_weight = SEVERITY_WEIGHTS.get(existing.severity, 0)
            new_weight = SEVERITY_WEIGHTS.get(f.severity, 0)
            if new_weight > existing_weight:
                seen[key] = f
        else:
            seen[key] = f

    return list(seen.values())
