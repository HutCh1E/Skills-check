"""
Tests for the scoring module.
"""

import pytest
from app.core.scoring import (
    calculate_risk_score,
    get_risk_level,
    generate_summary,
    deduplicate_findings,
)
from app.models.schemas import (
    AnalyzerType,
    Finding,
    RiskLevel,
    Severity,
    ThreatCategory,
)


def _make_finding(severity: Severity, category: ThreatCategory = ThreatCategory.OTHER, line: int = 1, title: str = "test") -> Finding:
    return Finding(
        category=category,
        severity=severity,
        analyzer=AnalyzerType.STATIC,
        title=title,
        description="test finding",
        line_number=line,
    )


class TestRiskScore:

    def test_no_findings(self):
        assert calculate_risk_score([]) == 0

    def test_single_critical(self):
        findings = [_make_finding(Severity.CRITICAL)]
        score = calculate_risk_score(findings)
        assert score == 25

    def test_single_info(self):
        findings = [_make_finding(Severity.INFO)]
        score = calculate_risk_score(findings)
        assert score == 1

    def test_multiple_findings(self):
        findings = [
            _make_finding(Severity.CRITICAL),
            _make_finding(Severity.HIGH),
            _make_finding(Severity.MEDIUM),
        ]
        score = calculate_risk_score(findings)
        assert score == 25 + 15 + 8  # 48

    def test_score_capped_at_100(self):
        findings = [_make_finding(Severity.CRITICAL) for _ in range(10)]
        score = calculate_risk_score(findings)
        assert score == 100


class TestRiskLevel:

    def test_safe(self):
        assert get_risk_level(0) == RiskLevel.SAFE
        assert get_risk_level(5) == RiskLevel.SAFE

    def test_low(self):
        assert get_risk_level(15) == RiskLevel.LOW

    def test_medium(self):
        assert get_risk_level(45) == RiskLevel.MEDIUM

    def test_high(self):
        assert get_risk_level(70) == RiskLevel.HIGH

    def test_critical(self):
        assert get_risk_level(90) == RiskLevel.CRITICAL
        assert get_risk_level(100) == RiskLevel.CRITICAL


class TestSummary:

    def test_no_findings_summary(self):
        summary = generate_summary([], RiskLevel.SAFE, 0)
        assert "No security issues" in summary

    def test_critical_summary(self):
        findings = [_make_finding(Severity.CRITICAL)]
        summary = generate_summary(findings, RiskLevel.CRITICAL, 90)
        assert "CRITICAL" in summary


class TestDeduplication:

    def test_same_finding_keeps_higher_severity(self):
        f1 = _make_finding(Severity.MEDIUM, ThreatCategory.CODE_INJECTION, line=10, title="eval() usage")
        f2 = _make_finding(Severity.CRITICAL, ThreatCategory.CODE_INJECTION, line=10, title="eval() usage")
        result = deduplicate_findings([f1, f2])
        assert len(result) == 1
        assert result[0].severity == Severity.CRITICAL

    def test_different_findings_kept(self):
        f1 = _make_finding(Severity.HIGH, ThreatCategory.REVERSE_SHELL, line=5, title="socket import")
        f2 = _make_finding(Severity.HIGH, ThreatCategory.CODE_INJECTION, line=10, title="eval usage")
        result = deduplicate_findings([f1, f2])
        assert len(result) == 2
